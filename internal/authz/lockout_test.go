package authz_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// lockoutFixture is a deployment with two would-be administrators and one
// bystander:
//
//   - root holds role:write@system directly (binding b-root)
//   - chief holds it twice: directly (b-chief) and through the group
//     "admins" (b-group)
//   - dev holds repo:write at "*" -- broad, but not an administrator
//
// Each test whittles this down along one removal vector and asks the
// evaluator whether anyone can still administer roles.
func lockoutFixture(t *testing.T) *memory.Store {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	for _, subject := range []meta.Subject{
		{ID: "u-root", Kind: meta.User, Name: "root"},
		{ID: "u-chief", Kind: meta.User, Name: "chief"},
		{ID: "u-dev", Kind: meta.User, Name: "dev"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	if err := store.CreateGroup(ctx, meta.SubjectGroup{ID: "gid-admins", Name: "admins"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := store.AddGroupMember(ctx, "admins", "chief"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	for _, role := range []meta.Role{
		{Name: "role-admin", Verbs: []string{"role:write", "role:read"}},
		{Name: "pusher", Verbs: []string{"repo:write"}},
	} {
		if err := store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-root", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-root", Role: "role-admin", Scope: "system"},
		{ID: "b-chief", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-chief", Role: "role-admin", Scope: "system"},
		{ID: "b-group", PrincipalKind: meta.PrincipalGroup, PrincipalID: "gid-admins", Role: "role-admin", Scope: "system"},
		{ID: "b-dev", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-dev", Role: "pusher", Scope: "*"},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}
	return store
}

// effective returns each named subject's effective bindings, the way a
// mutation handler will assemble them: one FetchBindings per subject, so the
// evaluator sees exactly what the decision function would.
func effective(t *testing.T, store *memory.Store, subjects ...string) map[string][]authz.Binding {
	t.Helper()
	out := make(map[string][]authz.Binding, len(subjects))
	for _, subject := range subjects {
		bindings, err := server.FetchBindings(context.Background(), store, subject)
		if err != nil {
			t.Fatalf("FetchBindings(%q): %v", subject, err)
		}
		out[subject] = bindings
	}
	return out
}

func remaining(state map[string][]authz.Binding) [][]authz.Binding {
	out := make([][]authz.Binding, 0, len(state))
	for _, bindings := range state {
		out = append(out, bindings)
	}
	return out
}

func TestAdminGrant(t *testing.T) {
	t.Parallel()

	store := lockoutFixture(t)
	state := effective(t, store, "root", "chief", "dev")

	if !authz.AdminGrant(state["root"]) || !authz.AdminGrant(state["chief"]) {
		t.Error("the administrators do not read as administrators")
	}
	// Scope disjointness: repo:write at "*" reaches every repository and no
	// part of the system scope. Breadth is not administration.
	if authz.AdminGrant(state["dev"]) {
		t.Error("a repository-wide grant read as system administration")
	}
	if authz.AdminGrant(nil) {
		t.Error("no bindings read as administration")
	}
}

// The exact §5 scenario, along every removal vector: whatever would leave the
// deployment with nobody able to administer roles is refused with a clear
// error, and anything redundant goes through.
func TestEnsureAdminRemains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// after mutates the effective state the way one removal vector would.
		after   func(map[string][]authz.Binding) map[string][]authz.Binding
		lockout bool
	}{
		{
			name:  "untouched state is fine",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding { return s },
		},
		{
			// Two admins: one may lose their grant.
			name: "removing a redundant admin's binding succeeds",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				s["root"] = authz.WithoutBinding(s["root"], "b-root")
				return s
			},
		},
		{
			// chief still holds the group-carried grant after losing the
			// direct one, and root is untouched.
			name: "removing one of a subject's two grants succeeds",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				s["chief"] = authz.WithoutBinding(s["chief"], "b-chief")
				return s
			},
		},
		{
			name: "removing every admin binding is refused",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				s["root"] = authz.WithoutBinding(s["root"], "b-root")
				s["chief"] = authz.WithoutBinding(s["chief"], "b-chief")
				s["chief"] = authz.WithoutGroup(s["chief"], "admins")
				return s
			},
			lockout: true,
		},
		{
			// Deleting the role cascades every binding that granted it
			// (store contract) -- the cascade is the removal vector.
			name: "deleting the admin role is refused",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				for subject := range s {
					s[subject] = authz.WithoutRole(s[subject], "role-admin")
				}
				return s
			},
			lockout: true,
		},
		{
			// Group membership is a removal vector too (§5): losing the
			// group must count exactly like losing a binding.
			name: "leaving the group is fine while direct grants remain",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				s["chief"] = authz.WithoutGroup(s["chief"], "admins")
				return s
			},
		},
		{
			name: "disabling or deleting the last admins is refused",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				// A disabled subject has no effective bindings at all
				// (store contract), and a deleted one is not in the state.
				delete(s, "root")
				delete(s, "chief")
				return s
			},
			lockout: true,
		},
		{
			// Narrowing the role's verbs is the subtle vector: the bindings
			// all survive, and none of them grants anything that matters.
			name: "narrowing the admin role below role:write is refused",
			after: func(s map[string][]authz.Binding) map[string][]authz.Binding {
				for subject, bindings := range s {
					for i, binding := range bindings {
						if binding.Role == "role-admin" {
							bindings[i].Verbs = []authz.Verb{authz.RoleRead}
						}
					}
					s[subject] = bindings
				}
				return s
			},
			lockout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := lockoutFixture(t)
			state := tt.after(effective(t, store, "root", "chief", "dev"))

			err := authz.EnsureAdminRemains(remaining(state))
			if tt.lockout {
				if !errors.Is(err, authz.ErrLastAdmin) {
					t.Fatalf("EnsureAdminRemains = %v, want ErrLastAdmin", err)
				}
				// The message is what the API surfaces verbatim (§5): it has
				// to say what to do, not only what was refused.
				if msg := err.Error(); !strings.Contains(msg, "role:write") || !strings.Contains(msg, "system") {
					t.Errorf("error %q does not name the grant that must remain", msg)
				}
			} else if err != nil {
				t.Fatalf("EnsureAdminRemains = %v, want the change allowed", err)
			}
		})
	}
}

func TestRemovalHelpers(t *testing.T) {
	t.Parallel()

	store := lockoutFixture(t)
	state := effective(t, store, "chief")
	chief := state["chief"]
	if len(chief) != 2 {
		t.Fatalf("chief holds %d bindings, want the direct and the group-carried one", len(chief))
	}

	if got := authz.WithoutBinding(chief, "b-chief"); len(got) != 1 || got[0].ID != "b-group" {
		t.Errorf("WithoutBinding = %+v, want only the group-carried binding", got)
	}
	if got := authz.WithoutGroup(chief, "admins"); len(got) != 1 || got[0].ID != "b-chief" {
		t.Errorf("WithoutGroup = %+v, want only the direct binding", got)
	}
	if got := authz.WithoutRole(chief, "role-admin"); len(got) != 0 {
		t.Errorf("WithoutRole = %+v, want nothing: both bindings grant it", got)
	}

	// The helpers copy; the input survives for the caller's next simulation.
	if len(chief) != 2 {
		t.Error("a helper mutated its input")
	}
	if got := authz.WithoutBinding(nil, "x"); len(got) != 0 {
		t.Errorf("WithoutBinding(nil) = %+v", got)
	}
}
