package server_test

import (
	"context"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

func TestVisibilityForCompilesBindings(t *testing.T) {
	t.Parallel()

	lister := func(scope authz.Scope) authz.Binding {
		return authz.Binding{ID: "b", Role: "lister", Scope: scope,
			Verbs: []authz.Verb{authz.RepoList, authz.RepoRead}}
	}

	tests := []struct {
		name     string
		bindings []authz.Binding
		verb     authz.Verb
		allowed  []string
		denied   []string
	}{
		{
			name:     "prefix scope shows the subtree and nothing beside it",
			bindings: []authz.Binding{lister("team-a/*")},
			verb:     authz.RepoList,
			allowed:  []string{"team-a/api", "team-a/sub/deep"},
			// "team-a" is not under "team-a/", and "team-ab" only shares a
			// string prefix -- the classic naive-prefix leak.
			denied: []string{"team-a", "team-ab/api", "team-b/api"},
		},
		{
			name:     "exact scope shows one repository",
			bindings: []authz.Binding{lister("team-b/api")},
			verb:     authz.RepoList,
			allowed:  []string{"team-b/api"},
			denied:   []string{"team-b/api-2", "team-b", "nginx"},
		},
		{
			name:     "scopes union across bindings",
			bindings: []authz.Binding{lister("team-a/*"), lister("nginx")},
			verb:     authz.RepoList,
			allowed:  []string{"team-a/api", "nginx"},
			denied:   []string{"team-b/api"},
		},
		{
			name:     "system scope selects no repositories",
			bindings: []authz.Binding{lister("system")},
			verb:     authz.RepoList,
			denied:   []string{"nginx", "system", "team-a/api"},
		},
		{
			name:     "a verb the bindings do not grant sees nothing",
			bindings: []authz.Binding{lister("team-a/*")},
			verb:     authz.RepoWrite,
			denied:   []string{"team-a/api"},
		},
		{
			name:   "no bindings sees nothing",
			verb:   authz.RepoList,
			denied: []string{"nginx", "team-a/api"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			visibility := server.VisibilityFor(tt.bindings, tt.verb)
			for _, name := range tt.allowed {
				if !visibility.Allows(name) {
					t.Errorf("Allows(%q) = false, want the bindings to show it", name)
				}
			}
			for _, name := range tt.denied {
				if visibility.Allows(name) {
					t.Errorf("Allows(%q) = true, want it hidden", name)
				}
			}
		})
	}
}

// A subject bound to every repository still goes through the filtered path.
// Unrestricted is reserved for internal callers with no subject at all
// (migrations, GC): if a binding could compile to it, the day the two paths
// diverge nobody would notice which one a wildcard subject was on.
func TestVisibilityForNeverCompilesToUnrestricted(t *testing.T) {
	t.Parallel()

	everything := []authz.Binding{{ID: "b", Role: "admin", Scope: "*",
		Verbs: []authz.Verb{authz.RepoList}}}

	visibility := server.VisibilityFor(everything, authz.RepoList)
	if visibility.IsUnrestricted() {
		t.Fatal("a wildcard binding compiled to Unrestricted")
	}
	for _, name := range []string{"nginx", "team-a/api"} {
		if !visibility.Allows(name) {
			t.Errorf("Allows(%q) = false, want the wildcard to show everything", name)
		}
	}
}

// The whole pipeline against a real store: subject → effective bindings →
// visibility → filtered listing. This is where repo:list is actually enforced,
// which is why the §9 marks live here — a subject granted it sees exactly its
// scope, and a subject without it sees nothing, wildcard scope or not.
func TestListRepositoriesFiltersByEffectiveBindings(t *testing.T) {
	t.Parallel()

	verbtest.Positive(t, authz.RepoList)
	verbtest.Negative(t, authz.RepoList)

	ctx := context.Background()
	store := memory.New()
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	for _, name := range []string{"team-a/api", "team-a/web", "team-b/api", "public/nginx"} {
		if _, err := store.CreateRepository(ctx, meta.Repository{Name: name, Type: meta.Hosted}); err != nil {
			t.Fatalf("CreateRepository(%q): %v", name, err)
		}
	}
	// "lister" carries repo:list; "pusher" deliberately does not, so bob is the
	// verb-negative case rather than the scope-negative one: his scope covers
	// every repository and it must not matter.
	for _, role := range []meta.Role{
		{Name: "lister", Verbs: []string{"repo:list", "repo:read"}},
		{Name: "pusher", Verbs: []string{"repo:write"}},
	} {
		if err := store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole(%q): %v", role.Name, err)
		}
	}
	for _, subject := range []meta.Subject{
		{ID: "u-alice", Kind: meta.User, Name: "alice"},
		{ID: "u-bob", Kind: meta.User, Name: "bob"},
		{ID: "u-mallory", Kind: meta.User, Name: "mallory"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject(%q): %v", subject.Name, err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "vb-alice", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-alice", Role: "lister", Scope: "team-a/*"},
		{ID: "vb-bob", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-bob", Role: "pusher", Scope: "*"},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding(%q): %v", binding.ID, err)
		}
	}

	list := func(t *testing.T, subject string) []string {
		t.Helper()
		bindings, err := server.FetchBindings(ctx, store, subject)
		if err != nil {
			t.Fatalf("FetchBindings(%q): %v", subject, err)
		}
		page, err := store.ListRepositories(ctx, meta.ListOptions{
			Visibility: server.VisibilityFor(bindings, authz.RepoList),
		})
		if err != nil {
			t.Fatalf("ListRepositories for %q: %v", subject, err)
		}
		var names []string
		for _, repo := range page.Repositories {
			names = append(names, repo.Name)
		}
		return names
	}

	if got := list(t, "alice"); len(got) != 2 || got[0] != "team-a/api" || got[1] != "team-a/web" {
		t.Errorf("alice sees %v, want exactly [team-a/api team-a/web]", got)
	}
	if got := list(t, "bob"); len(got) != 0 {
		t.Errorf("bob sees %v, want nothing: his wildcard binding does not grant repo:list", got)
	}
	if got := list(t, "mallory"); len(got) != 0 {
		t.Errorf("mallory sees %v, want nothing: she holds no bindings at all", got)
	}
}
