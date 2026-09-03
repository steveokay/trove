package authz_test

import (
	"errors"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

func TestBindingValidate(t *testing.T) {
	t.Parallel()

	valid := authz.Binding{
		ID:    "b1",
		Role:  "developer",
		Scope: "team-a/*",
		Verbs: []authz.Verb{authz.RepoList, authz.RepoRead},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// A role with no verbs is odd but legal: an operator can create an empty
	// role and fill it in later, and it grants nothing meanwhile.
	empty := valid
	empty.Verbs = nil
	if err := empty.Validate(); err != nil {
		t.Errorf("a binding to a role with no verbs = %v, want nil", err)
	}

	tests := []struct {
		name    string
		binding authz.Binding
	}{
		{
			name:    "no role",
			binding: authz.Binding{ID: "b1", Scope: "team-a/*", Verbs: []authz.Verb{authz.RepoRead}},
		},
		{
			name:    "no scope",
			binding: authz.Binding{ID: "b1", Role: "developer", Verbs: []authz.Verb{authz.RepoRead}},
		},
		{
			name:    "invalid scope",
			binding: authz.Binding{ID: "b1", Role: "developer", Scope: "team-*/api"},
		},
		{
			name: "unknown verb",
			binding: authz.Binding{
				ID: "b1", Role: "developer", Scope: "*",
				Verbs: []authz.Verb{authz.RepoRead, "repo:admin"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Storing a binding that could never grant anything is worse than
			// refusing it: it reads as a grant in the explainer and is none.
			err := tt.binding.Validate()
			if !errors.Is(err, authz.ErrInvalidBinding) {
				t.Fatalf("Validate = %v, want ErrInvalidBinding", err)
			}
		})
	}
}

func TestBindingGrantsAndAllows(t *testing.T) {
	t.Parallel()

	binding := authz.Binding{
		ID:    "b1",
		Role:  "developer",
		Scope: "team-a/*",
		Verbs: []authz.Verb{authz.RepoList, authz.RepoRead},
	}

	if !binding.Grants(authz.RepoRead) {
		t.Error("Grants(repo:read) = false for a role that has it")
	}
	// Scope is a separate question: the query layer asks this one alone, with
	// no single resource to check against.
	if binding.Grants(authz.RepoWrite) {
		t.Error("Grants(repo:write) = true for a role that does not have it")
	}

	inScope, err := authz.Repository("team-a/api")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	outOfScope, err := authz.Repository("team-b/api")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}

	if !binding.Allows(authz.RepoRead, inScope) {
		t.Error("Allows(repo:read, team-a/api) = false")
	}
	if binding.Allows(authz.RepoRead, outOfScope) {
		t.Error("Allows(repo:read, team-b/api) = true: the scope does not cover it")
	}
	if binding.Allows(authz.RepoWrite, inScope) {
		t.Error("Allows(repo:write, team-a/api) = true: the role does not grant it")
	}
	// Repository scopes never reach the system resource, however wide.
	if binding.Allows(authz.RepoRead, authz.System()) {
		t.Error("a repository binding allows something at system scope")
	}
}

// A binding that never went through validation grants nothing, rather than
// grants everything: an unparseable scope matches no resource and a verb
// outside the vocabulary is not the verb anything checks for.
func TestInvalidBindingsGrantNothing(t *testing.T) {
	t.Parallel()

	resource, err := authz.Repository("team-a/api")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}

	bindings := []authz.Binding{
		{ID: "b1", Role: "r", Scope: "team-*/api", Verbs: []authz.Verb{authz.RepoRead}},
		{ID: "b2", Role: "r", Scope: "../*", Verbs: []authz.Verb{authz.RepoRead}},
		{ID: "b3", Role: "r", Scope: "", Verbs: []authz.Verb{authz.RepoRead}},
		{ID: "b4", Role: "r", Scope: "*", Verbs: []authz.Verb{"repo:admin"}},
	}
	for _, binding := range bindings {
		if binding.Allows(authz.RepoRead, resource) {
			t.Errorf("binding %s with scope %q allowed something", binding.ID, binding.Scope)
		}
	}
}

func TestSortBindings(t *testing.T) {
	t.Parallel()

	bindings := []authz.Binding{{ID: "b3"}, {ID: "b1"}, {ID: "b2"}}
	authz.SortBindings(bindings)

	// A decision's explanation and its audit record read the same way every
	// time, whatever order the store returned.
	for i, want := range []string{"b1", "b2", "b3"} {
		if bindings[i].ID != want {
			t.Errorf("bindings[%d] = %s, want %s", i, bindings[i].ID, want)
		}
	}
}
