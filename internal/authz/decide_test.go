package authz_test

import (
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

func repository(t *testing.T, name string) authz.Resource {
	t.Helper()

	resource, err := authz.Repository(name)
	if err != nil {
		t.Fatalf("Repository(%q): %v", name, err)
	}
	return resource
}

// binding is a shorthand for the fixtures below: a role's verbs at a scope.
func binding(id, scope string, verbs ...authz.Verb) authz.Binding {
	return authz.Binding{ID: id, Role: "role-" + id, Scope: authz.Scope(scope), Verbs: verbs}
}

// The table that matters: what a set of bindings permits. Every row is a
// question a handler will ask.
func TestDecide(t *testing.T) {
	t.Parallel()

	developer := binding("b1", "team-a/*", authz.RepoList, authz.RepoRead)
	publisher := binding("b2", "team-b/api", authz.RepoRead, authz.RepoWrite)
	admin := binding("b3", "system", authz.UserWrite, authz.GCRun)

	tests := []struct {
		name     string
		bindings []authz.Binding
		verb     authz.Verb
		resource string // empty means the system resource
		want     bool
		matched  []string
	}{
		{
			name:     "granted in scope",
			bindings: []authz.Binding{developer, publisher, admin},
			verb:     authz.RepoRead,
			resource: "team-a/api",
			want:     true,
			matched:  []string{"b1"},
		},
		{
			name:     "verb not held",
			bindings: []authz.Binding{developer},
			verb:     authz.RepoWrite,
			resource: "team-a/api",
		},
		{
			name:     "held but out of scope",
			bindings: []authz.Binding{developer},
			verb:     authz.RepoRead,
			resource: "team-b/api",
		},
		{
			name:     "exact scope",
			bindings: []authz.Binding{developer, publisher},
			verb:     authz.RepoWrite,
			resource: "team-b/api",
			want:     true,
			matched:  []string{"b2"},
		},
		{
			// Two bindings can grant the same thing; both are reported,
			// because the explainer's job is to show every reason.
			name: "two grants match",
			bindings: []authz.Binding{
				developer,
				binding("b4", "*", authz.RepoRead),
			},
			verb:     authz.RepoRead,
			resource: "team-a/api",
			want:     true,
			matched:  []string{"b1", "b4"},
		},
		{
			name:     "system verb at system scope",
			bindings: []authz.Binding{admin},
			verb:     authz.UserWrite,
			want:     true,
			matched:  []string{"b3"},
		},
		{
			// The scopes are disjoint: everything-repositories is not
			// everything.
			name:     "wildcard does not reach the system",
			bindings: []authz.Binding{binding("b5", "*", authz.UserWrite)},
			verb:     authz.UserWrite,
		},
		{
			name:     "system scope does not reach a repository",
			bindings: []authz.Binding{binding("b6", "system", authz.RepoRead)},
			verb:     authz.RepoRead,
			resource: "team-a/api",
		},
		{
			name:     "no bindings",
			bindings: nil,
			verb:     authz.RepoRead,
			resource: "team-a/api",
		},
		{
			// Pushing is not purging: the deliberate non-implications of
			// ADR 0002 are not rules in Decide, they are the absence of rules.
			name:     "write does not imply delete",
			bindings: []authz.Binding{binding("b7", "*", authz.RepoWrite)},
			verb:     authz.RepoDelete,
			resource: "team-a/api",
		},
		{
			name:     "policy write does not imply apply",
			bindings: []authz.Binding{binding("b8", "*", authz.PolicyWrite)},
			verb:     authz.PolicyApply,
			resource: "team-a/api",
		},
		{
			name:     "proxy write does not imply credentials",
			bindings: []authz.Binding{binding("b9", "*", authz.ProxyWrite)},
			verb:     authz.ProxyCredentials,
			resource: "team-a/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resource := authz.System()
			if tt.resource != "" {
				resource = repository(t, tt.resource)
			}

			decision := authz.Decide(tt.bindings, tt.verb, resource)
			if decision.Allowed != tt.want {
				t.Errorf("Allowed = %v, want %v (%s)", decision.Allowed, tt.want, decision)
			}
			if decision.Verb != tt.verb || decision.Resource != resource {
				t.Errorf("decision does not carry what was asked: %+v", decision)
			}
			if got := authz.Allows(tt.bindings, tt.verb, resource); got != tt.want {
				t.Errorf("Allows = %v, want %v", got, tt.want)
			}

			if len(decision.Matched) != len(tt.matched) {
				t.Fatalf("matched %d bindings, want %v", len(decision.Matched), tt.matched)
			}
			for i, want := range tt.matched {
				if decision.Matched[i].ID != want {
					t.Errorf("matched[%d] = %s, want %s", i, decision.Matched[i].ID, want)
				}
			}
		})
	}
}

// A denial explains itself by what is missing; a grant by what produced it.
// These strings end up in audit records and in `trove auth explain`.
func TestDecisionExplains(t *testing.T) {
	t.Parallel()

	resource := repository(t, "team-a/api")
	granted := authz.Decide([]authz.Binding{
		{ID: "b1", Role: "developer", Scope: "team-a/*", Verbs: []authz.Verb{authz.RepoRead}, ViaGroup: "platform"},
	}, authz.RepoRead, resource)

	explanation := granted.String()
	for _, want := range []string{"allowed", "repo:read", "team-a/api", "b1", "developer", "team-a/*", "platform"} {
		if !strings.Contains(explanation, want) {
			t.Errorf("explanation %q does not mention %q", explanation, want)
		}
	}

	denied := authz.Decide(nil, authz.RepoRead, resource)
	explanation = denied.String()
	if !strings.Contains(explanation, "denied") || !strings.Contains(explanation, "no binding grants it") {
		t.Errorf("denial explanation = %q", explanation)
	}
	// A denial that listed the bindings the subject does hold would leak what
	// it has access to elsewhere into an error it can read.
	if strings.Contains(explanation, "role ") {
		t.Errorf("denial explanation names a role: %q", explanation)
	}

	// Every reason is listed, not just the first: an operator removing one
	// grant needs to know the other one is still there.
	both := authz.Decide([]authz.Binding{
		{ID: "b1", Role: "developer", Scope: "team-a/*", Verbs: []authz.Verb{authz.RepoRead}},
		{ID: "b2", Role: "auditor", Scope: "*", Verbs: []authz.Verb{authz.RepoRead}},
	}, authz.RepoRead, resource)
	explanation = both.String()
	for _, want := range []string{"b1", "b2", "developer", "auditor"} {
		if !strings.Contains(explanation, want) {
			t.Errorf("explanation %q does not mention %q", explanation, want)
		}
	}

	// A grant with no group says nothing about groups rather than saying
	// "via group ".
	direct := authz.Decide([]authz.Binding{
		{ID: "b2", Role: "admin", Scope: "system", Verbs: []authz.Verb{authz.UserWrite}},
	}, authz.UserWrite, authz.System())
	if strings.Contains(direct.String(), "via group") {
		t.Errorf("a direct grant claims a group: %q", direct)
	}
}

// A verb outside the vocabulary is refused before any binding is considered.
// A row can be edited in the database; a permission nothing enforces must not
// become one that everything does.
func TestDecideRefusesUnknownVerbs(t *testing.T) {
	t.Parallel()

	resource := repository(t, "team-a/api")
	bindings := []authz.Binding{
		{ID: "b1", Role: "shadow", Scope: "*", Verbs: []authz.Verb{"repo:admin"}},
	}

	decision := authz.Decide(bindings, "repo:admin", resource)
	if decision.Allowed {
		t.Error("a verb outside the vocabulary was allowed by a binding that holds it")
	}
	if len(decision.Matched) != 0 {
		t.Errorf("matched %v for an unknown verb", decision.Matched)
	}
}

// Bindings whose scope never parsed grant nothing: an unvalidated pattern
// matches no resource, so a row edited to "team-*" is inert rather than wide.
func TestDecideIgnoresInvalidBindings(t *testing.T) {
	t.Parallel()

	resource := repository(t, "team-a/api")
	bindings := []authz.Binding{
		binding("b1", "team-*", authz.RepoRead),
		binding("b2", "../*", authz.RepoRead),
		binding("b3", "", authz.RepoRead),
	}
	if decision := authz.Decide(bindings, authz.RepoRead, resource); decision.Allowed {
		t.Errorf("an invalid binding allowed something: %s", decision)
	}
}

// Built-in roles are the shipped configuration, so what they permit is worth
// asserting through the decision rather than only through their verb lists.
func TestDecideWithBuiltinRoles(t *testing.T) {
	t.Parallel()

	bindingFor := func(t *testing.T, name, scope string) authz.Binding {
		t.Helper()

		role, ok := authz.BuiltinRole(name)
		if !ok {
			t.Fatalf("%s is not a built-in role", name)
		}
		return authz.Binding{ID: "b-" + name, Role: name, Scope: authz.Scope(scope), Verbs: role.Verbs}
	}

	repo := repository(t, "team-a/api")

	developer := []authz.Binding{bindingFor(t, authz.RoleDeveloper, "team-a/*")}
	if !authz.Allows(developer, authz.RepoRead, repo) {
		t.Error("developer cannot read in scope")
	}
	if authz.Allows(developer, authz.RepoWrite, repo) {
		t.Error("developer can push")
	}

	auditor := []authz.Binding{bindingFor(t, authz.RoleAuditor, "*"), bindingFor(t, authz.RoleAuditor, "system")}
	if !authz.Allows(auditor, authz.AuditRead, authz.System()) {
		t.Error("auditor cannot read the audit log")
	}
	if authz.Allows(auditor, authz.RepoWrite, repo) {
		t.Error("auditor can write")
	}

	// An administrator holds both scopes, because they are disjoint.
	admin := []authz.Binding{
		bindingFor(t, authz.RoleAdmin, "system"),
		bindingFor(t, authz.RoleAdmin, "*"),
	}
	for _, verb := range authz.AllVerbs() {
		if !authz.Allows(admin, verb, repo) && !authz.Allows(admin, verb, authz.System()) {
			t.Errorf("admin cannot %s anywhere", verb)
		}
	}

	// An operator has everything except administering people, at either scope.
	operator := []authz.Binding{
		bindingFor(t, authz.RoleOperator, "system"),
		bindingFor(t, authz.RoleOperator, "*"),
	}
	if authz.Allows(operator, authz.UserWrite, authz.System()) {
		t.Error("operator can administer users")
	}
	if !authz.Allows(operator, authz.GCRun, authz.System()) {
		t.Error("operator cannot run garbage collection")
	}
}
