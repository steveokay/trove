package authz_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

// The built-in roles are what an operator gets before they configure anything,
// so their contents are the contract. ADR 0001's table is written out here:
// changing what "developer" grants has to be a deliberate edit in both places.
func TestBuiltinRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role  string
		verbs []authz.Verb
	}{
		{
			role: authz.RolePublisher,
			verbs: []authz.Verb{
				authz.ReferrerRead, authz.RepoList, authz.RepoRead, authz.RepoWrite,
				authz.ScanRead, authz.SearchRead, authz.TagDelete,
			},
		},
		{
			role: authz.RoleDeveloper,
			verbs: []authz.Verb{
				authz.ReferrerRead, authz.RepoList, authz.RepoRead, authz.ScanRead, authz.SearchRead,
			},
		},
		{
			role:  authz.RoleAnonymousReader,
			verbs: []authz.Verb{authz.ReferrerRead, authz.RepoList, authz.RepoRead},
		},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			t.Parallel()

			role, ok := authz.BuiltinRole(tt.role)
			if !ok {
				t.Fatalf("%s is not a built-in role", tt.role)
			}
			if !role.Builtin {
				t.Error("Builtin = false for a built-in role")
			}
			if len(role.Verbs) != len(tt.verbs) {
				t.Fatalf("verbs = %v, want %v", role.Verbs, tt.verbs)
			}
			for i := range role.Verbs {
				if role.Verbs[i] != tt.verbs[i] {
					t.Errorf("verb %d = %s, want %s", i, role.Verbs[i], tt.verbs[i])
				}
			}
		})
	}
}

// admin holds every verb. Nothing implies anything else in this model, so the
// only way admin can break glass past a vulnerability block is by holding
// gate:override literally -- which ADR 0001 says it does and ADR 0002's
// non-implication rule does not contradict.
func TestAdminHoldsEveryVerb(t *testing.T) {
	t.Parallel()

	admin, ok := authz.BuiltinRole(authz.RoleAdmin)
	if !ok {
		t.Fatal("admin is not a built-in role")
	}
	for _, verb := range authz.AllVerbs() {
		if !admin.Grants(verb) {
			t.Errorf("admin does not grant %s", verb)
		}
	}
	if !admin.Grants(authz.GateOverride) {
		t.Error("admin does not grant gate:override: it must hold it explicitly, since nothing implies it")
	}
}

// operator runs the registry without administering its people. The split is
// the whole point of the role: an operator who could grant themselves
// user:write would make every other boundary advisory.
func TestOperatorCannotAdministerPeople(t *testing.T) {
	t.Parallel()

	operator, ok := authz.BuiltinRole(authz.RoleOperator)
	if !ok {
		t.Fatal("operator is not a built-in role")
	}

	for _, verb := range []authz.Verb{authz.UserRead, authz.UserWrite, authz.RoleRead, authz.RoleWrite} {
		if operator.Grants(verb) {
			t.Errorf("operator grants %s, which is user and role administration", verb)
		}
	}
	// Everything else it does hold, so the role is "everything except", not a
	// hand-picked list that quietly falls behind the vocabulary.
	for _, verb := range authz.AllVerbs() {
		administrative := strings.HasPrefix(string(verb), "user:") || strings.HasPrefix(string(verb), "role:")
		if administrative {
			continue
		}
		if !operator.Grants(verb) {
			t.Errorf("operator does not grant %s", verb)
		}
	}
}

// auditor reads everything and writes nothing. A role that could write would
// not be an auditor, and one that could not see a repository exists could not
// audit it.
func TestAuditorReadsEverythingAndWritesNothing(t *testing.T) {
	t.Parallel()

	auditor, ok := authz.BuiltinRole(authz.RoleAuditor)
	if !ok {
		t.Fatal("auditor is not a built-in role")
	}

	if !auditor.Grants(authz.AuditRead) {
		t.Error("auditor does not grant audit:read")
	}
	if !auditor.Grants(authz.RepoList) {
		t.Error("auditor cannot see that a repository exists")
	}
	for _, verb := range authz.AllVerbs() {
		if strings.HasSuffix(string(verb), ":read") && !auditor.Grants(verb) {
			t.Errorf("auditor does not grant %s", verb)
		}
	}

	// Nothing that changes anything, including the two that are spelled
	// without "write".
	for _, verb := range []authz.Verb{
		authz.RepoWrite, authz.TagDelete, authz.ManifestDelete, authz.RepoCreate,
		authz.RepoConfigure, authz.RepoDelete, authz.PolicyWrite, authz.PolicyApply,
		authz.GateOverride, authz.ProxyWrite, authz.ProxyCredentials, authz.QuotaWrite,
		authz.WebhookWrite, authz.UserWrite, authz.RoleWrite, authz.GCRun,
		authz.SystemMaintenance, authz.ScanTrigger,
	} {
		if auditor.Grants(verb) {
			t.Errorf("auditor grants %s, which is not a read", verb)
		}
	}
}

func TestBuiltinRolesAreListedAndCopied(t *testing.T) {
	t.Parallel()

	roles := authz.BuiltinRoles()
	want := []string{
		authz.RoleAdmin, authz.RoleAnonymousReader, authz.RoleAuditor,
		authz.RoleDeveloper, authz.RoleOperator, authz.RolePublisher,
	}
	if len(roles) != len(want) {
		t.Fatalf("BuiltinRoles returned %d roles, want %d", len(roles), len(want))
	}
	for i, role := range roles {
		if role.Name != want[i] {
			t.Errorf("role %d = %s, want %s (ordered by name)", i, role.Name, want[i])
		}
		if !role.Builtin {
			t.Errorf("%s does not report itself as built in", role.Name)
		}
		if !authz.IsBuiltin(role.Name) {
			t.Errorf("IsBuiltin(%s) = false", role.Name)
		}
	}

	// Mutating a returned role must not reach the definitions: they are what
	// the bootstrap path seeds and what a drift test compares against.
	roles[0].Verbs[0] = "mutated"
	again := authz.BuiltinRoles()
	if again[0].Verbs[0] == "mutated" {
		t.Error("BuiltinRoles hands out the package's own slice")
	}

	if _, ok := authz.BuiltinRole("nonexistent"); ok {
		t.Error("BuiltinRole invented a role")
	}
	if authz.IsBuiltin("nonexistent") {
		t.Error("IsBuiltin invented a role")
	}
}

// anonymous-reader exists but ships unbound: a fresh install is not readable
// by the internet because somebody forgot to look (ADR 0001).
func TestAnonymousReaderIsReadOnly(t *testing.T) {
	t.Parallel()

	role, ok := authz.BuiltinRole(authz.RoleAnonymousReader)
	if !ok {
		t.Fatal("anonymous-reader is not a built-in role")
	}
	for _, verb := range role.Verbs {
		if !strings.HasSuffix(string(verb), ":read") && verb != authz.RepoList {
			t.Errorf("anonymous-reader grants %s, which is not a read", verb)
		}
	}
}

func TestNewRole(t *testing.T) {
	t.Parallel()

	role, err := authz.NewRole("releaser", []string{"repo:write", "repo:read", "repo:read"})
	if err != nil {
		t.Fatalf("NewRole: %v", err)
	}
	if role.Builtin {
		t.Error("a custom role claims to be built in")
	}
	// Canonical at rest: sorted and deduplicated, so two roles granting the
	// same thing look the same in the explainer and in the database.
	if len(role.Verbs) != 2 || role.Verbs[0] != authz.RepoRead || role.Verbs[1] != authz.RepoWrite {
		t.Errorf("verbs = %v, want [repo:read repo:write]", role.Verbs)
	}
	if err := role.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// There is deliberately no verb a custom role cannot hold: a permission an
	// administrator cannot delegate would be one that only exists in code.
	everything := make([]string, 0, len(authz.AllVerbs()))
	for _, verb := range authz.AllVerbs() {
		everything = append(everything, string(verb))
	}
	custom, err := authz.NewRole("shadow-admin", everything)
	if err != nil {
		t.Fatalf("NewRole with every verb: %v", err)
	}
	if len(custom.Verbs) != len(authz.AllVerbs()) {
		t.Errorf("custom role holds %d verbs, want all %d", len(custom.Verbs), len(authz.AllVerbs()))
	}

	empty, err := authz.NewRole("empty", nil)
	if err != nil {
		t.Fatalf("NewRole with no verbs: %v", err)
	}
	if len(empty.Verbs) != 0 {
		t.Errorf("verbs = %v, want none", empty.Verbs)
	}
}

func TestRoleValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		role  string
		verbs []string
	}{
		{name: "no name", verbs: []string{"repo:read"}},
		{name: "unknown verb", role: "releaser", verbs: []string{"repo:read", "repo:admin"}},
		{name: "wildcard verb", role: "releaser", verbs: []string{"repo:*"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := authz.NewRole(tt.role, tt.verbs); !errors.Is(err, authz.ErrInvalidRole) {
				t.Errorf("NewRole = %v, want ErrInvalidRole", err)
			}
		})
	}

	// Validate is also reachable on a role built by hand, and has to be as
	// strict as the constructor.
	direct := authz.Role{Name: "releaser", Verbs: []authz.Verb{"repo:admin"}}
	if err := direct.Validate(); !errors.Is(err, authz.ErrInvalidRole) {
		t.Errorf("Validate = %v, want ErrInvalidRole", err)
	}
	if !errors.Is(direct.Validate(), authz.ErrUnknownVerb) {
		t.Error("the error does not say which part was wrong")
	}
}
