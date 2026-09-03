package authz_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

func TestParseScope(t *testing.T) {
	t.Parallel()

	valid := []string{
		"system",
		"*",
		"nginx",
		"library/nginx",
		"team-a/api",
		"team-a/*",
		"all/library/*",
		"registry.k8s.io/pause",
	}
	for _, input := range valid {
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			scope, err := authz.ParseScope(input)
			if err != nil {
				t.Fatalf("ParseScope(%q) = %v", input, err)
			}
			if string(scope) != input {
				t.Errorf("scope = %q, want it unchanged", scope)
			}
			if err := scope.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
			if scope.String() != input {
				t.Errorf("String() = %q, want %q", scope, input)
			}
		})
	}
}

// The grammar is total: everything is one of the four forms or a typed error.
// A pattern that could not name a legal repository never reaches storage,
// which is what closes traversal through a binding pattern (ADR 0001).
func TestParseScopeRejections(t *testing.T) {
	t.Parallel()

	invalid := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"mid-pattern wildcard", "team-*/api"},
		{"leading wildcard", "*/prod"},
		{"double wildcard", "**"},
		{"nested wildcards", "team-a/*/api"},
		{"wildcard without prefix", "/*"},
		{"bare slash", "/"},
		{"trailing slash", "team-a/"},
		{"traversal", "../etc/passwd"},
		{"traversal in prefix", "../etc/*"},
		{"traversal segment", "team-a/../secret"},
		{"traversal segment wildcard", "team-a/../*"},
		{"empty segment", "team-a//api"},
		{"uppercase", "Team-A/*"},
		{"space", "team a/*"},
		{"null byte", "team\x00a"},
		{"backslash", `team-a\*`},
		{"wildcard suffix without separator", "team-a*"},
		{"system with wildcard", "system/*"},
		{"repository under system", "system/api"},
		{"system prefix wildcard", "system/sub/*"},
		{"tag scope", "team-a/api:latest"},
		{"digest scope", "team-a/api@sha256:abc"},
	}

	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := authz.ParseScope(tt.input)
			if !errors.Is(err, authz.ErrInvalidScope) {
				t.Fatalf("ParseScope(%q) = %v, want ErrInvalidScope", tt.input, err)
			}

			var invalidErr *authz.InvalidScopeError
			if !errors.As(err, &invalidErr) {
				t.Fatalf("error type = %T, want *authz.InvalidScopeError", err)
			}
			if invalidErr.Scope != tt.input {
				t.Errorf("error carries %q, want %q", invalidErr.Scope, tt.input)
			}
			if invalidErr.Reason == "" {
				t.Error("error carries no reason")
			}

			// A Scope can be produced by conversion, so Validate has to be as
			// strict as the parser -- and an unvalidated scope must match
			// nothing rather than everything.
			scope := authz.Scope(tt.input)
			if err := scope.Validate(); !errors.Is(err, authz.ErrInvalidScope) {
				t.Errorf("Scope(%q).Validate() = %v, want ErrInvalidScope", tt.input, err)
			}
			resource, err := authz.Repository("team-a/api")
			if err != nil {
				t.Fatalf("Repository: %v", err)
			}
			if scope.Matches(resource) || scope.Matches(authz.System()) {
				t.Errorf("Scope(%q) matches something despite being invalid", tt.input)
			}
		})
	}
}

func TestResource(t *testing.T) {
	t.Parallel()

	system := authz.System()
	if !system.IsSystem() || system.IsRepository() {
		t.Error("System() is not the system resource")
	}
	if system.Name() != "" {
		t.Errorf("System().Name() = %q, want empty", system.Name())
	}
	if system.String() != "system" {
		t.Errorf("String() = %q, want system", system)
	}

	repository, err := authz.Repository("team-a/api")
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	if !repository.IsRepository() || repository.IsSystem() {
		t.Error("Repository() is not a repository resource")
	}
	if repository.Name() != "team-a/api" {
		t.Errorf("Name() = %q, want team-a/api", repository.Name())
	}
	if !strings.Contains(repository.String(), "team-a/api") {
		t.Errorf("String() = %q, want it to name the repository", repository)
	}

	// Names arrive from URLs, so this is a gate rather than a formality.
	if _, err := authz.Repository("../etc/passwd"); err == nil {
		t.Error("Repository accepted a traversal string")
	}

	// The zero value is meaningless rather than dangerous: nothing matches it.
	var zero authz.Resource
	if zero.IsSystem() || zero.IsRepository() {
		t.Error("the zero Resource claims to be something")
	}
	if zero.String() != "invalid resource" {
		t.Errorf("String() = %q, want it to say so", zero)
	}
	for _, scope := range []authz.Scope{authz.SystemScope, authz.AllRepositories, "team-a/*", "team-a/api"} {
		if scope.Matches(zero) {
			t.Errorf("%s matches the zero Resource", scope)
		}
	}
}

// The matrix that matters: which scope covers which resource. Overlap between
// patterns is irrelevant because nothing can subtract (Q14), so this is the
// whole of the rule.
func TestScopeMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scope    authz.Scope
		resource string // empty means the system resource
		want     bool
	}{
		// The system scope and the repository scopes are disjoint.
		{scope: "system", want: true},
		{scope: "system", resource: "team-a/api"},
		{scope: "*", want: false},
		{scope: "*", resource: "team-a/api", want: true},
		{scope: "*", resource: "nginx", want: true},
		{scope: "team-a/api", want: false},

		// Exact.
		{scope: "team-a/api", resource: "team-a/api", want: true},
		{scope: "team-a/api", resource: "team-a/api-2"},
		{scope: "team-a/api", resource: "team-a"},
		{scope: "team-a/api", resource: "team-a/api/sub"},

		// Prefix: everything under it, at any depth, but not the repository
		// that shares the prefix's name.
		{scope: "team-a/*", resource: "team-a/api", want: true},
		{scope: "team-a/*", resource: "team-a/sub/api", want: true},
		{scope: "team-a/*", resource: "team-a"},
		{scope: "team-a/*", resource: "team-ab/api"},
		{scope: "team-a/*", resource: "team-a-b/api"},
		{scope: "team-a/*", resource: "other/team-a/api"},

		// A prefix grants everything beneath it, including what looks
		// private: carve-outs are impossible by design, and the remedy is
		// naming discipline (ADR 0001).
		{scope: "team-a/*", resource: "team-a/secret", want: true},

		// The wildcard covers every repository, however deep.
		{scope: "*", resource: "all/library/nginx", want: true},
	}

	for _, tt := range tests {
		name := string(tt.scope) + " vs " + tt.resource
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resource := authz.System()
			if tt.resource != "" {
				var err error
				resource, err = authz.Repository(tt.resource)
				if err != nil {
					t.Fatalf("Repository(%q): %v", tt.resource, err)
				}
			}
			if got := tt.scope.Matches(resource); got != tt.want {
				t.Errorf("%s.Matches(%s) = %v, want %v", tt.scope, resource, got, tt.want)
			}
		})
	}
}

// "system" is a legal repository name, so the keyword is reserved: an exact
// scope can never name a repository called system. Repository creation refuses
// the name for that reason (C-016), and this pins the behaviour that makes the
// refusal necessary.
func TestSystemScopeIsReserved(t *testing.T) {
	t.Parallel()

	scope, err := authz.ParseScope("system")
	if err != nil {
		t.Fatalf("ParseScope: %v", err)
	}
	if scope != authz.SystemScope {
		t.Fatalf("ParseScope(system) = %q, want the system scope", scope)
	}

	repository, err := authz.Repository("system")
	if err != nil {
		t.Fatalf("Repository(system): %v", err)
	}
	if scope.Matches(repository) {
		t.Error("the system scope matches a repository named system")
	}
	// It is still reachable by the wildcard, so the reservation costs only
	// the ability to name it specifically.
	if !authz.AllRepositories.Matches(repository) {
		t.Error("a repository named system is invisible to the wildcard scope")
	}

	// The reservation covers the whole prefix, not just the bare word: a
	// binding written as admin@system/* by somebody who meant the global scope
	// would otherwise grant nothing while looking like it granted everything.
	for _, input := range []string{"system/*", "system/api", "system/sub/*"} {
		if _, err := authz.ParseScope(input); !errors.Is(err, authz.ErrInvalidScope) {
			t.Errorf("ParseScope(%q) = %v, want ErrInvalidScope", input, err)
		}
	}
}
