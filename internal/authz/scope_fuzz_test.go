package authz_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/reponame"
)

// scopeCorpus is the adversarial seed set: the shapes §9 calls out --
// traversal, overlap, and every way somebody might try to widen a pattern.
var scopeCorpus = []string{
	"system",
	"*",
	"team-a/api",
	"team-a/*",
	"all/library/*",
	"",
	"/",
	"/*",
	"**",
	"*/*",
	"*/prod",
	"team-*/api",
	"team-a/*/api",
	"team-a/",
	"team-a*",
	"../etc/passwd",
	"../*",
	"team-a/../secret",
	"team-a/../*",
	"team-a//api",
	"system/*",
	"system/api",
	"Team-A/*",
	"team a/*",
	"team\x00a",
	`team-a\*`,
	"team-a/api:latest",
	strings.Repeat("a/", 200) + "*",
}

// FuzzParseScope asserts the grammar is total and that nothing it accepts
// could reach outside the repository it names.
func FuzzParseScope(f *testing.F) {
	for _, seed := range scopeCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		scope, err := authz.ParseScope(input)
		if err != nil {
			if !errors.Is(err, authz.ErrInvalidScope) {
				t.Fatalf("ParseScope(%q) failed with %v, want ErrInvalidScope", input, err)
			}
			return
		}

		if string(scope) != input {
			t.Fatalf("ParseScope(%q) returned %q: a scope must not be rewritten", input, scope)
		}
		if err := scope.Validate(); err != nil {
			t.Fatalf("a parsed scope failed Validate: %v", err)
		}

		if scope == authz.SystemScope || scope == authz.AllRepositories {
			return
		}

		// Everything else is a repository scope, and its repository part has
		// to be a name this deployment could actually have.
		name := strings.TrimSuffix(input, "/*")
		if err := reponame.Validate(name); err != nil {
			t.Fatalf("accepted %q, whose repository part is not a legal name: %v", input, err)
		}
		if reponame.Prefix(name) == string(authz.SystemScope) {
			t.Fatalf("accepted %q, which shadows the global scope", input)
		}
		if strings.Count(input, "*") > 1 {
			t.Fatalf("accepted %q, which has more than one wildcard", input)
		}
		if strings.Contains(name, "*") {
			t.Fatalf("accepted %q, which has a wildcard outside the trailing position", input)
		}
	})
}

// FuzzScopeMatches asserts that a scope and the filter compiled from it agree
// on every name.
//
// They are two readings of one pattern -- one used by the decision, one by the
// query that builds a listing -- and a difference between them is a disclosure
// bug on whichever side is more generous (ADR 0003).
func FuzzScopeMatches(f *testing.F) {
	for _, scope := range scopeCorpus {
		for _, name := range []string{
			"team-a/api", "team-a", "team-a/sub/api", "team-ab/api", "nginx", "system", "system/api",
		} {
			f.Add(scope, name)
		}
	}

	f.Fuzz(func(t *testing.T, scopeInput, name string) {
		scope, err := authz.ParseScope(scopeInput)
		if err != nil {
			return
		}
		resource, err := authz.Repository(name)
		if err != nil {
			return
		}

		matched := scope.Matches(resource)
		filter, selectsRepositories := scope.Filter()

		if !selectsRepositories {
			// Only the system scope compiles to nothing, and it matches no
			// repository either.
			if scope != authz.SystemScope {
				t.Fatalf("%q compiled to no filter but is not the system scope", scope)
			}
			if matched {
				t.Fatalf("%q matched repository %q despite selecting no repositories", scope, name)
			}
			return
		}
		if got := filter.Matches(name); got != matched {
			t.Fatalf("scope %q and its filter %+v disagree about %q: %v vs %v",
				scope, filter, name, matched, got)
		}
	})
}
