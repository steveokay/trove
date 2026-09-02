package authz_test

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

// The vocabulary is closed and its exact contents are the contract: handlers
// reference these constants, roles store them, and the enumeration test counts
// them. This is the list from ADR 0002, written out so that adding or renaming
// a verb has to be a deliberate edit here as well as there.
func TestVocabulary(t *testing.T) {
	t.Parallel()

	want := []string{
		"audit:read",
		"gate:override",
		"gc:run",
		"manifest:delete",
		"policy:apply",
		"policy:read",
		"policy:write",
		"proxy:credentials",
		"proxy:read",
		"proxy:write",
		"quota:read",
		"quota:write",
		"referrer:read",
		"repo:configure",
		"repo:create",
		"repo:delete",
		"repo:list",
		"repo:read",
		"repo:write",
		"role:read",
		"role:write",
		"scan:read",
		"scan:trigger",
		"search:read",
		"system:maintenance",
		"tag:delete",
		"user:read",
		"user:write",
		"webhook:read",
		"webhook:write",
	}

	got := authz.AllVerbs()
	if len(got) != len(want) {
		t.Fatalf("vocabulary has %d verbs, want %d:\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if string(got[i]) != want[i] {
			t.Errorf("verb %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAllVerbsIsSortedAndCopied(t *testing.T) {
	t.Parallel()

	first := authz.AllVerbs()
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i] < first[j] }) {
		t.Error("AllVerbs is not sorted: callers render and compare it")
	}

	// Mutating the result must not reach the vocabulary; a caller sorting or
	// filtering its own copy is ordinary, and the next caller must not see it.
	first[0] = authz.Verb("mutated")
	second := authz.AllVerbs()
	if second[0] == "mutated" {
		t.Error("AllVerbs returns the package's own slice")
	}
}

func TestVerbValidity(t *testing.T) {
	t.Parallel()

	for _, verb := range authz.AllVerbs() {
		if !verb.Valid() {
			t.Errorf("%s is in AllVerbs but not Valid", verb)
		}
		if verb.String() != string(verb) {
			t.Errorf("String() = %q, want %q", verb.String(), string(verb))
		}
	}

	notVerbs := []authz.Verb{
		"",
		"repo",
		"repo:",
		":read",
		"repo:admin", // the bundle verb ADR 0002 rejected
		"repo:*",     // wildcards expand at grant time, never at rest
		"REPO:READ",  // one spelling per permission
		"repo:read ", // no forgiving whitespace
		" repo:read",
		"repo:read;drop", // nothing clever survives a closed set
	}
	for _, verb := range notVerbs {
		if verb.Valid() {
			t.Errorf("%q is not in the vocabulary but reports Valid", verb)
		}
	}
}

func TestParseVerb(t *testing.T) {
	t.Parallel()

	verb, err := authz.ParseVerb("repo:read")
	if err != nil || verb != authz.RepoRead {
		t.Fatalf("ParseVerb(repo:read) = %q, %v; want repo:read", verb, err)
	}

	// A role holding a verb nothing enforces would look like a grant and be
	// none, so an unknown one is refused where somebody typed it.
	_, err = authz.ParseVerb("repo:admin")
	if !errors.Is(err, authz.ErrUnknownVerb) {
		t.Fatalf("ParseVerb(repo:admin) = %v, want ErrUnknownVerb", err)
	}
	if !strings.Contains(err.Error(), "repo:admin") {
		t.Errorf("error %q does not name what was rejected", err)
	}

	var unknown *authz.UnknownVerbError
	if !errors.As(err, &unknown) {
		t.Fatalf("error type = %T, want *authz.UnknownVerbError", err)
	}
}

func TestParseVerbs(t *testing.T) {
	t.Parallel()

	got, err := authz.ParseVerbs([]string{"repo:read", "repo:write"})
	if err != nil {
		t.Fatalf("ParseVerbs: %v", err)
	}
	if len(got) != 2 || got[0] != authz.RepoRead || got[1] != authz.RepoWrite {
		t.Errorf("ParseVerbs = %v, want [repo:read repo:write]", got)
	}

	if got, err := authz.ParseVerbs(nil); err != nil || len(got) != 0 {
		t.Errorf("ParseVerbs(nil) = %v, %v; want empty", got, err)
	}

	// Every typo at once: an operator pasting a role definition should not
	// have to fix them one restart at a time.
	_, err = authz.ParseVerbs([]string{"repo:read", "repo:admin", "repo:write", "gate:overide"})
	if !errors.Is(err, authz.ErrUnknownVerb) {
		t.Fatalf("ParseVerbs with unknown verbs = %v, want ErrUnknownVerb", err)
	}
	for _, want := range []string{"repo:admin", "gate:overide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "repo:read") {
		t.Errorf("error %q names a verb that was fine", err)
	}
}
