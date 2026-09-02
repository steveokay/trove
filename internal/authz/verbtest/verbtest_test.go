package verbtest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
)

// The mechanism is only worth having if it actually reads marks back out of
// test sources, so it is exercised against a fixture repository rather than
// only against the real one -- where, today, nothing is covered at all.
func TestScanFindsMarks(t *testing.T) {
	t.Parallel()

	root := fixtureRepository(t, map[string]string{
		"internal/service/service_test.go": `
package service_test

import (
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
)

func TestReadIsAllowed(t *testing.T) {
	verbtest.Positive(t, authz.RepoRead)
}

func TestReadIsRefused(t *testing.T) {
	verbtest.Negative(t, authz.RepoRead)
}

func TestWriteIsAllowed(t *testing.T) {
	verbtest.Positive(t, authz.RepoWrite)
}
`,
		// A second package, to prove the scan aggregates across them -- which
		// is the whole reason it reads sources instead of using a registry.
		"internal/other/other_test.go": `
package other_test

import (
	"testing"

	"github.com/steveokay/trove/internal/authz"
	marks "github.com/steveokay/trove/internal/authz/verbtest"
)

func TestWriteIsRefused(t *testing.T) {
	marks.Negative(t, authz.RepoWrite)
}
`,
	})

	coverage, err := verbtest.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if got := coverage[authz.RepoRead]; !got.Complete() {
		t.Errorf("repo:read = %+v, want both polarities", got)
	}
	// Aliased imports count: the mark is the call, not the spelling.
	if got := coverage[authz.RepoWrite]; !got.Complete() {
		t.Errorf("repo:write = %+v, want both polarities", got)
	}
	if got := coverage[authz.GCRun]; got.Positive || got.Negative {
		t.Errorf("gc:run = %+v, want nothing: no test mentions it", got)
	}
	if len(verbtest.SortedVerbs(coverage)) != 2 {
		t.Errorf("coverage names %v, want exactly the two marked verbs", verbtest.SortedVerbs(coverage))
	}
}

// A mark only counts when it comes from this package. Anything else called
// Positive is somebody else's function, and counting it would let a verb pass
// as covered because an unrelated helper happened to share a name.
func TestScanIgnoresLookalikes(t *testing.T) {
	t.Parallel()

	root := fixtureRepository(t, map[string]string{
		"internal/service/service_test.go": `
package service_test

import (
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/service/assert"
)

func TestSomething(t *testing.T) {
	assert.Positive(t, authz.RepoRead)
	assert.Negative(t, authz.RepoRead)
}
`,
		// Not a test file, so not scanned: production code referencing a verb
		// is not a test of it.
		"internal/service/service.go": `
package service

import (
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
)

func Wired(t *testing.T) {
	verbtest.Positive(t, authz.RepoWrite)
	verbtest.Negative(t, authz.RepoWrite)
}
`,
	})

	coverage, err := verbtest.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(coverage) != 0 {
		t.Errorf("Scan found %v, want nothing", verbtest.SortedVerbs(coverage))
	}
}

// Marks written from inside the authz package itself name the constant
// directly, with no package qualifier.
func TestScanResolvesUnqualifiedConstants(t *testing.T) {
	t.Parallel()

	root := fixtureRepository(t, map[string]string{
		"internal/authz/decide_test.go": `
package authz

import (
	"testing"

	"github.com/steveokay/trove/internal/authz/verbtest"
)

func TestDecide(t *testing.T) {
	verbtest.Positive(t, RepoRead)
	verbtest.Negative(t, RepoRead)
}
`,
	})

	coverage, err := verbtest.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := coverage[authz.RepoRead]; !got.Complete() {
		t.Errorf("repo:read = %+v, want both polarities", got)
	}
}

func TestScanRejectsAMissingVocabulary(t *testing.T) {
	t.Parallel()

	// Without the vocabulary's own source there is no way to resolve a mark,
	// and guessing would be worse than failing.
	if _, err := verbtest.Scan(t.TempDir()); err == nil {
		t.Error("Scan without a vocabulary succeeded, want an error")
	}
}

func TestScanRejectsUnparseableSources(t *testing.T) {
	t.Parallel()

	root := fixtureRepository(t, map[string]string{
		"internal/service/broken_test.go": "package service_test\n\nfunc (\n",
	})
	_, err := verbtest.Scan(root)
	if err == nil {
		t.Fatal("Scan over an unparseable test file succeeded")
	}
	if !strings.Contains(err.Error(), "broken_test.go") {
		t.Errorf("error %q does not name the file", err)
	}
}

// fixtureRepository builds a throwaway tree with a real copy of the vocabulary
// -- the scan resolves marks against it, so a fixture that faked it would be
// testing something else.
func fixtureRepository(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	vocabulary, err := os.ReadFile(filepath.Join("verbs.go"))
	if err != nil {
		// The test runs in the verbtest directory; the vocabulary is a level up.
		vocabulary, err = os.ReadFile(filepath.Join("..", "verbs.go"))
		if err != nil {
			t.Fatalf("read the vocabulary: %v", err)
		}
	}
	write(t, root, "internal/authz/verbs.go", string(vocabulary))
	write(t, root, "go.mod", "module github.com/steveokay/trove\n\ngo 1.25.0\n")

	for path, body := range files {
		write(t, root, path, body)
	}
	return root
}

func write(t *testing.T, root, path, body string) {
	t.Helper()

	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// The ratchet is the part that has to be right: it must complain both when a
// verb is untested and when an allowlisted verb has quietly become tested, or
// the allowlist would never shrink.
func TestProblems(t *testing.T) {
	t.Parallel()

	both := verbtest.Polarities{Positive: true, Negative: true}
	positiveOnly := verbtest.Polarities{Positive: true}
	negativeOnly := verbtest.Polarities{Negative: true}

	// Every verb covered and nothing allowlisted is the state this whole
	// mechanism exists to reach.
	full := verbtest.Coverage{}
	for _, verb := range authz.AllVerbs() {
		full[verb] = both
	}
	if problems := verbtest.Problems(full, nil); len(problems) != 0 {
		t.Errorf("a fully covered vocabulary reported %v", problems)
	}

	// An allowlist covering everything is silent, however little is tested.
	allowAll := map[authz.Verb]string{}
	for _, verb := range authz.AllVerbs() {
		allowAll[verb] = "not wired yet"
	}
	if problems := verbtest.Problems(verbtest.Coverage{}, allowAll); len(problems) != 0 {
		t.Errorf("a fully allowlisted vocabulary reported %v", problems)
	}

	tests := []struct {
		name     string
		coverage verbtest.Polarities
		allowed  bool
		want     string
	}{
		{name: "untested", want: "has no tests"},
		{name: "positive only", coverage: positiveOnly, want: "has no negative test"},
		{name: "negative only", coverage: negativeOnly, want: "has no positive test"},
		{name: "covered but allowlisted", coverage: both, allowed: true, want: "remove it from the allowlist"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// One verb differs from the fully covered baseline, so exactly one
			// problem is expected and it is about that verb.
			coverage := verbtest.Coverage{}
			allowlist := map[authz.Verb]string{}
			for _, verb := range authz.AllVerbs() {
				coverage[verb] = both
			}
			coverage[authz.RepoRead] = tt.coverage
			if tt.allowed {
				allowlist[authz.RepoRead] = "Z-010 handler enforcement"
			}

			problems := verbtest.Problems(coverage, allowlist)
			if len(problems) != 1 {
				t.Fatalf("reported %v, want exactly one problem", problems)
			}
			if !strings.Contains(problems[0], "repo:read") {
				t.Errorf("problem %q does not name the verb", problems[0])
			}
			if !strings.Contains(problems[0], tt.want) {
				t.Errorf("problem %q does not say %q", problems[0], tt.want)
			}
		})
	}
}

// An allowlist entry that is not a verb is usually a rename that only happened
// on one side, and it would otherwise sit there exempting nothing.
func TestProblemsRejectsStaleAllowlistEntries(t *testing.T) {
	t.Parallel()

	coverage := verbtest.Coverage{}
	for _, verb := range authz.AllVerbs() {
		coverage[verb] = verbtest.Polarities{Positive: true, Negative: true}
	}

	problems := verbtest.Problems(coverage, map[authz.Verb]string{"repo:admin": "renamed away"})
	if len(problems) != 1 || !strings.Contains(problems[0], "repo:admin") {
		t.Fatalf("reported %v, want a complaint about repo:admin", problems)
	}
}

// The marks themselves are ordinary calls, and they check what they are given:
// a mark naming something outside the vocabulary would be a silent no-op.
func TestMarksAcceptRealVerbs(t *testing.T) {
	t.Parallel()

	verbtest.Positive(t, authz.RepoRead)
	verbtest.Negative(t, authz.RepoRead)
}
