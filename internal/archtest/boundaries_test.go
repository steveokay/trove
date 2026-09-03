package archtest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fixtureDir is the synthetic module the self-tests run the whole pipeline
// against: it is a real module with real violations, so the exec, decode, and
// rule-evaluation stages are all proven, not just the pure ones.
const fixtureDir = "testdata/fixture"

// fixtureRules mirrors the shape of the real rules -- one transitive rule with a
// multi-hop chain, one direct rule with an exemption -- against packages that
// deliberately break them.
func fixtureRules() []Rule {
	return []Rule{
		{
			Name:      "fixture-decider-reaches-no-storage",
			Reason:    "fixture: transitive reachability",
			From:      []string{"example.com/fixture/decider/..."},
			Forbidden: []string{"example.com/fixture/storage/..."},
			Mode:      Transitive,
		},
		{
			Name:      "fixture-aead-quarantine",
			Reason:    "fixture: direct import with one exemption",
			From:      []string{"example.com/fixture/..."},
			Except:    []string{"example.com/fixture/allowed/..."},
			Forbidden: []string{"crypto/aes", "crypto/cipher"},
			Mode:      Direct,
		},
	}
}

// TestRepositoryBoundariesHold is the rule this task exists to enforce: the real
// module, the real rules, no violations.
func TestRepositoryBoundariesHold(t *testing.T) {
	t.Parallel()

	graph, err := Load(t.Context(), Options{Patterns: []string{modulePath + "/..."}})
	if err != nil {
		t.Fatalf("loading the repository import graph: %v", err)
	}

	// A silent pass on an empty graph would make this test worthless, so prove
	// the packages the rules constrain were actually loaded.
	if !slices.Contains(graph.Packages(), pkg("internal/authz")) {
		t.Fatalf("internal/authz missing from the loaded graph; the rules would pass vacuously")
	}

	if violations := graph.Check(Rules()); len(violations) > 0 {
		t.Fatalf("architectural boundaries violated:\n\n%s", FormatViolations(violations))
	}
}

// TestFixtureViolationsAreCaught proves the checker fails when it should. A
// boundary test that has never been seen to fail is indistinguishable from one
// that cannot fail.
func TestFixtureViolationsAreCaught(t *testing.T) {
	t.Parallel()

	graph, err := Load(t.Context(), Options{
		Dir:      fixtureDir,
		Patterns: []string{"example.com/fixture/..."},
	})
	if err != nil {
		t.Fatalf("loading the fixture import graph: %v", err)
	}

	violations := graph.Check(fixtureRules())

	want := [][]string{
		{"example.com/fixture/decider", "example.com/fixture/middle", "example.com/fixture/storage"},
		{"example.com/fixture/aead", "crypto/aes"},
	}
	if len(violations) != len(want) {
		t.Fatalf("got %d violations, want %d:\n\n%s", len(violations), len(want), FormatViolations(violations))
	}
	for i, wantChain := range want {
		if !slices.Equal(violations[i].Chain, wantChain) {
			t.Errorf("violation %d chain = %v, want %v", i, violations[i].Chain, wantChain)
		}
	}

	// The exemption and the clean package must not be reported, or the checker
	// is just a source of noise nobody will read.
	for _, v := range violations {
		if v.From() == "example.com/fixture/allowed" {
			t.Errorf("exempt package reported: %s", v)
		}
		if v.From() == "example.com/fixture/pure" {
			t.Errorf("clean package reported: %s", v)
		}
	}

	// The report has to name the chain, not just the endpoints.
	report := FormatViolations(violations)
	for _, want := range []string{"example.com/fixture/middle", "-> example.com/fixture/storage", "why: fixture"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		graph map[string][]string
		rule  Rule
		want  [][]string
	}{
		{
			name:  "transitive violation reports the whole chain",
			graph: map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a"}, Forbidden: []string{"store"}, Mode: Transitive},
			want:  [][]string{{"a", "b", "c", "store"}},
		},
		{
			name:  "transitive rule tolerates an unrelated dependency",
			graph: map[string][]string{"a": {"b"}, "b": nil, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a"}, Forbidden: []string{"store"}, Mode: Transitive},
			want:  nil,
		},
		{
			name:  "direct rule ignores an indirect reach",
			graph: map[string][]string{"a": {"b"}, "b": {"store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a"}, Forbidden: []string{"store"}, Mode: Direct},
			want:  nil,
		},
		{
			name:  "direct rule catches a named import",
			graph: map[string][]string{"a": {"store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a"}, Forbidden: []string{"store"}, Mode: Direct},
			want:  [][]string{{"a", "store"}},
		},
		{
			name:  "except removes a package from the rule",
			graph: map[string][]string{"a/x": {"store"}, "a/y": {"store"}, "store": nil},
			rule: Rule{
				Name:      "r",
				From:      []string{"a/..."},
				Except:    []string{"a/x"},
				Forbidden: []string{"store"},
				Mode:      Direct,
			},
			want: [][]string{{"a/y", "store"}},
		},
		{
			name:  "shortest chain wins when two routes exist",
			graph: map[string][]string{"a": {"long", "short"}, "short": {"store"}, "long": {"mid"}, "mid": {"store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a"}, Forbidden: []string{"store"}, Mode: Transitive},
			want:  [][]string{{"a", "short", "store"}},
		},
		{
			name:  "an import cycle terminates",
			graph: map[string][]string{"a": {"b"}, "b": {"a", "store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a"}, Forbidden: []string{"store"}, Mode: Transitive},
			want:  [][]string{{"a", "b", "store"}},
		},
		{
			name:  "every constrained package is reported",
			graph: map[string][]string{"a/x": {"store"}, "a/y": {"store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"a/..."}, Forbidden: []string{"store"}, Mode: Direct},
			want:  [][]string{{"a/x", "store"}, {"a/y", "store"}},
		},
		{
			name:  "a rule matching nothing passes vacuously",
			graph: map[string][]string{"a": {"store"}, "store": nil},
			rule:  Rule{Name: "r", From: []string{"absent/..."}, Forbidden: []string{"store"}, Mode: Transitive},
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := NewGraph(tc.graph).Check([]Rule{tc.rule})
			if len(got) != len(tc.want) {
				t.Fatalf("got %d violations %v, want %d", len(got), got, len(tc.want))
			}
			for i, wantChain := range tc.want {
				if !slices.Equal(got[i].Chain, wantChain) {
					t.Errorf("violation %d chain = %v, want %v", i, got[i].Chain, wantChain)
				}
				if got[i].Rule != tc.rule.Name {
					t.Errorf("violation %d rule = %q, want %q", i, got[i].Rule, tc.rule.Name)
				}
			}
		})
	}
}

func TestGraphAccessors(t *testing.T) {
	t.Parallel()

	g := NewGraph(map[string][]string{"b": {"z", "a"}, "a": nil})

	if got, want := g.Packages(), []string{"a", "b"}; !slices.Equal(got, want) {
		t.Errorf("Packages() = %v, want %v", got, want)
	}
	if got, want := g.Imports("b"), []string{"a", "z"}; !slices.Equal(got, want) {
		t.Errorf("Imports(b) = %v, want %v", got, want)
	}
	if got := g.Imports("absent"); got != nil {
		t.Errorf("Imports(absent) = %v, want nil", got)
	}

	// Imports must hand back a copy: a caller sorting or truncating the result
	// would otherwise corrupt the graph for every later rule.
	g.Imports("b")[0] = "mutated"
	if got, want := g.Imports("b"), []string{"a", "z"}; !slices.Equal(got, want) {
		t.Errorf("graph mutated through Imports(): %v, want %v", got, want)
	}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		pkg     string
		want    bool
	}{
		{"crypto/aes", "crypto/aes", true},
		{"crypto/aes", "crypto/aesx", false},
		{"crypto/aes", "crypto", false},
		{"a/b/...", "a/b", true},
		{"a/b/...", "a/b/c", true},
		{"a/b/...", "a/b/c/d", true},
		{"a/b/...", "a/bc", false},
		{"a/b/...", "a", false},
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"|"+tc.pkg, func(t *testing.T) {
			t.Parallel()

			if got := matchPattern(tc.pattern, tc.pkg); got != tc.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.pkg, got, tc.want)
			}
		})
	}

	if matchAny(nil, "anything") {
		t.Error("matchAny(nil, ...) = true, want false")
	}
	if !matchAny([]string{"x", "a/b/..."}, "a/b/c") {
		t.Error("matchAny did not match on a later pattern")
	}
}

func TestParseGraph(t *testing.T) {
	t.Parallel()

	t.Run("decodes a concatenated object stream", func(t *testing.T) {
		t.Parallel()

		const input = `{"ImportPath":"a","Imports":["z","b"]}
		{"ImportPath":"b","Imports":null}`

		g, err := parseGraph(strings.NewReader(input))
		if err != nil {
			t.Fatalf("parseGraph: %v", err)
		}
		if got, want := g.Packages(), []string{"a", "b"}; !slices.Equal(got, want) {
			t.Errorf("Packages() = %v, want %v", got, want)
		}
		if got, want := g.Imports("a"), []string{"b", "z"}; !slices.Equal(got, want) {
			t.Errorf("Imports(a) = %v, want %v (sorted for determinism)", got, want)
		}
	})

	t.Run("skips a record with no import path", func(t *testing.T) {
		t.Parallel()

		g, err := parseGraph(strings.NewReader(`{"Imports":["b"]}`))
		if err != nil {
			t.Fatalf("parseGraph: %v", err)
		}
		if got := g.Packages(); len(got) != 0 {
			t.Errorf("Packages() = %v, want empty", got)
		}
	})

	t.Run("empty input yields an empty graph", func(t *testing.T) {
		t.Parallel()

		g, err := parseGraph(strings.NewReader(""))
		if err != nil {
			t.Fatalf("parseGraph: %v", err)
		}
		if got := g.Packages(); len(got) != 0 {
			t.Errorf("Packages() = %v, want empty", got)
		}
	})

	t.Run("malformed output is an error, not an empty pass", func(t *testing.T) {
		t.Parallel()

		if _, err := parseGraph(strings.NewReader(`{"ImportPath":`)); err == nil {
			t.Fatal("parseGraph accepted malformed JSON")
		}
	})
}

func TestResolveGoBin(t *testing.T) {
	t.Parallel()

	wantName := "go"
	if runtime.GOOS == "windows" {
		wantName = "go.exe"
	}

	t.Run("prefers PATH", func(t *testing.T) {
		t.Parallel()

		lookPath := func(string) (string, error) { return "/from/path/go", nil }
		got, err := resolveGoBin(lookPath, "/unused")
		if err != nil {
			t.Fatalf("resolveGoBin: %v", err)
		}
		if got != "/from/path/go" {
			t.Errorf("resolveGoBin = %q, want the PATH result", got)
		}
	})

	t.Run("falls back to GOROOT", func(t *testing.T) {
		t.Parallel()

		goroot := t.TempDir()
		binDir := filepath.Join(goroot, "bin")
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatalf("creating fake GOROOT: %v", err)
		}
		want := filepath.Join(binDir, wantName)
		if err := os.WriteFile(want, []byte("not really go"), 0o600); err != nil {
			t.Fatalf("creating fake go binary: %v", err)
		}

		got, err := resolveGoBin(failingLookPath, goroot)
		if err != nil {
			t.Fatalf("resolveGoBin: %v", err)
		}
		if got != want {
			t.Errorf("resolveGoBin = %q, want %q", got, want)
		}
	})

	t.Run("a directory named go is not a go binary", func(t *testing.T) {
		t.Parallel()

		goroot := t.TempDir()
		if err := os.MkdirAll(filepath.Join(goroot, "bin", wantName), 0o755); err != nil {
			t.Fatalf("creating fake GOROOT: %v", err)
		}

		if _, err := resolveGoBin(failingLookPath, goroot); !errors.Is(err, ErrGoToolNotFound) {
			t.Fatalf("resolveGoBin error = %v, want ErrGoToolNotFound", err)
		}
	})

	t.Run("no PATH and no GOROOT is an error", func(t *testing.T) {
		t.Parallel()

		if _, err := resolveGoBin(failingLookPath, ""); !errors.Is(err, ErrGoToolNotFound) {
			t.Fatalf("resolveGoBin error = %v, want ErrGoToolNotFound", err)
		}
	})
}

// failingLookPath stands in for a PATH with no go tool on it.
func failingLookPath(string) (string, error) {
	return "", exec.ErrNotFound
}

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("defaults to ./... in the current directory", func(t *testing.T) {
		t.Parallel()

		graph, err := Load(t.Context(), Options{})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !slices.Contains(graph.Packages(), pkg("internal/archtest")) {
			t.Errorf("default pattern did not load this package")
		}
	})

	t.Run("honours an explicit go binary", func(t *testing.T) {
		t.Parallel()

		goBin, err := resolveGoBin(exec.LookPath, "")
		if err != nil {
			t.Fatalf("resolveGoBin: %v", err)
		}
		graph, err := Load(t.Context(), Options{GoBin: goBin, Patterns: []string{pkg("internal/authz")}})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !slices.Contains(graph.Packages(), pkg("internal/authz")) {
			t.Errorf("explicit go binary did not load the requested package")
		}
	})

	t.Run("a go list failure is reported, not swallowed", func(t *testing.T) {
		t.Parallel()

		_, err := Load(t.Context(), Options{Patterns: []string{"github.com/steveokay/trove/internal/does-not-exist"}})
		if !errors.Is(err, ErrGoListFailed) {
			t.Fatalf("Load error = %v, want ErrGoListFailed", err)
		}
	})
}

func TestViolationRendering(t *testing.T) {
	t.Parallel()

	v := Violation{
		Rule:   "some-rule",
		Reason: "because ADR 0001 says so",
		Chain:  []string{"a", "b", "c"},
	}

	if got, want := v.From(), "a"; got != want {
		t.Errorf("From() = %q, want %q", got, want)
	}
	if got, want := v.Forbidden(), "c"; got != want {
		t.Errorf("Forbidden() = %q, want %q", got, want)
	}

	rendered := v.String()
	for _, want := range []string{`rule "some-rule"`, "a must not reach c", "-> b", "-> c", "why: because ADR 0001 says so"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("String() missing %q:\n%s", want, rendered)
		}
	}

	empty := Violation{}
	if got := empty.From(); got != "" {
		t.Errorf("From() on an empty chain = %q, want %q", got, "")
	}
	if got := empty.Forbidden(); got != "" {
		t.Errorf("Forbidden() on an empty chain = %q, want %q", got, "")
	}

	if got := FormatViolations(nil); got != "" {
		t.Errorf("FormatViolations(nil) = %q, want empty", got)
	}
	joined := FormatViolations([]Violation{v, v})
	if strings.Count(joined, `rule "some-rule"`) != 2 {
		t.Errorf("FormatViolations did not render both violations:\n%s", joined)
	}
}

func TestModeString(t *testing.T) {
	t.Parallel()

	tests := map[Mode]string{
		Transitive: "transitive",
		Direct:     "direct",
		Mode(7):    "Mode(7)",
	}
	for mode, want := range tests {
		if got := mode.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", int(mode), got, want)
		}
	}
}

// TestRulesAreWellFormed guards the rule set itself: a rule with an empty From
// or Forbidden list passes against every graph, which looks exactly like a
// boundary being enforced.
func TestRulesAreWellFormed(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for _, r := range Rules() {
		if r.Name == "" {
			t.Fatalf("a rule has no name: %+v", r)
		}
		if seen[r.Name] {
			t.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true

		if r.Reason == "" {
			t.Errorf("rule %q has no reason; a failure message without the ADR is a puzzle", r.Name)
		}
		if len(r.From) == 0 {
			t.Errorf("rule %q constrains no packages", r.Name)
		}
		if len(r.Forbidden) == 0 {
			t.Errorf("rule %q forbids nothing", r.Name)
		}
		for _, pattern := range slices.Concat(r.From, r.Except, r.Forbidden) {
			if pattern == "" || strings.HasSuffix(pattern, "/") {
				t.Errorf("rule %q has malformed pattern %q", r.Name, pattern)
			}
		}
	}

	// The four boundaries the ADRs name must all be present.
	for _, name := range []string{
		"authz-reaches-no-storage",
		"cache-reaches-no-hosted-deletion",
		"hosted-deletion-reaches-no-cache",
		"trivy-is-quarantined",
		"aead-primitives-are-quarantined",
		"password-hashing-is-quarantined",
	} {
		if !seen[name] {
			t.Errorf("rule %q is missing from Rules()", name)
		}
	}
}

// TestRulesCatchTheirOwnViolations proves each repository rule is live: a
// synthetic graph that breaks it must be reported. Without this, a typo in a
// pattern would leave a rule silently unenforced and the suite still green.
func TestRulesCatchTheirOwnViolations(t *testing.T) {
	t.Parallel()

	// A package that the rule constrains, paired with an import that must trip
	// it. Transitive rules get a two-hop route so the chain is exercised too.
	tests := []struct {
		rule     string
		from     string
		via      string
		to       string
		wantHops int
	}{
		{rule: "authz-reaches-no-storage", from: pkg("internal/authz"), via: pkg("internal/authn"), to: pkg("internal/meta/sqlite"), wantHops: 3},
		{rule: "authz-does-no-io", from: pkg("internal/authz"), via: pkg("internal/authn"), to: "database/sql", wantHops: 3},
		{rule: "cache-reaches-no-hosted-deletion", from: pkg("internal/cache"), via: pkg("internal/blob"), to: pkg("internal/gc"), wantHops: 3},
		{rule: "hosted-deletion-reaches-no-cache", from: pkg("internal/policy"), via: pkg("internal/blob"), to: pkg("internal/cache"), wantHops: 3},
		{rule: "trivy-is-quarantined", from: pkg("internal/scan"), to: "github.com/aquasecurity/trivy/pkg/fanal", wantHops: 2},
		{rule: "aead-primitives-are-quarantined", from: pkg("internal/authn"), to: "crypto/cipher", wantHops: 2},
		{rule: "password-hashing-is-quarantined", from: pkg("internal/server"), to: "golang.org/x/crypto/argon2", wantHops: 2},
	}

	rulesByName := make(map[string]Rule)
	for _, r := range Rules() {
		rulesByName[r.Name] = r
	}

	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()

			rule, ok := rulesByName[tc.rule]
			if !ok {
				t.Fatalf("rule %q not found", tc.rule)
			}

			imports := map[string][]string{tc.to: nil}
			if tc.via == "" {
				imports[tc.from] = []string{tc.to}
			} else {
				imports[tc.from] = []string{tc.via}
				imports[tc.via] = []string{tc.to}
			}

			got := NewGraph(imports).Check([]Rule{rule})
			if len(got) != 1 {
				t.Fatalf("rule %q reported %d violations, want 1", tc.rule, len(got))
			}
			if len(got[0].Chain) != tc.wantHops {
				t.Errorf("chain = %v, want %d hops", got[0].Chain, tc.wantHops)
			}
			if got[0].From() != tc.from || got[0].Forbidden() != tc.to {
				t.Errorf("chain endpoints = %s..%s, want %s..%s", got[0].From(), got[0].Forbidden(), tc.from, tc.to)
			}
		})
	}
}

// TestQuarantineExemptionsAreHonoured proves the exempt package may do what
// everyone else may not -- the other half of a quarantine rule, and the half
// that breaks silently if a pattern is mistyped.
func TestQuarantineExemptionsAreHonoured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rule   string
		exempt string
		imp    string
	}{
		{rule: "trivy-is-quarantined", exempt: pkg("internal/scan/trivy"), imp: "github.com/aquasecurity/trivy/pkg/fanal"},
		{rule: "aead-primitives-are-quarantined", exempt: pkg("internal/secretbox"), imp: "crypto/cipher"},
		{rule: "password-hashing-is-quarantined", exempt: pkg("internal/authn"), imp: "golang.org/x/crypto/argon2"},
	}

	rulesByName := make(map[string]Rule)
	for _, r := range Rules() {
		rulesByName[r.Name] = r
	}

	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()

			graph := NewGraph(map[string][]string{tc.exempt: {tc.imp}, tc.imp: nil})
			if got := graph.Check([]Rule{rulesByName[tc.rule]}); len(got) != 0 {
				t.Errorf("exempt package %s reported:\n%s", tc.exempt, FormatViolations(got))
			}
		})
	}
}

// TestAuthzExternalTestImportsAreNotCounted pins the design constraint recorded
// in the package doc: authz's external test package imports internal/meta and
// internal/meta/sqlutil for the differential scope test, and that must not read
// as a violation. If someone ever adds "-test" to the go list invocation, the
// only way to make the suite green again would be to delete a correct test.
func TestAuthzExternalTestImportsAreNotCounted(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile(filepath.Join("..", "authz", "scope_sql_test.go"))
	if err != nil {
		t.Skipf("differential scope test not present: %v", err)
	}
	if !strings.Contains(string(source), pkg("internal/meta")) {
		t.Skip("differential scope test no longer imports internal/meta")
	}

	graph, err := Load(t.Context(), Options{Patterns: []string{pkg("internal/authz")}})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if slices.Contains(graph.Imports(pkg("internal/authz")), pkg("internal/meta")) {
		t.Fatalf("non-test graph contains a test-only import; the loader is passing -test")
	}
	if violations := graph.Check(Rules()); len(violations) > 0 {
		t.Fatalf("authz reported as violating despite the import being test-only:\n\n%s", FormatViolations(violations))
	}
}

// Compile-time proof the exported surface is usable as documented.
var _ = fmt.Stringer(Violation{})
