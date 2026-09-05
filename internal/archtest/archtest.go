// Package archtest enforces the architectural import boundaries the ADRs
// establish, by inspecting the real dependency graph the Go toolchain reports.
//
// The boundaries are load-bearing, not stylistic. Each one exists because
// crossing it turns a design guarantee into a comment:
//
//   - internal/authz must reach no registry, repository, or storage package
//     (ADR 0001, CLAUDE.md section 3). The decision engine takes plain values in
//     and returns a decision; the moment it can query, "filter at the query
//     layer" becomes optional and the catalog starts leaking.
//   - internal/cache and internal/gc / internal/policy must not reach each other
//     (ADR 0009 wall 3). Evicting a cached blob is recoverable; deleting a
//     hosted one is not. Shared code between those paths is how a retention rule
//     ends up deleting an irreplaceable blob.
//   - Only internal/scan/trivy may import Trivy (ADR 0017). The vendor stays
//     quarantined behind scan.Scanner so results are normalised and the vendor
//     is replaceable.
//   - Only internal/secretbox may import the AEAD primitives (ADR 0016), so
//     every use of crypto/aes and crypto/cipher is auditable in one file.
//
// # Non-test dependencies only
//
// The graph is loaded with "go list -deps", deliberately without "-test". The
// boundary is about what the shipped binary links, not about what a test
// compares. internal/authz's external test package (authz_test in
// scope_sql_test.go) imports internal/meta and internal/meta/sqlutil on purpose:
// it is a differential test pinning the Go scope matcher against the SQL
// predicate, which is exactly the test that keeps the two implementations from
// diverging. Loading test dependencies would flag that correct test as a
// violation, and the only way to silence it would be to delete the test.
package archtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// ErrGoToolNotFound is returned when no usable "go" binary can be located.
var ErrGoToolNotFound = errors.New("archtest: go tool not found")

// ErrGoListFailed is returned when the "go list" invocation exits non-zero. The
// wrapped error carries the exit status and the tool's stderr.
var ErrGoListFailed = errors.New("archtest: go list failed")

// Mode selects how far a rule looks for a forbidden import.
type Mode int

const (
	// Transitive forbids reaching a package through any chain of imports. Use
	// it when the guarantee is "this code cannot touch that subsystem at all",
	// as for internal/authz and for the cache/gc wall.
	Transitive Mode = iota

	// Direct forbids naming a package in an import statement, while allowing it
	// to be reached through an intermediary. Use it for quarantine rules, where
	// exactly one adapter may speak to a dependency and everyone else must go
	// through the adapter -- a transitive rule there would flag the binary's
	// own wiring, which is required to link the adapter.
	Direct
)

// String renders the mode for use in failure messages.
func (m Mode) String() string {
	switch m {
	case Transitive:
		return "transitive"
	case Direct:
		return "direct"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// Rule is one allowlist boundary: packages matching From (minus Except) must
// not reach any package matching Forbidden.
//
// Patterns are Go package paths. A pattern ending in "/..." matches the prefix
// package itself and everything beneath it; any other pattern is an exact
// package path.
type Rule struct {
	// Name identifies the rule in failure output.
	Name string
	// Reason cites the ADR the rule comes from, so a developer who trips it can
	// read the argument rather than guess at it.
	Reason string
	// From selects the packages the rule constrains.
	From []string
	// Except removes packages from From. This is where the single legitimate
	// importer of a quarantined dependency is named.
	Except []string
	// Forbidden selects the packages that must not be reached.
	Forbidden []string
	// Mode selects direct-import or transitive-reachability checking.
	Mode Mode
}

// appliesTo reports whether the rule constrains a package.
func (r Rule) appliesTo(pkg string) bool {
	return matchAny(r.From, pkg) && !matchAny(r.Except, pkg)
}

// Violation is one rule breach, carrying the import chain that produced it.
type Violation struct {
	// Rule is the name of the rule that was broken.
	Rule string
	// Reason is the rule's ADR citation.
	Reason string
	// Chain is the import path from the constrained package to the forbidden
	// one, starting with the former and ending with the latter. For a Direct
	// rule it always has two elements.
	Chain []string
}

// From returns the constrained package that broke the rule.
func (v Violation) From() string {
	if len(v.Chain) == 0 {
		return ""
	}
	return v.Chain[0]
}

// Forbidden returns the forbidden package that was reached.
func (v Violation) Forbidden() string {
	if len(v.Chain) == 0 {
		return ""
	}
	return v.Chain[len(v.Chain)-1]
}

// String renders the violation with the full import chain, so the reader can
// see how the forbidden dependency was reached and which edge to cut -- naming
// only the endpoints leaves them hunting through a transitive graph.
func (v Violation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "rule %q: %s must not reach %s\n", v.Rule, v.From(), v.Forbidden())
	for i, pkg := range v.Chain {
		if i == 0 {
			fmt.Fprintf(&b, "    %s\n", pkg)
			continue
		}
		fmt.Fprintf(&b, "    %s-> %s\n", strings.Repeat("  ", i), pkg)
	}
	fmt.Fprintf(&b, "  why: %s", v.Reason)
	return b.String()
}

// FormatViolations renders violations as one blank-line-separated report.
func FormatViolations(vs []Violation) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, "\n\n")
}

// Options configures a graph load.
type Options struct {
	// Dir is the working directory for "go list". An empty value uses the
	// process's current directory, which inside a test is the package under
	// test -- fine for module-wide patterns, which resolve from anywhere in the
	// module.
	Dir string
	// Patterns are the "go list" package patterns to expand. Defaults to
	// "./..." when empty.
	Patterns []string
	// GoBin overrides the "go" binary. Empty means resolve it.
	GoBin string
}

// Graph is a package import graph: every package in the loaded closure mapped
// to the packages it imports directly.
type Graph struct {
	imports map[string][]string
}

// Load runs "go list -deps" once for the given patterns and returns the import
// graph of the whole transitive closure.
//
// One invocation covers every package, because -deps already emits the closure;
// listing packages individually would be correct but would pay the module-load
// cost once per package.
func Load(ctx context.Context, opts Options) (*Graph, error) {
	goBin := opts.GoBin
	if goBin == "" {
		resolved, err := resolveGoBin(exec.LookPath, build.Default.GOROOT)
		if err != nil {
			return nil, err
		}
		goBin = resolved
	}

	patterns := opts.Patterns
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	// Only ImportPath and Imports are requested: the full -json record carries
	// file lists and build flags for thousands of packages, and decoding it is
	// the dominant cost of this check.
	args := append([]string{"list", "-deps", "-json=ImportPath,Imports"}, patterns...)

	// #nosec G204 -- the arguments are package patterns from the caller's own
	// rule configuration, not from any request or user input.
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = opts.Dir
	var stderr strings.Builder
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %v: %s", ErrGoListFailed, err, strings.TrimSpace(stderr.String()))
	}

	return parseGraph(strings.NewReader(string(out)))
}

// resolveGoBin locates the go tool, preferring PATH and falling back to GOROOT.
//
// PATH is tried first because that is the toolchain the developer and CI
// actually invoke. GOROOT is the fallback for a test binary run with a stripped
// environment, where the toolchain still exists but is not on PATH. lookPath and
// goroot are parameters so both branches are reachable from a test.
func resolveGoBin(lookPath func(string) (string, error), goroot string) (string, error) {
	name := "go"
	if runtime.GOOS == "windows" {
		name = "go.exe"
	}

	if path, err := lookPath("go"); err == nil {
		return path, nil
	}

	if goroot != "" {
		candidate := filepath.Join(goroot, "bin", name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%w: not on PATH and not under GOROOT %q", ErrGoToolNotFound, goroot)
}

// listPackage is the subset of the "go list -json" record this package reads.
type listPackage struct {
	ImportPath string
	Imports    []string
}

// parseGraph decodes the concatenated JSON objects "go list -json" emits.
func parseGraph(r io.Reader) (*Graph, error) {
	g := &Graph{imports: make(map[string][]string)}
	dec := json.NewDecoder(r)
	for {
		var pkg listPackage
		if err := dec.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("archtest: decoding go list output: %w", err)
		}
		if pkg.ImportPath == "" {
			continue
		}
		imports := slices.Clone(pkg.Imports)
		sort.Strings(imports)
		g.imports[pkg.ImportPath] = imports
	}
	return g, nil
}

// NewGraph builds a graph from an explicit adjacency map. It exists so callers
// -- including this package's own tests -- can exercise rule evaluation against
// a synthetic graph without running the toolchain.
func NewGraph(imports map[string][]string) *Graph {
	g := &Graph{imports: make(map[string][]string, len(imports))}
	for pkg, imps := range imports {
		cloned := slices.Clone(imps)
		sort.Strings(cloned)
		g.imports[pkg] = cloned
	}
	return g
}

// Packages returns every package in the graph, sorted.
func (g *Graph) Packages() []string {
	pkgs := make([]string, 0, len(g.imports))
	for pkg := range g.imports {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	return pkgs
}

// Imports returns the packages a package imports directly, sorted. The result
// is a copy; mutating it does not affect the graph.
func (g *Graph) Imports(pkg string) []string {
	return slices.Clone(g.imports[pkg])
}

// Check evaluates every rule against the graph and returns the violations, in a
// deterministic order: rules in the order given, packages sorted within a rule.
//
// At most one chain is reported per (rule, package) pair, and it is a shortest
// one, because that is the edge worth cutting; listing every route to the same
// forbidden package buries it.
func (g *Graph) Check(rules []Rule) []Violation {
	var violations []Violation
	pkgs := g.Packages()
	for _, rule := range rules {
		for _, pkg := range pkgs {
			if !rule.appliesTo(pkg) {
				continue
			}
			chain := g.findChain(pkg, rule)
			if chain == nil {
				continue
			}
			violations = append(violations, Violation{
				Rule:   rule.Name,
				Reason: rule.Reason,
				Chain:  chain,
			})
		}
	}
	return violations
}

// findChain returns the import chain from pkg to a forbidden package, or nil.
func (g *Graph) findChain(pkg string, rule Rule) []string {
	if rule.Mode == Direct {
		for _, imp := range g.imports[pkg] {
			if matchAny(rule.Forbidden, imp) {
				return []string{pkg, imp}
			}
		}
		return nil
	}

	// Breadth-first, so the first hit is a shortest chain. Ties break on the
	// sorted import order the graph keeps, making the output reproducible.
	parent := map[string]string{pkg: ""}
	queue := []string{pkg}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, imp := range g.imports[current] {
			if _, seen := parent[imp]; seen {
				continue
			}
			parent[imp] = current
			if matchAny(rule.Forbidden, imp) {
				return buildChain(parent, pkg, imp)
			}
			queue = append(queue, imp)
		}
	}
	return nil
}

// buildChain walks the breadth-first parent map back to the start package.
func buildChain(parent map[string]string, start, hit string) []string {
	chain := []string{hit}
	for node := parent[hit]; node != ""; node = parent[node] {
		chain = append(chain, node)
		if node == start {
			break
		}
	}
	slices.Reverse(chain)
	return chain
}

// matchAny reports whether any pattern selects the package path.
func matchAny(patterns []string, pkg string) bool {
	for _, pattern := range patterns {
		if matchPattern(pattern, pkg) {
			return true
		}
	}
	return false
}

// matchPattern reports whether pattern selects pkg. A "/..." suffix matches the
// prefix package and its subtree, mirroring "go list" pattern semantics; every
// other pattern is an exact match, so forbidding "crypto/aes" cannot
// accidentally forbid "crypto/aessomething".
func matchPattern(pattern, pkg string) bool {
	if subtree, ok := strings.CutSuffix(pattern, "/..."); ok {
		return pkg == subtree || strings.HasPrefix(pkg, subtree+"/")
	}
	return pattern == pkg
}

// modulePath is the repository's module path, the prefix every first-party
// package shares.
const modulePath = "github.com/steveokay/trove"

// pkg qualifies a repository-relative package path.
func pkg(rel string) string {
	return modulePath + "/" + rel
}

// Rules returns the boundaries this repository enforces.
//
// A rule with no matching packages passes vacuously, which is intentional: the
// rules for subsystems that are still empty are written now, so the boundary is
// in place before the first line of code that could cross it.
func Rules() []Rule {
	return []Rule{
		{
			Name:   "authz-reaches-no-storage",
			Reason: "ADR 0001 / CLAUDE.md section 3: the decision engine takes plain values in and returns a decision. If it can query, `filter at the query layer` becomes optional and listings start leaking repositories the subject cannot read.",
			From:   []string{pkg("internal/authz") + "/..."},
			Forbidden: []string{
				pkg("internal/registry") + "/...",
				pkg("internal/repo") + "/...",
				pkg("internal/meta") + "/...",
				pkg("internal/blob") + "/...",
				pkg("internal/cache") + "/...",
				pkg("internal/gc") + "/...",
				pkg("internal/proxy") + "/...",
				pkg("internal/search") + "/...",
				pkg("internal/server") + "/...",
			},
			Mode: Transitive,
		},
		{
			Name:   "authz-does-no-io",
			Reason: "ADR 0001 / Z-008: Decide is pure. An I/O dependency in the decision path is a decision that can fail open, time out, or vary between the check and the listing.",
			From:   []string{pkg("internal/authz") + "/..."},
			Forbidden: []string{
				"net",
				"net/http",
				"net/url",
				"database/sql",
				"database/sql/driver",
				"os/exec",
				"modernc.org/sqlite/...",
				"github.com/jackc/pgx/...",
				"github.com/minio/minio-go/...",
			},
			Mode: Transitive,
		},
		{
			Name:   "cache-reaches-no-hosted-deletion",
			Reason: "ADR 0009 wall 3: evicting a cached blob is always recoverable, deleting a hosted one never is. Shared code between the two paths is how a cache sweep reaches an irreplaceable blob.",
			From:   []string{pkg("internal/cache") + "/..."},
			Forbidden: []string{
				pkg("internal/gc") + "/...",
				pkg("internal/policy") + "/...",
			},
			Mode: Transitive,
		},
		{
			Name:   "hosted-deletion-reaches-no-cache",
			Reason: "ADR 0009 wall 3, the other direction: a retention plan must not be able to select a cached artifact through a hosted-deletion code path.",
			From: []string{
				pkg("internal/gc") + "/...",
				pkg("internal/policy") + "/...",
			},
			Forbidden: []string{pkg("internal/cache") + "/..."},
			Mode:      Transitive,
		},
		{
			Name:   "trivy-is-quarantined",
			Reason: "ADR 0017 / S-001: internal/scan/trivy is the only package that may name a vendor scanner. Everything else goes through scan.Scanner, so results stay normalised and the vendor stays replaceable. The whole aquasecurity module namespace is listed, not just trivy itself: the sibling modules Trivy's API hands back are vendor types too, and a normalised report that carries one is not normalised.",
			From:   []string{modulePath + "/..."},
			Except: []string{pkg("internal/scan/trivy") + "/..."},
			Forbidden: []string{
				"github.com/aquasecurity/...",
				"github.com/anchore/grype/...",
				"github.com/quay/claircore/...",
			},
			Mode: Direct,
		},
		{
			Name:   "jwt-is-quarantined",
			Reason: "ADR 0004 / Z-004: internal/authn/token is the only importer of the JWT library. The algorithm allowlist that stops an alg-confusion forgery lives there once; a second caller of the library is a second chance to parse a token without it.",
			From:   []string{modulePath + "/..."},
			Except: []string{pkg("internal/authn/token") + "/..."},
			Forbidden: []string{
				"github.com/golang-jwt/jwt/...",
			},
			Mode: Direct,
		},
		{
			Name:   "password-hashing-is-quarantined",
			Reason: "ADR 0004 / Z-002: internal/authn owns password hashing. A second caller of the primitive is a second set of cost parameters and a second encoding, and the one that drifts is the one nobody is looking at.",
			From:   []string{modulePath + "/..."},
			Except: []string{pkg("internal/authn") + "/..."},
			Forbidden: []string{
				"golang.org/x/crypto/argon2",
				"golang.org/x/crypto/bcrypt",
				"golang.org/x/crypto/scrypt",
			},
			Mode: Direct,
		},
		{
			Name:   "aead-primitives-are-quarantined",
			Reason: "ADR 0016: internal/secretbox owns encrypt/decrypt/rotate and is the only importer of the AEAD primitives, so every use of them is auditable in one file.",
			From:   []string{modulePath + "/..."},
			Except: []string{pkg("internal/secretbox") + "/..."},
			Forbidden: []string{
				"crypto/aes",
				"crypto/cipher",
			},
			Mode: Direct,
		},
	}
}
