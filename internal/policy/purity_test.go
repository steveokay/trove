package policy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// evaluatorFiles are the files that make up the pure retention evaluator
// (P-002). They are named rather than globbed, because the point of the check
// below is that these files stay pure while the package around them grows: the
// apply path (P-005) does real I/O by definition, and lives in this package
// too.
var evaluatorFiles = []string{"inventory.go", "retention.go", "plan.go"}

// pureImports is everything the evaluator may import. It is an allowlist and
// not a denylist, because a denylist only forbids the ways of doing I/O that
// somebody thought of.
var pureImports = []string{"cmp", "errors", "fmt", "regexp", "slices", "strings", "time"}

// The evaluator does no I/O. ADR 0010 states it as an interface --
// `Evaluate(inventory, rules, now) → Plan` -- and this is the check that the
// interface stayed true of the implementation.
//
// It matters beyond testability. The plan is the thing an operator approves
// before blobs that cannot be re-fetched are deleted. An evaluator that can
// read the store can disagree with the snapshot it was handed, and once it
// can, approving the plan stops meaning that the approved deletions are the
// ones that happen.
//
// This is deliberately file-scoped rather than package-scoped, which is what
// internal/archtest can express. The package-level boundary belongs there
// (policy reaches no cache, ADR 0009 wall 3, already enforced); the file-level
// one has to live here.
func TestEvaluatorImportsNothingThatCanDoIO(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	for _, name := range evaluatorFiles {
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unquoting import %s: %v", name, spec.Path.Value, err)
			}
			if !slices.Contains(pureImports, path) {
				t.Fatalf("%s imports %q: the retention evaluator is pure (ADR 0010) and may import only %v",
					name, path, pureImports)
			}
		}
	}
}

// The clock is injected. A time.Now anywhere in the evaluator would make a
// plan depend on when it was rendered rather than on the evaluation time it
// carries, and would make the boundary cases -- pushed exactly at the cutoff,
// pulled exactly at the cutoff -- untestable.
func TestEvaluatorReadsNoClock(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	for _, name := range evaluatorFiles {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		file, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "time" && strings.HasPrefix(selector.Sel.Name, "Now") {
				t.Errorf("%s calls time.%s: the evaluation time is a parameter (§7)",
					name, selector.Sel.Name)
			}
			return true
		})
	}
}
