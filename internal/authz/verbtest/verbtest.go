// Package verbtest records which permission verbs a test suite exercises, and
// checks the vocabulary against what it finds.
//
// CLAUDE.md §9 requires every verb to have at least one positive and one
// negative test: a verb with no negative test is an unenforced verb, and the
// only way to notice is to count. Counting is awkward because the tests that
// exercise a verb live in whichever package enforces it, and each package's
// tests are a separate process -- so a registry in memory could never see more
// than one package's worth.
//
// So the record is made in the source rather than at runtime. A test marks
// what it exercises:
//
//	verbtest.Positive(t, authz.RepoRead)   // this test asserts access is granted
//	verbtest.Negative(t, authz.RepoRead)   // ... and this one that it is refused
//
// and Scan reads those call sites back out of the repository's test files. The
// marks are ordinary Go, so a renamed constant updates them and a deleted verb
// stops compiling; the scan resolves them without needing type information by
// reading the vocabulary's own definitions.
package verbtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

// packagePath is how a test file imports this package. Scan uses it to tell a
// mark from any other function that happens to be called Positive.
const packagePath = "github.com/steveokay/trove/internal/authz/verbtest"

// Positive records that the calling test asserts the verb grants access.
//
// At runtime it only checks that the verb is real; its purpose is to be found
// by Scan. That is deliberate: a mark that is a live call cannot drift from
// the constant it names.
func Positive(t *testing.T, v authz.Verb) {
	t.Helper()
	requireKnown(t, v)
}

// Negative records that the calling test asserts the verb refuses access.
func Negative(t *testing.T, v authz.Verb) {
	t.Helper()
	requireKnown(t, v)
}

func requireKnown(t *testing.T, v authz.Verb) {
	t.Helper()

	if !v.Valid() {
		t.Fatalf("verbtest: %q is not in the vocabulary", v)
	}
}

// Polarities is what a verb's tests cover.
type Polarities struct {
	Positive bool
	Negative bool
}

// Complete reports whether both polarities are present.
func (p Polarities) Complete() bool { return p.Positive && p.Negative }

// Coverage maps each marked verb to the polarities its tests cover.
type Coverage map[authz.Verb]Polarities

// Scan reads every Go test file under root and reports what they mark.
//
// root is the repository root. Directories that cannot hold Go sources --
// version control, build output, the web tree -- are skipped.
func Scan(root string) (Coverage, error) {
	byIdentifier, err := vocabularyIdentifiers(root)
	if err != nil {
		return nil, err
	}

	coverage := Coverage{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skipDir(entry.Name()) && path != root {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		return scanFile(path, byIdentifier, coverage)
	})
	if err != nil {
		return nil, err
	}
	return coverage, nil
}

func skipDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		// Dot-directories are not the tree being vouched for: .git holds
		// checkouts, and .claude/worktrees holds parallel agents' working
		// copies whose marks would count for code that has not merged.
		return true
	}
	switch name {
	case "bin", "node_modules", "testdata", "web":
		return true
	case "verbtest":
		// This package's own tests call the marks to check that they work.
		// Counting those would let the mechanism vouch for verbs nothing
		// enforces, which is the opposite of what it is for.
		return true
	default:
		return false
	}
}

// vocabularyIdentifiers maps each verb constant's Go identifier to its value,
// read from the file that declares them. Deriving the map from the source of
// record means it cannot drift from the vocabulary the way a hand-written copy
// would.
func vocabularyIdentifiers(root string) (map[string]authz.Verb, error) {
	path := filepath.Join(root, "internal", "authz", "verbs.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse vocabulary: %w", err)
	}

	out := map[string]authz.Verb{}
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			unquoted, err := strconv.Unquote(literal.Value)
			if err != nil {
				continue
			}
			if verb := authz.Verb(unquoted); verb.Valid() {
				out[value.Names[0].Name] = verb
			}
		}
	}
	if len(out) != len(authz.AllVerbs()) {
		return nil, fmt.Errorf("read %d verb constants from %s, want %d: the vocabulary and its declarations disagree",
			len(out), path, len(authz.AllVerbs()))
	}
	return out, nil
}

// scanFile records the marks in one test file.
func scanFile(path string, byIdentifier map[string]authz.Verb, coverage Coverage) error {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	local := importName(file)
	if local == "" {
		return nil
	}

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != local {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}

		verb, ok := verbArgument(call.Args[len(call.Args)-1], byIdentifier)
		if !ok {
			return true
		}
		polarities := coverage[verb]
		switch selector.Sel.Name {
		case "Positive":
			polarities.Positive = true
		case "Negative":
			polarities.Negative = true
		default:
			return true
		}
		coverage[verb] = polarities
		return true
	})
	return nil
}

// importName returns the identifier this package is imported as, or empty if
// the file does not import it.
func importName(file *ast.File) string {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != packagePath {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		return "verbtest"
	}
	return ""
}

// verbArgument resolves a mark's verb argument, which is written either as
// authz.RepoRead from another package or as RepoRead from within authz itself.
func verbArgument(arg ast.Expr, byIdentifier map[string]authz.Verb) (authz.Verb, bool) {
	var name string
	switch expr := arg.(type) {
	case *ast.SelectorExpr:
		name = expr.Sel.Name
	case *ast.Ident:
		name = expr.Name
	default:
		return "", false
	}
	verb, ok := byIdentifier[name]
	return verb, ok
}

// AssertVocabularyIsCovered fails unless every verb outside the allowlist has
// both a positive and a negative test, and every verb inside it still has
// neither.
func AssertVocabularyIsCovered(t *testing.T, root string, allowlist map[authz.Verb]string) {
	t.Helper()

	coverage, err := Scan(root)
	if err != nil {
		t.Fatalf("scan for verb coverage: %v", err)
	}
	for _, problem := range Problems(coverage, allowlist) {
		t.Error(problem)
	}
}

// Problems reports every way the vocabulary falls short of §9, given what the
// scan found and which verbs are allowed to be uncovered for now.
//
// The allowlist is a ratchet rather than a graveyard: a verb that acquires
// tests is reported until its entry is removed, so the list can only shrink.
// Deleting the last entry is the point at which §9's requirement is met in
// full, and this check is what keeps it met afterwards.
func Problems(coverage Coverage, allowlist map[authz.Verb]string) []string {
	var problems []string

	for _, verb := range authz.AllVerbs() {
		reason, allowed := allowlist[verb]
		polarities := coverage[verb]

		switch {
		case allowed && polarities.Complete():
			problems = append(problems, fmt.Sprintf(
				"%s is now covered by tests (%s): remove it from the allowlist", verb, reason))
		case allowed:
			continue
		case !polarities.Positive && !polarities.Negative:
			problems = append(problems, fmt.Sprintf(
				"%s has no tests: a verb nothing exercises is an unenforced verb", verb))
		case !polarities.Positive:
			problems = append(problems, fmt.Sprintf(
				"%s has no positive test: nothing proves it grants anything", verb))
		case !polarities.Negative:
			problems = append(problems, fmt.Sprintf(
				"%s has no negative test: an unenforced verb looks identical to an enforced one", verb))
		}
	}

	// An allowlist entry for something that is not a verb is dead weight, and
	// usually means a verb was renamed on one side only.
	names := make([]authz.Verb, 0, len(allowlist))
	for verb := range allowlist {
		names = append(names, verb)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, verb := range names {
		if !verb.Valid() {
			problems = append(problems, fmt.Sprintf(
				"the allowlist names %q, which is not in the vocabulary", verb))
		}
	}
	return problems
}

// SortedVerbs renders a coverage map's verbs in order, for test messages.
func SortedVerbs(coverage Coverage) []authz.Verb {
	out := make([]authz.Verb, 0, len(coverage))
	for verb := range coverage {
		out = append(out, verb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
