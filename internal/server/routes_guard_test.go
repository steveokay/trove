package server_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/server"
)

// A table where every route carries a verb, plus a public route that is on the
// frozen list with its approved reason, verifies clean. This is the shape the
// application's router is expected to have.
func TestVerifyAcceptsAGuardedTable(t *testing.T) {
	t.Parallel()

	r := router(t)
	r.HandleFunc(http.MethodGet, "/api/v1/repositories/{name}",
		server.Permission{Verb: authz.RepoRead}, noop)
	r.HandleFunc(http.MethodPost, "/api/v1/system/gc",
		server.Permission{Verb: authz.GCRun}, noop)
	r.HandlePublic(http.MethodGet, "/healthz",
		"liveness must answer before anything is configured", http.HandlerFunc(noop))

	if err := r.Verify(); err != nil {
		t.Errorf("Verify = %v, want nil", err)
	}
}

// An unguarded endpoint reaches the frozen list or it fails, and the failure
// names the route -- an error saying only "a route is unguarded" would send
// whoever reads CI back to grep for it.
func TestVerifyRefusesUnapprovedPublicRoutes(t *testing.T) {
	t.Parallel()

	r := router(t)
	r.HandlePublic(http.MethodGet, "/api/v1/users",
		"it is only the user list", http.HandlerFunc(noop))

	err := r.Verify()
	if !errors.Is(err, server.ErrUnapprovedPublicRoute) {
		t.Fatalf("Verify = %v, want ErrUnapprovedPublicRoute", err)
	}
	if !strings.Contains(err.Error(), "GET /api/v1/users") {
		t.Errorf("the error does not name the route: %v", err)
	}
}

// The reason at registration and the reason on the frozen list are the same
// claim written twice, so they must agree. Drift means the approval was given
// for something other than what is now being served -- which is exactly the
// case the frozen list exists to catch.
func TestVerifyRefusesADriftedReason(t *testing.T) {
	t.Parallel()

	r := router(t)
	r.HandlePublic(http.MethodGet, "/token",
		"handy for debugging", http.HandlerFunc(noop))

	err := r.Verify()
	if !errors.Is(err, server.ErrPublicReasonMismatch) {
		t.Fatalf("Verify = %v, want ErrPublicReasonMismatch", err)
	}
	// The approved wording is quoted, so the fix is visible from the failure.
	if !strings.Contains(err.Error(), "issues credentials") {
		t.Errorf("the error does not quote the approved reason: %v", err)
	}
}

// Approval is by exact method and pattern. A pattern that merely looks like an
// approved one -- a different method, a wildcard where the list has a literal,
// a longer path under an approved prefix -- is not approved.
func TestVerifyApprovesByExactRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		pattern string
	}{
		{name: "different method", method: http.MethodPost, pattern: "/token"},
		{name: "wildcard for a literal", method: http.MethodGet, pattern: "/{path...}"},
		{name: "deeper than the shell", method: http.MethodGet, pattern: "/healthz/detail"},
		{name: "outside the assets prefix", method: http.MethodGet, pattern: "/assets2/{path...}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := router(t)
			r.HandlePublic(tt.method, tt.pattern, "looks approved", http.HandlerFunc(noop))
			if err := r.Verify(); !errors.Is(err, server.ErrUnapprovedPublicRoute) {
				t.Errorf("Verify = %v, want ErrUnapprovedPublicRoute", err)
			}
		})
	}
}

// Somebody adding three unguarded routes should learn about all three at once.
func TestVerifyReportsEveryProblem(t *testing.T) {
	t.Parallel()

	r := router(t)
	for _, pattern := range []string{"/one", "/two", "/three"} {
		r.HandlePublic(http.MethodGet, pattern, "no reason at all", http.HandlerFunc(noop))
	}

	err := r.Verify()
	if err == nil {
		t.Fatal("Verify = nil, want three problems")
	}
	for _, pattern := range []string{"/one", "/two", "/three"} {
		if !strings.Contains(err.Error(), "GET "+pattern) {
			t.Errorf("%s is not named in the failure: %v", pattern, err)
		}
	}
}

// The frozen list is read by people, so each entry has to carry what a reader
// needs: a route, a reason, and the task that will register it. An entry
// approving a route nobody is building is an approval nobody reviewed against
// a purpose.
func TestPublicRouteListIsReviewable(t *testing.T) {
	t.Parallel()

	routes := server.PublicRoutes()
	if len(routes) == 0 {
		t.Fatal("no public routes are approved, which cannot be right while the UI and token endpoint exist")
	}

	status := readStatus(t)
	seen := make(map[string]bool, len(routes))

	for _, route := range routes {
		label := route.Method + " " + route.Pattern
		switch {
		case route.Method == "" || route.Pattern == "":
			t.Errorf("%q is not a route", label)
		case route.Reason == "":
			t.Errorf("%s is approved with no reason", label)
		case route.Task == "":
			t.Errorf("%s names no task", label)
		}
		if seen[label] {
			t.Errorf("%s is approved twice", label)
		}
		seen[label] = true

		// The task must be a real one. A typo here would look like provenance
		// and provide none.
		if route.Task != "" && !strings.Contains(status, "| "+route.Task+" |") {
			t.Errorf("%s names task %s, which is not in status.md", label, route.Task)
		}

		// A pattern the mux cannot parse would approve a route that can never
		// be registered, so the approval would be unfalsifiable.
		assertPatternIsRoutable(t, route.Method, route.Pattern)
	}
}

// The frozen list is short on purpose. This is not a style rule: every entry is
// an endpoint served to anyone who can reach the port, and a list that grows
// quietly is how "we only have a handful" stops being true.
func TestPublicRouteListStaysSmall(t *testing.T) {
	t.Parallel()

	const approved = 5
	if got := len(server.PublicRoutes()); got != approved {
		t.Errorf("%d public routes are approved, expected %d -- if the change is deliberate, "+
			"update this count in the same commit so it is reviewed", got, approved)
	}
}

// A table that does not verify serves nothing. This is what turns Verify from
// a step somebody remembers into a property of the router: the unguarded
// endpoint is never reachable, whether or not anyone thought to run the check.
func TestAnUnverifiedTableServesNothing(t *testing.T) {
	t.Parallel()

	served := false
	r := router(t)
	r.HandlePublic(http.MethodGet, "/api/v1/users", "it is only the user list",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true }))

	// Wrapped so the refusal's log line goes nowhere instead of to stderr.
	handler := server.WithRequestLogging(quietLogger(), nil)(r)

	for _, attempt := range []string{"first", "second"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))

		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("%s request: status = %d, want 500", attempt, recorder.Code)
		}
		if served {
			t.Fatalf("%s request: the unapproved route was served", attempt)
		}
	}

	// A guarded request to the same router is refused too. The table is
	// unsound as a whole, so nothing on it is trustworthy.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/nowhere", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for every path while the table is unsound", recorder.Code)
	}
}

// Every route the binary serves has to be in a table Verify can see. Nothing
// makes that true by itself: an alternative mux built anywhere in the tree
// would serve whatever was registered on it, guarded or not, and the route
// table would not know the endpoints existed.
//
// So the mux is quarantined. Only the router owns one, and this walks the
// source to prove it. It reads non-test files only, on the same reasoning as
// the import-boundary test (Z-009): a test may stand up any mux it likes
// because nothing it registers is ever served.
func TestOnlyTheRouterRegistersRoutes(t *testing.T) {
	t.Parallel()

	found, scanned, err := findMuxUses(repositoryRoot(t))
	if err != nil {
		t.Fatalf("scanning the tree: %v", err)
	}
	// A walk that found nothing to read would pass this test while checking
	// nothing at all, which is the failure mode of every source-scanning test.
	if scanned < 40 {
		t.Fatalf("scanned only %d files, so the walk is not reaching the tree", scanned)
	}
	for _, use := range found {
		t.Errorf("%s: %s -- HTTP routes are registered through server.Router so the "+
			"route table sees them; if this file needs its own mux, Z-011's quarantine "+
			"has to change first", use.position, use.name)
	}
}

// The scanner has to be able to fail, or it is a test that always passes.
func TestMuxScannerFindsWhatItLooksFor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	write("offender.go", `package p

import "net/http"

func Serve() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/secret", nil)
	return mux
}
`)
	// A handler is not a mux: taking an http.Handler or writing an
	// http.HandlerFunc registers nothing, and flagging it would make the rule
	// unusable.
	write("innocent.go", `package p

import "net/http"

func Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(next.ServeHTTP)
}
`)
	// Test files are out of scope, as in the tree itself.
	write("offender_test.go", `package p

import "net/http"

func mux() *http.ServeMux { return http.NewServeMux() }
`)

	found, scanned, err := findMuxUses(dir)
	if err != nil {
		t.Fatalf("findMuxUses: %v", err)
	}
	if scanned != 2 {
		t.Errorf("scanned %d files, want the two non-test ones", scanned)
	}
	if len(found) != 1 {
		t.Fatalf("found %v, want exactly the one in offender.go", found)
	}
	if found[0].name != "http.NewServeMux" || !strings.Contains(found[0].position, "offender.go") {
		t.Errorf("found %+v, want http.NewServeMux in offender.go", found[0])
	}
}

// quietLogger keeps a deliberate failure's log line out of the test output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// muxUse is one reference to a route-registration API outside the router.
type muxUse struct {
	position string
	name     string
}

func (u muxUse) String() string { return u.position + ": " + u.name }

// quarantinedNames are the ways to register an HTTP route without the route
// table hearing about it. http.Handler and http.HandlerFunc are deliberately
// absent: they are handlers, not registrations.
var quarantinedNames = map[string]bool{
	"http.NewServeMux":     true,
	"http.DefaultServeMux": true,
	"http.Handle":          true,
	"http.HandleFunc":      true,
	"http.ListenAndServe":  true,
	"http.ServeMux":        true,
	"chi.NewRouter":        true,
	"chi.NewMux":           true,
}

// muxOwner is the one file permitted to hold a mux: the router that records
// every route it registers.
const muxOwner = "internal/server/router.go"

// findMuxUses parses every non-test Go file under root and reports references
// to the quarantined names.
//
// It is syntactic, which is enough here because every one of those names must
// be written out to be used: there is no way to obtain a ServeMux without
// naming it. What it cannot see is a single handler composed elsewhere and
// passed straight to server.New -- but a handler is not a route table, and
// anything wanting more than one path has to name one of these.
func findMuxUses(root string) ([]muxUse, int, error) {
	var (
		found   []muxUse
		scanned int
		fset    = token.NewFileSet()
	)

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if skipDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(relative) == muxOwner {
			return nil
		}

		scanned++
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", relative, err)
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
			name := pkg.Name + "." + selector.Sel.Name
			if quarantinedNames[name] {
				position := fset.Position(selector.Pos())
				found = append(found, muxUse{
					position: fmt.Sprintf("%s:%d", filepath.ToSlash(relative), position.Line),
					name:     name,
				})
			}
			return true
		})
		return nil
	})

	return found, scanned, err
}

// skipDir keeps the walk out of trees that hold no Go source we own: the git
// database, the UI's dependencies and build output, and the archtest fixture
// module, which contains deliberate violations of other rules. web/ itself is
// not skipped -- its embed file is ours, and exempting the directory would
// exempt whatever else lands in it.
func skipDir(name string) bool {
	switch name {
	case ".git", ".github", "node_modules", "dist", "testdata":
		return true
	}
	return false
}

// assertPatternIsRoutable proves a pattern is one the mux accepts, which is
// what makes an approval falsifiable.
func assertPatternIsRoutable(t *testing.T, method, pattern string) {
	t.Helper()

	defer func() {
		if problem := recover(); problem != nil {
			t.Errorf("%s %s is not a routable pattern: %v", method, pattern, problem)
		}
	}()
	http.NewServeMux().Handle(method+" "+pattern, http.HandlerFunc(noop))
}

// readStatus returns status.md, which is where a task ID is either real or not.
func readStatus(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), "status.md"))
	if err != nil {
		t.Fatalf("reading status.md: %v", err)
	}
	return string(content)
}

// repositoryRoot walks up from the test's directory to the module root.
func repositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}
