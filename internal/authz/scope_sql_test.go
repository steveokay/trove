package authz_test

// The differential test between the scope matcher and the SQL predicate the
// query layer filters with. It imports the storage packages, which the authz
// package itself must never do (Z-009 checks production imports, not test
// ones): the point is precisely to compare the two sides, and the comparison
// has to live on one of them.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
	"github.com/steveokay/trove/internal/server"

	_ "modernc.org/sqlite"
)

func TestScopeFilters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scope   authz.Scope
		want    authz.Filter
		selects bool
	}{
		{scope: "system", selects: false},
		{scope: "*", want: authz.Filter{All: true}, selects: true},
		{scope: "team-a/api", want: authz.Filter{Exact: "team-a/api"}, selects: true},
		{scope: "team-a/*", want: authz.Filter{Prefix: "team-a/"}, selects: true},
		{scope: "nginx", want: authz.Filter{Exact: "nginx"}, selects: true},
		// A scope that never went through the parser selects nothing, the same
		// as it matches nothing.
		{scope: "team-*/api", selects: false},
		{scope: "", selects: false},
	}

	for _, tt := range tests {
		t.Run(string(tt.scope), func(t *testing.T) {
			t.Parallel()

			got, selects := tt.scope.Filter()
			if selects != tt.selects {
				t.Fatalf("Filter() selects = %v, want %v", selects, tt.selects)
			}
			if got != tt.want {
				t.Errorf("Filter() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFiltersAndVisibleScopes(t *testing.T) {
	t.Parallel()

	bindings := []authz.Binding{
		{ID: "b1", Role: "developer", Scope: "team-a/*", Verbs: []authz.Verb{authz.RepoList, authz.RepoRead}},
		{ID: "b2", Role: "publisher", Scope: "team-b/api", Verbs: []authz.Verb{authz.RepoRead, authz.RepoWrite}},
		{ID: "b3", Role: "admin", Scope: "system", Verbs: []authz.Verb{authz.RepoList, authz.UserWrite}},
	}

	// A listing asks which scopes grant the verb it lists by, so the query and
	// the decision start from the same bindings rather than from two ideas of
	// what the subject can see.
	scopes := authz.VisibleScopes(bindings, authz.RepoList)
	if len(scopes) != 2 || scopes[0] != "team-a/*" || scopes[1] != "system" {
		t.Fatalf("VisibleScopes(repo:list) = %v, want [team-a/* system]", scopes)
	}

	// The system scope drops out: it selects no repositories, and a listing
	// built from it must return nothing rather than everything.
	filters := authz.Filters(scopes)
	if len(filters) != 1 || filters[0] != (authz.Filter{Prefix: "team-a/"}) {
		t.Fatalf("Filters = %+v, want just the team-a prefix", filters)
	}

	// A verb nothing grants yields no scopes, which compiles to no filters --
	// which is "nothing visible", not "no filtering".
	if scopes := authz.VisibleScopes(bindings, authz.GateOverride); len(scopes) != 0 {
		t.Errorf("VisibleScopes(gate:override) = %v, want none", scopes)
	}
	if filters := authz.Filters(nil); len(filters) != 0 {
		t.Errorf("Filters(nil) = %+v, want none", filters)
	}
}

func TestFilterMatchesTheZeroValue(t *testing.T) {
	t.Parallel()

	// A filter nobody built selects nothing: the correct reading of a subject
	// holding no bindings, and the case a nil slice would have turned into
	// "everything" (ADR 0003).
	var zero authz.Filter
	for _, name := range []string{"", "team-a/api", "nginx"} {
		if zero.Matches(name) {
			t.Errorf("the zero Filter matched %q", name)
		}
	}
}

// names is the corpus both sides are compared over: neighbours that differ by
// one character, prefixes of each other, and the shapes that break a naive
// prefix match.
var names = []string{
	"nginx",
	"system",
	"team-a",
	"team-a/api",
	"team-a/api-2",
	"team-a/apix",
	"team-a/sub/api",
	"team-a/sub/deep/api",
	"team-ab",
	"team-ab/api",
	"team-a-b/api",
	"team-b/api",
	"other/team-a/api",
	"all/library/nginx",
	"a",
	"a/b",
	"a/b/c",
}

// The matcher and the SQL predicate must agree on every name, or a catalog
// will show a repository the subject cannot pull -- or hide one it can. They
// are checked against a real engine rather than against a reimplementation of
// LIKE, because the disagreement would be in the engine's semantics.
func TestScopeMatcherAgreesWithSQL(t *testing.T) {
	t.Parallel()

	db := seedRepositories(t, names)

	scopes := []authz.Scope{
		"*",
		"team-a/api",
		"team-a/*",
		"team-ab/*",
		"team-a/sub/*",
		"a/*",
		"a",
		"nginx",
		"other/*",
		"all/library/nginx",
		"system",
	}

	for _, scope := range scopes {
		t.Run(string(scope), func(t *testing.T) {
			t.Parallel()

			var want []string
			for _, name := range names {
				resource, err := authz.Repository(name)
				if err != nil {
					t.Fatalf("Repository(%q): %v", name, err)
				}
				if scope.Matches(resource) {
					want = append(want, name)
				}
			}

			got := selectVisible(t, db, scope)
			assertSameNames(t, scope, got, want)
		})
	}
}

// FuzzScopeMatcherAgreesWithSQL runs the same comparison over generated
// patterns and names, which is where the disagreements that a hand-written
// table would miss actually live.
func FuzzScopeMatcherAgreesWithSQL(f *testing.F) {
	db := seedRepositories(f, names)

	for _, scope := range []string{"*", "team-a/*", "team-a/api", "a/*", "system", "team-*/api"} {
		for _, name := range names {
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

		// The generated name is inserted so the query has something to find;
		// duplicates are ignored, which keeps the corpus growing rather than
		// resetting per case.
		insertRepository(t, db, name)

		var want []string
		if scope.Matches(resource) {
			want = []string{name}
		}

		got := selectVisible(t, db, scope)
		// Only the generated name is compared: the seeded corpus is shared
		// across cases and its own agreement is covered by the table test.
		var relevant []string
		for _, candidate := range got {
			if candidate == name {
				relevant = append(relevant, candidate)
			}
		}
		assertSameNames(t, scope, relevant, want)
	})
}

// selectVisible runs the query layer's own predicate for a scope and returns
// the names it selects.
func selectVisible(t *testing.T, db *sql.DB, scope authz.Scope) []string {
	t.Helper()

	visibility := visibilityFor(scope)
	where, args := sqlutil.VisibilityClause("name", visibility, sqlutil.Question, 1)

	rows, err := db.QueryContext(context.Background(),
		`SELECT name FROM repositories WHERE `+where+` ORDER BY name`, args...)
	if err != nil {
		t.Fatalf("query for %q: %v", scope, err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// visibilityFor runs a single scope through the production bridge
// (server.VisibilityFor, Z-012), so the differential tests pin the code the
// query layer actually filters with rather than a test-local copy of it.
func visibilityFor(scope authz.Scope) meta.Visibility {
	bindings := []authz.Binding{{
		ID: "b", Role: "lister", Scope: scope, Verbs: []authz.Verb{authz.RepoList},
	}}
	return server.VisibilityFor(bindings, authz.RepoList)
}

// The storage layer has its own matcher for the same filter, used wherever a
// decision is made in Go rather than in SQL. It has to agree too, or the two
// halves of the query layer would disagree with each other.
func TestScopeMatcherAgreesWithTheStorageFilter(t *testing.T) {
	t.Parallel()

	scopes := []authz.Scope{"*", "team-a/api", "team-a/*", "a/*", "team-ab/*", "system"}
	for _, scope := range scopes {
		for _, name := range names {
			resource, err := authz.Repository(name)
			if err != nil {
				t.Fatalf("Repository(%q): %v", name, err)
			}
			want := scope.Matches(resource)
			got := visibilityFor(scope).Allows(name)
			if got != want {
				t.Errorf("%q vs %q: authz says %v, the storage filter says %v", scope, name, want, got)
			}
		}
	}
}

func seedRepositories(t testing.TB, seed []string) *sql.DB {
	t.Helper()

	// A file rather than ":memory:" so every connection in the pool sees the
	// same database.
	path := filepath.Join(t.TempDir(), "scopes.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	if _, err := db.ExecContext(context.Background(),
		`CREATE TABLE repositories (name TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	for _, name := range seed {
		insertRepository(t, db, name)
	}
	return db
}

func insertRepository(t testing.TB, db *sql.DB, name string) {
	t.Helper()

	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO repositories (name) VALUES (?) ON CONFLICT (name) DO NOTHING`, name); err != nil {
		t.Fatalf("insert %q: %v", name, err)
	}
}

func assertSameNames(t *testing.T, scope authz.Scope, got, want []string) {
	t.Helper()

	sort.Strings(got)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("scope %q: SQL selected %v, the matcher selected %v", scope, got, want)
	}
}
