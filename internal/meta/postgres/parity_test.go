package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlite"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// The two engines' head schemas are held to the same shape. Without this, the
// shared contract suite would slowly stop proving what it looks like it
// proves: it would show that two different schemas each work, rather than that
// an operator can pick either engine and get the same registry. A column added
// to one migration directory and forgotten in the other fails here.

// column is one column, reduced to what has to match across engines. Storage
// sizes and engine-specific type names deliberately do not.
type column struct {
	name     string
	class    string
	nullable bool
}

func (c column) String() string {
	null := "NOT NULL"
	if c.nullable {
		null = "NULL"
	}
	return fmt.Sprintf("%s %s %s", c.name, c.class, null)
}

func TestSchemasAreIdenticalAcrossEngines(t *testing.T) {
	t.Parallel()

	sqliteSchema := sqliteHeadSchema(t)
	postgresSchema := postgresHeadSchema(t)

	for _, table := range union(tableNames(sqliteSchema), tableNames(postgresSchema)) {
		t.Run(table, func(t *testing.T) {
			left, inSQLite := sqliteSchema[table]
			right, inPostgres := postgresSchema[table]
			switch {
			case !inSQLite:
				t.Fatalf("table %q exists only in the Postgres schema", table)
			case !inPostgres:
				t.Fatalf("table %q exists only in the SQLite schema", table)
			}

			if len(left) != len(right) {
				t.Fatalf("column counts differ:\n sqlite: %v\n   pg:   %v", render(left), render(right))
			}
			for i := range left {
				if left[i] != right[i] {
					t.Errorf("column %d differs:\n sqlite: %s\n   pg:   %s", i, left[i], right[i])
				}
			}
		})
	}
}

// Parity of shape is not enough: the two engines must also order the same way.
// SQLite compares text byte by byte and cannot do anything else; Postgres uses
// the database's collation unless told otherwise, and in a typical locale
// punctuation sorts differently. Since every listing is ordered and paginated
// by these columns, a difference here would hand the same page back in a
// different order depending on which engine an operator chose.
func TestListingOrderMatchesAcrossEngines(t *testing.T) {
	t.Parallel()

	// Names chosen so byte order and a locale collation disagree: the
	// separators are exactly what a locale tends to ignore at the first pass.
	names := []string{
		"team-a/api", "teama/api", "team.a/api", "team_a/api", "team/a-api",
		"Team-a/api", "team-A/api", "team-a-api", "team-a/API", "team-a/api-2",
	}

	sqliteStore, err := sqlite.Open(context.Background(), sqlite.Options{
		Path: filepath.Join(t.TempDir(), "order.db"),
		Now:  func() time.Time { return testTime },
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqliteStore.Close() })

	postgresStore := open(t)

	ctx := context.Background()
	for _, name := range names {
		for _, store := range []meta.Store{sqliteStore, postgresStore} {
			if _, err := store.CreateRepository(ctx, meta.Repository{Name: name, Type: meta.Hosted}); err != nil {
				t.Fatalf("CreateRepository(%q): %v", name, err)
			}
		}
	}

	// Page through both a couple of names at a time, so the cursor comparison
	// is exercised alongside the ordering rather than just a single big page.
	sqliteOrder := pageThrough(t, sqliteStore)
	postgresOrder := pageThrough(t, postgresStore)

	if len(sqliteOrder) != len(names) || len(postgresOrder) != len(names) {
		t.Fatalf("paged %d (sqlite) and %d (postgres) repositories, want %d",
			len(sqliteOrder), len(postgresOrder), len(names))
	}
	for i := range sqliteOrder {
		if sqliteOrder[i] != postgresOrder[i] {
			t.Fatalf("engines disagree at position %d:\n sqlite: %v\n   pg:   %v",
				i, sqliteOrder, postgresOrder)
		}
	}
}

func pageThrough(t *testing.T, store meta.Store) []string {
	t.Helper()

	var (
		seen   []string
		cursor string
	)
	for pages := 0; ; pages++ {
		if pages > 32 {
			t.Fatal("pagination did not terminate")
		}
		page, err := store.ListRepositories(context.Background(), meta.ListOptions{
			Visibility: meta.Unrestricted(),
			Limit:      3,
			Cursor:     cursor,
		})
		if err != nil {
			t.Fatalf("ListRepositories: %v", err)
		}
		for _, repo := range page.Repositories {
			seen = append(seen, repo.Name)
		}
		if page.NextCursor == "" {
			return seen
		}
		cursor = page.NextCursor
	}
}

// sqliteHeadSchema migrates a throwaway SQLite database and reads its shape
// back out of the engine, rather than parsing the migration files: what the
// engine ended up with is what matters.
func sqliteHeadSchema(t *testing.T) map[string][]column {
	t.Helper()

	path := filepath.Join(t.TempDir(), "parity.db")
	store, err := sqlite.Open(context.Background(), sqlite.Options{
		Path: path,
		Now:  func() time.Time { return testTime },
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	tables := queryStrings(t, db, `SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)

	schema := make(map[string][]column, len(tables))
	for _, table := range tables {
		// table_info is a table-valued function, so the table name cannot be a
		// bound parameter; it comes from sqlite_master, not from a caller.
		rows, err := db.QueryContext(ctx, `SELECT name, type, "notnull", pk FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatalf("table_info(%s): %v", table, err)
		}
		var columns []column
		for rows.Next() {
			var (
				name    string
				typ     string
				notNull int
				pk      int
			)
			if err := rows.Scan(&name, &typ, &notNull, &pk); err != nil {
				t.Fatalf("scan table_info: %v", err)
			}
			// SQLite lets a non-integer PRIMARY KEY column hold NULL, a
			// historical quirk Postgres does not share. Treating a key as
			// NOT NULL is the semantics both engines actually have here.
			columns = append(columns, column{
				name:     name,
				class:    sqliteClass(t, typ),
				nullable: notNull == 0 && pk == 0,
			})
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("table_info(%s): %v", table, err)
		}
		if err := rows.Close(); err != nil {
			t.Fatalf("close table_info(%s): %v", table, err)
		}
		schema[table] = columns
	}
	return schema
}

func postgresHeadSchema(t *testing.T) map[string][]column {
	t.Helper()

	dsn := requireDSN(t)
	store, err := Open(context.Background(), Options{
		DSN: dsn,
		Now: func() time.Time { return testTime },
	})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close postgres: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("reopen postgres: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.QueryContext(context.Background(),
		`SELECT table_name, column_name, data_type, is_nullable
		   FROM information_schema.columns
		  WHERE table_schema = 'public'
		  ORDER BY table_name, ordinal_position`)
	if err != nil {
		t.Fatalf("information_schema: %v", err)
	}
	defer func() { _ = rows.Close() }()

	schema := make(map[string][]column)
	for rows.Next() {
		var table, name, dataType, isNullable string
		if err := rows.Scan(&table, &name, &dataType, &isNullable); err != nil {
			t.Fatalf("scan information_schema: %v", err)
		}
		schema[table] = append(schema[table], column{
			name:     name,
			class:    postgresClass(t, dataType),
			nullable: isNullable == "YES",
		})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("information_schema: %v", err)
	}
	return schema
}

// sqliteClass and postgresClass reduce each engine's type names to the three
// classes the store actually depends on. Postgres booleans map to integer
// because SQLite has no boolean type: both hold 0/1 and Go sees a bool either
// way, and pretending otherwise would fail parity for a difference that does
// not exist above the driver.
func sqliteClass(t *testing.T, typ string) string {
	t.Helper()

	switch strings.ToUpper(typ) {
	case "TEXT":
		return "text"
	case "INTEGER":
		return "integer"
	case "BLOB":
		return "blob"
	default:
		t.Fatalf("unexpected SQLite column type %q: add it to the parity mapping deliberately", typ)
		return ""
	}
}

func postgresClass(t *testing.T, dataType string) string {
	t.Helper()

	switch dataType {
	case "text":
		return "text"
	case "bigint", "integer", "boolean":
		return "integer"
	case "bytea":
		return "blob"
	default:
		t.Fatalf("unexpected Postgres column type %q: add it to the parity mapping deliberately", dataType)
		return ""
	}
}

func queryStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func tableNames(schema map[string][]column) []string {
	out := make([]string, 0, len(schema))
	for name := range schema {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, list := range [][]string{a, b} {
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func render(columns []column) string {
	out := make([]string, len(columns))
	for i, c := range columns {
		out[i] = c.String()
	}
	return strings.Join(out, ", ")
}
