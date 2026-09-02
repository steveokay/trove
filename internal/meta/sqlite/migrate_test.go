package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

var migrateTestTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// testDB opens an empty database with the same settings the store uses.
func testDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", dsn(filepath.Join(t.TempDir(), "migrate.db"), time.Second))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

func TestLoadMigrationsReadsTheEmbeddedSchema(t *testing.T) {
	t.Parallel()

	all, err := loadMigrations(migrationFiles)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no migrations embedded")
	}
	for i := 1; i < len(all); i++ {
		if all[i].version <= all[i-1].version {
			t.Fatalf("migrations are not ordered by version: %d then %d", all[i-1].version, all[i].version)
		}
	}
}

// A file that does not parse is a packaging mistake. Guessing at its version is
// how two deployments end up with different schemas, so it is refused.
func TestLoadMigrationsRejectsUnparseableFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "not sql",
			files: map[string]string{"migrations/0001_init.txt": "SELECT 1"},
			want:  "want a .sql file",
		},
		{
			name:  "no name",
			files: map[string]string{"migrations/0001.sql": "SELECT 1"},
			want:  "want NNNN_name.sql",
		},
		{
			name:  "empty name",
			files: map[string]string{"migrations/0001_.sql": "SELECT 1"},
			want:  "want NNNN_name.sql",
		},
		{
			name:  "non numeric version",
			files: map[string]string{"migrations/init_first.sql": "SELECT 1"},
			want:  "must be a positive number",
		},
		{
			name:  "zero version",
			files: map[string]string{"migrations/0000_init.sql": "SELECT 1"},
			want:  "must be a positive number",
		},
		{
			name: "duplicate version",
			files: map[string]string{
				"migrations/0001_init.sql":  "SELECT 1",
				"migrations/0001_again.sql": "SELECT 1",
			},
			want: "share version 1",
		},
		{
			name:  "no migrations",
			files: map[string]string{"migrations/README.md": "not a migration"},
			want:  "want a .sql file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := loadMigrations(fstest.MapFS(mapFiles(tt.files)))
			if err == nil {
				t.Fatalf("loadMigrations succeeded, want an error mentioning %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestLoadMigrationsNeedsADirectory(t *testing.T) {
	t.Parallel()

	if _, err := loadMigrations(fstest.MapFS(nil)); err == nil {
		t.Error("loadMigrations on an empty filesystem succeeded, want an error")
	}

	// A directory that exists but holds nothing is a build that shipped no
	// schema, which must not be mistaken for "already at head".
	empty := fstest.MapFS{"migrations/sub/keep": {Data: []byte("x")}}
	_, err := loadMigrations(empty)
	if err == nil || !strings.Contains(err.Error(), "no migrations found") {
		t.Errorf("loadMigrations on an empty directory = %v, want 'no migrations found'", err)
	}
}

func mapFiles(files map[string]string) map[string]*fstest.MapFile {
	out := make(map[string]*fstest.MapFile, len(files))
	for name, body := range files {
		out[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return out
}

func TestPendingRefusesADatabaseAheadOfTheBinary(t *testing.T) {
	t.Parallel()

	all := []migration{{version: 1, name: "init"}}
	_, err := pending([]int{1, 2}, all)
	if !errors.Is(err, ErrMigrationsAhead) {
		t.Errorf("pending with an unknown applied version = %v, want ErrMigrationsAhead", err)
	}
}

func TestPendingRefusesASkippedMigration(t *testing.T) {
	t.Parallel()

	// Applying 0001 after 0002 would run an old schema change against a newer
	// database. Migrations are forward-only, so this is a refusal.
	all := []migration{{version: 1, name: "init"}, {version: 2, name: "later"}}
	_, err := pending([]int{2}, all)
	if err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Errorf("pending with a gap = %v, want a forward-only refusal", err)
	}
}

func TestPendingReturnsWhatIsMissing(t *testing.T) {
	t.Parallel()

	all := []migration{{version: 1, name: "init"}, {version: 2, name: "later"}}
	todo, err := pending([]int{1}, all)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(todo) != 1 || todo[0].version != 2 {
		t.Errorf("pending = %+v, want only version 2", todo)
	}
}

func TestMigrateAppliesEachVersionOnce(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	ctx := context.Background()
	all := []migration{
		{version: 1, name: "init", sql: `CREATE TABLE a (x INTEGER)`},
		{version: 2, name: "more", sql: `CREATE TABLE b (y INTEGER)`},
	}

	applied, err := migrate(ctx, db, all, migrateTestTime)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %v, want both versions", applied)
	}

	// Running again is a no-op: re-applying CREATE TABLE would fail, so this
	// also proves the ledger is consulted rather than the schema guessed at.
	again, err := migrate(ctx, db, all, migrateTestTime)
	if err != nil {
		t.Fatalf("migrate (second run): %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second run applied %v, want nothing", again)
	}

	versions, err := appliedVersions(ctx, db)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(versions) != 2 || versions[0] != 1 || versions[1] != 2 {
		t.Errorf("recorded versions = %v, want [1 2]", versions)
	}
}

// A migration that fails part way must leave the database at the previous
// version, not half way through the new one.
func TestFailedMigrationRollsBackAndNamesTheVersion(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	ctx := context.Background()
	all := []migration{
		{version: 1, name: "init", sql: `CREATE TABLE a (x INTEGER)`},
		{version: 2, name: "broken", sql: `CREATE TABLE b (y INTEGER); NOT SQL AT ALL;`},
	}

	applied, err := migrate(ctx, db, all, migrateTestTime)
	if err == nil {
		t.Fatal("migrate succeeded, want the broken migration to fail")
	}
	if len(applied) != 1 || applied[0] != 1 {
		t.Errorf("applied = %v, want the first migration to have stuck", applied)
	}

	var migrationErr *MigrationError
	if !errors.As(err, &migrationErr) {
		t.Fatalf("error type = %T, want *MigrationError naming the version", err)
	}
	if migrationErr.Version != 2 || migrationErr.Name != "broken" {
		t.Errorf("error names %04d_%s, want 0002_broken", migrationErr.Version, migrationErr.Name)
	}
	if migrationErr.Unwrap() == nil {
		t.Error("MigrationError does not carry the underlying failure")
	}
	// "migration failed" without a version is not an actionable message.
	if !strings.Contains(migrationErr.Error(), "0002_broken") {
		t.Errorf("message %q does not name the failing migration", migrationErr)
	}

	// The table the broken migration created before failing must be gone with
	// it, and the version must not be recorded.
	if _, err := db.ExecContext(ctx, `SELECT 1 FROM b`); err == nil {
		t.Error("a table from the failed migration survived: the step did not roll back")
	}
	versions, err := appliedVersions(ctx, db)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(versions) != 1 || versions[0] != 1 {
		t.Errorf("recorded versions = %v, want only the migration that completed", versions)
	}
}

// The ledger lives in the database, so a closed handle must surface rather
// than read as "nothing applied yet" -- which would re-run every migration.
func TestMigrateSurfacesLedgerFailures(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	all := []migration{{version: 1, name: "init", sql: `CREATE TABLE a (x INTEGER)`}}
	if _, err := migrate(context.Background(), db, all, migrateTestTime); err == nil {
		t.Error("migrate against a closed database succeeded, want an error")
	}
}
