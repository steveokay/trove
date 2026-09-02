package migrate_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/steveokay/trove/internal/meta/migrate"

	// SQLite stands in for "a database" here. The runner is engine-neutral;
	// what it does with a real one is the same either way.
	_ "modernc.org/sqlite"
)

var testTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

var testDialect = migrate.Dialect{
	CreateLedger: `CREATE TABLE IF NOT EXISTS schema_migrations (
	    version    INTEGER PRIMARY KEY,
	    applied_at INTEGER NOT NULL
	)`,
	SelectVersions: `SELECT version FROM schema_migrations ORDER BY version`,
	InsertVersion:  `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migrate.db"))
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

// A file that does not parse is a packaging mistake. Guessing at its version is
// how two deployments end up with different schemas, so it is refused.
func TestLoadRejectsUnparseableFiles(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := migrate.Load(mapFS(tt.files))
			if err == nil {
				t.Fatalf("Load succeeded, want an error mentioning %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestLoadOrdersByVersionAndSkipsDirectories(t *testing.T) {
	t.Parallel()

	all, err := migrate.Load(mapFS(map[string]string{
		"migrations/0002_later.sql":   "SELECT 2",
		"migrations/0001_init.sql":    "SELECT 1",
		"migrations/archive/keep.txt": "not a migration",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(all) != 2 || all[0].Version != 1 || all[1].Version != 2 {
		t.Fatalf("Load = %+v, want both ordered by version", all)
	}
	if all[0].SQL != "SELECT 1" {
		t.Errorf("body = %q, want the file's contents", all[0].SQL)
	}
	if got := all[1].String(); got != "0002_later" {
		t.Errorf("String() = %q, want 0002_later", got)
	}
}

func TestLoadNeedsMigrations(t *testing.T) {
	t.Parallel()

	if _, err := migrate.Load(fstest.MapFS(nil)); err == nil {
		t.Error("Load on a filesystem with no migrations directory succeeded, want an error")
	}

	// A directory that exists but holds nothing is a build that shipped no
	// schema, which must not be mistaken for "already at head".
	_, err := migrate.Load(fstest.MapFS{"migrations/sub/keep": {Data: []byte("x")}})
	if err == nil || !strings.Contains(err.Error(), "no migrations found") {
		t.Errorf("Load on an empty directory = %v, want 'no migrations found'", err)
	}
}

func mapFS(files map[string]string) fstest.MapFS {
	out := make(fstest.MapFS, len(files))
	for name, body := range files {
		out[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return out
}

func TestPendingRefusesADatabaseAheadOfTheBinary(t *testing.T) {
	t.Parallel()

	all := []migrate.Migration{{Version: 1, Name: "init"}}
	_, err := migrate.Pending([]int{1, 2}, all)
	if !errors.Is(err, migrate.ErrAhead) {
		t.Errorf("Pending with an unknown applied version = %v, want ErrAhead", err)
	}
}

func TestPendingRefusesASkippedMigration(t *testing.T) {
	t.Parallel()

	// Applying 0001 after 0002 would run an old schema change against a newer
	// database. Migrations are forward-only, so this is a refusal.
	all := []migrate.Migration{{Version: 1, Name: "init"}, {Version: 2, Name: "later"}}
	_, err := migrate.Pending([]int{2}, all)
	if err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Errorf("Pending with a gap = %v, want a forward-only refusal", err)
	}
}

func TestPendingReturnsWhatIsMissing(t *testing.T) {
	t.Parallel()

	all := []migrate.Migration{{Version: 1, Name: "init"}, {Version: 2, Name: "later"}}
	todo, err := migrate.Pending([]int{1}, all)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(todo) != 1 || todo[0].Version != 2 {
		t.Errorf("Pending = %+v, want only version 2", todo)
	}
}

func TestApplyRunsEachVersionOnce(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	ctx := context.Background()
	all := []migrate.Migration{
		{Version: 1, Name: "init", SQL: `CREATE TABLE a (x INTEGER)`},
		{Version: 2, Name: "more", SQL: `CREATE TABLE b (y INTEGER)`},
	}

	applied, err := migrate.Apply(ctx, db, testDialect, all, testTime)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %v, want both versions", applied)
	}

	// Running again is a no-op: re-applying CREATE TABLE would fail, so this
	// also proves the ledger is consulted rather than the schema guessed at.
	again, err := migrate.Apply(ctx, db, testDialect, all, testTime)
	if err != nil {
		t.Fatalf("Apply (second run): %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second run applied %v, want nothing", again)
	}

	versions, err := migrate.Applied(ctx, db, testDialect)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if len(versions) != 2 || versions[0] != 1 || versions[1] != 2 {
		t.Errorf("recorded versions = %v, want [1 2]", versions)
	}

	if err := migrate.CheckAtHead(ctx, db, testDialect, all); err != nil {
		t.Errorf("CheckAtHead on a migrated database = %v, want nil", err)
	}
}

// A migration that fails part way must leave the database at the previous
// version, not half way through the new one.
func TestFailedMigrationRollsBackAndNamesTheVersion(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	ctx := context.Background()
	all := []migrate.Migration{
		{Version: 1, Name: "init", SQL: `CREATE TABLE a (x INTEGER)`},
		{Version: 2, Name: "broken", SQL: `CREATE TABLE b (y INTEGER); NOT SQL AT ALL;`},
	}

	applied, err := migrate.Apply(ctx, db, testDialect, all, testTime)
	if err == nil {
		t.Fatal("Apply succeeded, want the broken migration to fail")
	}
	if len(applied) != 1 || applied[0] != 1 {
		t.Errorf("applied = %v, want the first migration to have stuck", applied)
	}

	var migrationErr *migrate.Error
	if !errors.As(err, &migrationErr) {
		t.Fatalf("error type = %T, want *migrate.Error naming the version", err)
	}
	if migrationErr.Version != 2 || migrationErr.Name != "broken" {
		t.Errorf("error names %04d_%s, want 0002_broken", migrationErr.Version, migrationErr.Name)
	}
	if migrationErr.Unwrap() == nil {
		t.Error("migrate.Error does not carry the underlying failure")
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
	versions, err := migrate.Applied(ctx, db, testDialect)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if len(versions) != 1 || versions[0] != 1 {
		t.Errorf("recorded versions = %v, want only the migration that completed", versions)
	}
}

func TestCheckAtHeadNamesWhatIsPending(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	all := []migrate.Migration{{Version: 1, Name: "init", SQL: `CREATE TABLE a (x INTEGER)`}}

	err := migrate.CheckAtHead(context.Background(), db, testDialect, all)
	if !errors.Is(err, migrate.ErrPending) {
		t.Fatalf("CheckAtHead on an unmigrated database = %v, want ErrPending", err)
	}
	if !strings.Contains(err.Error(), "0001_init") {
		t.Errorf("error %q does not name the pending migration", err)
	}
}

// The ledger lives in the database, so a failure reading it must surface
// rather than read as "nothing applied yet", which would re-run everything.
func TestLedgerFailuresSurface(t *testing.T) {
	t.Parallel()

	all := []migrate.Migration{{Version: 1, Name: "init", SQL: `CREATE TABLE a (x INTEGER)`}}
	ctx := context.Background()

	dead := testDB(t)
	if err := dead.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := migrate.Apply(ctx, dead, testDialect, all, testTime); err == nil {
		t.Error("Apply against a closed database succeeded, want an error")
	}
	if err := migrate.CheckAtHead(ctx, dead, testDialect, all); err == nil {
		t.Error("CheckAtHead against a closed database succeeded, want an error")
	}

	// A ledger that exists but cannot be read the way the dialect expects is
	// a corrupt database, not an empty one.
	wrongShape := testDB(t)
	if _, err := wrongShape.ExecContext(ctx, `CREATE TABLE schema_migrations (unexpected TEXT)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := migrate.Applied(ctx, wrongShape, testDialect); err == nil {
		t.Error("Applied with an unreadable ledger succeeded, want an error")
	}

	// A ledger holding something that is not a version is corrupt too, and
	// treating it as absent would re-run every migration over a live schema.
	corrupt := testDB(t)
	if _, err := corrupt.ExecContext(ctx,
		`CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);
		 INSERT INTO schema_migrations (version, applied_at) VALUES ('not-a-version', 0)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := migrate.Applied(ctx, corrupt, testDialect); err == nil {
		t.Error("Applied with a non-numeric version succeeded, want an error")
	}
}

// A migration that runs but cannot be recorded must fail: a schema change the
// ledger does not know about would be applied twice on the next start.
func TestUnrecordableMigrationFails(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	ctx := context.Background()
	broken := testDialect
	broken.InsertVersion = `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?, ?)`

	_, err := migrate.Apply(ctx, db, broken,
		[]migrate.Migration{{Version: 1, Name: "init", SQL: `CREATE TABLE a (x INTEGER)`}}, testTime)
	if err == nil {
		t.Fatal("Apply succeeded, want recording the version to fail")
	}
	if !strings.Contains(err.Error(), "record version") {
		t.Errorf("error = %v, want it to name the recording step", err)
	}
	if _, err := db.ExecContext(ctx, `SELECT 1 FROM a`); err == nil {
		t.Error("the migration's table survived a failed ledger write")
	}
}
