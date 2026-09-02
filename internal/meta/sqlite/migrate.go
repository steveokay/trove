package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// migrationFiles holds the schema, compiled into the binary so a deployment is
// one file and an air-gapped install needs nothing extra (Q6).
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// ErrMigrationsPending reports that the database is behind the binary and
// automatic migration was disabled. It is what --no-auto-migrate produces, so
// an operator staging an upgrade gets a refusal rather than a schema change
// they did not ask for.
var ErrMigrationsPending = errors.New("migrations pending")

// ErrMigrationsAhead reports that the database carries a migration this binary
// does not know about, which means an older binary is looking at a newer
// database. Continuing would write rows the running code cannot read back.
var ErrMigrationsAhead = errors.New("database schema is ahead of this binary")

// migration is one forward-only schema step. There are no down-migrations:
// recovery is restore-from-backup, which is honest about what a down-migration
// actually delivers (ADR 0006).
type migration struct {
	version int
	name    string
	sql     string
}

// MigrationError names the step that failed, because "migration failed" without
// a version is not an actionable message at 3am.
type MigrationError struct {
	Version int
	Name    string
	Err     error
}

func (e *MigrationError) Error() string {
	return fmt.Sprintf("migration %04d_%s: %v", e.Version, e.Name, e.Err)
}

// Unwrap exposes the underlying failure to errors.Is and errors.As.
func (e *MigrationError) Unwrap() error { return e.Err }

// createMigrationsTable is applied before anything else and is the one piece of
// schema the migrations themselves do not own.
const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
)`

// loadMigrations reads every migration from fsys, ordered by version. Names are
// strict on purpose: a file that does not parse is a packaging mistake, and
// guessing at its version is how two deployments end up with different schemas.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	var out []migration
	seen := make(map[int]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version, name, err := parseMigrationName(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", previous, entry.Name(), version)
		}
		seen[version] = entry.Name()

		body, err := fs.ReadFile(fsys, path.Join("migrations", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		out = append(out, migration{version: version, name: name, sql: string(body)})
	}
	if len(out) == 0 {
		return nil, errors.New("no migrations found")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// parseMigrationName splits "0001_init.sql" into its version and name.
func parseMigrationName(filename string) (int, string, error) {
	base, ok := strings.CutSuffix(filename, ".sql")
	if !ok {
		return 0, "", fmt.Errorf("migration %q: want a .sql file", filename)
	}
	prefix, name, ok := strings.Cut(base, "_")
	if !ok || name == "" {
		return 0, "", fmt.Errorf("migration %q: want NNNN_name.sql", filename)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil || version <= 0 {
		return 0, "", fmt.Errorf("migration %q: version prefix must be a positive number", filename)
	}
	return version, name, nil
}

// appliedVersions returns the versions already recorded, ascending.
func appliedVersions(ctx context.Context, db *sql.DB) ([]int, error) {
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}
	return collect(ctx, db, `SELECT version FROM schema_migrations ORDER BY version`, nil,
		func(rows *sql.Rows) (int, error) {
			var v int
			return v, rows.Scan(&v)
		})
}

// pending returns the migrations that still have to run. It refuses two states
// rather than papering over them: a database carrying a version this binary
// does not have, and a gap that would apply an old migration after a newer one.
func pending(applied []int, all []migration) ([]migration, error) {
	known := make(map[int]bool, len(all))
	for _, m := range all {
		known[m.version] = true
	}
	appliedSet := make(map[int]bool, len(applied))
	highest := 0
	for _, v := range applied {
		if !known[v] {
			return nil, fmt.Errorf("%w: version %d is applied but not embedded", ErrMigrationsAhead, v)
		}
		appliedSet[v] = true
		if v > highest {
			highest = v
		}
	}

	var out []migration
	for _, m := range all {
		if appliedSet[m.version] {
			continue
		}
		if m.version < highest {
			return nil, fmt.Errorf("migration %04d_%s was skipped: %d is already applied, and migrations are forward-only",
				m.version, m.name, highest)
		}
		out = append(out, m)
	}
	return out, nil
}

// migrate applies every pending migration, each in its own transaction, so a
// failure leaves the database at the last version that completed rather than
// half way through one.
func migrate(ctx context.Context, db *sql.DB, all []migration, now time.Time) ([]int, error) {
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return nil, err
	}
	todo, err := pending(applied, all)
	if err != nil {
		return nil, err
	}

	var done []int
	for _, m := range todo {
		if err := applyMigration(ctx, db, m, now); err != nil {
			return done, &MigrationError{Version: m.version, Name: m.name, Err: err}
		}
		done = append(done, m.version)
	}
	return done, nil
}

// applyMigration runs one migration and records it in the same transaction, so
// the schema and the version it claims can never disagree.
func applyMigration(ctx context.Context, db *sql.DB, m migration, now time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, now.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("record version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
