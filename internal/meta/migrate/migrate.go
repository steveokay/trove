// Package migrate applies numbered, forward-only schema migrations.
//
// Both metadata engines share it. What differs between them is three
// statements -- creating the ledger, reading it, and writing to it -- which
// they supply as a Dialect; the ordering rules, the refusals, and the
// per-step transaction are the same everywhere, and a store that migrated
// differently from its sibling would be a store the contract suite cannot
// meaningfully compare.
//
// There are no down-migrations. Recovery is restore-from-backup (ADR 0006),
// which is honest about what a down-migration actually delivers.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrPending reports that the database is behind the binary and automatic
// migration was disabled. It is what --no-auto-migrate produces, so an
// operator staging an upgrade gets a refusal rather than a schema change they
// did not ask for.
var ErrPending = errors.New("migrations pending")

// ErrAhead reports that the database carries a migration this binary does not
// know about, which means an older binary is looking at a newer database.
// Continuing would write rows the running code cannot read back.
var ErrAhead = errors.New("database schema is ahead of this binary")

// Dialect carries the statements that differ between engines. Everything else
// about migration is identical, which is the point of sharing this package.
type Dialect struct {
	// CreateLedger creates the schema_migrations table if it is absent.
	CreateLedger string
	// SelectVersions lists the applied versions in ascending order.
	SelectVersions string
	// InsertVersion records one applied version. It takes the version and the
	// applied-at timestamp as its two parameters, in that order.
	InsertVersion string
}

// Migration is one forward-only schema step.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// String renders the migration the way its file is named, which is how errors
// and logs refer to it.
func (m Migration) String() string { return fmt.Sprintf("%04d_%s", m.Version, m.Name) }

// Error names the step that failed, because "migration failed" without a
// version is not an actionable message at 3am.
type Error struct {
	Version int
	Name    string
	Err     error
}

func (e *Error) Error() string {
	return fmt.Sprintf("migration %04d_%s: %v", e.Version, e.Name, e.Err)
}

// Unwrap exposes the underlying failure to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Err }

// Load reads every migration from the "migrations" directory of fsys, ordered
// by version. Names are strict on purpose: a file that does not parse is a
// packaging mistake, and guessing at its version is how two deployments end up
// with different schemas.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	var out []Migration
	seen := make(map[int]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version, name, err := parseName(entry.Name())
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
		out = append(out, Migration{Version: version, Name: name, SQL: string(body)})
	}
	if len(out) == 0 {
		return nil, errors.New("no migrations found")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// parseName splits "0001_init.sql" into its version and name.
func parseName(filename string) (int, string, error) {
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

// Applied returns the versions already recorded, ascending, creating the
// ledger table if this is a fresh database.
func Applied(ctx context.Context, db *sql.DB, d Dialect) ([]int, error) {
	if _, err := db.ExecContext(ctx, d.CreateLedger); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	rows, err := db.QueryContext(ctx, d.SelectVersions)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		out = append(out, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	return out, nil
}

// Pending returns the migrations that still have to run. It refuses two states
// rather than papering over them: a database carrying a version this binary
// does not have, and a gap that would apply an old migration after a newer one.
func Pending(applied []int, all []Migration) ([]Migration, error) {
	known := make(map[int]bool, len(all))
	for _, m := range all {
		known[m.Version] = true
	}
	appliedSet := make(map[int]bool, len(applied))
	highest := 0
	for _, v := range applied {
		if !known[v] {
			return nil, fmt.Errorf("%w: version %d is applied but not embedded", ErrAhead, v)
		}
		appliedSet[v] = true
		if v > highest {
			highest = v
		}
	}

	var out []Migration
	for _, m := range all {
		if appliedSet[m.Version] {
			continue
		}
		if m.Version < highest {
			return nil, fmt.Errorf("migration %s was skipped: %d is already applied, and migrations are forward-only",
				m, highest)
		}
		out = append(out, m)
	}
	return out, nil
}

// Apply runs every pending migration, each in its own transaction, so a
// failure leaves the database at the last version that completed rather than
// half way through one. It returns the versions it applied.
func Apply(ctx context.Context, db *sql.DB, d Dialect, all []Migration, now time.Time) ([]int, error) {
	applied, err := Applied(ctx, db, d)
	if err != nil {
		return nil, err
	}
	todo, err := Pending(applied, all)
	if err != nil {
		return nil, err
	}

	var done []int
	for _, m := range todo {
		if err := applyOne(ctx, db, d, m, now); err != nil {
			return done, &Error{Version: m.Version, Name: m.Name, Err: err}
		}
		done = append(done, m.Version)
	}
	return done, nil
}

// applyOne runs one migration and records it in the same transaction, so the
// schema and the version it claims can never disagree.
func applyOne(ctx context.Context, db *sql.DB, d Dialect, m Migration, now time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, d.InsertVersion, m.Version, now.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("record version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// CheckAtHead reports whether every migration is already applied, naming what
// is missing so an operator can run it deliberately. It is what a store opened
// with automatic migration disabled calls instead of Apply.
func CheckAtHead(ctx context.Context, db *sql.DB, d Dialect, all []Migration) error {
	applied, err := Applied(ctx, db, d)
	if err != nil {
		return err
	}
	todo, err := Pending(applied, all)
	if err != nil {
		return err
	}
	if len(todo) == 0 {
		return nil
	}

	names := make([]string, len(todo))
	for i, m := range todo {
		names[i] = m.String()
	}
	return fmt.Errorf("%w: %s", ErrPending, strings.Join(names, ", "))
}
