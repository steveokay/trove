// Package sqlite is the default meta.Store: SQLite through the pure-Go
// modernc.org/sqlite driver, so the binary stays static and CGO-free.
//
// Two properties of SQLite shape everything here. It allows one writer at a
// time, so the pool is capped at a single connection and every multi-statement
// operation runs in an immediate transaction -- a writer never discovers half
// way through that it cannot upgrade its lock. And it enforces foreign keys
// only when asked, so `foreign_keys` is switched on for every connection and
// verified at open: the cascades this schema relies on are correctness, not
// convenience.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/steveokay/trove/internal/meta"

	// The pure-Go SQLite driver, registered as "sqlite".
	_ "modernc.org/sqlite"
)

// Options configure a store.
type Options struct {
	// Path is the database file. Required. Use ":memory:" for a throwaway
	// database that lives as long as the store.
	Path string

	// NoAutoMigrate refuses to open a database that is behind the binary
	// instead of migrating it, for operators who stage upgrades themselves.
	// The flag is named for the operator-facing switch (§3) so the zero value
	// keeps the documented default: migrate on startup.
	NoAutoMigrate bool

	// BusyTimeout bounds how long a statement waits for the write lock before
	// failing. Zero means DefaultBusyTimeout.
	BusyTimeout time.Duration

	// Now supplies the current time. Tests inject one; production leaves it
	// nil and gets time.Now. Nothing in the store's business logic calls the
	// clock -- only the migration ledger does (§7).
	Now func() time.Time
}

// DefaultBusyTimeout is how long a statement waits for SQLite's write lock.
// Long enough to ride out a slow transaction, short enough that a deadlocked
// deployment fails visibly instead of hanging.
const DefaultBusyTimeout = 5 * time.Second

// Store is a SQLite-backed meta.Store.
type Store struct {
	db *sql.DB

	mu     sync.RWMutex
	closed bool
}

// assert the interface is satisfied at compile time.
var _ meta.Store = (*Store)(nil)

// Open opens or creates a database and brings it to the current schema.
//
// Migration failure is fatal and names the version that failed: starting on a
// schema nobody has verified is worse than not starting.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, meta.Invalid("path", "must not be empty")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	busy := opts.BusyTimeout
	if busy <= 0 {
		busy = DefaultBusyTimeout
	}

	db, err := sql.Open("sqlite", dsn(opts.Path, busy))
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", opts.Path, err)
	}
	// SQLite serialises writes anyway; one connection makes that explicit and
	// removes SQLITE_BUSY as a failure mode. ADR 0018 records the seam where a
	// shared-state deployment would replace this.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store, err := prepare(ctx, db, opts, now)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// prepare verifies the connection, applies migrations, and wraps the handle.
func prepare(ctx context.Context, db *sql.DB, opts Options, now func() time.Time) (*Store, error) {
	var foreignKeys int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return nil, fmt.Errorf("check foreign_keys: %w", err)
	}
	if foreignKeys != 1 {
		return nil, errors.New("foreign key enforcement is off: the schema's cascades would silently not happen")
	}

	all, err := loadMigrations(migrationFiles)
	if err != nil {
		return nil, err
	}
	if opts.NoAutoMigrate {
		if err := checkAtHead(ctx, db, all); err != nil {
			return nil, err
		}
	} else if _, err := migrate(ctx, db, all, now()); err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

// checkAtHead reports whether every embedded migration is already applied,
// naming what is missing so the operator can run it deliberately.
func checkAtHead(ctx context.Context, db *sql.DB, all []migration) error {
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}
	todo, err := pending(applied, all)
	if err != nil {
		return err
	}
	if len(todo) == 0 {
		return nil
	}
	versions := make([]string, len(todo))
	for i, m := range todo {
		versions[i] = fmt.Sprintf("%04d_%s", m.version, m.name)
	}
	return fmt.Errorf("%w: %s", ErrMigrationsPending, strings.Join(versions, ", "))
}

// dsn builds the driver DSN. The pragmas are per connection, so they belong in
// the DSN rather than in a one-off statement after opening: the pool may
// replace a connection at any time.
func dsn(path string, busy time.Duration) string {
	return fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_txlock=immediate",
		path, busy.Milliseconds())
}

// Close releases the database handle. It is idempotent, and every method
// refuses to run afterwards rather than serving from a torn-down handle.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

var errClosed = fmt.Errorf("%w: store is closed", meta.ErrInvalid)

// ready reports whether the store may serve a call: the caller's context is
// still live and the handle is open. Every method starts with it, so a
// cancelled request cannot mutate state and a closed store cannot be used.
func (s *Store) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errClosed
	}
	return nil
}

// --- SQL helpers ---
//
// Error handling funnels through these four so the package has a handful of
// wrap sites rather than one per statement.

// querier is the part of *sql.DB and *sql.Tx this package uses.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// collect runs a query and scans every row.
func collect[T any](ctx context.Context, q querier, query string, args []any, scan func(*sql.Rows) (T, error)) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// exists reports whether a query matches any row. The query must select a
// single column.
func exists(ctx context.Context, q querier, query string, args ...any) (bool, error) {
	var probe int
	err := q.QueryRowContext(ctx, query, args...).Scan(&probe)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("query: %w", err)
	default:
		return true, nil
	}
}

// execute runs a statement and reports how many rows it changed.
func execute(ctx context.Context, q querier, query string, args ...any) (int64, error) {
	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("exec: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return affected, nil
}

// inTx runs fn in a transaction, rolling back unless it returns nil. Every
// multi-statement operation goes through it: a manifest without its reference
// edges, or a subject without its bindings removed, is a corrupt state that
// nothing downstream can detect.
func (s *Store) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// --- value conversion ---

// millis converts a time to UTC epoch milliseconds, mapping the zero time to
// NULL so "unset" stays distinguishable from "the epoch".
func millis(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UTC().UnixMilli(), Valid: true}
}

// asTime converts a stored timestamp back, in UTC.
func asTime(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMilli(v.Int64).UTC()
}

// visibilityClause compiles a Visibility into a SQL predicate over the given
// column, plus its arguments. Filtering happens in the query and nowhere else:
// a handler-side filter leaks through counts and pagination (ADR 0003).
//
// The predicate is assembled from literal fragments and the column name chosen
// by the caller; every value is bound, never interpolated.
func visibilityClause(column string, v meta.Visibility) (string, []any) {
	if v.IsUnrestricted() {
		return "1 = 1", nil
	}

	var (
		clauses []string
		args    []any
	)
	for _, f := range v.Filters() {
		switch {
		case f.All:
			return "1 = 1", nil
		case f.Exact != "":
			clauses = append(clauses, column+" = ?")
			args = append(args, f.Exact)
		case f.Prefix != "":
			// Matches ScopeFilter.Matches: the name must be under the prefix,
			// not equal to it, so "team-a/" never selects a repository called
			// "team-a/".
			clauses = append(clauses, "(substr("+column+", 1, ?) = ? AND length("+column+") > ?)")
			n := utf8.RuneCountInString(f.Prefix)
			args = append(args, n, f.Prefix, n)
		}
	}
	if len(clauses) == 0 {
		// No filters means no visibility. This is the case a nil slice would
		// have quietly turned into "everything".
		return "1 = 0", nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}
