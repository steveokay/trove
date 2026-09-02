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
	"sync"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/migrate"

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

	all, err := migrate.Load(migrationFiles)
	if err != nil {
		return nil, err
	}
	if opts.NoAutoMigrate {
		if err := migrate.CheckAtHead(ctx, db, dialect, all); err != nil {
			return nil, err
		}
	} else if _, err := migrate.Apply(ctx, db, dialect, all, now()); err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
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
