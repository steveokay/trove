// Package postgres is the optional meta.Store for operators who already run
// Postgres, through the pure-Go jackc/pgx driver so the binary stays static
// and CGO-free.
//
// It is the SQLite store's twin, not its superset. Both run the same contract
// suite, and a schema-parity test holds their tables to the same columns and
// nullability, because an engine choice that quietly changed behaviour would
// make the contract suite a proof about two different systems rather than one.
//
// What genuinely differs is confined to three things: parameter placeholders,
// LEAST where SQLite writes min, and the absence of SQLite's single-writer
// constraint -- Postgres handles concurrent writers itself, so the pool is not
// capped at one connection. Where two writers can now race a check-then-insert,
// the unique constraints are the backstop and their violations map to the same
// ErrConflict a serialised store would have returned.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/migrate"

	// The pgx database/sql driver, registered as "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Options configure a store.
type Options struct {
	// DSN is the connection string, in either libpq keyword form or a
	// postgres:// URL. Required.
	DSN string

	// NoAutoMigrate refuses to open a database that is behind the binary
	// instead of migrating it, for operators who stage upgrades themselves.
	// The flag is named for the operator-facing switch (§3) so the zero value
	// keeps the documented default: migrate on startup.
	NoAutoMigrate bool

	// MaxOpenConns caps the connection pool. Zero means DefaultMaxOpenConns.
	MaxOpenConns int

	// Now supplies the current time. Tests inject one; production leaves it
	// nil and gets time.Now. Nothing in the store's business logic calls the
	// clock -- only the migration ledger does (§7).
	Now func() time.Time
}

// DefaultMaxOpenConns bounds the pool. Postgres charges real memory per
// backend, and a registry's metadata queries are short: a small pool that
// queues is friendlier to the database than an unbounded one that stampedes.
const DefaultMaxOpenConns = 16

// Store is a Postgres-backed meta.Store.
type Store struct {
	db *sql.DB

	mu     sync.RWMutex
	closed bool
}

// assert the interface is satisfied at compile time.
var _ meta.Store = (*Store)(nil)

// Open connects to the database and brings it to the current schema.
//
// Migration failure is fatal and names the version that failed: starting on a
// schema nobody has verified is worse than not starting.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.DSN == "" {
		return nil, meta.Invalid("dsn", "must not be empty")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	maxOpen := opts.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = DefaultMaxOpenConns
	}

	db, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)

	store, err := prepare(ctx, db, opts, now)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// prepare verifies the connection, applies migrations, and wraps the handle.
func prepare(ctx context.Context, db *sql.DB, opts Options, now func() time.Time) (*Store, error) {
	// sql.Open is lazy, so without this the first failure would surface
	// somewhere unrelated, long after the operator could act on it.
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
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

// Close releases the pool. It is idempotent, and every method refuses to run
// afterwards rather than serving from a torn-down handle.
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

// uniqueViolation is the SQLSTATE Postgres raises when a unique constraint
// rejects a row.
const uniqueViolation = "23505"

// asConflict translates a lost race into the same answer a serialised store
// would have given. Every create checks for an existing row first, but two
// writers can pass that check at once; the constraint catches the second, and
// the caller should see ErrConflict rather than a driver error it cannot
// reasonably match on.
func asConflict(err error, kind, id string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return meta.Conflict(kind, id)
	}
	return err
}
