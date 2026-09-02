package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/metatest"
	"github.com/steveokay/trove/internal/meta/migrate"
)

var testTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// open builds a store on a fresh database inside the shared container.
func open(t *testing.T, opts ...func(*Options)) *Store {
	t.Helper()

	options := Options{
		DSN: requireDSN(t),
		Now: func() time.Time { return testTime },
	}
	for _, apply := range opts {
		apply(&options)
	}

	store, err := Open(context.Background(), options)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

// The Postgres store must satisfy the same contract as SQLite and the
// in-memory reference, unmodified. An engine that needed its own version of
// the suite would not be substitutable, which is the only reason to have two.
func TestContract(t *testing.T) {
	t.Parallel()

	metatest.Run(t, func(t *testing.T) meta.Store {
		t.Helper()
		return open(t)
	})
}

// Behaviour specific to this implementation, which the shared contract does
// not cover.

func TestOpenRequiresADSN(t *testing.T) {
	t.Parallel()

	_, err := Open(context.Background(), Options{})
	if !errors.Is(err, meta.ErrInvalid) {
		t.Errorf("Open without a DSN = %v, want ErrInvalid", err)
	}
}

func TestOpenFailsOnAnUnreachableServer(t *testing.T) {
	t.Parallel()

	// sql.Open is lazy, so the store must reach out during Open: a connection
	// failure surfacing on the first request instead would be reported
	// somewhere unrelated, long after the operator could act on it.
	_, err := Open(context.Background(), Options{
		DSN: "postgres://trove:trove@127.0.0.1:1/trove?sslmode=disable&connect_timeout=2",
	})
	if err == nil {
		t.Fatal("Open against an unreachable server succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("error = %v, want it to name the connection attempt", err)
	}
}

func TestOpenRejectsAMalformedDSN(t *testing.T) {
	t.Parallel()

	if _, err := Open(context.Background(), Options{DSN: "://not a dsn"}); err == nil {
		t.Error("Open with a malformed DSN succeeded, want an error")
	}
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	t.Parallel()

	dsn := requireDSN(t)
	first := open(t, func(o *Options) { o.DSN = dsn })
	if _, err := first.CreateRepository(context.Background(), meta.Repository{
		Name: "team-a/api", Type: meta.Hosted,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening an already-migrated database must be a no-op that keeps the
	// data, not a second attempt at the same migration.
	second := open(t, func(o *Options) { o.DSN = dsn })
	if _, err := second.GetRepository(context.Background(), "team-a/api"); err != nil {
		t.Errorf("data did not survive a reopen: %v", err)
	}
}

func TestNoAutoMigrateRefusesAnUnmigratedDatabase(t *testing.T) {
	t.Parallel()

	dsn := requireDSN(t)
	_, err := Open(context.Background(), Options{DSN: dsn, NoAutoMigrate: true})
	if !errors.Is(err, migrate.ErrPending) {
		t.Fatalf("Open with NoAutoMigrate = %v, want migrate.ErrPending", err)
	}
	// The error names what is missing, so the operator knows what they are
	// being asked to run.
	if !strings.Contains(err.Error(), "0001_init") {
		t.Errorf("error %q does not name the pending migration", err)
	}

	// Once migrated, the same option opens cleanly.
	migrated := open(t, func(o *Options) { o.DSN = dsn })
	if err := migrated.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	staged, err := Open(context.Background(), Options{DSN: dsn, NoAutoMigrate: true})
	if err != nil {
		t.Fatalf("Open with NoAutoMigrate on a migrated database: %v", err)
	}
	if err := staged.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// A closed store must refuse every method rather than serving from a
// torn-down pool.
func TestClosedStoreRefusesEveryMethod(t *testing.T) {
	t.Parallel()

	store := open(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	calls := metatest.Calls(context.Background(), store)
	if len(calls) != len(metatest.MethodNames()) {
		t.Fatalf("got %d calls, want one per store method", len(calls))
	}
	for _, c := range calls {
		t.Run(c.Name, func(t *testing.T) {
			if err := c.Fn(); !errors.Is(err, meta.ErrInvalid) {
				t.Errorf("%s on a closed store = %v, want ErrInvalid", c.Name, err)
			}
		})
	}
}

// Timestamps are stored as epoch milliseconds, so they must come back equal
// and in UTC rather than in whatever zone the caller or the server uses.
func TestTimestampsRoundTripInUTC(t *testing.T) {
	t.Parallel()

	store := open(t)
	ctx := context.Background()

	zone := time.FixedZone("test", 3*60*60)
	created := testTime.In(zone)
	if _, err := store.CreateRepository(ctx, meta.Repository{
		Name: "repo", Type: meta.Hosted, CreatedAt: created, UpdatedAt: created,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	got, err := store.GetRepository(ctx, "repo")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, created)
	}
	if got.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", got.CreatedAt.Location())
	}

	// A zero time is "unset", not the epoch: the two must stay distinguishable.
	if _, err := store.CreateRepository(ctx, meta.Repository{Name: "unset", Type: meta.Hosted}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	unset, err := store.GetRepository(ctx, "unset")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !unset.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want the zero time", unset.CreatedAt)
	}
}

// Repository config is opaque and must survive byte for byte. This is why the
// column is BYTEA and not JSONB: JSONB would rewrite key order and whitespace,
// so two engines would hand back different bytes for the same input.
func TestRepositoryConfigIsStoredVerbatim(t *testing.T) {
	t.Parallel()

	store := open(t)
	ctx := context.Background()
	config := []byte(`{"b":1,   "a":  [2,3]}`)

	if _, err := store.CreateRepository(ctx, meta.Repository{
		Name: "verbatim", Type: meta.Proxy, Config: config,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	got, err := store.GetRepository(ctx, "verbatim")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if string(got.Config) != string(config) {
		t.Errorf("config = %s, want it byte for byte: %s", got.Config, config)
	}
}

// Postgres serves concurrent writers, so unlike SQLite the store does not
// serialise them. Two callers racing the same create must still see one
// success and one ErrConflict, never a driver error the caller cannot match on.
func TestConcurrentCreatesResolveToOneConflict(t *testing.T) {
	t.Parallel()

	store := open(t)
	ctx := context.Background()

	const workers = 6
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
		other     []error
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			_, err := store.CreateRepository(ctx, meta.Repository{Name: "contested", Type: meta.Hosted})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, meta.ErrConflict):
				conflicts++
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if succeeded != 1 {
		t.Errorf("%d creates succeeded, want exactly 1", succeeded)
	}
	if conflicts != workers-1 {
		t.Errorf("%d conflicts, want %d", conflicts, workers-1)
	}
	if len(other) > 0 {
		t.Errorf("unexpected errors: %v", other)
	}
}
