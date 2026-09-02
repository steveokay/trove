package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/metatest"
	"github.com/steveokay/trove/internal/meta/sqlite"
)

var testTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// open builds a store on a fresh database file. A file rather than ":memory:"
// on purpose: the file path is the one operators use, and it is the only one
// that exercises WAL and reopening.
func open(t *testing.T, opts ...func(*sqlite.Options)) *sqlite.Store {
	t.Helper()

	options := sqlite.Options{
		Path: filepath.Join(t.TempDir(), "trove.db"),
		Now:  func() time.Time { return testTime },
	}
	for _, apply := range opts {
		apply(&options)
	}

	store, err := sqlite.Open(context.Background(), options)
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

// The database-backed store must satisfy the same contract as the in-memory
// reference implementation, unmodified.
func TestContract(t *testing.T) {
	t.Parallel()

	metatest.Run(t, func(t *testing.T) meta.Store {
		t.Helper()
		return open(t)
	})
}

// Behaviour specific to this implementation, which the shared contract does
// not cover.

func TestOpenRequiresAPath(t *testing.T) {
	t.Parallel()

	_, err := sqlite.Open(context.Background(), sqlite.Options{})
	if !errors.Is(err, meta.ErrInvalid) {
		t.Errorf("Open without a path = %v, want ErrInvalid", err)
	}
}

func TestOpenFailsOnAnUnusablePath(t *testing.T) {
	t.Parallel()

	// A directory where the file should be: the driver cannot open it, and
	// refusing to start beats starting with no storage.
	dir := t.TempDir()
	if _, err := sqlite.Open(context.Background(), sqlite.Options{Path: dir}); err == nil {
		t.Error("Open on a directory succeeded, want an error")
	}
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "trove.db")
	first := open(t, func(o *sqlite.Options) { o.Path = path })
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
	second := open(t, func(o *sqlite.Options) { o.Path = path })
	if _, err := second.GetRepository(context.Background(), "team-a/api"); err != nil {
		t.Errorf("data did not survive a reopen: %v", err)
	}
}

func TestNoAutoMigrateRefusesAnUnmigratedDatabase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "trove.db")
	_, err := sqlite.Open(context.Background(), sqlite.Options{Path: path, NoAutoMigrate: true})
	if !errors.Is(err, sqlite.ErrMigrationsPending) {
		t.Fatalf("Open with NoAutoMigrate = %v, want ErrMigrationsPending", err)
	}
	// The error names what is missing, so the operator knows what they are
	// being asked to run.
	if got := err.Error(); !strings.Contains(got, "0001_init") {
		t.Errorf("error %q does not name the pending migration", got)
	}

	// Once migrated, the same option opens cleanly.
	migrated := open(t, func(o *sqlite.Options) { o.Path = path })
	if err := migrated.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	staged, err := sqlite.Open(context.Background(), sqlite.Options{Path: path, NoAutoMigrate: true})
	if err != nil {
		t.Fatalf("Open with NoAutoMigrate on a migrated database: %v", err)
	}
	if err := staged.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// A closed store must refuse every method rather than serving from a
// torn-down handle.
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
// and in UTC rather than in whatever zone the caller supplied.
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

func TestConcurrentAccessIsSafe(t *testing.T) {
	t.Parallel()

	store := open(t)
	ctx := context.Background()
	if _, err := store.CreateRepository(ctx, meta.Repository{Name: "repo", Type: meta.Hosted}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	// SQLite takes one writer at a time; concurrent callers must queue rather
	// than fail, and the race detector must stay quiet.
	const workers = 8
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			d := meta.Digest("sha256:" + string(rune('a'+i)))
			if err := store.PutBlob(ctx, meta.Blob{Digest: d, Size: int64(i)}); err != nil {
				t.Errorf("PutBlob: %v", err)
			}
			if _, err := store.GetBlob(ctx, d); err != nil {
				t.Errorf("GetBlob: %v", err)
			}
			if _, err := store.ListRepositories(ctx, meta.ListOptions{Visibility: meta.Unrestricted()}); err != nil {
				t.Errorf("ListRepositories: %v", err)
			}
		}(i)
	}
	wg.Wait()
}
