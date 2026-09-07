package cache_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/meta"
)

func TestNewSchedulerRequiresAnEvictor(t *testing.T) {
	t.Parallel()

	scheduler, err := cache.NewScheduler(cache.SchedulerOptions{})
	if !errors.Is(err, cache.ErrInvalidOptions) {
		t.Fatalf("NewScheduler error = %v, want ErrInvalidOptions", err)
	}
	if scheduler != nil {
		t.Error("NewScheduler returned a scheduler alongside an error")
	}

	// Everything else has a default: an evictor is all a deployment must
	// supply.
	env := newEnv(t)
	if _, err := cache.NewScheduler(cache.SchedulerOptions{Evictor: env.evictor(cache.Budget{})}); err != nil {
		t.Fatalf("NewScheduler with defaults: %v", err)
	}
}

func TestSchedulerIsQuietAboutShutdown(t *testing.T) {
	t.Parallel()

	// A sweep that fails because the process is shutting down is not an
	// operator's problem, and logging it at every shutdown would teach them to
	// ignore the message that matters.
	env := newEnv(t, "dockerhub")
	logger, logged := captureLogger()
	store := &stubStore{inner: env.meta, usage: func(context.Context, string) (meta.CacheUsage, error) {
		return meta.CacheUsage{}, context.Canceled
	}}
	blobs := &stubBlobs{inner: env.blobs, walk: func(context.Context, func(blob.Descriptor) error) error {
		return context.Canceled
	}}

	scheduler, _, stop := scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
			o.Meta = store
			o.Blobs = blobs
			o.Log = logger
		}),
		Touches:     &recordingFlusher{fail: context.Canceled},
		Ticks:       make(chan time.Time),
		OrphanEvery: 1,
		Log:         logger,
	})
	scheduler.Trigger()
	waitFor(t, func() bool { return store.called("CachedUsage") }, "the cancelled sweep")
	stop()

	for _, unwanted := range []string{"failed", "could not flush"} {
		if strings.Contains(logged(), unwanted) {
			t.Errorf("logged %q about a cancelled shutdown:\n%s", unwanted, logged())
		}
	}
}

// scheduled starts a scheduler over an env and returns it with a stop
// function the test can call to end the loop and wait for it.
func scheduled(t *testing.T, env *env, opts cache.SchedulerOptions) (*cache.Scheduler, chan error, func()) {
	t.Helper()

	if opts.Evictor == nil {
		opts.Evictor = env.evictor(cache.Budget{Global: 1})
	}
	if opts.Log == nil {
		opts.Log = discardLogger()
	}
	scheduler, err := cache.NewScheduler(opts)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()

	// Idempotent, because a test that stops the loop to assert on it is also
	// the test whose cleanup would stop it again.
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("Run returned %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("Run did not return after its context was cancelled")
			}
		})
	}
	t.Cleanup(stop)
	return scheduler, done, stop
}

func TestSchedulerSweepsOnTheTimer(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)
	swept := make(chan struct{}, 4)

	ticks := make(chan time.Time)
	_, _, _ = scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
			o.Meta = &notifyingStore{inner: env.meta, swept: swept}
		}),
		Ticks: ticks,
	})

	ticks <- testTime
	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		t.Fatal("the timer did not produce a sweep")
	}

	waitFor(t, func() bool { return !env.hasBlobRow(repo, digest) }, "the row to be evicted")
}

func TestSchedulerSweepsOnATrigger(t *testing.T) {
	t.Parallel()

	// The breach trigger: whoever fills the cache says it grew, and the sweep
	// runs after the fill rather than in front of it.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)

	scheduler, _, _ := scheduled(t, env, cache.SchedulerOptions{Ticks: make(chan time.Time)})
	scheduler.Trigger()

	waitFor(t, func() bool { return !env.hasBlobRow(repo, digest) }, "a triggered sweep to evict the row")
}

func TestSchedulerCoalescesTriggers(t *testing.T) {
	t.Parallel()

	// A hundred fills during one sweep leave one sweep pending afterwards: a
	// trigger means "the cache grew", and a sweep that has not started yet
	// will see all of that growth anyway.
	env := newEnv(t, "dockerhub")
	swept := make(chan struct{}, 128)
	gate := make(chan struct{})
	scheduler, _, stop := scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
			o.Meta = &notifyingStore{inner: env.meta, swept: swept, gate: gate}
		}),
		Ticks: make(chan time.Time),
	})

	// One sweep, held open, and ninety-nine more triggers arriving while it
	// runs. Holding it is what makes the count deterministic: without the
	// gate the sweeps are fast enough that the test would be measuring how
	// many triggers it managed to send between them.
	scheduler.Trigger()
	awaitSignal(t, swept, "the first sweep")
	for range 99 {
		scheduler.Trigger()
	}
	close(gate)

	awaitSignal(t, swept, "the one pending sweep")
	stop()

	// One sweep for the trigger that started it, one for everything that
	// arrived while it ran, and nothing else: a fill does not queue a sweep of
	// its own.
	if got := len(swept) + 2; got != 2 {
		t.Errorf("%d sweeps for 100 triggers, want 2", got)
	}
}

func TestSchedulerFlushesTouchesBeforeSweeping(t *testing.T) {
	t.Parallel()

	// Eviction ranks on the times in the store, so a sweep that ran with a
	// minute of accesses still queued would rank content served seconds ago as
	// the coldest thing in the cache.
	env := newEnv(t, "dockerhub")
	flusher := &recordingFlusher{}
	ticks := make(chan time.Time)
	swept := make(chan struct{}, 4)
	store := &notifyingStore{inner: env.meta, swept: swept, flushed: &flusher.count}
	_, _, _ = scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) { o.Meta = store }),
		Touches: flusher,
		Ticks:   ticks,
	})

	ticks <- testTime
	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		t.Fatal("no sweep ran")
	}

	if flusher.count.Load() == 0 {
		t.Fatal("swept without flushing pending accesses")
	}
	if got := store.flushesAtFirstRead(); got == 0 {
		t.Error("the sweep read usage before the accesses were flushed")
	}
}

func TestSchedulerSweepsEvenWhenTheFlushFails(t *testing.T) {
	t.Parallel()

	// Ranking on slightly stale access times costs a refill; not sweeping
	// costs the budget.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)

	scheduler, _, _ := scheduled(t, env, cache.SchedulerOptions{
		Touches: &recordingFlusher{fail: errFailed},
		Ticks:   make(chan time.Time),
	})
	scheduler.Trigger()

	waitFor(t, func() bool { return !env.hasBlobRow(repo, digest) }, "the sweep to run despite a failed flush")
}

func TestSchedulerKeepsRunningAfterAFailedSweep(t *testing.T) {
	t.Parallel()

	// A store that is not answering resolves without this goroutine's help,
	// and a cache that stopped evicting the moment its store hiccuped would
	// fill up silently.
	env := newEnv(t, "dockerhub")
	env.putBlob("dockerhub/library/nginx", "layer-one", testTime)

	var failing atomic.Bool
	failing.Store(true)
	var failures atomic.Int64
	evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
		o.Meta = &stubStore{inner: env.meta, usage: func(ctx context.Context, entity string) (meta.CacheUsage, error) {
			if failing.Load() {
				failures.Add(1)
				return meta.CacheUsage{}, errFailed
			}
			return env.meta.CachedUsage(ctx, entity)
		}}
	})

	scheduler, _, _ := scheduled(t, env, cache.SchedulerOptions{Evictor: evictor, Ticks: make(chan time.Time)})
	scheduler.Trigger()
	waitFor(t, func() bool { return failures.Load() > 0 }, "the first sweep to fail")
	if got := env.usage("").Blobs; got != 1 {
		t.Fatalf("%d rows left after a failed sweep, want 1", got)
	}

	failing.Store(false)
	scheduler.Trigger()
	waitFor(t, func() bool { return env.usage("").Blobs == 0 }, "a later sweep to succeed")
}

func TestSchedulerRunsTheOrphanPassOnItsOwnCadence(t *testing.T) {
	t.Parallel()

	// The orphan pass walks the whole cache store, so it is pinned to a
	// multiple of the sweep rather than to a second timer that drifts.
	env := newEnv(t, "dockerhub")
	stray := env.orphan("interrupted-fill")
	walks := make(chan struct{}, 8)
	swept := make(chan struct{}, 8)
	blobs := &countingBlobs{inner: env.blobs, walked: walks}

	scheduler, _, _ := scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
			o.Blobs = blobs
			o.Meta = &notifyingStore{inner: env.meta, swept: swept}
		}),
		Ticks:       make(chan time.Time),
		OrphanEvery: 2,
	})

	// Each trigger is sent only once the previous sweep has been picked up, so
	// the two are two sweeps rather than one plus a coalesced trigger.
	scheduler.Trigger()
	awaitSignal(t, swept, "the first sweep")
	if !env.hasBytes(stray) {
		t.Fatal("the first sweep ran an orphan pass")
	}

	scheduler.Trigger()
	awaitSignal(t, walks, "an orphan pass on the second sweep")
	waitFor(t, func() bool { return !env.hasBytes(stray) }, "the orphan to be reclaimed")
}

// awaitSignal waits for one send on a channel a fake writes to.
func awaitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestSchedulerCanRunWithoutTheOrphanPass(t *testing.T) {
	t.Parallel()

	// For a deployment that would rather run it from the CLI.
	env := newEnv(t, "dockerhub")
	stray := env.orphan("interrupted-fill")
	walks := make(chan struct{}, 8)
	blobs := &countingBlobs{inner: env.blobs, walked: walks}
	swept := make(chan struct{}, 8)

	scheduler, _, _ := scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
			o.Blobs = blobs
			o.Meta = &notifyingStore{inner: env.meta, swept: swept}
		}),
		Ticks:       make(chan time.Time),
		OrphanEvery: -1,
	})

	for range 3 {
		scheduler.Trigger()
		select {
		case <-swept:
		case <-time.After(5 * time.Second):
			t.Fatal("no sweep ran")
		}
	}
	if len(walks) != 0 {
		t.Error("ran an orphan pass with the pass switched off")
	}
	if !env.hasBytes(stray) {
		t.Error("the orphan was reclaimed with the pass switched off")
	}
}

func TestSchedulerReportsWhatEachSweepDid(t *testing.T) {
	t.Parallel()

	// The three outcomes an operator reads: rows reclaimed, rows that would
	// not go, and a cache that was already inside its budget.
	for _, tc := range []struct {
		name string
		fail bool
		want string
	}{
		{name: "reclaimed", want: "cache sweep reclaimed space"},
		{name: "failed", fail: true, want: "cache sweep finished with failures"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t, "dockerhub")
			env.putBlob("dockerhub/library/nginx", "layer-one", testTime)
			logger, logged := captureLogger()

			store := &stubStore{inner: env.meta}
			if tc.fail {
				store.delBlob = func(context.Context, string, meta.Digest) (int64, error) { return 0, errFailed }
			}
			evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
				o.Meta = store
				o.Log = logger
			})

			scheduler, _, stop := scheduled(t, env, cache.SchedulerOptions{
				Evictor: evictor, Ticks: make(chan time.Time), Log: logger,
			})
			scheduler.Trigger()
			waitFor(t, func() bool { return strings.Contains(logged(), tc.want) }, "the sweep's report")
			stop()
		})
	}

	t.Run("nothing to do", func(t *testing.T) {
		t.Parallel()

		env := newEnv(t, "dockerhub")
		logger, logged := captureLogger()
		scheduler, _, stop := scheduled(t, env, cache.SchedulerOptions{
			Evictor: env.evictor(cache.Budget{Global: 1 << 20}, func(o *cache.Options) { o.Log = logger }),
			Ticks:   make(chan time.Time),
			Log:     logger,
		})
		scheduler.Trigger()
		waitFor(t, func() bool { return strings.Contains(logged(), "found nothing to reclaim") }, "the quiet report")
		stop()
	})
}

func TestSchedulerReportsAFailedOrphanPass(t *testing.T) {
	t.Parallel()

	// The pass fails on its own and the loop keeps running: what a walk
	// failure means is a storage layer that is unhappy, not a scheduler that
	// should stop.
	env := newEnv(t, "dockerhub")
	logger, logged := captureLogger()
	blobs := &stubBlobs{inner: env.blobs, walk: func(context.Context, func(blob.Descriptor) error) error {
		return errFailed
	}}

	scheduler, _, stop := scheduled(t, env, cache.SchedulerOptions{
		Evictor: env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) {
			o.Blobs = blobs
			o.Log = logger
		}),
		Ticks:       make(chan time.Time),
		OrphanEvery: 1,
		Log:         logger,
	})
	scheduler.Trigger()
	waitFor(t, func() bool { return strings.Contains(logged(), "cache orphan pass failed") }, "the orphan pass's report")
	stop()
}

func TestSchedulerReportsAQuietOrphanPass(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	logger, logged := captureLogger()
	scheduler, _, stop := scheduled(t, env, cache.SchedulerOptions{
		Evictor:     env.evictor(cache.Budget{Global: 1 << 20}, func(o *cache.Options) { o.Log = logger }),
		Ticks:       make(chan time.Time),
		OrphanEvery: 1,
		Log:         logger,
	})
	scheduler.Trigger()
	waitFor(t, func() bool { return strings.Contains(logged(), "orphan pass found nothing") }, "the quiet orphan report")
	stop()
}

func TestSchedulerStartsItsOwnTicker(t *testing.T) {
	t.Parallel()

	// Production leaves Ticks nil. The interval is short here only so the test
	// observes a real timer rather than asserting one exists.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)

	_, _, _ = scheduled(t, env, cache.SchedulerOptions{Interval: time.Millisecond})
	waitFor(t, func() bool { return !env.hasBlobRow(repo, digest) }, "the ticker to produce a sweep")
}

// waitFor polls a condition until it holds. It exists because the sweeps run
// on the scheduler's goroutine; the alternative is a sleep, and a sleep is
// either flaky or slow (§9).
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// notifyingStore signals every usage read, which is the first thing a sweep
// does and therefore the thing a test can count sweeps by.
type notifyingStore struct {
	inner   cache.Store
	swept   chan struct{}
	flushed *atomic.Int64
	// gate, when set, holds each sweep at its usage read until the test lets
	// it go.
	gate chan struct{}

	// flushesAtFirstRead records how many flushes had happened when the sweep
	// first read usage, which is what orders the two against each other
	// without a sleep.
	firstRead atomic.Int64
	once      sync.Once
}

// flushesAtFirstRead reports the flush count observed at the first usage read.
func (s *notifyingStore) flushesAtFirstRead() int64 { return s.firstRead.Load() }

func (s *notifyingStore) CachedUsage(ctx context.Context, entity string) (meta.CacheUsage, error) {
	if s.flushed != nil {
		s.once.Do(func() { s.firstRead.Store(s.flushed.Load()) })
	}
	select {
	case s.swept <- struct{}{}:
	default:
	}
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return meta.CacheUsage{}, ctx.Err()
		}
	}
	return s.inner.CachedUsage(ctx, entity)
}

func (s *notifyingStore) ListEvictable(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error) {
	return s.inner.ListEvictable(ctx, entity, limit)
}

func (s *notifyingStore) DeleteCachedManifest(ctx context.Context, repo string, digest meta.Digest) error {
	return s.inner.DeleteCachedManifest(ctx, repo, digest)
}

func (s *notifyingStore) DeleteCachedBlob(ctx context.Context, repo string, digest meta.Digest) (int64, error) {
	return s.inner.DeleteCachedBlob(ctx, repo, digest)
}

func (s *notifyingStore) CachedBlobClaims(ctx context.Context, digest meta.Digest) (int64, error) {
	return s.inner.CachedBlobClaims(ctx, digest)
}

// countingBlobs signals every walk, which only the orphan pass performs.
type countingBlobs struct {
	inner  cache.BlobStore
	walked chan struct{}
}

func (b *countingBlobs) Delete(ctx context.Context, digest blob.Digest) error {
	return b.inner.Delete(ctx, digest)
}

func (b *countingBlobs) Walk(ctx context.Context, fn func(blob.Descriptor) error) error {
	select {
	case b.walked <- struct{}{}:
	default:
	}
	return b.inner.Walk(ctx, fn)
}

// recordingFlusher stands in for the touch batcher.
type recordingFlusher struct {
	fail  error
	count atomic.Int64
}

func (f *recordingFlusher) Flush(context.Context) error {
	f.count.Add(1)
	return f.fail
}
