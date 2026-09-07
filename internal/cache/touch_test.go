package cache_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/meta"
)

// touchSink collects the batches a TouchBatcher writes.
type touchSink struct {
	mu      sync.Mutex
	batches [][]meta.CacheAccess
	fail    error
	written chan struct{}
}

func newTouchSink() *touchSink {
	return &touchSink{written: make(chan struct{}, 16)}
}

func (s *touchSink) TouchCached(_ context.Context, accesses []meta.CacheAccess) error {
	s.mu.Lock()
	batch := append([]meta.CacheAccess(nil), accesses...)
	s.batches = append(s.batches, batch)
	err := s.fail
	s.mu.Unlock()

	select {
	case s.written <- struct{}{}:
	default:
	}
	return err
}

func (s *touchSink) all() []meta.CacheAccess {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []meta.CacheAccess
	for _, batch := range s.batches {
		out = append(out, batch...)
	}
	return out
}

func (s *touchSink) batchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

func (s *touchSink) refuse(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

// newBatcher starts a batcher over a sink with a clock the test owns.
func newBatcher(t *testing.T, sink *touchSink, tweak ...func(*cache.TouchBatcherOptions)) *cache.TouchBatcher {
	t.Helper()

	opts := cache.TouchBatcherOptions{
		Meta: sink,
		Now:  func() time.Time { return testTime },
		Log:  discardLogger(),
	}
	for _, apply := range tweak {
		apply(&opts)
	}
	batcher, err := cache.NewTouchBatcher(opts)
	if err != nil {
		t.Fatalf("NewTouchBatcher: %v", err)
	}
	t.Cleanup(func() { _ = batcher.Close(context.Background()) })
	return batcher
}

func TestNewTouchBatcherRequiresAStore(t *testing.T) {
	t.Parallel()

	batcher, err := cache.NewTouchBatcher(cache.TouchBatcherOptions{})
	if !errors.Is(err, cache.ErrInvalidOptions) {
		t.Fatalf("NewTouchBatcher error = %v, want ErrInvalidOptions", err)
	}
	if batcher != nil {
		t.Error("NewTouchBatcher returned a batcher alongside an error")
	}
}

func TestTouchesFlushOnDemand(t *testing.T) {
	t.Parallel()

	sink := newTouchSink()
	batcher := newBatcher(t, sink)
	digest := blob.FromBytes(blob.SHA256, []byte("layer"))

	batcher.Touch("dockerhub/library/nginx", meta.Digest(digest), meta.CachedBlobKind)
	if err := batcher.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	written := sink.all()
	if len(written) != 1 {
		t.Fatalf("wrote %d accesses, want 1", len(written))
	}
	want := meta.CacheAccess{
		Repository: "dockerhub/library/nginx", Digest: meta.Digest(digest),
		Kind: meta.CachedBlobKind, At: testTime,
	}
	if written[0] != want {
		t.Errorf("access = %+v, want %+v", written[0], want)
	}
}

func TestTouchesFlushWhenTheBatchIsFull(t *testing.T) {
	t.Parallel()

	sink := newTouchSink()
	batcher := newBatcher(t, sink, func(o *cache.TouchBatcherOptions) { o.MaxRows = 2 })

	for i := range 2 {
		batcher.Touch("dockerhub/library/nginx", meta.Digest(blob.FromBytes(blob.SHA256, []byte{byte(i)})), meta.CachedBlobKind)
	}

	// The flush happens on the batcher's goroutine, so the sink's signal is
	// what the test waits on rather than a sleep (§9).
	select {
	case <-sink.written:
	case <-time.After(5 * time.Second):
		t.Fatal("a full batch was never written")
	}
	if got := len(sink.all()); got != 2 {
		t.Errorf("wrote %d accesses, want 2", got)
	}
}

func TestTouchesFlushOnTheInterval(t *testing.T) {
	t.Parallel()

	sink := newTouchSink()
	ticks := make(chan time.Time, 1)
	batcher := newBatcher(t, sink, func(o *cache.TouchBatcherOptions) { o.Ticks = ticks })

	batcher.Touch("dockerhub/library/nginx", "sha256:"+meta.Digest(hex64('a')), meta.CachedManifestKind)
	ticks <- testTime

	select {
	case <-sink.written:
	case <-time.After(5 * time.Second):
		t.Fatal("the interval flush never happened")
	}
	if got := len(sink.all()); got != 1 {
		t.Errorf("wrote %d accesses, want 1", got)
	}
}

func TestTouchesKeepTheLatestTimePerRow(t *testing.T) {
	t.Parallel()

	// An LRU key is a maximum, not a sum: what the row wants to know is the
	// last time anybody wanted it, and a flush that arrives late must not make
	// hot content look cold.
	sink := newTouchSink()
	var now time.Time
	var mu sync.Mutex
	batcher := newBatcher(t, sink, func(o *cache.TouchBatcherOptions) {
		o.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})

	digest := meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer")))
	for _, at := range []time.Time{testTime.Add(time.Minute), testTime, testTime.Add(30 * time.Second)} {
		mu.Lock()
		now = at
		mu.Unlock()
		batcher.Touch("dockerhub/library/nginx", digest, meta.CachedBlobKind)
	}
	if err := batcher.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	written := sink.all()
	if len(written) != 1 {
		t.Fatalf("wrote %d rows for one digest, want 1", len(written))
	}
	if !written[0].At.Equal(testTime.Add(time.Minute)) {
		t.Errorf("At = %v, want the latest touch %v", written[0].At, testTime.Add(time.Minute))
	}
}

func TestTouchesForDifferentRowsDoNotMerge(t *testing.T) {
	t.Parallel()

	sink := newTouchSink()
	batcher := newBatcher(t, sink)
	digest := meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer")))

	// Same digest, three rows: two proxies claim it, and a manifest and a blob
	// with one digest are different rows in different tables.
	batcher.Touch("dockerhub/library/nginx", digest, meta.CachedBlobKind)
	batcher.Touch("quay/other/app", digest, meta.CachedBlobKind)
	batcher.Touch("dockerhub/library/nginx", digest, meta.CachedManifestKind)
	if err := batcher.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := len(sink.all()); got != 3 {
		t.Errorf("wrote %d rows, want 3", got)
	}
}

func TestTouchesDropWhenTheQueueIsFull(t *testing.T) {
	t.Parallel()

	// Blocking a pull behind an LRU write inverts what matters. The drop is
	// counted and logged; the pull is already served.
	sink := newTouchSink()
	release := make(chan struct{})
	blocking := &blockingTouchMeta{inner: sink, block: release}
	batcher := newBatcher(t, sink, func(o *cache.TouchBatcherOptions) {
		o.Meta = blocking
		o.MaxRows = 1
		o.QueueDepth = 1
	})

	// The first touch is picked up and blocks the goroutine mid-flush; the
	// queue then holds one and refuses the rest.
	for i := range 50 {
		batcher.Touch("dockerhub/library/nginx", meta.Digest(blob.FromBytes(blob.SHA256, []byte{byte(i)})), meta.CachedBlobKind)
	}
	close(release)

	if err := batcher.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(sink.all()); got >= 50 {
		t.Errorf("wrote %d accesses; the queue was supposed to drop what did not fit", got)
	}
	if got := len(sink.all()); got == 0 {
		t.Error("wrote nothing at all")
	}
}

func TestTouchBatcherDropsARefusedBatch(t *testing.T) {
	t.Parallel()

	// A retry queue in front of a broken store grows without bound while the
	// store stays broken, which is exactly when memory is worth least. A lost
	// touch makes content look colder than it is; the worst case is a refill.
	sink := newTouchSink()
	sink.refuse(errFailed)
	batcher := newBatcher(t, sink)

	digest := meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer")))
	batcher.Touch("dockerhub/library/nginx", digest, meta.CachedBlobKind)
	if err := batcher.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	sink.refuse(nil)
	if err := batcher.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := sink.batchCount(); got != 1 {
		t.Errorf("wrote %d batches, want 1: the refused batch was retried", got)
	}
}

func TestTouchBatcherFlushesWhatItHoldsOnClose(t *testing.T) {
	t.Parallel()

	sink := newTouchSink()
	batcher := newBatcher(t, sink)
	batcher.Touch("dockerhub/library/nginx", meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer"))), meta.CachedBlobKind)

	if err := batcher.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(sink.all()); got != 1 {
		t.Errorf("wrote %d accesses on close, want 1", got)
	}

	// Closing twice is safe, and a flush afterwards is a no-op rather than a
	// send on a goroutine that is gone.
	if err := batcher.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := batcher.Flush(context.Background()); err != nil {
		t.Errorf("Flush after Close: %v", err)
	}
	if got := sink.batchCount(); got != 1 {
		t.Errorf("wrote %d batches, want 1", got)
	}
}

func TestTouchBatcherFlushRespectsItsContext(t *testing.T) {
	t.Parallel()

	// Shutdown does not hang on a store that has stopped answering. The write
	// is held open, so the cancellation lands while the caller is waiting for
	// a flush that has genuinely started -- not before it was accepted.
	sink := newTouchSink()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	batcher := newBatcher(t, sink, func(o *cache.TouchBatcherOptions) {
		o.Meta = &blockingTouchMeta{inner: sink, block: release, entered: entered}
	})
	// Registered after the batcher's own cleanup so it runs before it:
	// cleanups are LIFO, and the batcher cannot shut down while its goroutine
	// is parked in the write this channel is holding.
	t.Cleanup(func() { close(release) })

	batcher.Touch("dockerhub/library/nginx", meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer"))), meta.CachedBlobKind)

	ctx, cancel := context.WithCancel(context.Background())
	flushed := make(chan error, 1)
	go func() { flushed <- batcher.Flush(ctx) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the flush never reached the store")
	}
	cancel()

	select {
	case err := <-flushed:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Flush error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Flush did not return after its context was cancelled")
	}
	if err := batcher.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close error = %v, want context.Canceled", err)
	}
}

func TestTouchBatcherFlushGivesUpBeforeItIsAccepted(t *testing.T) {
	t.Parallel()

	// The other half: a caller whose context is already gone does not queue a
	// flush request at all. The batcher is held mid-write first, so the
	// request genuinely cannot be accepted and the test is not choosing
	// between two ready cases.
	sink := newTouchSink()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	batcher := newBatcher(t, sink, func(o *cache.TouchBatcherOptions) {
		o.Meta = &blockingTouchMeta{inner: sink, block: release, entered: entered}
		o.MaxRows = 1
	})
	t.Cleanup(func() { close(release) })

	batcher.Touch("dockerhub/library/nginx", meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer"))), meta.CachedBlobKind)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the batch was never written")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := batcher.Flush(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Flush error = %v, want context.Canceled", err)
	}
}

func TestTouchBatcherRunsOnItsDefaults(t *testing.T) {
	t.Parallel()

	// Nothing but a store: the clock, the logger, the interval, the batch
	// size, and the queue depth all come from the package.
	sink := newTouchSink()
	batcher, err := cache.NewTouchBatcher(cache.TouchBatcherOptions{Meta: sink})
	if err != nil {
		t.Fatalf("NewTouchBatcher: %v", err)
	}

	batcher.Touch("dockerhub/library/nginx", meta.Digest(blob.FromBytes(blob.SHA256, []byte("layer"))), meta.CachedBlobKind)
	if err := batcher.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	written := sink.all()
	if len(written) != 1 {
		t.Fatalf("wrote %d accesses, want 1", len(written))
	}
	if written[0].At.IsZero() {
		t.Error("the default clock stamped a zero time")
	}
}

// blockingTouchMeta holds the first write until the test releases it, so a
// test can observe a batcher whose goroutine is busy.
type blockingTouchMeta struct {
	inner   cache.TouchMeta
	block   chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (m *blockingTouchMeta) TouchCached(ctx context.Context, accesses []meta.CacheAccess) error {
	m.once.Do(func() {
		if m.entered != nil {
			select {
			case m.entered <- struct{}{}:
			default:
			}
		}
		<-m.block
	})
	return m.inner.TouchCached(ctx, accesses)
}

// hex64 builds a 64-character hex string from one repeated digit, for the
// cases that need a well-formed digest and do not care which.
func hex64(c byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c
	}
	return string(out)
}
