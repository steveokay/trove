package cache

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// The touch batcher's default bounds. Together they say what an approximate
// LRU costs: at most a minute of accesses, or a thousand distinct rows, may be
// lost to a hard kill, and content whose touch was lost ranks as colder than
// it is. The penalty for getting that wrong is one refill of content that is
// refillable by definition, which is why the LRU is allowed to be approximate
// and the pull path is not allowed to wait.
const (
	// DefaultTouchFlushInterval is how long a pending batch may wait.
	DefaultTouchFlushInterval = 60 * time.Second

	// DefaultTouchFlushRows is how many distinct rows may accumulate before
	// the batch is written regardless of the clock. It counts rows, not
	// accesses: a layer served a thousand times between flushes is one row.
	DefaultTouchFlushRows = 1000

	// DefaultTouchQueueDepth is how many accesses may await aggregation. The
	// queue absorbs a burst while a flush is in flight; past that, accesses
	// are dropped rather than allowed to slow a pull.
	DefaultTouchQueueDepth = 4096
)

// TouchRecorder observes that cached content was served.
//
// Touch must not block and cannot fail: its caller is a pull that has already
// succeeded, and an LRU key is never worth a byte of latency.
type TouchRecorder interface {
	Touch(repo string, digest meta.Digest, kind meta.CachedKind)
}

// TouchMeta is the slice of the metadata store the batcher writes through,
// declared by the consumer (§11). One method wide: there is nothing here
// through which recording an access could reach a row it should not, in either
// family.
type TouchMeta interface {
	TouchCached(ctx context.Context, accesses []meta.CacheAccess) error
}

// touchKey identifies the row an access accumulates into.
type touchKey struct {
	repository string
	digest     meta.Digest
	kind       meta.CachedKind
}

// TouchBatcher advances last-access times without a pull ever waiting for a
// database (C-013, the shape R-010 established for pull statistics).
//
// A served manifest or blob hands one access to a buffered channel and
// returns. A single goroutine aggregates what arrives -- keeping the latest
// time per row, since that is what an LRU ranks on -- and flushes when the
// batch reaches MaxRows, when the interval elapses, when a sweep asks, or when
// Close drains it.
//
// Two things are dropped rather than defended, for the reasons the pull
// batcher drops them:
//
//   - An access arriving when the queue is full. Blocking a pull behind an LRU
//     write inverts what matters. Drops are counted and logged at the next
//     flush, so an operator sizing the queue has the number.
//   - A batch the store refused. An access is an observation, and a retry
//     queue in front of a broken store grows without bound while the store
//     stays broken.
//
// Neither loses anything irreplaceable: a lost touch makes content look colder
// than it is, and the worst case of that is a refill.
type TouchBatcher struct {
	meta     TouchMeta
	now      func() time.Time
	log      *slog.Logger
	maxRows  int
	interval time.Duration

	accesses chan meta.CacheAccess
	ticks    <-chan time.Time
	stopTick func()

	flushes chan chan struct{}

	stop      chan struct{}
	stopCtx   context.Context
	done      chan struct{}
	closeOnce sync.Once

	dropped atomic.Int64
}

// TouchBatcherOptions configures a TouchBatcher. Only Meta is required.
type TouchBatcherOptions struct {
	// Meta receives the flushed batches.
	Meta TouchMeta

	// Interval is how long a pending batch may wait. Zero means
	// DefaultTouchFlushInterval.
	Interval time.Duration

	// MaxRows is how many distinct rows may accumulate before a flush. Zero
	// means DefaultTouchFlushRows.
	MaxRows int

	// QueueDepth bounds the accesses awaiting aggregation. Zero means
	// DefaultTouchQueueDepth.
	QueueDepth int

	// Now supplies the time an access is stamped with. Nil means time.Now.
	Now func() time.Time

	// Log receives drop counts and flush failures. Nil means slog.Default.
	Log *slog.Logger

	// Ticks replaces the internal timer, so a test can trigger the interval
	// flush at a moment it chooses instead of waiting a minute for one.
	// Production leaves it nil and gets a ticker at Interval.
	Ticks <-chan time.Time
}

// NewTouchBatcher starts a batcher. The caller must Close it: an unclosed
// batcher leaks its goroutine and loses its last batch.
func NewTouchBatcher(opts TouchBatcherOptions) (*TouchBatcher, error) {
	if opts.Meta == nil {
		return nil, errInvalid("a cache metadata store is required")
	}

	b := &TouchBatcher{
		meta:     opts.Meta,
		now:      opts.Now,
		log:      opts.Log,
		maxRows:  opts.MaxRows,
		interval: opts.Interval,

		ticks:    opts.Ticks,
		stopTick: func() {},
		flushes:  make(chan chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.log == nil {
		b.log = slog.Default()
	}
	if b.maxRows <= 0 {
		b.maxRows = DefaultTouchFlushRows
	}
	if b.interval <= 0 {
		b.interval = DefaultTouchFlushInterval
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = DefaultTouchQueueDepth
	}
	b.accesses = make(chan meta.CacheAccess, depth)
	if b.ticks == nil {
		ticker := time.NewTicker(b.interval)
		b.ticks = ticker.C
		b.stopTick = ticker.Stop
	}

	go b.run()
	return b, nil
}

// Touch notes that cached content was served. It never blocks: an access that
// does not fit in the queue is counted as dropped, because the caller is a
// pull that has already been served.
func (b *TouchBatcher) Touch(repo string, digest meta.Digest, kind meta.CachedKind) {
	access := meta.CacheAccess{Repository: repo, Digest: digest, Kind: kind, At: b.now()}
	select {
	case b.accesses <- access:
	default:
		b.dropped.Add(1)
	}
}

// Flush writes everything observed so far and waits for the write to finish.
//
// It exists for the sweep. Eviction ranks on the times in the store, so a
// sweep that ran with a minute of accesses still in this queue would rank
// content that was served seconds ago as the coldest thing in the cache. The
// Scheduler calls it before every sweep, which narrows that window to the
// flush itself.
//
// A ctx that expires first returns its error; the batcher keeps running.
func (b *TouchBatcher) Flush(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case b.flushes <- ack:
	case <-b.done:
		// Already closed, and Close flushed what it held.
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the batcher, writing everything already observed, and waits for
// the goroutine to finish. It is safe to call twice. A ctx that expires first
// abandons the wait and returns its error: shutdown does not hang on a store
// that has stopped answering.
func (b *TouchBatcher) Close(ctx context.Context) error {
	b.closeOnce.Do(func() {
		// Written before the close that releases the reader, so the goroutine
		// reads it safely.
		b.stopCtx = ctx
		close(b.stop)
	})

	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run owns the pending batch. Nothing else touches it, which is what makes
// aggregation lock-free.
func (b *TouchBatcher) run() {
	defer close(b.done)
	defer b.stopTick()

	pending := make(map[touchKey]meta.CacheAccess)
	for {
		select {
		case access := <-b.accesses:
			b.add(pending, access)
			if len(pending) >= b.maxRows {
				b.flush(context.Background(), pending)
			}
		case <-b.ticks:
			// Drained first: an access sitting in the queue when the interval
			// elapsed was observed before it, and leaving it for the next
			// interval would make one touch wait two of them.
			b.drain(pending)
			b.flush(context.Background(), pending)
		case ack := <-b.flushes:
			// Everything already queued was observed before the caller asked,
			// so it belongs in the batch the caller is waiting for.
			b.drain(pending)
			b.flush(context.Background(), pending)
			close(ack)
		case <-b.stop:
			b.drain(pending)
			b.flush(b.stopCtx, pending)
			return
		}
	}
}

// drain moves whatever is queued into the pending batch without waiting for
// more.
func (b *TouchBatcher) drain(pending map[touchKey]meta.CacheAccess) {
	for {
		select {
		case access := <-b.accesses:
			b.add(pending, access)
		default:
			return
		}
	}
}

// add folds one access into the batch, keeping the most recent time. An LRU
// key is a maximum, not a sum: what the row wants is the last time anybody
// wanted it.
func (b *TouchBatcher) add(pending map[touchKey]meta.CacheAccess, access meta.CacheAccess) {
	key := touchKey{repository: access.Repository, digest: access.Digest, kind: access.Kind}
	if existing, ok := pending[key]; ok && !access.At.After(existing.At) {
		return
	}
	pending[key] = access
}

// flush writes the batch and empties it, whatever happened. See the type's
// documentation for why a refused batch is dropped rather than retried.
func (b *TouchBatcher) flush(ctx context.Context, pending map[touchKey]meta.CacheAccess) {
	if dropped := b.dropped.Swap(0); dropped > 0 {
		// The queue is a configured bound, so this is an operator's number: it
		// says the depth is too small for the pull rate, and how badly.
		b.log.WarnContext(ctx, "dropped cache accesses: the queue was full",
			"count", dropped, "queue_depth", cap(b.accesses))
	}
	if len(pending) == 0 {
		return
	}

	accesses := make([]meta.CacheAccess, 0, len(pending))
	for key, access := range pending {
		accesses = append(accesses, access)
		delete(pending, key)
	}
	if err := b.meta.TouchCached(ctx, accesses); err != nil {
		b.log.ErrorContext(ctx, "dropped a batch of cache accesses", "rows", len(accesses), "error", err)
	}
}

// assert the interface is satisfied at compile time.
var _ TouchRecorder = (*TouchBatcher)(nil)
