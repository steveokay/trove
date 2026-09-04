package registry

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// The batcher's default bounds (R-010). Together they say what "off the hot
// path" costs: at most a minute of pulls, or a thousand distinct references,
// may be lost to a hard kill, and that is the price of a pull that writes
// nothing. An orderly shutdown loses none of it -- Close flushes.
const (
	// DefaultPullFlushInterval is how long a pending batch may wait.
	DefaultPullFlushInterval = 60 * time.Second

	// DefaultPullFlushRows is how many distinct references may accumulate
	// before the batch is written regardless of the clock. It counts rows, not
	// pulls: a thousand pulls of one tag is one row.
	DefaultPullFlushRows = 1000

	// DefaultPullQueueDepth is how many observations may await aggregation.
	// The queue absorbs a burst while a flush is in flight; past that,
	// observations are dropped rather than allowed to slow a pull.
	DefaultPullQueueDepth = 4096
)

// PullRecorder observes that an artifact was served.
//
// Record must not block and cannot fail: its caller is a request that has
// already succeeded, and a statistic is never worth a pull.
type PullRecorder interface {
	Record(repo, reference string)
}

// PullStatsMeta is the slice of the metadata store the batcher writes through,
// declared by the consumer (§11). It is one method wide: there is nothing here
// through which counting a pull could reach a manifest, a tag, or a blob row.
type PullStatsMeta interface {
	RecordPulls(ctx context.Context, records []meta.PullRecord) error
}

// pullObservation is one pull, as the handler saw it.
type pullObservation struct {
	repository string
	reference  string
	at         time.Time
}

// pullKey identifies the row an observation accumulates into.
type pullKey struct {
	repository string
	reference  string
}

// PullBatcher records pulls without a pull ever waiting for a database.
//
// A served manifest GET hands one observation to a buffered channel and
// returns. A single goroutine aggregates what arrives -- a hot tag pulled a
// thousand times between flushes is one row with a count of a thousand, not a
// thousand writes -- and flushes when the batch reaches DefaultPullFlushRows
// distinct references, when the interval elapses, or when Close drains it.
// The metadata store therefore sees one transaction per flush, and the pull
// path sees no store call at all.
//
// Two things are deliberately dropped rather than defended:
//
//   - An observation arriving when the queue is full. The alternative is
//     blocking a pull behind a statistic, which inverts what matters. Drops
//     are counted and logged at the next flush, so an operator sizing the
//     queue has the number.
//   - A batch the store refused. Statistics are best-effort observations, and
//     a retry queue in front of a broken store grows without bound while the
//     store stays broken -- which is exactly when memory is worth least. The
//     failure is logged; the next flush starts clean.
//
// Neither loses anything that can be reconstructed, because there is nothing
// to reconstruct it from: a pull leaves no other trace.
//
// The clock is injected (§7), so what a test records is a value it chose.
//
// The artifact.pulled event belongs to the same moment and is not emitted
// here: the event bus arrives with E-001, and this batcher gains the emit then
// (ADR 0012 -- pulled events are not persisted by default). There is no stub
// for it in the meantime.
type PullBatcher struct {
	meta     PullStatsMeta
	now      func() time.Time
	log      *slog.Logger
	maxRows  int
	interval time.Duration

	observations chan pullObservation
	ticks        <-chan time.Time
	stopTicker   func()

	stop      chan struct{}
	stopCtx   context.Context
	done      chan struct{}
	closeOnce sync.Once

	dropped atomic.Int64
}

// PullBatcherOptions configures a PullBatcher. Only Meta is required.
type PullBatcherOptions struct {
	// Meta receives the flushed batches.
	Meta PullStatsMeta

	// Interval is how long a pending batch may wait. Zero means
	// DefaultPullFlushInterval.
	Interval time.Duration

	// MaxRows is how many distinct references may accumulate before a flush.
	// Zero means DefaultPullFlushRows.
	MaxRows int

	// QueueDepth bounds the observations awaiting aggregation. Zero means
	// DefaultPullQueueDepth.
	QueueDepth int

	// Now supplies the time an observation is stamped with. Nil means
	// time.Now.
	Now func() time.Time

	// Log receives drop counts and flush failures. Nil falls back to the
	// default logger.
	Log *slog.Logger

	// Ticks replaces the internal timer. It exists so a test can trigger the
	// interval flush at a moment it chooses instead of waiting a minute for
	// one; production leaves it nil and gets a ticker at Interval.
	Ticks <-chan time.Time
}

// NewPullBatcher starts a batcher. The caller must Close it: an unclosed
// batcher leaks its goroutine and loses its last batch.
func NewPullBatcher(opts PullBatcherOptions) *PullBatcher {
	b := &PullBatcher{
		meta:     opts.Meta,
		now:      opts.Now,
		log:      opts.Log,
		maxRows:  opts.MaxRows,
		interval: opts.Interval,

		ticks:      opts.Ticks,
		stopTicker: func() {},
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.maxRows <= 0 {
		b.maxRows = DefaultPullFlushRows
	}
	if b.interval <= 0 {
		b.interval = DefaultPullFlushInterval
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = DefaultPullQueueDepth
	}
	b.observations = make(chan pullObservation, depth)
	if b.ticks == nil {
		ticker := time.NewTicker(b.interval)
		b.ticks = ticker.C
		b.stopTicker = ticker.Stop
	}

	go b.run()
	return b
}

// Record notes one pull. It never blocks: an observation that does not fit in
// the queue is counted as dropped and discarded, because the caller is a pull
// that has already been served.
func (b *PullBatcher) Record(repo, reference string) {
	select {
	case b.observations <- pullObservation{repository: repo, reference: reference, at: b.now()}:
	default:
		b.dropped.Add(1)
	}
}

// Close stops the batcher, writing everything already observed, and waits for
// the goroutine to finish. It is safe to call twice. A ctx that expires first
// abandons the wait and returns its error: shutdown does not hang on a store
// that has stopped answering.
func (b *PullBatcher) Close(ctx context.Context) error {
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
func (b *PullBatcher) run() {
	defer close(b.done)
	defer b.stopTicker()

	pending := make(map[pullKey]meta.PullRecord)
	for {
		select {
		case observation := <-b.observations:
			b.add(pending, observation)
			if len(pending) >= b.maxRows {
				b.flush(context.Background(), pending)
			}
		case <-b.ticks:
			b.flush(context.Background(), pending)
		case <-b.stop:
			// Everything already queued was observed before shutdown and
			// belongs in the last batch.
			b.drain(pending)
			b.flush(b.stopCtx, pending)
			return
		}
	}
}

// drain moves whatever is queued into the pending batch without waiting for
// more.
func (b *PullBatcher) drain(pending map[pullKey]meta.PullRecord) {
	for {
		select {
		case observation := <-b.observations:
			b.add(pending, observation)
		default:
			return
		}
	}
}

// add folds one observation into the batch: counts sum and the timestamp keeps
// the most recent pull, so the row written is what the store would have
// accumulated one write at a time.
func (b *PullBatcher) add(pending map[pullKey]meta.PullRecord, o pullObservation) {
	key := pullKey{repository: o.repository, reference: o.reference}
	record, ok := pending[key]
	if !ok {
		record = meta.PullRecord{Repository: o.repository, Reference: o.reference}
	}
	record.Count++
	if o.at.After(record.At) {
		record.At = o.at
	}
	pending[key] = record
}

// flush writes the batch and empties it, whatever happened. See the type's
// documentation for why a refused batch is dropped rather than retried.
func (b *PullBatcher) flush(ctx context.Context, pending map[pullKey]meta.PullRecord) {
	log := server.Logger(ctx, b.log)
	if dropped := b.dropped.Swap(0); dropped > 0 {
		// The queue is a configured bound, so this is an operator's number:
		// it says the depth is too small for the pull rate, and how badly.
		log.Warn("dropped pull observations: the queue was full",
			"count", dropped, "queue_depth", cap(b.observations))
	}
	if len(pending) == 0 {
		return
	}

	records := make([]meta.PullRecord, 0, len(pending))
	for key, record := range pending {
		records = append(records, record)
		delete(pending, key)
	}
	if err := b.meta.RecordPulls(ctx, records); err != nil {
		log.Error("dropped a batch of pull statistics", "rows", len(records), "error", err)
	}
}

// assert the interface is satisfied at compile time.
var _ PullRecorder = (*PullBatcher)(nil)
