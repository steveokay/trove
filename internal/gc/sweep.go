package gc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
)

// Store is what the sweep asks of the metadata store, declared here by the
// consumer (§11).
//
// Six methods, every one of them about hosted blobs or about the run's own
// bookkeeping. There is nothing here through which a sweep could reach a
// cached row, a tag, or a manifest -- and in particular nothing that could
// delete one (ADR 0009 wall 2).
type Store interface {
	ListSweepCandidates(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error)
	DeleteBlobIfUnreferenced(ctx context.Context, digest meta.Digest, before time.Time) (bool, error)

	StartGCRun(ctx context.Context, run meta.GCRun) error
	SaveGCProgress(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freedBytes int64) error
	FinishGCRun(ctx context.Context, id string, at time.Time, failure string) error
	ResumableGCRun(ctx context.Context) (meta.GCRun, error)
}

// BlobStore is the hosted blob store (ADR 0007): a different instance over a
// disjoint root from the cache's, chosen at wiring time.
//
// One method. A collector that could read or write content would be a
// collector whose blast radius needed arguing about; this one can only remove
// what it has already proven unreferenced.
type BlobStore interface {
	Delete(ctx context.Context, digest blob.Digest) error
}

// Publisher accepts events. The bus satisfies it; nil means the sweeps happen
// unobserved, which is right for a test and for a deployment whose event
// system is not wired yet.
type Publisher interface {
	Publish(ctx context.Context, e event.Event)
}

// Defaults for a sweep.
const (
	// DefaultGrace is how long a blob is protected from collection after it is
	// recorded (ADR 0010, Q16).
	//
	// It is what covers the window between a push's blob upload and its
	// manifest PUT: the blob row exists, nothing references it yet, and it is
	// not wrong to collect it -- it is merely catastrophic. Twenty-four hours
	// is far longer than any push, and the cost of the slack is disk.
	DefaultGrace = 24 * time.Hour

	// DefaultBatchSize is how many candidates one listing asks for. The cursor
	// is persisted after each batch, so this is also how much progress an
	// interrupted sweep can lose.
	DefaultBatchSize = 256
)

// ErrInvalidOptions reports a Collector that cannot be built from what it was
// given. Callers assert with errors.Is.
var ErrInvalidOptions = errors.New("gc: invalid options")

func errInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOptions, fmt.Sprintf(format, args...))
}

// Collector runs mark-and-sweep garbage collection (P-007).
type Collector struct {
	meta   Store
	blobs  BlobStore
	events Publisher

	grace time.Duration
	batch int
	newID func() string
	now   func() time.Time
	log   *slog.Logger
}

// Options configures a Collector. Meta, Blobs, and NewID are required.
type Options struct {
	// Meta is the hosted metadata store's collection surface.
	Meta Store

	// Blobs is the hosted blob store.
	Blobs BlobStore

	// Events receives gc.completed. Nil means nobody is listening.
	Events Publisher

	// Grace is how long a blob is protected after it is recorded. Zero means
	// DefaultGrace. A negative grace is refused rather than treated as zero:
	// "collect blobs from the future" is not a configuration anybody means,
	// and reading it as "no protection at all" would turn a typo into data
	// loss.
	Grace time.Duration

	// BatchSize is how many candidates one listing asks for. Zero means
	// DefaultBatchSize.
	BatchSize int

	// NewID mints a run identifier. It is injected rather than generated here
	// so a test's runs are named by the test, and so an operator triggering a
	// sweep from the API can carry their own correlation id.
	NewID func() string

	// Now is the clock. Nil means time.Now.
	Now func() time.Time

	// Log receives per-blob failures and sweep summaries. Nil means
	// slog.Default.
	Log *slog.Logger
}

// New builds a Collector.
func New(opts Options) (*Collector, error) {
	switch {
	case opts.Meta == nil:
		return nil, errInvalid("a metadata store is required")
	case opts.Blobs == nil:
		return nil, errInvalid("a hosted blob store is required")
	case opts.NewID == nil:
		return nil, errInvalid("a run identifier source is required")
	case opts.Grace < 0:
		return nil, errInvalid("the grace window must not be negative, got %v", opts.Grace)
	}

	c := &Collector{
		meta:   opts.Meta,
		blobs:  opts.Blobs,
		events: opts.Events,
		grace:  opts.Grace,
		batch:  opts.BatchSize,
		newID:  opts.NewID,
		now:    opts.Now,
		log:    opts.Log,
	}
	if c.grace == 0 {
		c.grace = DefaultGrace
	}
	if c.batch <= 0 {
		c.batch = DefaultBatchSize
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	return c, nil
}

// Result is what one sweep did.
type Result struct {
	// RunID identifies the run, so an operator can find it in gc_runs.
	RunID string

	// Resumed marks a sweep that picked up an interrupted run rather than
	// starting one.
	Resumed bool

	// Scanned counts the blobs considered.
	Scanned int64

	// Deleted counts the rows removed, and Bytes what they accounted for.
	Deleted int64
	Bytes   int64

	// Skipped counts candidates the re-check refused -- something referenced
	// them between the listing and the delete. It is the number that says the
	// safety check is doing work, and it is reported rather than hidden.
	Skipped int64

	// Leaked counts blobs whose row went but whose bytes would not delete.
	// They are unreferenced bytes on disk: reclaimed by a later sweep's
	// orphan-free re-listing (they no longer have a row, so nothing will
	// offer them again) or by `trove verify` (P-012). This number is the
	// honest cost of preferring a leak to a loss.
	Leaked int64

	// Complete reports that the sweep reached the end of the candidates. A
	// sweep stopped by its context is not complete and its run stays open for
	// the next one to resume.
	Complete bool
}

// Run performs a sweep, resuming an interrupted one when there is one.
//
// It returns when the candidates are exhausted or the context is cancelled.
// Cancellation is not a failure: the cursor is already persisted, the run
// stays open, and the next sweep continues from it.
func (c *Collector) Run(ctx context.Context) (Result, error) {
	run, resumed, err := c.begin(ctx)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		RunID:   run.ID,
		Resumed: resumed,
		Scanned: run.Scanned,
		Deleted: run.Deleted,
		Bytes:   run.FreedBytes,
	}
	started := c.now()

	cursor := run.Cursor
	for {
		if err := ctx.Err(); err != nil {
			return c.interrupted(ctx, run.ID, cursor, result, err)
		}

		candidates, err := c.meta.ListSweepCandidates(ctx, run.SweepBefore, cursor, c.batch)
		if err != nil && ctx.Err() != nil {
			// Asked to stop, so this is a stop. A store does not necessarily
			// report cancellation as context.Canceled -- SQLite surfaces its
			// own "interrupted" -- and a caller that logged every shutdown as
			// a garbage-collection failure would be teaching its operator to
			// ignore the message that matters.
			return c.interrupted(ctx, run.ID, cursor, result, ctx.Err())
		}
		if err != nil {
			// A sweep that cannot see its candidates has failed rather than
			// been interrupted, and the difference is worth keeping: the run
			// is closed with the reason, so an operator sees that collection
			// is failing instead of an unfinished row that looks like a
			// shutdown. Starting the next one fresh costs almost nothing --
			// the blobs already deleted are gone from the candidate set, so a
			// restart re-lists rather than re-deletes.
			wrapped := fmt.Errorf("list sweep candidates: %w", err)
			c.saveProgress(ctx, run.ID, cursor, result)
			c.finish(ctx, run.ID, result, started, wrapped.Error())
			return result, wrapped
		}
		if len(candidates) == 0 {
			result.Complete = true
			break
		}

		for _, candidate := range candidates {
			if err := ctx.Err(); err != nil {
				return c.interrupted(ctx, run.ID, cursor, result, err)
			}
			c.collect(ctx, run, candidate, &result)
			cursor = candidate.Digest
		}
		c.saveProgress(ctx, run.ID, cursor, result)
	}

	c.saveProgress(ctx, run.ID, cursor, result)
	c.finish(ctx, run.ID, result, started, "")
	c.publishCompleted(ctx, result, c.now().Sub(started))
	return result, nil
}

// interrupted records where a cancelled sweep stopped and leaves its run
// open.
//
// This is the asymmetry with a failed sweep, and it is deliberate. A
// cancellation is a shutdown: the work will be continued, so the run stays
// unfinished and the next sweep resumes it -- with the same deadline, which is
// the whole reason resuming is safe. A store failure is not continuable in the
// same sense, so that path closes the run with its reason. An unfinished row
// therefore means "interrupted", and an operator reading one is not left
// guessing which kind of stop it was.
func (c *Collector) interrupted(ctx context.Context, runID string, cursor meta.Digest, result Result, cause error) (Result, error) {
	c.saveProgress(ctx, runID, cursor, result)
	c.log.InfoContext(ctx, "garbage collection interrupted; the run stays open for the next sweep",
		"run", runID, "cursor", string(cursor), "scanned", result.Scanned,
		"deleted", result.Deleted, "bytes", result.Bytes, "reason", cause.Error())
	return result, cause
}

// begin resumes an interrupted run or starts a new one.
//
// A resumed run keeps its own deadline. Recomputing it would move the window
// forward and admit blobs that were protected when the sweep began, so an
// interruption would quietly widen what it may delete.
func (c *Collector) begin(ctx context.Context) (meta.GCRun, bool, error) {
	switch existing, err := c.meta.ResumableGCRun(ctx); {
	case err == nil:
		c.log.InfoContext(ctx, "resuming an interrupted garbage collection",
			"run", existing.ID, "cursor", string(existing.Cursor), "sweep_before", existing.SweepBefore)
		return existing, true, nil
	case errors.Is(err, meta.ErrNotFound):
		// Nothing to resume: start one below.
	case ctx.Err() != nil:
		return meta.GCRun{}, false, ctx.Err()
	default:
		return meta.GCRun{}, false, fmt.Errorf("look for a run to resume: %w", err)
	}

	now := c.now()
	run := meta.GCRun{
		ID:          c.newID(),
		StartedAt:   now,
		SweepBefore: now.Add(-c.grace),
	}
	if err := c.meta.StartGCRun(ctx, run); err != nil {
		// Cancellation is reported as cancellation whatever the store called
		// it, so a shutdown never reads as a failed collection.
		if ctx.Err() != nil {
			return meta.GCRun{}, false, ctx.Err()
		}
		return meta.GCRun{}, false, fmt.Errorf("start a run: %w", err)
	}
	return run, false, nil
}

// collect removes one candidate: the row first, then its bytes.
//
// Nothing here fails the sweep. A row the re-check refused is a blob something
// started referencing, which is the check working; a byte delete that fails
// leaves unreferenced bytes on disk, which is the failure mode this design
// prefers over every alternative.
func (c *Collector) collect(ctx context.Context, run meta.GCRun, candidate meta.Blob, result *Result) {
	result.Scanned++

	deleted, err := c.meta.DeleteBlobIfUnreferenced(ctx, candidate.Digest, run.SweepBefore)
	switch {
	case err != nil:
		// The store could not answer. Leave the blob alone: an unknown answer
		// is not a licence to delete.
		c.log.ErrorContext(ctx, "could not re-check a blob before deleting it",
			"run", run.ID, "digest", string(candidate.Digest), "error", err)
		result.Skipped++
		return
	case !deleted:
		result.Skipped++
		return
	}

	result.Deleted++
	result.Bytes += candidate.Size
	if !c.reclaim(ctx, run.ID, candidate.Digest) {
		result.Leaked++
	}
}

// reclaim deletes hosted bytes and reports whether they went.
//
// It is the only function in trove that removes content from the hosted blob
// store, and it takes a blob.HostedRef: a cached digest cannot be converted
// into one, so no caller can arrive here holding something whose loss would
// merely cost a refill -- and, more to the point, nothing in internal/cache
// can arrive here at all (ADR 0009 wall 1).
func (c *Collector) reclaim(ctx context.Context, runID string, digest meta.Digest) bool {
	ref, err := blob.NewHostedRef(blob.Digest(digest))
	if err != nil {
		// A row naming something that is not a digest. Its bytes cannot be
		// addressed, so there is nothing to delete and nothing to leak.
		c.log.ErrorContext(ctx, "blob row named an unparseable digest",
			"run", runID, "digest", string(digest), "error", err)
		return false
	}

	switch err := c.blobs.Delete(ctx, ref.Digest()); {
	case err == nil, errors.Is(err, blob.ErrNotFound):
		// Already gone is the outcome asked for.
		return true
	default:
		// The row is gone and the bytes are not. They are unreferenced and
		// nothing will offer them again, so this is a leak: recorded loudly,
		// reclaimed by `trove verify`, and never worth reversing into a delete
		// of something still referenced.
		c.log.ErrorContext(ctx, "leaked a blob: its row went and its bytes would not",
			"run", runID, "digest", ref.String(), "error", err)
		return false
	}
}

// saveProgress persists the cursor and counters after a batch.
//
// A failure here is logged and not returned: the sweep has already deleted
// what it deleted, and stopping now would neither undo that nor make the next
// run safer. The cost is that a resumed sweep re-lists from an older cursor,
// which is wasted work rather than lost data.
func (c *Collector) saveProgress(ctx context.Context, runID string, cursor meta.Digest, result Result) {
	// Detached from the caller's context: a cancelled sweep still wants its
	// cursor written, or the cancellation would cost the whole batch's
	// progress.
	saveCtx := context.WithoutCancel(ctx)
	if err := c.meta.SaveGCProgress(saveCtx, runID, cursor, result.Scanned, result.Deleted, result.Bytes); err != nil {
		c.log.ErrorContext(ctx, "could not save garbage collection progress",
			"run", runID, "cursor", string(cursor), "error", err)
	}
}

// finish closes the run, recording why it stopped.
func (c *Collector) finish(ctx context.Context, runID string, result Result, started time.Time, failure string) {
	closeCtx := context.WithoutCancel(ctx)
	if err := c.meta.FinishGCRun(closeCtx, runID, c.now(), failure); err != nil {
		c.log.ErrorContext(ctx, "could not close a garbage collection run",
			"run", runID, "error", err)
	}

	switch {
	case failure != "":
		c.log.WarnContext(ctx, "garbage collection stopped early",
			"run", runID, "scanned", result.Scanned, "deleted", result.Deleted,
			"bytes", result.Bytes, "skipped", result.Skipped, "leaked", result.Leaked,
			"reason", failure)
	default:
		c.log.InfoContext(ctx, "garbage collection finished",
			"run", runID, "scanned", result.Scanned, "deleted", result.Deleted,
			"bytes", result.Bytes, "skipped", result.Skipped, "leaked", result.Leaked,
			"elapsed", c.now().Sub(started))
	}
}

// publishCompleted reports a finished sweep. Only a completed one is
// published: gc.completed is what an operator's automation waits on, and
// firing it for a sweep that stopped halfway would make "the collection ran"
// mean less than it says.
func (c *Collector) publishCompleted(ctx context.Context, result Result, elapsed time.Duration) {
	if c.events == nil {
		return
	}
	c.events.Publish(ctx, event.Event{
		Type:     event.GCCompleted,
		Resource: result.RunID,
		Payload: event.GCCompletedPayload{
			RunID:           result.RunID,
			BlobsScanned:    result.Scanned,
			BlobsDeleted:    result.Deleted,
			BytesReclaimed:  result.Bytes,
			DurationSeconds: int64(elapsed.Seconds()),
			Resumed:         result.Resumed,
		},
	})
}
