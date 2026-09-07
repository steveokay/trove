package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
)

// Store is the eviction half of the cached-content family, declared here by
// the consumer (§11).
//
// It names five methods and none of them can reach a hosted table. It also
// omits the fill half deliberately: an evictor that could write cached content
// would be a package that both creates and destroys, and the reason to keep
// them apart is the reason the whole ADR exists -- the destroying half is the
// one worth being unable to point in the wrong direction.
type Store interface {
	CachedUsage(ctx context.Context, entity string) (meta.CacheUsage, error)
	ListEvictable(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error)
	DeleteCachedManifest(ctx context.Context, repo string, digest meta.Digest) error
	DeleteCachedBlob(ctx context.Context, repo string, digest meta.Digest) (int64, error)
	CachedBlobClaims(ctx context.Context, digest meta.Digest) (int64, error)
}

// BlobStore is the cache-rooted blob store (ADR 0007): a different instance
// over a disjoint root from the hosted one, chosen at wiring time.
//
// Two methods. Delete reclaims the bytes of an evicted blob; Walk is what the
// orphan pass enumerates. Nothing here can name the hosted store, and the
// interface being this narrow is what makes that visible at a glance.
type BlobStore interface {
	Delete(ctx context.Context, digest blob.Digest) error
	Walk(ctx context.Context, fn func(blob.Descriptor) error) error
}

// Publisher accepts events. The bus satisfies it; nil means the sweeps happen
// unobserved, which is right for a test and for a deployment whose event
// system is not wired yet.
type Publisher interface {
	Publish(ctx context.Context, e event.Event)
}

// Reasons carried by the cache.evicted payload. They answer an operator's
// first question -- which sweep took this -- without a join.
const (
	// reasonBudget is the LRU bound: the cache was over budget and this row
	// was the coldest thing in it.
	reasonBudget = "budget"

	// reasonOrphan is the orphan pass: bytes in the cache store that no proxy
	// had a row for, so nothing could have served them.
	reasonOrphan = "orphan"
)

// Defaults for the sweep. They are deliberately modest: a sweep is a
// background reclaim, not a deadline.
const (
	// DefaultPageSize is how many evictable rows one listing asks for. The
	// sweep takes what it needs from a page and comes back for another, so
	// this bounds memory rather than work.
	DefaultPageSize = 256

	// DefaultHeadroom is the fraction of the budget freed beyond the breach.
	// A sweep that stopped exactly at the line would be triggered again by the
	// next byte cached, so it goes slightly under and buys the cache room to
	// keep working.
	DefaultHeadroom = 0.05

	// maxHeadroom caps the configured fraction. Past this the "eviction" is a
	// cache flush with extra steps, which is never what an operator setting a
	// headroom meant.
	maxHeadroom = 0.5

	// DefaultMaxOrphans bounds one orphan pass. Reclaiming is cheap and
	// deferring the rest to the next pass costs only disk, so the bound exists
	// to keep one pass from holding a large digest list rather than to ration
	// the work. What it leaves behind is logged (§9: no silent caps).
	DefaultMaxOrphans = 10000
)

// Budget is how much space cached content may occupy (Q11).
//
// Zero means unlimited, at both levels, and is the value of a deployment that
// has not configured eviction: a cache nobody bounded grows, which is visible
// in the storage metrics, rather than one that quietly empties itself because
// a config key was missing.
type Budget struct {
	// Global bounds the whole cache. The default is 50 GB (Q11).
	Global int64

	// PerEntity bounds one proxy entity, keyed by entity name -- `dockerhub`,
	// not `dockerhub/library/nginx`. It is a carve-out, not an allocation: an
	// entity under its own ceiling can still lose content to the global pass,
	// because the disk is finite whatever the per-proxy configuration says.
	PerEntity map[string]int64
}

// Evictor reclaims cache space (C-013).
//
// A sweep runs the per-entity carve-outs first and the global budget last. The
// order matters: a proxy over its own ceiling should pay for its own excess
// before everything is ranked together, or one greedy upstream's fills would
// evict a well-behaved proxy's content while the greedy one stayed over its
// configured limit.
//
// Nothing here fails a pull. Every delete failure is logged and counted, the
// sweep continues with the next row, and the content the sweep could not
// reclaim is simply still there for the next one.
type Evictor struct {
	meta     Store
	blobs    BlobStore
	events   Publisher
	budget   Budget
	headroom float64
	pageSize int
	maxOrph  int
	log      *slog.Logger
}

// Options configures an Evictor. Meta and Blobs are required.
type Options struct {
	// Meta is the cached-content half of the metadata store.
	Meta Store

	// Blobs is the cache-rooted blob store.
	Blobs BlobStore

	// Events receives cache.evicted. Nil means nobody is listening.
	Events Publisher

	// Budget is what the cache may occupy. The zero value is unlimited and
	// sweeps nothing.
	Budget Budget

	// Headroom is the fraction of the budget freed beyond the breach. Zero
	// means DefaultHeadroom; a negative value means none, which is how a
	// deployment asks for eviction that stops exactly at the budget.
	Headroom float64

	// PageSize bounds one listing of evictable rows. Zero means
	// DefaultPageSize.
	PageSize int

	// MaxOrphans bounds one orphan pass. Zero means DefaultMaxOrphans.
	MaxOrphans int

	// Log receives eviction failures and sweep summaries. Nil means
	// slog.Default.
	//
	// It is a plain logger rather than the request-scoped one internal/server
	// supplies: a sweep has no request, and importing that package here would
	// put internal/server on the path between internal/cache and whatever it
	// imports later -- which is exactly the transitive edge ADR 0009 wall 3
	// forbids.
	Log *slog.Logger
}

// New builds an Evictor. It refuses a missing store because an evictor that
// could not read usage would report a clean sweep over a cache it never looked
// at, and refuses a missing blob store because the rows would go while their
// bytes stayed -- a cache that shrinks in the metrics and not on the disk.
func New(opts Options) (*Evictor, error) {
	switch {
	case opts.Meta == nil:
		return nil, errInvalid("a cache metadata store is required")
	case opts.Blobs == nil:
		return nil, errInvalid("a cache blob store is required")
	case opts.Budget.Global < 0:
		return nil, errInvalid("the global budget must not be negative, got %d", opts.Budget.Global)
	case opts.Headroom > maxHeadroom:
		return nil, errInvalid("headroom must be at most %v, got %v", maxHeadroom, opts.Headroom)
	}
	for entity, budget := range opts.Budget.PerEntity {
		if budget < 0 {
			return nil, errInvalid("the budget for %q must not be negative, got %d", entity, budget)
		}
	}

	e := &Evictor{
		meta:     opts.Meta,
		blobs:    opts.Blobs,
		events:   opts.Events,
		budget:   opts.Budget,
		headroom: opts.Headroom,
		pageSize: opts.PageSize,
		maxOrph:  opts.MaxOrphans,
		log:      opts.Log,
	}
	switch {
	case opts.Headroom < 0:
		e.headroom = 0
	case opts.Headroom == 0:
		e.headroom = DefaultHeadroom
	}
	if e.pageSize <= 0 {
		e.pageSize = DefaultPageSize
	}
	if e.maxOrph <= 0 {
		e.maxOrph = DefaultMaxOrphans
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	return e, nil
}

// Result is what one budget sweep did.
type Result struct {
	// Manifests and Blobs count the rows evicted.
	Manifests int
	Blobs     int

	// Bytes is what those rows accounted for -- the number the budget is
	// measured in, since usage sums rows rather than the disk.
	Bytes int64

	// Shared counts blobs whose row went while their bytes stayed, because
	// another proxy still holds a claim on them. It is the gap between what
	// the budget reclaimed and what the disk gave back, and an operator
	// watching a cache that will not shrink is looking for exactly this
	// number.
	Shared int

	// Skipped counts rows that were already gone when the delete reached them
	// -- another sweep, or a repository deletion, got there first. Not a
	// failure: the space was reclaimed either way.
	Skipped int

	// Failed counts rows the store refused to delete. Their space was not
	// reclaimed and the next sweep will try again.
	Failed int

	// Scopes records one entry per pass, in the order they ran: the carve-outs
	// by entity name, then the global pass with an empty entity.
	Scopes []Scope
}

// Scope is one pass of a sweep: what it was bounded by and what it achieved.
type Scope struct {
	// Entity is the proxy entity the pass was scoped to. Empty is the global
	// pass over the whole cache.
	Entity string

	// Budget is the ceiling the pass enforced.
	Budget int64

	// Target is the ceiling minus the headroom -- what the pass evicted down
	// to, rather than merely down to.
	Target int64

	// Before and After are the scope's usage in bytes, as the pass computed
	// it. After is derived by subtracting what was evicted rather than
	// re-queried, so a concurrent fill does not make one pass's arithmetic
	// depend on another's timing.
	Before int64
	After  int64
}

// evicted reports whether the sweep removed anything.
func (r Result) evicted() bool { return r.Manifests+r.Blobs > 0 }

// Sweep brings the cache inside its budget and reports what it took.
//
// A sweep over a cache that is already inside its budget is cheap: one usage
// query per scope and no listing at all. That is what makes it safe to call on
// a short timer and on every breach trigger.
//
// The error return is for a cache that could not be read -- a broken metadata
// store -- and not for content that could not be evicted. The distinction
// matters to the caller: the first means the sweep does not know what it is
// looking at, and the second means it does and is behind.
func (e *Evictor) Sweep(ctx context.Context) (Result, error) {
	var result Result

	// Carve-outs run in name order so that two sweeps over the same cache do
	// the same thing in the same order. Map iteration order would make a
	// failing store produce a different partial result each time, which is the
	// kind of difference that turns a reproducible bug into a flaky one.
	entities := make([]string, 0, len(e.budget.PerEntity))
	for entity := range e.budget.PerEntity {
		entities = append(entities, entity)
	}
	slices.Sort(entities)

	for _, entity := range entities {
		if err := e.sweepScope(ctx, entity, e.budget.PerEntity[entity], &result); err != nil {
			return result, err
		}
	}
	if err := e.sweepScope(ctx, "", e.budget.Global, &result); err != nil {
		return result, err
	}
	return result, nil
}

// sweepScope enforces one budget over one scope.
func (e *Evictor) sweepScope(ctx context.Context, entity string, budget int64, result *Result) error {
	// An unbounded scope is not swept at all. Reading its usage would be a
	// query whose answer could not change what happens next.
	if budget <= 0 {
		return nil
	}

	usage, err := e.meta.CachedUsage(ctx, entity)
	if err != nil {
		return fmt.Errorf("read cache usage for %q: %w", entity, err)
	}

	target := budget - int64(float64(budget)*e.headroom)
	scope := Scope{Entity: entity, Budget: budget, Target: target, Before: usage.Bytes, After: usage.Bytes}
	defer func() { result.Scopes = append(result.Scopes, scope) }()

	if usage.Bytes <= budget {
		return nil
	}

	for scope.After > target {
		items, err := e.meta.ListEvictable(ctx, entity, e.pageSize)
		if err != nil {
			return fmt.Errorf("list evictable content for %q: %w", entity, err)
		}
		if len(items) == 0 {
			// Over budget with nothing left to evict. The cache is smaller
			// than its own accounting says, which happens when a concurrent
			// delete beat the sweep to everything, and the next sweep reads a
			// usage that agrees again.
			e.log.WarnContext(ctx, "cache is over budget with nothing evictable left",
				"entity", entity, "budget", budget, "usage", scope.After)
			return nil
		}

		before := scope.After
		for _, item := range items {
			if scope.After <= target {
				break
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if e.evictItem(ctx, item, result) {
				scope.After -= item.Size
			}
		}
		if scope.After == before {
			// A whole page and not one row reclaimed: every delete failed, and
			// the next listing would return the same rows in the same order
			// for the same failures. Stopping is what keeps a broken store
			// from becoming a spin.
			e.log.ErrorContext(ctx, "gave up sweeping: no row in the page could be evicted",
				"entity", entity, "budget", budget, "usage", scope.After, "failed", result.Failed)
			return nil
		}
	}
	return nil
}

// evictItem removes one cached row and, for a blob nothing else claims, its
// bytes. It reports whether the row is gone, which is what the scope's
// arithmetic counts -- a row another writer had already removed counts as gone
// too, because the space it held is just as reclaimed.
func (e *Evictor) evictItem(ctx context.Context, item meta.CachedItem, result *Result) bool {
	switch item.Kind {
	case meta.CachedManifestKind:
		return e.evictManifest(ctx, item, result)
	case meta.CachedBlobKind:
		return e.evictBlob(ctx, item, result)
	default:
		// A kind the store invented. Counting it as evicted would make the
		// sweep's arithmetic drift away from the usage it re-reads next time.
		e.log.ErrorContext(ctx, "skipped a cached row of an unknown kind",
			"repository", item.Repository, "digest", string(item.Digest), "kind", string(item.Kind))
		result.Failed++
		return false
	}
}

// evictManifest removes a cached manifest. Its payload is the row, so nothing
// else has to be reclaimed.
func (e *Evictor) evictManifest(ctx context.Context, item meta.CachedItem, result *Result) bool {
	switch err := e.meta.DeleteCachedManifest(ctx, item.Repository, item.Digest); {
	case err == nil:
		result.Manifests++
		result.Bytes += item.Size
		e.publishEvicted(ctx, item.Repository, item.Digest, item.Size, reasonBudget)
		return true
	case errors.Is(err, meta.ErrNotFound):
		result.Skipped++
		return true
	default:
		e.log.ErrorContext(ctx, "could not evict a cached manifest",
			"repository", item.Repository, "digest", string(item.Digest), "error", err)
		result.Failed++
		return false
	}
}

// evictBlob removes one proxy's claim on a cached blob, and the bytes when it
// was the last claim.
//
// The claim count comes back from the delete rather than from a second query,
// so no other proxy can take a claim between the two. Reclaiming shared bytes
// because this row went would break a cache that still has every right to
// serve them.
func (e *Evictor) evictBlob(ctx context.Context, item meta.CachedItem, result *Result) bool {
	remaining, err := e.meta.DeleteCachedBlob(ctx, item.Repository, item.Digest)
	switch {
	case err == nil:
	case errors.Is(err, meta.ErrNotFound):
		result.Skipped++
		return true
	default:
		e.log.ErrorContext(ctx, "could not evict a cached blob",
			"repository", item.Repository, "digest", string(item.Digest), "error", err)
		result.Failed++
		return false
	}

	result.Blobs++
	result.Bytes += item.Size
	if remaining > 0 {
		// Another proxy still holds these bytes. The budget has the row's
		// space back; the disk keeps the content until the last claim goes.
		result.Shared++
	} else {
		e.reclaim(ctx, item.Repository, item.Digest)
	}
	e.publishEvicted(ctx, item.Repository, item.Digest, item.Size, reasonBudget)
	return true
}

// reclaim deletes cache bytes. It is the only function in trove that removes
// content from the cache blob store, and it takes a blob.CachedRef: a hosted
// digest cannot be converted into one, so no caller can arrive here holding
// something irreplaceable (ADR 0009 wall 1).
//
// A failure leaves bytes with no row, which the orphan pass reclaims. That is
// why it is logged rather than returned: the row is already gone, the space
// accounting is already right, and the disk catches up on its own schedule.
func (e *Evictor) reclaim(ctx context.Context, repo string, digest meta.Digest) {
	ref, err := blob.NewCachedRef(blob.Digest(digest))
	if err != nil {
		e.log.ErrorContext(ctx, "cached row named an unparseable digest, leaving its bytes to the orphan pass",
			"repository", repo, "digest", string(digest), "error", err)
		return
	}
	if err := e.blobs.Delete(ctx, ref.Digest()); err != nil && !errors.Is(err, blob.ErrNotFound) {
		e.log.ErrorContext(ctx, "could not reclaim cached bytes, leaving them to the orphan pass",
			"repository", repo, "digest", ref.String(), "error", err)
	}
}

// publishEvicted reports one reclaimed row. Cached content only: this event
// type is how an operator answers "was that recoverable?" from the event alone
// (ADR 0009), so nothing that is not a cache row may ever be published with it.
func (e *Evictor) publishEvicted(ctx context.Context, repo string, digest meta.Digest, size int64, reason string) {
	if e.events == nil {
		return
	}
	e.events.Publish(ctx, event.Event{
		Type:       event.CacheEvicted,
		Repository: repo,
		Resource:   string(digest),
		Payload: event.CacheEvictedPayload{
			Repository: repo,
			Digest:     string(digest),
			Size:       size,
			Reason:     reason,
		},
	})
}

// logSweep summarises a sweep at the level its outcome deserves: a sweep that
// evicted nothing is not news, and one that could not evict something is.
func (e *Evictor) logSweep(ctx context.Context, result Result, elapsed time.Duration) {
	switch {
	case result.Failed > 0:
		e.log.WarnContext(ctx, "cache sweep finished with failures",
			"manifests", result.Manifests, "blobs", result.Blobs, "bytes", result.Bytes,
			"shared", result.Shared, "failed", result.Failed, "elapsed", elapsed)
	case result.evicted():
		e.log.InfoContext(ctx, "cache sweep reclaimed space",
			"manifests", result.Manifests, "blobs", result.Blobs, "bytes", result.Bytes,
			"shared", result.Shared, "elapsed", elapsed)
	default:
		e.log.DebugContext(ctx, "cache sweep found nothing to reclaim", "elapsed", elapsed)
	}
}
