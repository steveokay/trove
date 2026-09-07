package cache

import (
	"context"
	"errors"
	"fmt"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
)

// OrphanResult is what one orphan pass did.
type OrphanResult struct {
	// Scanned is how many blobs the pass looked at.
	Scanned int

	// Reclaimed is how many had no claim and were deleted.
	Reclaimed int

	// Bytes is what those blobs occupied.
	Bytes int64

	// Failed counts blobs the store refused to delete. They stay orphaned and
	// the next pass tries again.
	Failed int

	// Truncated reports that the pass stopped at its bound with orphans left
	// to find. The next pass continues; the flag exists so that a cache which
	// never quite empties is a number an operator can see rather than a
	// silently capped sweep (§9).
	Truncated bool
}

// SweepOrphans reclaims cache bytes that no proxy repository has a row for.
//
// They exist by design. A fill commits its bytes and then writes its row, in
// that order, because the two failure modes are not symmetric: a row without
// bytes claims a hit that then misses -- which every read on the cache path
// already handles -- while bytes without a row are invisible to every proxy
// and cost only space (C-004). This pass is what collects the second kind: an
// interrupted fill, a process killed between the commit and the insert, or a
// budget eviction whose byte delete failed after its row was gone.
//
// The walk collects first and deletes afterwards rather than deleting inside
// the callback, because a driver enumerating its own storage while that
// storage is being mutated is a contract no driver offers.
//
// One race is accepted knowingly: a fill that commits bytes after this pass
// asked about their claims and before it deletes them loses those bytes, and
// the proxy's row then points at content the store does not have. That is a
// cache miss and a refill -- the exact case the read path is built to survive
// -- and the alternative, a grace period keyed off a modification time, would
// require every blob driver to carry one just for this.
func (e *Evictor) SweepOrphans(ctx context.Context) (OrphanResult, error) {
	var result OrphanResult

	orphans := make([]blob.Descriptor, 0, 16)
	err := e.blobs.Walk(ctx, func(desc blob.Descriptor) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		result.Scanned++

		claims, err := e.meta.CachedBlobClaims(ctx, meta.Digest(desc.Digest))
		if err != nil {
			// Without an answer there is no way to tell an orphan from a
			// layer somebody is serving, and the safe reading of "I do not
			// know" is to keep the bytes.
			return fmt.Errorf("count claims on %s: %w", desc.Digest, err)
		}
		if claims > 0 {
			return nil
		}

		orphans = append(orphans, desc)
		if len(orphans) >= e.maxOrph {
			result.Truncated = true
			return errStopWalk
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return result, fmt.Errorf("walk the cache blob store: %w", err)
	}

	for _, desc := range orphans {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !e.reclaimOrphan(ctx, desc) {
			result.Failed++
			continue
		}
		result.Reclaimed++
		result.Bytes += desc.Size
	}

	if result.Truncated {
		e.log.InfoContext(ctx, "orphan pass stopped at its bound, more may remain",
			"reclaimed", result.Reclaimed, "bound", e.maxOrph)
	}
	return result, nil
}

// reclaimOrphan deletes one unclaimed blob's bytes and reports success.
//
// The repository is empty on the event because there is none: an orphan is by
// definition content no proxy has a row for, and naming one would be inventing
// an owner for bytes that have none.
func (e *Evictor) reclaimOrphan(ctx context.Context, desc blob.Descriptor) bool {
	ref, err := blob.NewCachedRef(desc.Digest)
	if err != nil {
		// A blob store that enumerated something unparseable. It cannot have
		// arrived through a fill, and this pass is not the place to decide
		// what to do about it.
		e.log.ErrorContext(ctx, "cache blob store enumerated an unparseable digest",
			"digest", string(desc.Digest), "error", err)
		return false
	}

	switch err := e.blobs.Delete(ctx, ref.Digest()); {
	case err == nil, errors.Is(err, blob.ErrNotFound):
		// Already gone is the outcome asked for.
	default:
		e.log.ErrorContext(ctx, "could not reclaim an orphaned cache blob",
			"digest", ref.String(), "error", err)
		return false
	}

	e.publishEvicted(ctx, "", meta.Digest(desc.Digest), desc.Size, reasonOrphan)
	return true
}

// errStopWalk ends a walk early without becoming a failure. It never escapes
// this package.
var errStopWalk = errors.New("cache: stop walking")
