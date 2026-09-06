package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// Negative caching (C-007).
//
// A tag nobody ever pushed is pulled as often as one that exists: a typo in a
// manifest, a deployment referring to a release that was never cut, a retry
// loop. Each of those is an upstream request that can only ever fail, and on a
// rate-limited remote they are the requests that cost the most -- they buy
// nothing and they count the same as a real pull.
//
// So an upstream's not-found is remembered, briefly. Two rules bound it:
//
//   - **Names only.** A digest that is absent now may exist a moment later --
//     somebody is pushing it -- and caching that absence would break a push
//     followed by a pull through a group. Nothing keyed by digest reaches this
//     file: Manifest and Blob never consult it and never write to it, which is
//     a property their tests assert rather than a convention this comment
//     asks for.
//   - **Briefly.** Sixty seconds by default (Q11). The entry exists to absorb a
//     retry loop, not to remember a decision; a tag pushed upstream a minute
//     ago must not be missing here for an hour.

// negative reads a recorded absence, distinguishing "nothing recorded" from
// "cannot say". A store that cannot be read fails the resolution for the reason
// the lease read does: working around a broken metadata store by asking the
// upstream harder is how a cache becomes a stampede.
func (f *Filler) negative(ctx context.Context, t Target, reference string) (meta.NegativeEntry, bool, error) {
	entry, err := f.meta.GetNegativeEntry(ctx, t.Repository, reference)
	switch {
	case err == nil:
		return entry, true, nil
	case errors.Is(err, meta.ErrNotFound):
		return meta.NegativeEntry{}, false, nil
	default:
		return meta.NegativeEntry{}, false, fmt.Errorf("read the negative cache: %w", err)
	}
}

// negativeFresh reports whether a recorded absence may still be believed.
//
// The TTL is the repository's current one rather than the recorded one, exactly
// as leases work: an operator who shortens it expects the next pull to try the
// upstream again. A TTL of zero switches negative caching off, which is the
// opposite of what zero means for a lease -- and deliberately so. A lease with
// no TTL means "confirm every time", which is the *safe* reading of a mapping
// that may have moved; an absence with no TTL would mean "believe it forever",
// which is the unsafe one. Off is the only sane zero here.
func (f *Filler) negativeFresh(entry meta.NegativeEntry, ttl time.Duration, now time.Time) bool {
	if ttl <= 0 {
		return false
	}
	return now.Sub(entry.ObservedAt) < ttl
}

// recordNegative remembers that the upstream did not have a name.
//
// A failure to record is logged and dropped: the pull already has its answer,
// and the only cost of not remembering is asking the upstream again.
func (f *Filler) recordNegative(ctx context.Context, t Target, reference string, at time.Time) {
	if t.NegativeTTL <= 0 {
		return
	}
	if err := f.meta.PutNegativeEntry(ctx, meta.NegativeEntry{
		Repository: t.Repository,
		Reference:  reference,
		ObservedAt: at,
		TTL:        t.NegativeTTL,
	}); err != nil {
		f.log.ErrorContext(ctx, "could not record an upstream not-found",
			"repository", t.Repository, "reference", reference, "error", err)
	}
}

// dropNegative forgets a recorded absence, which is what a successful
// resolution means. Leaving it would grow a table out of every typo anybody
// ever made, and the row has already done its job.
func (f *Filler) dropNegative(ctx context.Context, t Target, reference string) {
	if err := f.meta.DeleteNegativeEntry(ctx, t.Repository, reference); err != nil && !errors.Is(err, meta.ErrNotFound) {
		f.log.ErrorContext(ctx, "could not clear a negative cache entry",
			"repository", t.Repository, "reference", reference, "error", err)
	}
}

// negativeAnswer is the error a fresh negative entry produces. It is the
// upstream's own not-found -- a caller must not be able to tell a remembered
// absence from a fresh one, or group resolution would treat the two
// differently and a member's behaviour would depend on how recently somebody
// else mistyped a tag.
func negativeAnswer(t Target, reference string) error {
	return fmt.Errorf("%w: %s/%s is not at the upstream (remembered)", ErrNotFound, t.Upstream, reference)
}
