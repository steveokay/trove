package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
)

// Tag resolution against a proxy (C-005).
//
// Digests are immutable and tags are not, which is the distinction the whole
// subsystem turns on (ADR 0008). Content fetched by digest is cached forever
// and never revalidated; the mapping from a *name* to a digest is a lease, held
// for a TTL and then confirmed against the upstream with a conditional request
// that costs no bandwidth when nothing moved. Serving a week-old `:latest` is
// the failure that makes a pull-through cache worse than no cache at all, so
// the revalidation deadline is a first-class per-repository setting rather than
// a constant.
//
// Single-flight is deliberately absent: N concurrent pulls of a cold tag make N
// upstream resolutions today, and coalescing them is C-006. Nothing here caches
// a negative answer either -- that is C-007 -- so a typo'd tag reaches the
// upstream every time until it does.

// TagResolution is the answer to "what does this tag point at".
//
// It carries the mapping and how it was arrived at, and deliberately not the
// manifest: a caller that wants the bytes asks Manifest for the digest, which
// is a cache hit by then, and returning them here would make one method that
// sometimes fetches a manifest and sometimes does not.
type TagResolution struct {
	// Digest is what the tag resolves to.
	Digest blob.Digest

	// Hit reports that a lease inside its TTL answered, with no upstream
	// request at all.
	Hit bool

	// Revalidated reports that the upstream was asked. It is true for a cold
	// resolution and for an expired lease that was confirmed or replaced.
	Revalidated bool

	// Changed reports that the tag now points somewhere other than the lease
	// did. It is true for every cold resolution, because there was nothing to
	// disagree with.
	Changed bool

	// Stale reports that an expired lease was served because the upstream
	// could not be reached (ADR 0008). The content is still verified content;
	// what is unconfirmed is that the tag still points at it.
	Stale bool

	// StaleFor is how far past its revalidation deadline the lease was. It is
	// zero unless Stale is true.
	StaleFor time.Duration
}

// ResolveTag resolves a tag against a proxy repository, revalidating when the
// lease has expired.
//
// The three outcomes, in the order they are cheapest:
//
//   - A lease inside its TTL answers immediately. No upstream request is made,
//     which is the entire point of the cache.
//   - An expired lease is revalidated conditionally: the upstream is told the
//     digest and entity tag we hold, and an unchanged tag transfers no manifest
//     body at all. Unchanged refreshes the deadline and leaves the digest
//     alone; changed fetches, verifies, and caches the new manifest, updates
//     the lease, and leaves the old content cached -- images pinned by digest
//     keep working, which is why nothing is deleted here.
//   - An unreachable upstream serves the expired lease anyway, marked stale,
//     with an event -- unless the repository is in strict mode, or there is no
//     lease to serve. Only unreachability and throttling qualify: rejected
//     credentials and a refused redirect are configuration and security
//     problems that no amount of waiting fixes, and dressing them as an outage
//     would hide them behind a stale-content warning.
//
// A tag the upstream no longer has drops the lease and answers ErrNotFound. The
// manifest it named stays cached, because a name being withdrawn says nothing
// about the content, and a client pulling that digest is entitled to it.
func (f *Filler) ResolveTag(ctx context.Context, t Target, tag string) (TagResolution, error) {
	if err := t.validate(); err != nil {
		return TagResolution{}, err
	}
	if tag == "" {
		return TagResolution{}, &ReferenceError{Kind: "tag", Value: tag, Reason: "must not be empty"}
	}

	// Coalesced by repository and tag (C-006): fifty pods starting at once
	// resolve `:latest` once. The manifest fetch that a changed tag triggers is
	// inside this call and so is covered by the same flight, which is what
	// makes "one resolve and one fetch" true rather than "one resolve".
	return coalesce(ctx, f.coalescer, tagKey(t.Repository, tag),
		func(ctx context.Context) (TagResolution, error) { return f.resolveTag(ctx, t, tag) })
}

// resolveTag is ResolveTag's body, run once per tag across concurrent callers.
func (f *Filler) resolveTag(ctx context.Context, t Target, tag string) (TagResolution, error) {
	lease, held, err := f.lease(ctx, t, tag)
	if err != nil {
		return TagResolution{}, err
	}

	now := f.now()
	if held && f.fresh(lease, t.TagTTL, now) {
		return TagResolution{Digest: blob.Digest(lease.Digest), Hit: true}, nil
	}

	// A name the upstream did not have, asked for again inside the negative
	// TTL, is answered from the record (C-007). The check sits after the lease
	// and before the upstream: a live lease is a stronger statement than a
	// remembered absence, and the two cannot both be current anyway, because a
	// not-found deletes the lease that named it.
	absent, recorded, err := f.negative(ctx, t, tag)
	if err != nil {
		return TagResolution{}, err
	}
	if recorded && f.negativeFresh(absent, t.NegativeTTL, now) {
		return TagResolution{}, negativeAnswer(t, tag)
	}

	conditional := Conditional{}
	if held {
		conditional = Conditional{Digest: blob.Digest(lease.Digest), ETag: lease.ETag}
	}

	// A throttled upstream is answered from the backoff without being called,
	// and the answer travels the degraded path: cached content is served
	// stale, uncached content fails, `strict` fails both (C-008, C-009).
	if err := f.upstreamReady(t, now); err != nil {
		return f.resolveFailed(ctx, t, tag, lease, held, err, now)
	}

	resolution, err := t.Client.ResolveTag(ctx, t.Upstream, tag, conditional)
	f.recordUpstream(ctx, t, now, err)
	if err != nil {
		return f.resolveFailed(ctx, t, tag, lease, held, err, now)
	}
	if recorded {
		// The upstream has it after all, so the record has done its job. It is
		// dropped here rather than left to expire: a table that keeps every
		// name anybody ever mistyped grows without anything ever pruning it.
		f.dropNegative(ctx, t, tag)
	}

	if !resolution.Changed && held {
		// The upstream confirmed what we hold. Only the deadline moves: the
		// digest is the same content it always was, and rewriting it would
		// make an unchanged revalidation look like a change to anything
		// reading the row.
		refreshed := lease
		refreshed.FetchedAt = now
		refreshed.TTL = t.TagTTL
		refreshed.Stale = false
		if resolution.ETag != "" {
			refreshed.ETag = resolution.ETag
		}
		f.writeLease(ctx, refreshed)
		return TagResolution{Digest: blob.Digest(lease.Digest), Revalidated: true}, nil
	}

	// Either the tag moved or we had nothing to compare against. Both fetch.
	if err := f.cacheResolved(ctx, t, resolution); err != nil {
		return TagResolution{}, err
	}

	f.writeLease(ctx, meta.TagLease{
		Repository: t.Repository,
		Tag:        tag,
		Digest:     meta.Digest(resolution.Digest),
		ETag:       resolution.ETag,
		FetchedAt:  now,
		TTL:        t.TagTTL,
	})
	return TagResolution{Digest: resolution.Digest, Revalidated: true, Changed: true}, nil
}

// lease reads the stored lease, distinguishing "none yet" from "cannot say".
//
// A store that cannot be read fails the resolution rather than falling through
// to the upstream, for the reason the manifest path gives: a broken metadata
// store must not become a stampede against somebody else's registry.
func (f *Filler) lease(ctx context.Context, t Target, tag string) (meta.TagLease, bool, error) {
	lease, err := f.meta.GetTagLease(ctx, t.Repository, tag)
	switch {
	case err == nil:
		return lease, true, nil
	case errors.Is(err, meta.ErrNotFound):
		return meta.TagLease{}, false, nil
	default:
		return meta.TagLease{}, false, fmt.Errorf("read the tag lease: %w", err)
	}
}

// fresh reports whether a lease may be reused without asking the upstream.
//
// The TTL is the repository's current one, not the one recorded on the row: an
// operator who lowers it expects the next pull to revalidate, not the pull
// after every lease happens to be rewritten. A zero TTL is not "no expiry" but
// its opposite -- revalidate every time (Q11) -- which is why it is compared
// rather than treated as unset.
func (f *Filler) fresh(lease meta.TagLease, ttl time.Duration, now time.Time) bool {
	if ttl <= 0 {
		return false
	}
	return now.Sub(lease.FetchedAt) < ttl
}

// cacheResolved stores the manifest a resolution produced.
//
// A resolution that reports a change carries the manifest body with it, so the
// common path costs no second request. A client that reported a change without
// one is not one this package knows how to build, but it is one an
// implementation could be: falling back to a digest fetch keeps the contract
// "Changed means the caller can serve the new content" true either way.
func (f *Filler) cacheResolved(ctx context.Context, t Target, resolution Resolution) error {
	if len(resolution.Manifest) == 0 {
		_, err := f.Manifest(ctx, t, resolution.Digest)
		return err
	}
	_, err := f.storeManifest(ctx, t, resolution.Digest, resolution.Manifest, resolution.MediaType)
	return err
}

// resolveFailed decides what to do when the upstream could not answer.
func (f *Filler) resolveFailed(ctx context.Context, t Target, tag string,
	lease meta.TagLease, held bool, err error, now time.Time,
) (TagResolution, error) {
	if errors.Is(err, ErrNotFound) {
		// The tag is gone upstream. Keeping the mapping "just in case" is how a
		// proxy outlives the registry it mirrors; the manifest stays cached and
		// is still reachable by digest.
		if held {
			f.dropLease(ctx, t, tag)
		}
		// And the absence is remembered, briefly, so the retry loop behind this
		// pull costs the upstream one request rather than one per attempt
		// (C-007).
		f.recordNegative(ctx, t, tag, now)
		return TagResolution{}, err
	}

	cause, degraded := Classify(err)
	if !degraded || !held || t.Offline.strict() {
		return TagResolution{}, err
	}

	staleFor := now.Sub(lease.FetchedAt) - t.TagTTL
	if staleFor < 0 {
		staleFor = 0
	}

	// The lease is marked but its FetchedAt is not moved: the mapping was not
	// confirmed, and refreshing the deadline here would let one unreachable
	// upstream buy a full TTL of silence before the next attempt.
	if !lease.Stale {
		stale := lease
		stale.Stale = true
		f.writeLease(ctx, stale)
	}

	f.publishStale(ctx, t, tag, blob.Digest(lease.Digest), staleFor, cause)
	return TagResolution{Digest: blob.Digest(lease.Digest), Stale: true, StaleFor: staleFor}, nil
}

// writeLease stores a lease, logging rather than failing.
//
// A lease that cannot be written is a cache that will revalidate again next
// time: wasteful, and not worth failing a pull the upstream already answered.
// It is the same trade the fill path makes for the same reason.
func (f *Filler) writeLease(ctx context.Context, lease meta.TagLease) {
	if err := f.meta.PutTagLease(ctx, lease); err != nil {
		f.log.ErrorContext(ctx, "could not write a tag lease",
			"repository", lease.Repository, "tag", lease.Tag, "error", err)
	}
}

// dropLease removes a lease for a tag the upstream no longer has.
func (f *Filler) dropLease(ctx context.Context, t Target, tag string) {
	if err := f.meta.DeleteTagLease(ctx, t.Repository, tag); err != nil && !errors.Is(err, meta.ErrNotFound) {
		f.log.ErrorContext(ctx, "could not drop the lease for a tag the upstream no longer has",
			"repository", t.Repository, "tag", tag, "error", err)
	}
}

// publishStale reports content served past its revalidation deadline. It is one
// of the three ways degraded mode is visible (header, event, metric), and the
// one an operator can subscribe to.
func (f *Filler) publishStale(ctx context.Context, t Target, tag string,
	digest blob.Digest, staleFor time.Duration, cause DegradedCause,
) {
	if f.events == nil {
		return
	}
	f.events.Publish(ctx, event.Event{
		Type:       event.CacheStaleServed,
		Repository: t.Repository,
		Resource:   tag,
		Payload: event.CacheStaleServedPayload{
			Repository:   t.Repository,
			Upstream:     t.Remote,
			Reference:    tag,
			Digest:       digest.String(),
			StaleSeconds: int64(staleFor / time.Second),
			Reason:       string(cause),
		},
	})
}
