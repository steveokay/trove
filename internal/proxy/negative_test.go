package proxy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// C-007: the negative cache. A tag nobody ever pushed is pulled as often as one
// that exists, and on a rate-limited upstream those are the requests that cost
// the most -- they buy nothing and they count the same as a real pull.

const negativeTTL = 60 * time.Second

// negativeTarget is the environment's target with both TTLs set, since the
// zero values mean "revalidate every pull" and "do not remember absences".
func negativeTarget(env *fillEnv) proxy.Target {
	target := leaseTarget(env)
	target.NegativeTTL = negativeTTL
	return target
}

func TestNegativeCacheAbsorbsARetryLoop(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := negativeTarget(env)
	typo := env.fixture.MissingTag

	if _, err := env.filler.ResolveTag(fillCtx(), target, typo); !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("ResolveTag for a typo = %v, want ErrNotFound", err)
	}
	entry, err := env.meta.GetNegativeEntry(fillCtx(), target.Repository, typo)
	if err != nil {
		t.Fatalf("GetNegativeEntry: %v", err)
	}
	if !entry.ObservedAt.Equal(testTime) || entry.TTL != negativeTTL {
		t.Errorf("entry = %+v, want it observed on the injected clock with the target's TTL", entry)
	}

	// The retries inside the TTL are answered from the record. They are
	// answered with the upstream's own not-found: a caller must not be able to
	// tell a remembered absence from a fresh one, or a group member's behaviour
	// would depend on how recently somebody else mistyped a tag.
	env.clock.advance(negativeTTL - time.Second)
	for i := range 5 {
		if _, err := env.filler.ResolveTag(fillCtx(), target, typo); !errors.Is(err, proxy.ErrNotFound) {
			t.Fatalf("retry %d = %v, want ErrNotFound", i, err)
		}
	}

	// Which is provable by the upstream requests that did not happen.
	counter, ok := env.target.Client.(*fillCountingClient)
	if !ok {
		t.Fatalf("client = %T, want the counting one", env.target.Client)
	}
	if counter.resolutions() != 1 {
		t.Errorf("upstream resolutions = %d, want 1 for six attempts inside the TTL",
			counter.resolutions())
	}

	// Past the TTL the upstream is asked again: the entry absorbs a retry loop,
	// it does not remember a decision.
	env.clock.advance(2 * time.Second)
	if _, err := env.filler.ResolveTag(fillCtx(), target, typo); !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("ResolveTag after the TTL = %v, want ErrNotFound", err)
	}
	if counter.resolutions() != 2 {
		t.Errorf("upstream resolutions = %d, want the expired entry to have asked again",
			counter.resolutions())
	}
}

// The entry is short-lived on purpose: it absorbs a retry loop, it does not
// remember a decision. A tag pushed upstream a minute ago must not be missing
// here for an hour.
func TestNegativeCacheExpiresAndClearsOnSuccess(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	counter := &fillCountingClient{Client: mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})}
	env := newFillEnv(t, counter, seed)
	target := negativeTarget(env)

	// A name that is missing now and present later: the fixture's second
	// manifest under a tag the upstream does not have yet.
	missing := "not-yet"
	if _, err := env.filler.ResolveTag(fillCtx(), target, missing); !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("ResolveTag = %v, want ErrNotFound", err)
	}
	if _, err := env.meta.GetNegativeEntry(fillCtx(), target.Repository, missing); err != nil {
		t.Fatalf("GetNegativeEntry: %v", err)
	}

	server.tag(t, missing, seed.Next)
	env.clock.advance(negativeTTL + time.Second)

	got, err := env.filler.ResolveTag(fillCtx(), target, missing)
	if err != nil {
		t.Fatalf("ResolveTag after the entry expired: %v", err)
	}
	if got.Digest != seed.Next.Digest {
		t.Errorf("digest = %q, want %q", got.Digest, seed.Next.Digest)
	}

	// The record is cleared rather than left to expire: a table that keeps
	// every name anybody ever mistyped grows with nothing to prune it.
	if _, err := env.meta.GetNegativeEntry(fillCtx(), target.Repository,
		missing); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetNegativeEntry after a successful resolution = %v, want it cleared", err)
	}
}

// A zero negative TTL switches the mechanism off -- the opposite of what zero
// means for a lease TTL, and deliberately so: "confirm every time" is the safe
// reading of a mapping, "believe it forever" is not the safe reading of an
// absence.
func TestNegativeCacheOffByZeroTTL(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env) // NegativeTTL is zero.
	typo := env.fixture.MissingTag

	if _, err := env.filler.ResolveTag(fillCtx(), target, typo); !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("ResolveTag = %v, want ErrNotFound", err)
	}
	if _, err := env.meta.GetNegativeEntry(fillCtx(), target.Repository,
		typo); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetNegativeEntry = %v, want nothing recorded", err)
	}

	// A record left over from when the mechanism was on is ignored, not
	// believed: switching it off must take effect immediately, the same way
	// shortening the lease TTL does.
	if err := env.meta.PutNegativeEntry(fillCtx(), meta.NegativeEntry{
		Repository: target.Repository, Reference: env.fixture.Tag,
		ObservedAt: testTime, TTL: negativeTTL,
	}); err != nil {
		t.Fatalf("PutNegativeEntry: %v", err)
	}
	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err != nil {
		t.Errorf("ResolveTag with negative caching off: %v, want the upstream asked", err)
	}
}

// Digest lookups never touch the negative cache, in either direction. Digest
// existence can appear at any moment -- somebody is pushing it -- and caching
// that absence breaks a push followed by a pull through a group.
func TestNegativeCacheNeverCoversDigests(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := negativeTarget(env)
	absent := env.fixture.MissingDigest

	for i := range 3 {
		if _, err := env.filler.Manifest(fillCtx(), target, absent); !errors.Is(err, proxy.ErrNotFound) {
			t.Fatalf("Manifest %d = %v, want ErrNotFound", i, err)
		}
		if _, err := env.filler.Blob(fillCtx(), target, absent); !errors.Is(err, proxy.ErrNotFound) {
			t.Fatalf("Blob %d = %v, want ErrNotFound", i, err)
		}
	}

	if _, err := env.meta.GetNegativeEntry(fillCtx(), target.Repository,
		absent.String()); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetNegativeEntry = %v, want no digest ever recorded", err)
	}

	// And a record that names a digest -- however it got there -- does not
	// answer a digest request, because that path never reads this table.
	if err := env.meta.PutNegativeEntry(fillCtx(), meta.NegativeEntry{
		Repository: target.Repository, Reference: absent.String(),
		ObservedAt: testTime, TTL: negativeTTL,
	}); err != nil {
		t.Fatalf("PutNegativeEntry: %v", err)
	}
	if _, err := env.filler.Manifest(fillCtx(), target, env.fixture.Manifest.Digest); err != nil {
		t.Errorf("Manifest for cached content: %v, want the digest path unaffected", err)
	}
}

// The store failures, and which of them a pull survives. A record that cannot
// be written costs an upstream request; a record that cannot be read is a store
// that must not be worked around by asking the upstream harder.
func TestNegativeCacheStoreFailures(t *testing.T) {
	t.Parallel()

	t.Run("the record cannot be written", func(t *testing.T) {
		t.Parallel()

		env := newFillEnvOverFake(t, 0, false)
		target := negativeTarget(env)
		filler, err := proxy.NewFiller(proxy.FillerOptions{
			Blobs: env.blobs,
			Meta:  &fillBrokenCache{CacheStore: env.meta, writes: errors.New("disk full")},
			Now:   env.clock.Now,
		})
		if err != nil {
			t.Fatalf("NewFiller: %v", err)
		}
		if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.MissingTag); !errors.Is(err, proxy.ErrNotFound) {
			t.Errorf("ResolveTag = %v, want the upstream's answer regardless", err)
		}
	})

	t.Run("the record cannot be read", func(t *testing.T) {
		t.Parallel()

		env := newFillEnvOverFake(t, 0, false)
		target := negativeTarget(env)
		filler, err := proxy.NewFiller(proxy.FillerOptions{
			Blobs: env.blobs,
			Meta:  &fillBrokenNegativeCache{CacheStore: env.meta, reads: errors.New("connection reset")},
			Now:   env.clock.Now,
		})
		if err != nil {
			t.Fatalf("NewFiller: %v", err)
		}
		if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err == nil {
			t.Error("ResolveTag with an unreadable negative cache succeeded, want the failure surfaced")
		}
	})

	t.Run("the record cannot be cleared", func(t *testing.T) {
		t.Parallel()

		env := newFillEnvOverFake(t, 0, false)
		target := negativeTarget(env)
		if err := env.meta.PutNegativeEntry(fillCtx(), meta.NegativeEntry{
			Repository: target.Repository, Reference: env.fixture.Tag,
			ObservedAt: testTime, TTL: negativeTTL,
		}); err != nil {
			t.Fatalf("PutNegativeEntry: %v", err)
		}

		filler, err := proxy.NewFiller(proxy.FillerOptions{
			Blobs: env.blobs,
			Meta:  &fillBrokenCache{CacheStore: env.meta, deletes: errors.New("read-only transaction")},
			Now:   env.clock.Now,
		})
		if err != nil {
			t.Fatalf("NewFiller: %v", err)
		}
		env.clock.advance(negativeTTL + time.Second)
		if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err != nil {
			t.Errorf("ResolveTag = %v, want the resolution to survive an uncleared record", err)
		}
	})
}

// fillBrokenNegativeCache fails only the negative-cache read, so a test can
// separate that failure from the lease read that precedes it.
type fillBrokenNegativeCache struct {
	proxy.CacheStore

	reads error
}

func (c *fillBrokenNegativeCache) GetNegativeEntry(ctx context.Context, repo, reference string) (meta.NegativeEntry, error) {
	if c.reads != nil {
		return meta.NegativeEntry{}, c.reads
	}
	return c.CacheStore.GetNegativeEntry(ctx, repo, reference)
}
