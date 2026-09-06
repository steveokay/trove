package proxy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmemory "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// C-005: the lease. Every case here is about the mapping from a name to a
// digest and when it may be reused -- the content the mapping names is C-004's
// and is cached forever either way.

const leaseTTL = 15 * time.Minute

// leaseTarget is the environment's target with a TTL, since a zero TTL means
// "revalidate on every pull" and would make the freshness cases vacuous.
func leaseTarget(env *fillEnv) proxy.Target {
	target := env.target
	target.TagTTL = leaseTTL
	return target
}

func leaseOf(t *testing.T, env *fillEnv, tag string) meta.TagLease {
	t.Helper()

	lease, err := env.meta.GetTagLease(fillCtx(), env.target.Repository, tag)
	if err != nil {
		t.Fatalf("GetTagLease(%q): %v", tag, err)
	}
	return lease
}

func TestResolveTagFillsThenServesTheLease(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)

	got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	switch {
	case got.Digest != env.fixture.Manifest.Digest:
		t.Errorf("digest = %q, want %q", got.Digest, env.fixture.Manifest.Digest)
	case got.Hit:
		t.Error("a cold resolution reported a cache hit")
	case !got.Revalidated || !got.Changed:
		// A cold resolution has nothing to disagree with, so it is a change by
		// definition; a caller distinguishing "new content" from "same content"
		// must be told that.
		t.Errorf("resolution = %+v, want a revalidated change", got)
	}

	// The manifest the tag named was cached on the way past, so the pull that
	// follows this resolution is a cache hit rather than a second fetch.
	if _, err := env.meta.GetCachedManifest(fillCtx(), target.Repository,
		meta.Digest(env.fixture.Manifest.Digest)); err != nil {
		t.Errorf("GetCachedManifest: %v", err)
	}

	lease := leaseOf(t, env, env.fixture.Tag)
	switch {
	case lease.Digest != meta.Digest(env.fixture.Manifest.Digest):
		t.Errorf("lease digest = %q, want %q", lease.Digest, env.fixture.Manifest.Digest)
	case !lease.FetchedAt.Equal(testTime):
		t.Errorf("lease fetched at %s, want the injected clock %s", lease.FetchedAt, testTime)
	case lease.TTL != leaseTTL:
		t.Errorf("lease ttl = %s, want %s", lease.TTL, leaseTTL)
	case lease.Stale:
		t.Error("a fresh lease was written stale")
	}

	// Inside the TTL the upstream is not asked at all, which is the entire
	// point of the cache.
	before := env.upstreamCalls()
	env.clock.advance(leaseTTL - time.Second)
	hit, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag again: %v", err)
	}
	if !hit.Hit || hit.Revalidated {
		t.Errorf("resolution = %+v, want a lease hit", hit)
	}
	if hit.Digest != env.fixture.Manifest.Digest {
		t.Errorf("digest = %q, want the leased one", hit.Digest)
	}
	if env.upstreamCalls() != before {
		t.Errorf("upstream calls = %d, want none inside the TTL", env.upstreamCalls())
	}
}

// An expired lease is revalidated conditionally. An unchanged tag moves the
// deadline and nothing else: the digest is the same content it always was.
func TestResolveTagRevalidatesUnchanged(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	before := env.upstreamCalls()

	env.clock.advance(leaseTTL + time.Minute)
	got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag after expiry: %v", err)
	}
	switch {
	case got.Hit:
		t.Error("an expired lease reported a cache hit")
	case !got.Revalidated:
		t.Error("an expired lease was not revalidated")
	case got.Changed:
		t.Error("an unchanged tag reported a change")
	case got.Digest != env.fixture.Manifest.Digest:
		t.Errorf("digest = %q, want the unchanged one", got.Digest)
	}
	if env.upstreamCalls() != before {
		// The revalidation goes through ResolveTag, which the counter does not
		// wrap: what it proves here is that no *manifest body* was fetched, and
		// that is the property ADR 0008 asks for.
		t.Errorf("manifest fetches = %d, want none for an unchanged tag", env.upstreamCalls()-before)
	}

	lease := leaseOf(t, env, env.fixture.Tag)
	if !lease.FetchedAt.Equal(testTime.Add(leaseTTL + time.Minute)) {
		t.Errorf("lease fetched at %s, want the revalidation time", lease.FetchedAt)
	}
	if lease.Digest != meta.Digest(env.fixture.Manifest.Digest) {
		t.Errorf("lease digest = %q, want it unchanged", lease.Digest)
	}
}

// The `:latest`-moved scenario, end to end. The new manifest is cached, the
// lease follows it, and the old content stays exactly where it was -- an image
// pinned by digest keeps working, which is why nothing is deleted here.
func TestResolveTagFollowsAMovedTag(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	env := newFillEnv(t, mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow}), seed)
	target := leaseTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, seed.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}

	server.retag(t, seed.Next)
	env.clock.advance(leaseTTL + time.Minute)

	got, err := env.filler.ResolveTag(fillCtx(), target, seed.Tag)
	if err != nil {
		t.Fatalf("ResolveTag after the tag moved: %v", err)
	}
	if !got.Changed || got.Digest != seed.Next.Digest {
		t.Fatalf("resolution = %+v, want a change to %q", got, seed.Next.Digest)
	}

	if _, err := env.meta.GetCachedManifest(fillCtx(), target.Repository,
		meta.Digest(seed.Next.Digest)); err != nil {
		t.Errorf("GetCachedManifest for the new target: %v", err)
	}
	if _, err := env.meta.GetCachedManifest(fillCtx(), target.Repository,
		meta.Digest(seed.Manifest.Digest)); err != nil {
		t.Errorf("GetCachedManifest for the old target: %v, want it still cached", err)
	}

	lease := leaseOf(t, env, seed.Tag)
	if lease.Digest != meta.Digest(seed.Next.Digest) {
		t.Errorf("lease digest = %q, want the tag's new target", lease.Digest)
	}
}

// A zero TTL is a real setting rather than an unset one: revalidate on every
// pull (Q11), which is what an operator running a mutable tag in anger wants.
func TestResolveTagWithAZeroTTLAlwaysRevalidates(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := env.target // TagTTL is zero.

	for i := range 2 {
		got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
		if err != nil {
			t.Fatalf("ResolveTag %d: %v", i, err)
		}
		if got.Hit {
			t.Errorf("resolution %d reported a lease hit under a zero TTL", i)
		}
		if !got.Revalidated {
			t.Errorf("resolution %d did not revalidate", i)
		}
	}
}

// A tag the upstream no longer has takes its lease with it. Keeping the mapping
// is how a proxy outlives the registry it mirrors -- but the manifest it named
// stays cached, because withdrawing a name says nothing about the content.
func TestResolveTagNotFoundDropsTheLease(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)
	gone := env.fixture.MissingTag

	if err := env.meta.PutCachedManifest(fillCtx(), meta.CachedManifest{
		Repository:   target.Repository,
		Digest:       meta.Digest(env.fixture.Manifest.Digest),
		MediaType:    env.fixture.Manifest.MediaType,
		Payload:      env.fixture.Manifest.Bytes,
		Size:         int64(len(env.fixture.Manifest.Bytes)),
		CachedAt:     testTime,
		LastAccessAt: testTime,
	}, nil); err != nil {
		t.Fatalf("PutCachedManifest: %v", err)
	}
	if err := env.meta.PutTagLease(fillCtx(), meta.TagLease{
		Repository: target.Repository,
		Tag:        gone,
		Digest:     meta.Digest(env.fixture.Manifest.Digest),
		FetchedAt:  testTime,
		TTL:        leaseTTL,
	}); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}

	env.clock.advance(leaseTTL + time.Minute)
	if _, err := env.filler.ResolveTag(fillCtx(), target, gone); !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("ResolveTag for a withdrawn tag = %v, want ErrNotFound", err)
	}
	if _, err := env.meta.GetTagLease(fillCtx(), target.Repository, gone); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetTagLease = %v, want the lease dropped", err)
	}
	if _, err := env.meta.GetCachedManifest(fillCtx(), target.Repository,
		meta.Digest(env.fixture.Manifest.Digest)); err != nil {
		t.Errorf("GetCachedManifest = %v, want the content still cached", err)
	}

	// A tag that never had a lease is the same answer, without a delete.
	if _, err := env.filler.ResolveTag(fillCtx(), target, gone); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("ResolveTag for an unknown tag = %v, want ErrNotFound", err)
	}
}

// Degraded mode: an expired lease is served anyway when the upstream cannot be
// reached, marked stale and reported. The alternative is failing every deploy
// in a cluster because somebody else's registry is down.
func TestResolveTagServesStaleWhenTheUpstreamIsUnreachable(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}

	// The upstream goes away after the lease was taken.
	target.Client = mustClient(t, proxy.Options{Upstream: deadUpstream(t), Now: fixedNow})
	env.clock.advance(leaseTTL + 5*time.Minute)

	got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag against a dead upstream: %v, want the stale answer", err)
	}
	switch {
	case !got.Stale:
		t.Error("a served-stale resolution did not say so")
	case got.Digest != env.fixture.Manifest.Digest:
		t.Errorf("digest = %q, want the leased one", got.Digest)
	case got.StaleFor != 5*time.Minute:
		// How far past the deadline is what an operator judges the risk by.
		t.Errorf("stale for %s, want 5m", got.StaleFor)
	}

	stale := env.events.ofType(event.CacheStaleServed)
	if len(stale) != 1 {
		t.Fatalf("cache.stale-served events = %d, want 1", len(stale))
	}
	payload, ok := stale[0].Payload.(event.CacheStaleServedPayload)
	switch {
	case !ok:
		t.Fatalf("payload = %T, want a CacheStaleServedPayload", stale[0].Payload)
	case payload.Reason != "unreachable":
		t.Errorf("reason = %q, want %q", payload.Reason, "unreachable")
	case payload.Reference != env.fixture.Tag:
		t.Errorf("reference = %q, want the tag", payload.Reference)
	case payload.StaleSeconds != 300:
		t.Errorf("stale seconds = %d, want 300", payload.StaleSeconds)
	}

	// The lease is marked but its deadline is not moved: the mapping was never
	// confirmed, and refreshing it here would buy a full TTL of silence before
	// anything tried the upstream again.
	lease := leaseOf(t, env, env.fixture.Tag)
	if !lease.Stale {
		t.Error("the lease was not marked stale")
	}
	if !lease.FetchedAt.Equal(testTime) {
		t.Errorf("lease fetched at %s, want the original %s", lease.FetchedAt, testTime)
	}

	// A second attempt still tries the upstream, and still serves.
	again, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil || !again.Stale {
		t.Errorf("second stale resolution = %+v, %v", again, err)
	}
}

func TestResolveTagStrictModeRefusesToServeStale(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}

	target.Client = mustClient(t, proxy.Options{Upstream: deadUpstream(t), Now: fixedNow})
	target.Offline = proxy.Strict
	env.clock.advance(leaseTTL + time.Minute)

	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag in strict mode = %v, want ErrUpstreamUnavailable", err)
	}
	if len(env.events.ofType(event.CacheStaleServed)) != 0 {
		t.Error("strict mode published cache.stale-served")
	}
	lease := leaseOf(t, env, env.fixture.Tag)
	if lease.Stale {
		t.Error("strict mode marked the lease stale for content it did not serve")
	}
}

// Which failures degraded mode covers, and which it must not. Serving stale
// content through a rejected credential or a refused redirect would replace a
// loud failure with a quiet one.
func TestResolveTagDegradedModeCoversOnlyOutages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		err    error
		reason string
		stale  bool
	}{
		{"unreachable", proxy.ErrUpstreamUnavailable, "unreachable", true},
		{"rate limited", proxy.ErrRateLimited, "rate-limited", true},
		{"unauthorized", proxy.ErrUnauthorized, "", false},
		{"redirect refused", proxy.ErrRedirectRefused, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newFillEnv(t, &fillStubClient{resolveErr: tc.err}, clienttest.DefaultFixture())
			target := leaseTarget(env)
			if err := env.meta.PutTagLease(fillCtx(), meta.TagLease{
				Repository: target.Repository,
				Tag:        env.fixture.Tag,
				Digest:     meta.Digest(env.fixture.Manifest.Digest),
				FetchedAt:  testTime,
				TTL:        leaseTTL,
			}); err != nil {
				t.Fatalf("PutTagLease: %v", err)
			}
			env.clock.advance(leaseTTL + time.Minute)

			got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
			if !tc.stale {
				if !errors.Is(err, tc.err) {
					t.Fatalf("ResolveTag = %v, want %v", err, tc.err)
				}
				if len(env.events.ofType(event.CacheStaleServed)) != 0 {
					t.Error("a failure outside degraded mode published cache.stale-served")
				}
				return
			}

			if err != nil {
				t.Fatalf("ResolveTag: %v, want the stale answer", err)
			}
			if !got.Stale {
				t.Error("the resolution did not report itself stale")
			}
			stale := env.events.ofType(event.CacheStaleServed)
			if len(stale) != 1 {
				t.Fatalf("cache.stale-served events = %d, want 1", len(stale))
			}
			if payload, ok := stale[0].Payload.(event.CacheStaleServedPayload); !ok || payload.Reason != tc.reason {
				t.Errorf("payload = %+v, want reason %q", stale[0].Payload, tc.reason)
			}
		})
	}
}

// With nothing cached there is nothing to serve, so an unreachable upstream is
// a failed pull whatever the mode says.
func TestResolveTagWithNoLeaseFailsWhenTheUpstreamIsDown(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{resolveErr: proxy.ErrUpstreamUnavailable}, clienttest.DefaultFixture())
	target := leaseTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
	}
	if len(env.events.ofType(event.CacheStaleServed)) != 0 {
		t.Error("a cold miss published cache.stale-served")
	}
}

// A resolution that reports a change without carrying the manifest is not one
// this package builds, but the contract has to hold for one that does: the
// caller must be able to serve the new content afterwards.
func TestResolveTagFetchesAChangeThatCarriedNoManifest(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	client := &fillStubClient{
		resolution: proxy.Resolution{
			Changed:   true,
			Digest:    seed.Manifest.Digest,
			MediaType: seed.Manifest.MediaType,
		},
		manifest:  seed.Manifest.Bytes,
		mediaType: seed.Manifest.MediaType,
	}
	env := newFillEnv(t, client, seed)
	target := leaseTarget(env)

	got, err := env.filler.ResolveTag(fillCtx(), target, seed.Tag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if got.Digest != seed.Manifest.Digest || !got.Changed {
		t.Errorf("resolution = %+v, want the changed digest", got)
	}
	if _, err := env.meta.GetCachedManifest(fillCtx(), target.Repository,
		meta.Digest(seed.Manifest.Digest)); err != nil {
		t.Errorf("GetCachedManifest: %v, want the manifest fetched by digest", err)
	}
}

// Unusable content stops the resolution: a lease pointing at a manifest this
// registry refused would resolve to something no pull could then serve.
func TestResolveTagRefusesUnusableContent(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	payload := []byte(`{"schemaVersion":1,"name":"library/old","tag":"v1"}`)
	client := &fillStubClient{
		resolution: proxy.Resolution{
			Changed:   true,
			Digest:    blob.FromBytes(blob.SHA256, payload),
			MediaType: "application/vnd.docker.distribution.manifest.v1+prettyjws",
			Manifest:  payload,
		},
	}
	env := newFillEnv(t, client, seed)
	target := leaseTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, seed.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Fatalf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
	}
	if _, err := env.meta.GetTagLease(fillCtx(), target.Repository, seed.Tag); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetTagLease = %v, want no lease for content that was refused", err)
	}
}

// The store failures, and which of them a pull survives. A lease that cannot be
// written is a cache that revalidates again next time; a lease that cannot be
// read is a store that must not be worked around by asking the upstream harder.
func TestResolveTagSurvivesAnUnwritableLeaseStore(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)

	writes, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: env.blobs,
		Meta:  &fillBrokenCache{CacheStore: env.meta, writes: errors.New("disk full")},
		Now:   env.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}
	got, err := writes.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag with an unwritable store: %v, want it resolved anyway", err)
	}
	if got.Digest != env.fixture.Manifest.Digest {
		t.Errorf("digest = %q, want the upstream's answer", got.Digest)
	}
	if _, err := env.meta.GetTagLease(fillCtx(), target.Repository,
		env.fixture.Tag); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetTagLease = %v, want nothing written", err)
	}

	reads, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: env.blobs,
		Meta:  &fillBrokenCache{CacheStore: env.meta, reads: errors.New("connection reset")},
		Now:   env.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}
	if _, err := reads.ResolveTag(fillCtx(), target, env.fixture.Tag); err == nil {
		t.Error("ResolveTag with an unreadable store succeeded, want the failure surfaced")
	}
}

// A lease that cannot be deleted is logged and left: the pull still fails with
// the upstream's not-found, which is the answer the client needs either way.
func TestResolveTagSurvivesAnUndeletableLease(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := leaseTarget(env)
	gone := env.fixture.MissingTag

	if err := env.meta.PutTagLease(fillCtx(), meta.TagLease{
		Repository: target.Repository,
		Tag:        gone,
		Digest:     meta.Digest(env.fixture.Manifest.Digest),
		FetchedAt:  testTime,
		TTL:        leaseTTL,
	}); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: env.blobs,
		Meta:  &fillBrokenCache{CacheStore: env.meta, deletes: errors.New("read-only transaction")},
		Now:   env.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}
	env.clock.advance(leaseTTL + time.Minute)
	if _, err := filler.ResolveTag(fillCtx(), target, gone); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("ResolveTag = %v, want ErrNotFound", err)
	}
}

// A lease timestamped in the future -- a clock stepped backwards by NTP, or a
// database restored from a machine that was ahead -- is served as zero seconds
// stale rather than as a negative age nobody can read.
func TestResolveTagClampsNegativeStaleness(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{resolveErr: proxy.ErrUpstreamUnavailable}, clienttest.DefaultFixture())
	target := env.target // A zero TTL, so the future timestamp cannot read as fresh.

	if err := env.meta.PutTagLease(fillCtx(), meta.TagLease{
		Repository: target.Repository,
		Tag:        env.fixture.Tag,
		Digest:     meta.Digest(env.fixture.Manifest.Digest),
		FetchedAt:  testTime.Add(time.Hour),
		TTL:        0,
	}); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}

	got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if !got.Stale || got.StaleFor != 0 {
		t.Errorf("resolution = %+v, want stale with zero staleness", got)
	}
	stale := env.events.ofType(event.CacheStaleServed)
	if len(stale) != 1 {
		t.Fatalf("cache.stale-served events = %d, want 1", len(stale))
	}
	if payload, ok := stale[0].Payload.(event.CacheStaleServedPayload); !ok || payload.StaleSeconds != 0 {
		t.Errorf("payload = %+v, want zero stale seconds", stale[0].Payload)
	}
}

func TestResolveTagValidatesItsArguments(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{}, clienttest.DefaultFixture())

	if _, err := env.filler.ResolveTag(fillCtx(), env.target, ""); !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("ResolveTag with no tag = %v, want ErrInvalidReference", err)
	}
	if _, err := env.filler.ResolveTag(fillCtx(), proxy.Target{Upstream: "library/nginx"}, "v1"); !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("ResolveTag with no repository = %v, want ErrInvalidReference", err)
	}
}

// A filler with no event sink still serves stale content; it simply says so to
// nobody.
func TestResolveTagServesStaleWithoutAnEventSink(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{resolveErr: proxy.ErrUpstreamUnavailable}, clienttest.DefaultFixture())
	target := leaseTarget(env)
	if err := env.meta.PutTagLease(fillCtx(), meta.TagLease{
		Repository: target.Repository,
		Tag:        env.fixture.Tag,
		Digest:     meta.Digest(env.fixture.Manifest.Digest),
		FetchedAt:  testTime,
		TTL:        leaseTTL,
	}); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobmemory.New(blobmemory.Options{}), Meta: env.meta, Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}
	env.clock.advance(leaseTTL + time.Minute)

	got, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if !got.Stale {
		t.Error("the resolution did not report itself stale")
	}
}
