package proxy_test

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// C-009: rate-limit backoff. Avoiding Docker Hub throttling is a primary reason
// operators deploy a pull-through cache, so being throttled *by* Docker Hub is
// the one failure this subsystem must not make worse.
//
// The schedule is tested with the jitter injected away, because a delay drawn
// from a random range cannot be asserted and a schedule nobody can assert is
// one that drifts. The default jitter is covered separately, by its bounds.

// noJitter keeps a computed delay whole, so the curve is the thing under test.
func noJitter(d time.Duration) time.Duration { return d }

const backoffEntity = "dockerhub"

func TestBackoffCurve(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// retryAfter is what each successive refusal carried, one per attempt.
		retryAfter []time.Duration
		want       []time.Duration
		jitter     func(time.Duration) time.Duration
	}{
		{
			// Nothing to honour, so the exponential is the whole schedule:
			// 1s, 2s, 4s, 8s, capped at the maximum.
			name:       "exponential when the upstream names no deadline",
			retryAfter: []time.Duration{0, 0, 0, 0, 0},
			want:       []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second},
		},
		{
			// The upstream is the only party that knows when its window rolls
			// over, so its number wins whenever it is the longer one.
			name:       "the upstream's deadline is honoured when it is longer",
			retryAfter: []time.Duration{6 * time.Second, 3 * time.Second},
			want:       []time.Duration{6 * time.Second, 3 * time.Second},
		},
		{
			// ...and does not shorten a curve that has already climbed past it.
			name:       "the exponential wins when it is longer",
			retryAfter: []time.Duration{0, 0, 0, time.Second},
			want:       []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second},
		},
		{
			// A proxy that goes quiet for six hours is indistinguishable from
			// a broken one; one probe per cap costs the upstream nothing.
			name:       "an absurd deadline is capped",
			retryAfter: []time.Duration{6 * time.Hour},
			want:       []time.Duration{10 * time.Second},
		},
		{
			name:       "jitter shortens the delay it is given",
			retryAfter: []time.Duration{0, 0},
			want:       []time.Duration{500 * time.Millisecond, time.Second},
			jitter:     func(d time.Duration) time.Duration { return d / 2 },
		},
		{
			// A jitter function is injectable, so a hostile one is a case
			// rather than an impossibility: a negative delay would put the
			// deadline in the past and quietly disable the backoff.
			name:       "a negative jitter cannot un-back-off",
			retryAfter: []time.Duration{0},
			want:       []time.Duration{0},
			jitter:     func(time.Duration) time.Duration { return -time.Hour },
		},
		{
			// Penalize is exported, so "the upstream asked for minus an hour"
			// is a call somebody can make. A deadline in the past reads as
			// ready, which would be a backoff that silently does nothing.
			name:       "a negative deadline cannot pull the window into the past",
			retryAfter: []time.Duration{-time.Hour},
			want:       []time.Duration{0},
			jitter:     func(time.Duration) time.Duration { return -time.Minute },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			jitter := tc.jitter
			if jitter == nil {
				jitter = noJitter
			}
			backoff := proxy.NewBackoff(proxy.BackoffOptions{
				Base: time.Second, Max: 10 * time.Second, Jitter: jitter,
			})

			now := testTime
			for i, retryAfter := range tc.retryAfter {
				until := backoff.Penalize(backoffEntity, now, retryAfter)
				if got := until.Sub(now); got != tc.want[i] {
					t.Errorf("refusal %d: delay = %s, want %s", i+1, got, tc.want[i])
				}
			}
		})
	}
}

func TestBackoffReadiness(t *testing.T) {
	t.Parallel()

	backoff := proxy.NewBackoff(proxy.BackoffOptions{
		Base: time.Second, Max: time.Minute, Jitter: noJitter,
	})

	// An upstream nothing is known about is ready: a cache that refused to
	// talk to an upstream it had never met would never fill.
	if ready, until := backoff.Ready("never-seen", testTime); !ready || !until.IsZero() {
		t.Errorf("Ready for an unknown upstream = %v, %s, want ready", ready, until)
	}

	until := backoff.Penalize(backoffEntity, testTime, 30*time.Second)
	if ready, deadline := backoff.Ready(backoffEntity, testTime); ready || !deadline.Equal(until) {
		t.Errorf("Ready during the window = %v, %s, want not ready until %s", ready, deadline, until)
	}
	if ready, _ := backoff.Ready(backoffEntity, until.Add(-time.Nanosecond)); ready {
		t.Error("Ready one instant before the deadline, want not ready")
	}
	// The deadline itself is ready: it is when the upstream said to come back.
	if ready, _ := backoff.Ready(backoffEntity, until); !ready {
		t.Error("not ready at the deadline, want ready")
	}

	// Another upstream is unaffected. The state is per entity because that is
	// the unit a quota and a credential belong to.
	if ready, _ := backoff.Ready("quay", testTime); !ready {
		t.Error("one upstream's throttling reached another")
	}

	// A registry that answered is not one to keep avoiding, and the curve
	// starts over rather than continuing where it left off.
	backoff.Succeed(backoffEntity)
	if ready, _ := backoff.Ready(backoffEntity, testTime); !ready {
		t.Error("not ready after a success")
	}
	if restarted := backoff.Penalize(backoffEntity, testTime, 0); restarted.Sub(testTime) != time.Second {
		t.Errorf("delay after a success = %s, want the curve to restart at 1s", restarted.Sub(testTime))
	}
}

// The default jitter is random, so it is asserted by its bounds: within the
// window it was given, and never past it.
func TestBackoffDefaultJitterStaysInRange(t *testing.T) {
	t.Parallel()

	backoff := proxy.NewBackoff(proxy.BackoffOptions{Base: time.Second, Max: time.Minute})
	for range 32 {
		backoff.Succeed(backoffEntity)
		delay := backoff.Penalize(backoffEntity, testTime, 0).Sub(testTime)
		if delay < 0 || delay >= time.Second {
			t.Fatalf("delay = %s, want it drawn from [0s, 1s)", delay)
		}
	}

	// Zero cannot be jittered into anything else.
	if got := backoff.Penalize("zero", testTime, 0); got.Sub(testTime) < 0 {
		t.Errorf("delay = %s, want it non-negative", got.Sub(testTime))
	}
}

func TestBackoffSnapshot(t *testing.T) {
	t.Parallel()

	backoff := proxy.NewBackoff(proxy.BackoffOptions{
		Base: time.Second, Max: time.Minute, Jitter: noJitter,
	})
	if got := backoff.Snapshot(testTime); len(got) != 0 {
		t.Errorf("Snapshot of an untroubled cache = %+v, want nothing", got)
	}

	backoff.Penalize("quay", testTime, 30*time.Second)
	backoff.Penalize(backoffEntity, testTime, 0)
	backoff.Penalize(backoffEntity, testTime, 0)

	got := backoff.Snapshot(testTime)
	if len(got) != 2 {
		t.Fatalf("Snapshot = %+v, want both upstreams", got)
	}
	// Ordered by entity so a scrape is stable rather than map-ordered.
	if got[0].Entity != backoffEntity || got[1].Entity != "quay" {
		t.Errorf("Snapshot order = %q, %q, want them sorted", got[0].Entity, got[1].Entity)
	}
	if got[0].Failures != 2 || !got[0].Active {
		t.Errorf("state = %+v, want two failures and an active window", got[0])
	}

	// Past the window the record is still there -- an operator asking "what
	// happened" wants it -- but it no longer claims to be holding anything up.
	later := backoff.Snapshot(testTime.Add(time.Hour))
	for _, state := range later {
		if state.Active {
			t.Errorf("state = %+v, want it inactive an hour later", state)
		}
	}
}

// backoffFiller wires a filler with a deterministic backoff over the shared
// environment, so a 429 storm can be counted rather than estimated.
func backoffFiller(t *testing.T, env *fillEnv) *proxy.Filler {
	t.Helper()

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs:  env.blobs,
		Meta:   env.meta,
		Events: env.events,
		Now:    env.clock.Now,
		Backoff: proxy.NewBackoff(proxy.BackoffOptions{
			Base: time.Second, Max: time.Minute, Jitter: noJitter,
		}),
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}
	return filler
}

// The acceptance criterion: a 429 storm produces a bounded upstream call rate.
// Fifty pulls against a throttled upstream cost it one request, not fifty.
func TestBackoffBoundsA429Storm(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, clienttest.FaultRateLimited, true)
	target := negativeTarget(env)
	filler := backoffFiller(t, env)
	counter, ok := env.target.Client.(*fillCountingClient)
	if !ok {
		t.Fatalf("client = %T, want the counting one", env.target.Client)
	}

	if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag); !errors.Is(err, proxy.ErrRateLimited) {
		t.Fatalf("ResolveTag against a throttling upstream = %v, want ErrRateLimited", err)
	}
	if counter.resolutions() != 1 {
		t.Fatalf("upstream resolutions = %d, want 1", counter.resolutions())
	}

	// The fake's Retry-After is twelve seconds; everything inside that window
	// is answered without touching the upstream.
	for i := range 50 {
		if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag); !errors.Is(err, proxy.ErrRateLimited) {
			t.Fatalf("pull %d during the window = %v, want ErrRateLimited", i, err)
		}
	}
	if counter.resolutions() != 1 {
		t.Errorf("upstream resolutions = %d, want the window to have absorbed all fifty", counter.resolutions())
	}

	// Digest fetches are bounded by the same window: the request itself is the
	// harm, so nothing goes out regardless of what is being asked for.
	if _, err := filler.Manifest(fillCtx(), target, env.fixture.Manifest.Digest); !errors.Is(err, proxy.ErrRateLimited) {
		t.Errorf("Manifest during the window = %v, want ErrRateLimited", err)
	}
	if _, err := filler.Blob(fillCtx(), target, env.fixture.Layer.Digest); !errors.Is(err, proxy.ErrRateLimited) {
		t.Errorf("Blob during the window = %v, want ErrRateLimited", err)
	}
	if counter.calls() != 0 {
		t.Errorf("upstream fetches = %d, want none during the window", counter.calls())
	}

	// Past the deadline the upstream is tried again -- one probe, and the
	// window renews from the answer.
	env.clock.advance(13 * time.Second)
	if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag); !errors.Is(err, proxy.ErrRateLimited) {
		t.Fatalf("ResolveTag after the window = %v, want ErrRateLimited", err)
	}
	if counter.resolutions() != 2 {
		t.Errorf("upstream resolutions = %d, want exactly one probe per window", counter.resolutions())
	}
}

// While backing off, the proxy behaves exactly as it does when the upstream is
// unreachable (ADR 0008): cached content is served stale, uncached content
// fails, and strict mode fails both.
func TestBackoffBehavesAsOffline(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})
	env := newFillEnv(t, client, seed)
	target := negativeTarget(env)
	filler := backoffFiller(t, env)

	if _, err := filler.ResolveTag(fillCtx(), target, seed.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}

	// The upstream starts throttling and the lease expires.
	throttled := newFaultyUpstream(t, seed, clienttest.FaultRateLimited)
	target.Client = mustClient(t, proxy.Options{Upstream: throttled.url(), Now: fixedNow})
	env.clock.advance(leaseTTL + time.Minute)

	got, err := filler.ResolveTag(fillCtx(), target, seed.Tag)
	if err != nil {
		t.Fatalf("ResolveTag while throttled: %v, want the cached answer", err)
	}
	if !got.Stale || got.Digest != seed.Manifest.Digest {
		t.Errorf("resolution = %+v, want the leased digest marked stale", got)
	}
	stale := env.events.ofType(event.CacheStaleServed)
	if len(stale) != 1 {
		t.Fatalf("cache.stale-served events = %d, want 1", len(stale))
	}
	if payload, ok := stale[0].Payload.(event.CacheStaleServedPayload); !ok ||
		payload.Reason != string(proxy.CauseRateLimited) {
		t.Errorf("payload = %+v, want reason %q", stale[0].Payload, proxy.CauseRateLimited)
	}

	// The second pull is served from the same lease without a request: the
	// backoff, not the upstream, is what answers now.
	again, err := filler.ResolveTag(fillCtx(), target, seed.Tag)
	if err != nil || !again.Stale {
		t.Errorf("second pull = %+v, %v, want another stale answer", again, err)
	}

	// Uncached content fails, because there is nothing to serve.
	if _, err := filler.ResolveTag(fillCtx(), target, "never-resolved"); !errors.Is(err, proxy.ErrRateLimited) {
		t.Errorf("uncached tag = %v, want ErrRateLimited", err)
	}

	strict := target
	strict.Offline = proxy.Strict
	if _, err := filler.ResolveTag(fillCtx(), strict, seed.Tag); !errors.Is(err, proxy.ErrRateLimited) {
		t.Errorf("strict mode = %v, want ErrRateLimited", err)
	}
}

// A successful call clears the standing, so one 429 in a quiet hour does not
// leave a proxy half-throttled for the next one.
func TestBackoffClearsOnSuccess(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	env := newFillEnv(t, mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow}), seed)
	target := negativeTarget(env)
	backoff := proxy.NewBackoff(proxy.BackoffOptions{
		Base: time.Second, Max: time.Minute, Jitter: noJitter,
	})
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: env.blobs, Meta: env.meta, Events: env.events, Now: env.clock.Now, Backoff: backoff,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	backoff.Penalize(fillEntity, testTime, 30*time.Second)
	if _, err := filler.ResolveTag(fillCtx(), target, seed.Tag); !errors.Is(err, proxy.ErrRateLimited) {
		t.Fatalf("ResolveTag while backing off = %v, want ErrRateLimited", err)
	}

	env.clock.advance(31 * time.Second)
	if _, err := filler.ResolveTag(fillCtx(), target, seed.Tag); err != nil {
		t.Fatalf("ResolveTag after the window: %v", err)
	}
	if got := backoff.Snapshot(env.clock.Now()); len(got) != 0 {
		t.Errorf("Snapshot after a success = %+v, want the standing cleared", got)
	}

	// And the content is really there afterwards, so the recovery is a working
	// proxy rather than merely a cleared flag.
	result, err := filler.Blob(fillCtx(), target, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("Blob after recovery: %v", err)
	}
	if _, err := io.ReadAll(result.Content); err != nil {
		t.Fatalf("reading the fill: %v", err)
	}
	_ = result.Content.Close()
	if _, err := env.meta.GetCachedBlob(fillCtx(), target.Repository,
		meta.Digest(seed.Layer.Digest)); err != nil {
		t.Errorf("GetCachedBlob: %v", err)
	}
}

// Only throttling backs off. An unreachable upstream is retried on the next
// pull: a dial that fails costs nobody anything, and a proxy that stopped
// trying would keep failing for a window after the network came back.
func TestBackoffIgnoresOtherFailures(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{resolveErr: proxy.ErrUpstreamUnavailable}, clienttest.DefaultFixture())
	target := negativeTarget(env)
	backoff := proxy.NewBackoff(proxy.BackoffOptions{
		Base: time.Second, Max: time.Minute, Jitter: noJitter,
	})
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: env.blobs, Meta: env.meta, Events: env.events, Now: env.clock.Now, Backoff: backoff,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	for range 3 {
		if _, err := filler.ResolveTag(fillCtx(), target, env.fixture.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
			t.Fatalf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
		}
	}
	if got := backoff.Snapshot(env.clock.Now()); len(got) != 0 {
		t.Errorf("Snapshot = %+v, want an outage not to back off", got)
	}
}

// Forty refusals in a row must not wrap the exponential into an instant retry.
// The shift is bounded and the result is checked for overflow, so a very long
// streak lands on the cap rather than on a negative delay -- which would read as
// "ready" and turn the worst case into no backoff at all.
func TestBackoffOverflowsIntoTheCap(t *testing.T) {
	t.Parallel()

	// A maximum big enough that the cap can never be what stops the climb: the
	// only thing left to stop it is the overflow guard.
	const century = 100 * 365 * 24 * time.Hour
	backoff := proxy.NewBackoff(proxy.BackoffOptions{
		Base: time.Second, Max: century, Jitter: noJitter,
	})

	var last time.Duration
	for i := range 40 {
		delay := backoff.Penalize(backoffEntity, testTime, 0).Sub(testTime)
		if delay < 0 {
			t.Fatalf("refusal %d: delay = %s, want it never negative", i+1, delay)
		}
		if delay < last {
			t.Fatalf("refusal %d: delay = %s, want it never to shrink (was %s)", i+1, delay, last)
		}
		last = delay
	}
	if last != century {
		t.Errorf("final delay = %s, want the cap %s", last, century)
	}
}
