package proxy_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// C-008: degraded mode. The classification is driven from errors a real client
// produced against a real (mis)behaving transport rather than from
// hand-constructed error values -- the point of the exercise is that a DNS
// failure and a header timeout can be told apart *after* they have been through
// net/http, which is exactly where the distinction usually gets lost.

// dialerTransport is an http.Transport whose dial always fails in the named
// way. It is how a test blackholes DNS without touching a resolver.
func dialerTransport(t *testing.T, err error) *http.Transport {
	t.Helper()

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, err },
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

// degradedError produces one real client failure of the named kind.
func degradedError(t *testing.T, options proxy.Options) error {
	t.Helper()

	seed := clienttest.DefaultFixture()
	client := mustClient(t, options)
	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if err == nil {
		t.Fatal("ResolveTag succeeded, want a failure to classify")
	}
	return err
}

func TestClassifyFaultMatrix(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()

	cases := []struct {
		name  string
		build func(t *testing.T) error
		want  proxy.DegradedCause
		// degraded is false for failures degraded mode must not cover.
		degraded bool
	}{
		{
			name: "connection refused",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{Upstream: deadUpstream(t), Now: fixedNow})
			},
			want: proxy.CauseUnreachable, degraded: true,
		},
		{
			name: "name does not resolve",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: "https://nowhere.invalid",
					// The acceptance criterion's blackholed DNS, without a
					// resolver in the test's way.
					Transport: dialerTransport(t, &net.DNSError{
						Err: "no such host", Name: "nowhere.invalid", IsNotFound: true,
					}),
					Now: fixedNow,
				})
			},
			want: proxy.CauseUnreachable, degraded: true,
		},
		{
			name: "name resolution times out",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: "https://slow.invalid",
					Transport: dialerTransport(t, &net.DNSError{
						Err: "i/o timeout", Name: "slow.invalid", IsTimeout: true,
					}),
					Now: fixedNow,
				})
			},
			// A resolver that timed out and one that answered "no" are
			// different problems: the first may be worth waiting for.
			want: proxy.CauseTimeout, degraded: true,
		},
		{
			name: "connection reset",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream:  "https://reset.invalid",
					Transport: dialerTransport(t, errors.New("connection reset by peer")),
					Now:       fixedNow,
				})
			},
			want: proxy.CauseUnreachable, degraded: true,
		},
		{
			name: "the connection times out",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: "https://unreachable.invalid",
					// A dial deadline rather than a resolver one: the same
					// answer, reached through the generic net.Error rather
					// than through net.DNSError.
					Transport: dialerTransport(t, &net.OpError{
						Op: "dial", Net: "tcp", Err: dialTimeout{},
					}),
					Now: fixedNow,
				})
			},
			want: proxy.CauseTimeout, degraded: true,
		},
		{
			name: "the upstream never answers",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream:       newFaultyUpstream(t, seed, clienttest.FaultStalledHeaders).url(),
					RequestTimeout: 50 * time.Millisecond,
					Now:            fixedNow,
				})
			},
			want: proxy.CauseTimeout, degraded: true,
		},
		{
			name: "the upstream answers 500",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: newFaultyUpstream(t, seed, clienttest.FaultServerError).url(),
					Now:      fixedNow,
				})
			},
			// Up and unable to help is a different page in the runbook from
			// the network being down.
			want: proxy.CauseUpstreamError, degraded: true,
		},
		{
			name: "the upstream throttles us",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: newFaultyUpstream(t, seed, clienttest.FaultRateLimited).url(),
					Now:      fixedNow,
				})
			},
			want: proxy.CauseRateLimited, degraded: true,
		},
		{
			name: "the upstream rejects our credentials",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: newFaultyUpstream(t, seed, clienttest.FaultBearerTokenRejected).url(),
					Now:      fixedNow,
				})
			},
			// Configuration, not weather. Serving stale through it would
			// replace a loud failure with a quiet one.
			degraded: false,
		},
		{
			name: "the upstream sends us somewhere we will not go",
			build: func(t *testing.T) error {
				return degradedError(t, proxy.Options{
					Upstream: newFaultyUpstream(t, seed, clienttest.FaultRedirectOffHost).url(),
					Now:      fixedNow,
				})
			},
			// An SSRF attempt must never end up behind a stale-content
			// warning.
			degraded: false,
		},
		{
			name: "the upstream does not have it",
			build: func(t *testing.T) error {
				client := mustClient(t, proxy.Options{Upstream: newUpstream(t, seed).url(), Now: fixedNow})
				_, err := client.ResolveTag(context.Background(), seed.Repository, seed.MissingTag, proxy.Conditional{})
				if err == nil {
					t.Fatal("ResolveTag for a missing tag succeeded")
				}
				return err
			},
			degraded: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.build(t)
			cause, degraded := proxy.Classify(err)
			if degraded != tc.degraded {
				t.Fatalf("Classify(%v) degraded = %v, want %v", err, degraded, tc.degraded)
			}
			if degraded && cause != tc.want {
				t.Errorf("Classify(%v) = %q, want %q", err, cause, tc.want)
			}
		})
	}

	if cause, degraded := proxy.Classify(nil); degraded || cause != "" {
		t.Errorf("Classify(nil) = %q, %v, want no cause", cause, degraded)
	}
}

// The acceptance criterion, end to end: with the upstream's name blackholed, a
// cached pull succeeds and says it is stale, an uncached one fails cleanly, and
// strict mode fails both.
func TestDegradedModeWithABlackholedUpstream(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	target := negativeTarget(env)

	if _, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}

	blackholed := mustClient(t, proxy.Options{
		Upstream: "https://nowhere.invalid",
		Transport: dialerTransport(t, &net.DNSError{
			Err: "no such host", Name: "nowhere.invalid", IsNotFound: true,
		}),
		Now: fixedNow,
	})
	target.Client = blackholed
	env.clock.advance(leaseTTL + time.Minute)

	got, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	if err != nil {
		t.Fatalf("ResolveTag against a blackholed upstream: %v, want the cached answer", err)
	}
	if !got.Stale || got.Digest != env.fixture.Manifest.Digest {
		t.Errorf("resolution = %+v, want the leased digest marked stale", got)
	}
	stale := env.events.ofType(event.CacheStaleServed)
	if len(stale) != 1 {
		t.Fatalf("cache.stale-served events = %d, want 1", len(stale))
	}
	if payload, ok := stale[0].Payload.(event.CacheStaleServedPayload); !ok ||
		payload.Reason != string(proxy.CauseUnreachable) {
		t.Errorf("payload = %+v, want reason %q", stale[0].Payload, proxy.CauseUnreachable)
	}

	// Uncached content fails cleanly rather than pretending: there is nothing
	// to serve, and a proxy that invented an answer would be worse than one
	// that admitted the outage.
	if _, err := env.filler.ResolveTag(fillCtx(), target, "never-resolved"); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag for an uncached tag = %v, want ErrUpstreamUnavailable", err)
	}
	if _, err := env.filler.Manifest(fillCtx(), target, env.fixture.Next.Digest); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("Manifest for uncached content = %v, want ErrUpstreamUnavailable", err)
	}

	// The mode is per-call configuration, so switching it is a runtime change
	// with no restart and no cache to invalidate: the same filler, the same
	// lease, a different answer.
	strict := target
	strict.Offline = proxy.Strict
	if _, err := env.filler.ResolveTag(fillCtx(), strict, env.fixture.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag in strict mode = %v, want ErrUpstreamUnavailable", err)
	}
	if len(env.events.ofType(event.CacheStaleServed)) != 1 {
		t.Error("strict mode published a second cache.stale-served")
	}
}

// Degraded mode never invents content. A blob that was never cached fails while
// the upstream is down, whatever the mode says, and the lease that names it is
// untouched by the attempt.
func TestDegradedModeDoesNotCoverUncachedBlobs(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{blobErr: proxy.ErrUpstreamUnavailable}, clienttest.DefaultFixture())
	target := negativeTarget(env)

	if _, err := env.filler.Blob(fillCtx(), target, env.fixture.Layer.Digest); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("Blob = %v, want ErrUpstreamUnavailable", err)
	}
	if len(env.events.ofType(event.CacheStaleServed)) != 0 {
		t.Error("a blob fetch published cache.stale-served")
	}
	if _, err := env.meta.GetNegativeEntry(fillCtx(), target.Repository,
		env.fixture.Layer.Digest.String()); !errors.Is(err, meta.ErrNotFound) {
		t.Error("an outage was recorded as an absence")
	}
}

// dialTimeout is a net.Error that timed out, for the case where the deadline
// was the connection's rather than the resolver's.
type dialTimeout struct{}

func (dialTimeout) Error() string   { return "i/o timeout" }
func (dialTimeout) Timeout() bool   { return true }
func (dialTimeout) Temporary() bool { return true }
