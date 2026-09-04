package proxy_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// Revalidation is where a proxy's correctness bugs look like caching bugs
// (§4). These are the answers an upstream can give to "has this tag moved",
// including the ones that are not answers at all.

// headHandler answers HEAD one way and GET another, which is how every
// revalidation path is reached deliberately.
func headAndGet(head, get http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			head(w, r)
			return
		}
		get(w, r)
	}
}

func TestConditionalResolveOfAnAbsentTag(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var gets int
	var mu sync.Mutex
	upstream := staticServer(t, headAndGet(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) },
		func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gets++
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		}))
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("ResolveTag = %v, want ErrNotFound", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gets != 0 {
		t.Errorf("a 404 on HEAD was followed by %d GETs: an absent tag is a definitive answer", gets)
	}
}

func TestConditionalResolveOfAnUnreachableUpstream(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	client := mustClient(t, proxy.Options{Upstream: deadUpstream(t), Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
	}
	if _, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("FetchManifest = %v, want ErrUpstreamUnavailable", err)
	}
}

func TestThrottledRevalidationIsNotRetriedWithAGet(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var gets int
	var mu sync.Mutex
	upstream := staticServer(t, headAndGet(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		},
		func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gets++
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if !errors.Is(err, proxy.ErrRateLimited) {
		t.Fatalf("ResolveTag = %v, want ErrRateLimited", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gets != 0 {
		t.Errorf("a throttled HEAD was followed by %d GETs: that is how a 429 becomes a 429 storm", gets)
	}
}

func TestUnauthorizedRevalidationIsNotRetriedWithAGet(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
	}
}

func TestHeadWithoutADigestHeaderFallsThroughToAGet(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, headAndGet(
		func(w http.ResponseWriter, r *http.Request) {
			// A 200 that answers nothing: no digest, no ETag.
			w.Header().Set("Content-Type", seed.Manifest.MediaType)
			w.WriteHeader(http.StatusOK)
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", seed.Manifest.MediaType)
			_, _ = w.Write(seed.Manifest.Bytes)
		}))
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	resolution, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Changed || resolution.Manifest != nil {
		t.Errorf("Changed = %v with %d bytes: the tag did not move", resolution.Changed, len(resolution.Manifest))
	}
}

// TestHeadSettlesWithoutAnETag covers the upstream that answers the question
// but offers no entity tag: the lease is refreshed, and it carries no ETag
// into the next revalidation rather than an invented one.
func TestHeadSettlesWithoutAnETag(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		w.Header().Set("Docker-Content-Digest", seed.Manifest.Digest.String())
		w.WriteHeader(http.StatusOK)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	resolution, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Changed {
		t.Error("Changed = true for a tag that did not move")
	}
	if resolution.ETag != "" {
		t.Errorf("ETag = %q, want empty: the upstream offered none", resolution.ETag)
	}
	if resolution.Digest != seed.Manifest.Digest {
		t.Errorf("Digest = %s, want %s", resolution.Digest, seed.Manifest.Digest)
	}
}

// TestConditionalGetReceivesNotModified is the fallback path's conditional
// half: an upstream that refuses HEAD may still answer If-None-Match.
func TestConditionalGetReceivesNotModified(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	etag := `"` + seed.Manifest.Digest.String() + `"`
	upstream := staticServer(t, headAndGet(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusMethodNotAllowed) },
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-None-Match") != etag {
				t.Errorf("If-None-Match = %q, want %q", r.Header.Get("If-None-Match"), etag)
			}
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
		}))
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	resolution, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest, ETag: etag})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Changed || resolution.Manifest != nil {
		t.Error("a 304 was read as a change")
	}
	if resolution.Digest != seed.Manifest.Digest || resolution.ETag != etag {
		t.Errorf("resolution = %+v, want the lease carried through", resolution)
	}
}

// TestManifestBodyThatEndsEarly is the truncated-manifest case: a body that
// stops short must fail the read rather than parse as a shorter manifest.
func TestManifestBodyThatEndsEarly(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		w.Header().Set("Content-Length", strconv.Itoa(len(seed.Manifest.Bytes)))
		_, _ = w.Write(seed.Manifest.Bytes[:len(seed.Manifest.Bytes)/2])
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest)
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("FetchManifest = %v, want ErrUpstreamUnavailable for a truncated body", err)
	}
}

// rotatingCredentials succeeds once and then fails, which is what a keyfile
// that was replaced under a running process looks like (ADR 0016).
type rotatingCredentials struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (c *rotatingCredentials) Basic(context.Context) (string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls > 1 {
		return "", "", c.err
	}
	return "robot", "hunter2", nil
}

// TestCredentialsThatStopWorking exercises the preemptive-Basic path failing:
// the client remembers that the upstream wants Basic, then cannot produce it.
// The pull must fail rather than quietly continue as anonymous.
func TestCredentialsThatStopWorking(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})

	gone := errors.New("keyfile removed")
	client := mustClient(t, proxy.Options{
		Upstream:    upstream,
		Now:         fixedNow,
		Credentials: &rotatingCredentials{err: gone},
	})

	ctx := context.Background()
	if _, _, err := client.FetchManifest(ctx, seed.Repository, seed.Manifest.Digest); err != nil {
		t.Fatalf("first FetchManifest: %v", err)
	}
	_, _, err := client.FetchManifest(ctx, seed.Repository, seed.Manifest.Digest)
	if !errors.Is(err, proxy.ErrUnauthorized) || !errors.Is(err, gone) {
		t.Errorf("second FetchManifest = %v, want ErrUnauthorized wrapping the credential failure", err)
	}
}

// TestBearerDanceWithUnreadableCredentials is the same failure on the bearer
// path, where the credential is needed to mint a token rather than to sign the
// request.
func TestBearerDanceWithUnreadableCredentials(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	gone := errors.New("keyfile removed")
	client := mustClient(t, proxy.Options{
		Upstream:    upstream,
		Now:         fixedNow,
		Credentials: failingCredentials{err: gone},
	})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) || !errors.Is(err, gone) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized wrapping the credential failure", err)
	}
}

// TestTokenEndpointRejectsConfiguredCredentials is distinct from rejecting an
// anonymous request: the operator set a password and it was refused, which is
// a different line in the log and a different fix.
func TestTokenEndpointRejectsConfiguredCredentials(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{
		Upstream:    upstream,
		Now:         fixedNow,
		Credentials: proxy.StaticCredentials{Username: "robot", Password: "hunter2"},
	})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Fatalf("ResolveTag = %v, want ErrUnauthorized", err)
	}
	var authErr *proxy.AuthError
	if !errors.As(err, &authErr) || !strings.Contains(authErr.Reason, "rejected") {
		t.Errorf("error = %v, want it to say the configured credentials were rejected", err)
	}
}

func TestChallengeWithAnUnparseableRealm(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		// A realm that is not a URL, and so not something to go connecting to
		// on the strength of a header.
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://auth.example.com:notaport/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
	}
}

// TestTokenEndpointThatCannotBeReached is the outage in its other form: the
// registry answers, its authorization server does not.
func TestTokenEndpointThatCannotBeReached(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	// Port 1 on the same host: inside the upstream's family, so the policy
	// allows it, and nothing is listening there.
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+host+`:1/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
	}
}

// TestTokenResponseThatEndsEarly is a token document that stops mid-flight.
func TestTokenResponseThatEndsEarly(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "128")
			_, _ = io.WriteString(w, `{"token":"gra`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag = %v, want ErrUpstreamUnavailable for a truncated token document", err)
	}
}

// TestTokenResponseIsBounded stops a hostile authorization server from
// answering a token request with a body that never ends.
func TestTokenResponseIsBounded(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"`)
			for range 4096 {
				if _, err := io.WriteString(w, strings.Repeat("A", 1024)); err != nil {
					return
				}
			}
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized for an oversized token document", err)
	}
}
