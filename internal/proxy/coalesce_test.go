package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// C-006: single-flight. Fifty pods starting at once must cost the upstream one
// resolution and one fetch, not fifty of each.
//
// The concurrency here is deterministic rather than hopeful: the first caller
// is blocked inside the upstream client before any other caller is started, so
// every one of them is guaranteed to join a flight that is still in progress. A
// test that raced fifty goroutines and asserted "one call" would pass most of
// the time and fail on a slow machine, which is the shape of flake this
// project deletes rather than retries.

const coalesceWaiters = 50

// fillBlockingClient signals when its first upstream call starts and then waits
// to be released, so a test can be certain other callers arrive mid-flight.
type fillBlockingClient struct {
	proxy.Client

	started chan struct{}
	release chan struct{}
	err     error

	mu        sync.Mutex
	manifests int
	resolves  int
	once      sync.Once
}

func newBlockingClient(inner proxy.Client, err error) *fillBlockingClient {
	return &fillBlockingClient{
		Client:  inner,
		started: make(chan struct{}),
		release: make(chan struct{}),
		err:     err,
	}
}

func (c *fillBlockingClient) block() {
	c.once.Do(func() { close(c.started) })
	<-c.release
}

func (c *fillBlockingClient) counts() (manifests, resolves int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.manifests, c.resolves
}

func (c *fillBlockingClient) FetchManifest(ctx context.Context, repo string, d blob.Digest) ([]byte, string, error) {
	c.mu.Lock()
	c.manifests++
	c.mu.Unlock()

	c.block()
	if c.err != nil {
		return nil, "", c.err
	}
	return c.Client.FetchManifest(ctx, repo, d)
}

func (c *fillBlockingClient) ResolveTag(ctx context.Context, repo, tag string, cond proxy.Conditional) (proxy.Resolution, error) {
	c.mu.Lock()
	c.resolves++
	c.mu.Unlock()

	c.block()
	if c.err != nil {
		return proxy.Resolution{}, c.err
	}
	return c.Client.ResolveTag(ctx, repo, tag, cond)
}

// coalesceEnv wires a filler to an upstream that can be held mid-call.
func coalesceEnv(t *testing.T, err error) (*fillEnv, *fillBlockingClient) {
	t.Helper()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	blocking := newBlockingClient(mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow}), err)
	env := newFillEnv(t, blocking, seed)
	return env, blocking
}

// waitForFlight starts one caller, waits until it is inside the upstream call,
// and returns its result channel. Every caller started afterwards is certain to
// join the flight rather than begin one.
func waitForFlight[T any](t *testing.T, blocking *fillBlockingClient, call func() (T, error)) <-chan result[T] {
	t.Helper()

	out := make(chan result[T], 1)
	go func() {
		value, err := call()
		out <- result[T]{value: value, err: err}
	}()
	<-blocking.started
	return out
}

type result[T any] struct {
	value T
	err   error
}

func TestCoalesceManifestFetchesOnce(t *testing.T) {
	t.Parallel()

	env, blocking := coalesceEnv(t, nil)
	want := env.fixture.Manifest

	leader := waitForFlight(t, blocking, func() (proxy.ManifestResult, error) {
		return env.filler.Manifest(fillCtx(), env.target, want.Digest)
	})

	results := make([]result[proxy.ManifestResult], coalesceWaiters)
	var wg, ready sync.WaitGroup
	ready.Add(coalesceWaiters)
	for i := range coalesceWaiters {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ready.Done()
			value, err := env.filler.Manifest(fillCtx(), env.target, want.Digest)
			results[i] = result[proxy.ManifestResult]{value: value, err: err}
		}(i)
	}

	ready.Wait()
	close(blocking.release)
	wg.Wait()
	first := <-leader

	if first.err != nil {
		t.Fatalf("the leading fetch: %v", first.err)
	}
	for i, got := range results {
		switch {
		case got.err != nil:
			t.Errorf("waiter %d: %v", i, got.err)
		case !bytes.Equal(got.value.Payload, want.Bytes):
			t.Errorf("waiter %d received %d bytes, want the manifest's %d",
				i, len(got.value.Payload), len(want.Bytes))
		}
	}

	if manifests, _ := blocking.counts(); manifests != 1 {
		t.Errorf("upstream manifest fetches = %d, want exactly 1 for %d concurrent pulls",
			manifests, coalesceWaiters+1)
	}

	// Every caller owns its bytes. Handing fifty goroutines one slice would be
	// a data race the moment any of them wrote into what it was given.
	if len(results) > 1 && len(results[0].value.Payload) > 0 {
		results[0].value.Payload[0] ^= 0xff
		if bytes.Equal(results[0].value.Payload, results[1].value.Payload) {
			t.Error("two waiters were handed the same buffer")
		}
	}
	cached, err := env.meta.GetCachedManifest(fillCtx(), env.target.Repository, meta.Digest(want.Digest))
	if err != nil {
		t.Fatalf("GetCachedManifest: %v", err)
	}
	if !bytes.Equal(cached.Payload, want.Bytes) {
		t.Error("a caller's edit reached the cached copy")
	}
}

func TestCoalesceResolveTagResolvesOnce(t *testing.T) {
	t.Parallel()

	env, blocking := coalesceEnv(t, nil)
	target := leaseTarget(env)
	want := env.fixture.Manifest.Digest

	leader := waitForFlight(t, blocking, func() (proxy.TagResolution, error) {
		return env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
	})

	results := make([]result[proxy.TagResolution], coalesceWaiters)
	var wg, ready sync.WaitGroup
	ready.Add(coalesceWaiters)
	for i := range coalesceWaiters {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ready.Done()
			value, err := env.filler.ResolveTag(fillCtx(), target, env.fixture.Tag)
			results[i] = result[proxy.TagResolution]{value: value, err: err}
		}(i)
	}

	ready.Wait()
	close(blocking.release)
	wg.Wait()
	if first := <-leader; first.err != nil {
		t.Fatalf("the leading resolution: %v", first.err)
	}

	for i, got := range results {
		switch {
		case got.err != nil:
			t.Errorf("waiter %d: %v", i, got.err)
		case got.value.Digest != want:
			t.Errorf("waiter %d resolved to %q, want %q", i, got.value.Digest, want)
		}
	}

	manifests, resolves := blocking.counts()
	if resolves != 1 {
		t.Errorf("upstream resolutions = %d, want exactly 1 for %d concurrent pulls",
			resolves, coalesceWaiters+1)
	}
	// A cold resolution carries the manifest with it, so the whole flight costs
	// the upstream one request rather than one plus a fetch.
	if manifests != 0 {
		t.Errorf("upstream manifest fetches = %d, want none: the resolution carried it", manifests)
	}
}

// The upstream's failure reaches every waiter, and nothing is cached from it.
func TestCoalesceSharesFailures(t *testing.T) {
	t.Parallel()

	env, blocking := coalesceEnv(t, proxy.ErrUpstreamUnavailable)
	digest := env.fixture.Manifest.Digest

	leader := waitForFlight(t, blocking, func() (proxy.ManifestResult, error) {
		return env.filler.Manifest(fillCtx(), env.target, digest)
	})

	errs := make([]error, coalesceWaiters)
	var wg, ready sync.WaitGroup
	ready.Add(coalesceWaiters)
	for i := range coalesceWaiters {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ready.Done()
			_, errs[i] = env.filler.Manifest(fillCtx(), env.target, digest)
		}(i)
	}

	// Every waiter is running and about to join before the leader is let go.
	// Without this the leader could finish while goroutines were still being
	// scheduled, and each late one would start a flight of its own -- which is
	// correct behaviour after a failure, and would make the count below a
	// measure of the scheduler rather than of the coalescer.
	ready.Wait()
	close(blocking.release)
	wg.Wait()
	if first := <-leader; !errors.Is(first.err, proxy.ErrUpstreamUnavailable) {
		t.Fatalf("the leading fetch = %v, want ErrUpstreamUnavailable", first.err)
	}
	for i, err := range errs {
		if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
			t.Errorf("waiter %d = %v, want ErrUpstreamUnavailable", i, err)
		}
	}
	if _, err := env.meta.GetCachedManifest(fillCtx(), env.target.Repository,
		meta.Digest(digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedManifest = %v, want nothing cached from a failed flight", err)
	}

	// Deliberately no assertion on the number of upstream calls here. A failed
	// flight caches nothing, so a caller that arrives after it ends starts one
	// of its own -- which is the right behaviour, since the alternative is
	// serving one upstream hiccup to everybody who asks for the next minute.
	// The exactly-once count is asserted in the success cases above, where it
	// is the acceptance criterion and is not a measure of the scheduler.
}

// Each caller waits under its own context, and the work under neither. A
// waiter that goes away must not be held by somebody else's fetch, and the
// leader's client disconnecting must not fail the waiters behind it.
func TestCoalesceRespectsEachCallersContext(t *testing.T) {
	t.Parallel()

	t.Run("a waiter can leave", func(t *testing.T) {
		t.Parallel()

		env, blocking := coalesceEnv(t, nil)
		digest := env.fixture.Manifest.Digest

		leader := waitForFlight(t, blocking, func() (proxy.ManifestResult, error) {
			return env.filler.Manifest(fillCtx(), env.target, digest)
		})

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := env.filler.Manifest(cancelled, env.target, digest); !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled waiter = %v, want context.Canceled", err)
		}

		close(blocking.release)
		if first := <-leader; first.err != nil {
			t.Errorf("the leading fetch: %v, want it unaffected by a waiter leaving", first.err)
		}
	})

	t.Run("the leader can leave", func(t *testing.T) {
		t.Parallel()

		env, blocking := coalesceEnv(t, nil)
		digest := env.fixture.Manifest.Digest

		leaderCtx, cancelLeader := context.WithCancel(context.Background())
		leader := waitForFlight(t, blocking, func() (proxy.ManifestResult, error) {
			return env.filler.Manifest(leaderCtx, env.target, digest)
		})

		waiter := make(chan result[proxy.ManifestResult], 1)
		go func() {
			value, err := env.filler.Manifest(fillCtx(), env.target, digest)
			waiter <- result[proxy.ManifestResult]{value: value, err: err}
		}()

		// The leader gives up on its own answer; the fetch it started belongs
		// to the flight, not to it.
		cancelLeader()
		if first := <-leader; !errors.Is(first.err, context.Canceled) {
			t.Errorf("the departing leader = %v, want context.Canceled", first.err)
		}

		close(blocking.release)
		got := <-waiter
		if got.err != nil {
			t.Fatalf("the waiter: %v, want the shared result", got.err)
		}
		if !bytes.Equal(got.value.Payload, env.fixture.Manifest.Bytes) {
			t.Error("the waiter did not receive the manifest")
		}
	})
}

// Different content does not share a flight: the key carries the repository and
// the reference, separated by a byte neither can contain.
func TestCoalesceKeysDoNotCollide(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	counter := &fillCountingClient{Client: mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})}
	env := newFillEnv(t, counter, seed)

	for _, digest := range []blob.Digest{seed.Manifest.Digest, seed.Next.Digest} {
		if _, err := env.filler.Manifest(fillCtx(), env.target, digest); err != nil {
			t.Fatalf("Manifest(%q): %v", digest, err)
		}
	}
	if counter.calls() != 2 {
		t.Errorf("upstream fetches = %d, want one per digest", counter.calls())
	}
}

// The Coalescer is an extension point (ADR 0018), so an implementation that
// returns the wrong type fails the request that hit it rather than the process.
func TestCoalescerReturningTheWrongTypeIsAnError(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	env := newFillEnv(t, &fillStubClient{}, seed)
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs:     env.blobs,
		Meta:      env.meta,
		Coalescer: wrongTypeCoalescer{},
		Now:       env.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	if _, err := filler.Manifest(fillCtx(), env.target, seed.Manifest.Digest); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("Manifest = %v, want ErrUpstreamUnavailable", err)
	}
	if _, err := filler.ResolveTag(fillCtx(), env.target, seed.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
	}
}

// What gets coalesced, and under what key. The concurrency cases above prove
// the behaviour; this proves the wiring, deterministically: a fill that reached
// the upstream without going through the coalescer would still pass those, one
// scheduler in a hundred at a time.
func TestCoalesceKeysNameTheWork(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	env := newFillEnv(t, mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow}), seed)
	recorder := &recordingCoalescer{inner: proxy.NewSingleFlight()}

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: env.blobs, Meta: env.meta, Coalescer: recorder, Now: env.clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	if _, err := filler.ResolveTag(fillCtx(), leaseTarget(env), seed.Tag); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if _, err := filler.Manifest(fillCtx(), env.target, seed.Manifest.Digest); err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	result, err := filler.Blob(fillCtx(), env.target, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if _, err := io.ReadAll(result.Content); err != nil {
		t.Fatalf("reading the fill: %v", err)
	}
	_ = result.Content.Close()

	repo := env.target.Repository
	want := []string{
		"tag\x00" + repo + "\x00" + seed.Tag,
		"manifest\x00" + repo + "\x00" + seed.Manifest.Digest.String(),
	}
	got := recorder.keys()
	if len(got) != len(want) {
		// The blob is the absent one: a stream has a single reader, so there is
		// nothing to share between waiters (C-004 settles concurrent layer
		// fills at the content-addressed store instead).
		t.Fatalf("coalesced %v, want exactly %v", got, want)
	}
	for i, key := range want {
		if got[i] != key {
			t.Errorf("key %d = %q, want %q", i, got[i], key)
		}
	}
}

// recordingCoalescer delegates while remembering what it was asked to share.
type recordingCoalescer struct {
	inner proxy.Coalescer

	mu   sync.Mutex
	seen []string
}

func (c *recordingCoalescer) Do(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, bool, error) {
	c.mu.Lock()
	c.seen = append(c.seen, key)
	c.mu.Unlock()
	return c.inner.Do(ctx, key, fn)
}

func (c *recordingCoalescer) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...)
}

type wrongTypeCoalescer struct{}

func (wrongTypeCoalescer) Do(context.Context, string, func(context.Context) (any, error)) (any, bool, error) {
	return "not a result", false, nil
}

// Blobs are deliberately not coalesced: a stream has one reader, so two
// concurrent pulls of one layer make two upstream fetches and converge at the
// content-addressed store instead (C-004). This pins that as a decision rather
// than an oversight.
func TestCoalesceDoesNotCoverBlobStreams(t *testing.T) {
	t.Parallel()

	env, blocking := coalesceEnv(t, nil)
	layer := env.fixture.Layer

	// Nothing blocks a blob fetch in this client, so both fills run to
	// completion and the store settles them.
	close(blocking.release)

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			result, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
			if err != nil {
				t.Errorf("Blob: %v", err)
				return
			}
			got, err := io.ReadAll(result.Content)
			_ = result.Content.Close()
			if err != nil {
				t.Errorf("reading the fill: %v", err)
				return
			}
			if !bytes.Equal(got, layer.Bytes) {
				t.Error("a concurrent fill served the wrong bytes")
			}
		}()
	}
	wg.Wait()

	if stored := env.storedBlobs(t); len(stored) != 1 {
		t.Errorf("cache holds %v, want the layer once", stored)
	}
}
