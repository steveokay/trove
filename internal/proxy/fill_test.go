package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmemory "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// C-004: fetch-and-cache by digest. The cases below are about what ends up in
// the cache and what does not, which is the only question this task answers --
// tags, TTLs, and revalidation are C-005's and nothing here knows about them.

const fillEntity = "dockerhub"

// fillEnv is a filler wired to in-memory stores, with the proxy entity its
// writes require already created.
type fillEnv struct {
	filler  *proxy.Filler
	meta    *metamemory.Store
	blobs   *blobmemory.Store
	events  *fillEvents
	clock   *fillClock
	target  proxy.Target
	fixture clienttest.Fixture
}

// fillClock is an injected clock a test can move. Lease expiry is a function of
// time, so C-005's cases advance it rather than sleeping: a test that waited
// out a fifteen-minute TTL would be a test nobody runs.
type fillClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFillClock() *fillClock { return &fillClock{now: testTime} }

func (c *fillClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fillClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newFillEnv(t *testing.T, client proxy.Client, seed clienttest.Fixture) *fillEnv {
	t.Helper()

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: fillEntity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	blobs := blobmemory.New(blobmemory.Options{})
	events := &fillEvents{}
	clock := newFillClock()
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobs, Meta: store, Events: events, Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	return &fillEnv{
		filler: filler,
		meta:   store,
		blobs:  blobs,
		events: events,
		clock:  clock,
		target: proxy.Target{
			Repository: fillEntity + "/" + seed.Repository,
			Upstream:   seed.Repository,
			Remote:     "fake.example",
			Client:     client,
		},
		fixture: seed,
	}
}

// newFillEnvOverFake starts the fake upstream and wires a filler to a real
// client against it. The fake is contract-equivalent to registry:2 (C-002), so
// a fill proven here is a fill against a real registry.
func newFillEnvOverFake(t *testing.T, fault clienttest.Fault, faulty bool) *fillEnv {
	t.Helper()

	seed := clienttest.DefaultFixture()
	var server *upstream
	if faulty {
		server = newFaultyUpstream(t, seed, fault)
	} else {
		server = newUpstream(t, seed)
	}
	counter := &fillCountingClient{
		Client: mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow}),
	}
	env := newFillEnv(t, counter, seed)
	env.target.Client = counter
	return env
}

// upstreamCalls reports how many upstream fetches the target's client made.
func (e *fillEnv) upstreamCalls() int {
	if counter, ok := e.target.Client.(*fillCountingClient); ok {
		return counter.calls()
	}
	return 0
}

// storedBlobs returns the digests the cache blob store holds.
func (e *fillEnv) storedBlobs(t *testing.T) []blob.Digest {
	t.Helper()

	var digests []blob.Digest
	if err := e.blobs.Walk(context.Background(), func(d blob.Descriptor) error {
		digests = append(digests, d.Digest)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return digests
}

// fillEvents records what the filler published.
type fillEvents struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *fillEvents) Publish(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *fillEvents) ofType(t event.Type) []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []event.Event
	for _, e := range r.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// fillCountingClient counts fetches so a cache hit can be proven by the
// upstream request that did not happen.
type fillCountingClient struct {
	proxy.Client

	mu sync.Mutex
	n  int
}

func (c *fillCountingClient) count() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}

func (c *fillCountingClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *fillCountingClient) FetchManifest(ctx context.Context, repo string, d blob.Digest) ([]byte, string, error) {
	c.count()
	return c.Client.FetchManifest(ctx, repo, d)
}

func (c *fillCountingClient) FetchBlob(ctx context.Context, repo string, d blob.Digest) (io.ReadCloser, int64, error) {
	c.count()
	return c.Client.FetchBlob(ctx, repo, d)
}

func fillCtx() context.Context { return context.Background() }

func TestFillManifestCachesThenHits(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	want := env.fixture.Manifest

	got, err := env.filler.Manifest(fillCtx(), env.target, want.Digest)
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	switch {
	case !bytes.Equal(got.Payload, want.Bytes):
		t.Errorf("payload = %q, want the upstream's bytes", got.Payload)
	case got.MediaType != want.MediaType:
		t.Errorf("media type = %q, want %q", got.MediaType, want.MediaType)
	case got.Hit:
		t.Error("the first fetch reported a cache hit")
	case !got.Cached:
		t.Error("the first fetch did not report the content cached")
	}

	// The row carries what the manifest is, so the referrers API and the
	// scanner can read cached content the same way they read hosted content.
	record, err := env.meta.GetCachedManifest(fillCtx(), env.target.Repository, meta.Digest(want.Digest))
	if err != nil {
		t.Fatalf("GetCachedManifest: %v", err)
	}
	if record.Size != int64(len(want.Bytes)) || record.MediaType != want.MediaType {
		t.Errorf("record = %+v, want the manifest's size and media type", record)
	}
	if !record.CachedAt.Equal(testTime) || !record.LastAccessAt.Equal(testTime) {
		t.Errorf("timestamps = %s/%s, want the injected clock %s",
			record.CachedAt, record.LastAccessAt, testTime)
	}

	// The edges record what the fill brought in: the fixture's config and its
	// one layer, in the order the manifest listed them.
	edges, err := env.meta.ListCachedManifestRefs(fillCtx(), env.target.Repository, meta.Digest(want.Digest))
	if err != nil {
		t.Fatalf("ListCachedManifestRefs: %v", err)
	}
	if len(edges) != 2 || edges[0].Kind != meta.RefConfig || edges[1].Kind != meta.RefLayer {
		t.Fatalf("edges = %+v, want a config edge then a layer edge", edges)
	}
	if edges[1].Child != meta.Digest(env.fixture.Layer.Digest) {
		t.Errorf("layer edge = %q, want %q", edges[1].Child, env.fixture.Layer.Digest)
	}

	filled := env.events.ofType(event.CacheFilled)
	if len(filled) != 1 {
		t.Fatalf("cache.filled events = %d, want 1", len(filled))
	}
	payload, ok := filled[0].Payload.(event.CacheFilledPayload)
	switch {
	case !ok:
		t.Fatalf("payload = %T, want a CacheFilledPayload", filled[0].Payload)
	case payload.Upstream != "fake.example":
		// The remote is named, never its URL: a URL can carry credentials and
		// this payload leaves the process.
		t.Errorf("upstream = %q, want the remote's name", payload.Upstream)
	case payload.Digest != want.Digest.String() || payload.Size != int64(len(want.Bytes)):
		t.Errorf("payload = %+v, want the digest and size that were cached", payload)
	}

	before := env.upstreamCalls()
	again, err := env.filler.Manifest(fillCtx(), env.target, want.Digest)
	if err != nil {
		t.Fatalf("Manifest again: %v", err)
	}
	if !again.Hit || !again.Cached {
		t.Errorf("second fetch = %+v, want a cache hit", again)
	}
	if !bytes.Equal(again.Payload, want.Bytes) {
		t.Errorf("cached payload = %q, want the upstream's bytes", again.Payload)
	}
	if env.upstreamCalls() != before {
		t.Errorf("upstream calls = %d, want no further request after caching", env.upstreamCalls())
	}
	if len(env.events.ofType(event.CacheFilled)) != 1 {
		t.Error("a cache hit published a second cache.filled")
	}
}

// An upstream that mislabels its own content is not one we cache from. This is
// the case that matters most in the whole task: it is what a compromised or
// man-in-the-middled upstream looks like.
func TestFillManifestRejectsAMismatch(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, clienttest.FaultManifestDigestMismatch, true)
	want := env.fixture.Manifest

	_, err := env.filler.Manifest(fillCtx(), env.target, want.Digest)
	if !errors.Is(err, proxy.ErrDigestMismatch) {
		t.Fatalf("Manifest against a lying upstream = %v, want ErrDigestMismatch", err)
	}

	if _, err := env.meta.GetCachedManifest(fillCtx(), env.target.Repository,
		meta.Digest(want.Digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedManifest after a mismatch = %v, want nothing cached", err)
	}
	if len(env.events.ofType(event.CacheFilled)) != 0 {
		t.Error("a mismatch published cache.filled")
	}

	corrupt := env.events.ofType(event.BlobCorrupt)
	if len(corrupt) != 1 {
		t.Fatalf("blob.corrupt events = %d, want 1", len(corrupt))
	}
	payload, ok := corrupt[0].Payload.(event.BlobCorruptPayload)
	switch {
	case !ok:
		t.Fatalf("payload = %T, want a BlobCorruptPayload", corrupt[0].Payload)
	case payload.Source != "upstream":
		// Whose incident this is, is the operator's first question.
		t.Errorf("source = %q, want %q", payload.Source, "upstream")
	case payload.Expected != want.Digest.String():
		t.Errorf("expected = %q, want the digest that was asked for", payload.Expected)
	}
}

// A manifest this registry cannot parse is one it cannot account for, gate, or
// scan. It is refused as an unusable upstream answer rather than cached as an
// opaque blob -- and it is classified as an unavailable upstream, so group
// resolution treats such a member exactly as it treats one that is down.
func TestFillManifestRefusesUnusableContent(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"schemaVersion":1,"name":"library/old","tag":"v1"}`)
	digest := blob.FromBytes(blob.SHA256, payload)
	client := &fillStubClient{manifest: payload, mediaType: "application/vnd.docker.distribution.manifest.v1+prettyjws"}
	env := newFillEnv(t, client, clienttest.DefaultFixture())

	_, err := env.filler.Manifest(fillCtx(), env.target, digest)
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Fatalf("Manifest of an unparseable payload = %v, want ErrUpstreamUnavailable", err)
	}
	if _, err := env.meta.GetCachedManifest(fillCtx(), env.target.Repository,
		meta.Digest(digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedManifest = %v, want nothing cached", err)
	}
}

// A cache that cannot be written is a degraded cache, not a failed pull: the
// bytes are already correct and already in hand.
func TestFillManifestServesWhenTheCacheWriteFails(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(fillCtx(), meta.Repository{
		Name: fillEntity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	events := &fillEvents{}
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs:  blobmemory.New(blobmemory.Options{}),
		Meta:   &fillBrokenCache{CacheStore: store, writes: errors.New("disk full")},
		Events: events,
		Now:    fixedNow,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	target := proxy.Target{
		Repository: fillEntity + "/" + seed.Repository,
		Upstream:   seed.Repository,
		Remote:     "fake.example",
		Client:     client,
	}
	got, err := filler.Manifest(fillCtx(), target, seed.Manifest.Digest)
	if err != nil {
		t.Fatalf("Manifest with an unwritable cache: %v, want it served anyway", err)
	}
	if !bytes.Equal(got.Payload, seed.Manifest.Bytes) {
		t.Errorf("payload = %q, want the upstream's bytes", got.Payload)
	}
	if got.Cached {
		// The flag is what makes the degraded state visible instead of
		// indistinguishable from a successful fill.
		t.Error("Cached = true after the cache write failed")
	}
	if len(events.ofType(event.CacheFilled)) != 0 {
		t.Error("a failed cache write published cache.filled")
	}

	// A read failure is different: it is not something the upstream can make
	// up for, and treating it as a miss would turn a broken metadata store
	// into a stampede against somebody else's registry.
	reads := &fillBrokenCache{CacheStore: store, reads: errors.New("connection reset")}
	failing, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobmemory.New(blobmemory.Options{}), Meta: reads, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}
	if _, err := failing.Manifest(fillCtx(), target, seed.Manifest.Digest); err == nil {
		t.Error("Manifest with an unreadable cache succeeded, want the failure surfaced")
	}
}

func TestFillBlobStreamsAndCaches(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	layer := env.fixture.Layer

	result, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if result.Hit {
		t.Error("the first fetch reported a cache hit")
	}
	if result.Size != int64(len(layer.Bytes)) {
		t.Errorf("size = %d, want %d", result.Size, len(layer.Bytes))
	}

	got, err := io.ReadAll(result.Content)
	if err != nil {
		t.Fatalf("reading the fill: %v", err)
	}
	if err := result.Content.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(got, layer.Bytes) {
		t.Fatalf("read %d bytes, want the layer's %d", len(got), len(layer.Bytes))
	}

	// The bytes landed in the cache store and the row records them.
	stored := env.storedBlobs(t)
	if len(stored) != 1 || stored[0] != layer.Digest {
		t.Fatalf("cache holds %v, want just the layer", stored)
	}
	record, err := env.meta.GetCachedBlob(fillCtx(), env.target.Repository, meta.Digest(layer.Digest))
	if err != nil {
		t.Fatalf("GetCachedBlob: %v", err)
	}
	if record.Size != int64(len(layer.Bytes)) || !record.LastAccessAt.Equal(testTime) {
		t.Errorf("record = %+v, want the layer's size on the injected clock", record)
	}
	if len(env.events.ofType(event.CacheFilled)) != 1 {
		t.Errorf("cache.filled events = %d, want 1", len(env.events.ofType(event.CacheFilled)))
	}

	before := env.upstreamCalls()
	hit, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
	if err != nil {
		t.Fatalf("Blob again: %v", err)
	}
	defer func() { _ = hit.Content.Close() }()
	if !hit.Hit {
		t.Error("the second fetch did not report a cache hit")
	}
	served, err := io.ReadAll(hit.Content)
	if err != nil {
		t.Fatalf("reading the cached blob: %v", err)
	}
	if !bytes.Equal(served, layer.Bytes) {
		t.Error("the cached blob did not serve the layer's bytes")
	}
	if env.upstreamCalls() != before {
		t.Errorf("upstream calls = %d, want no further request after caching", env.upstreamCalls())
	}
}

// The stream ends short on a mismatch (ADR 0007) and nothing is published:
// content that failed verification must not become a cache entry that later
// pulls are served from without ever asking the upstream again.
func TestFillBlobDoesNotCacheContentThatFailedVerification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		fault clienttest.Fault
		// corrupt reports whether the failure is a verification failure, which
		// is the one an operator has to be told about.
		corrupt bool
	}{
		{"corrupt", clienttest.FaultBlobCorrupt, true},
		{"truncated", clienttest.FaultBlobTruncated, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newFillEnvOverFake(t, tc.fault, true)
			layer := env.fixture.Layer

			result, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
			if err != nil {
				t.Fatalf("Blob: %v", err)
			}
			got, err := io.ReadAll(result.Content)
			if err == nil {
				t.Fatal("reading unverifiable content succeeded")
			}
			if len(got) >= len(layer.Bytes) {
				t.Errorf("read %d of %d bytes before failing", len(got), len(layer.Bytes))
			}
			_ = result.Content.Close()

			if stored := env.storedBlobs(t); len(stored) != 0 {
				t.Errorf("cache holds %v, want nothing", stored)
			}
			if _, err := env.meta.GetCachedBlob(fillCtx(), env.target.Repository,
				meta.Digest(layer.Digest)); !errors.Is(err, meta.ErrNotFound) {
				t.Errorf("GetCachedBlob = %v, want no row", err)
			}
			if len(env.events.ofType(event.CacheFilled)) != 0 {
				t.Error("unverifiable content published cache.filled")
			}
			if tc.corrupt && len(env.events.ofType(event.BlobCorrupt)) != 1 {
				t.Error("a mid-stream verification failure published no blob.corrupt")
			}
		})
	}
}

// A client that disconnects halfway leaves no partial blob and no row claiming
// one: the fill is published only when the whole stream verified.
func TestFillBlobAbandonedStreamCachesNothing(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	layer := env.fixture.Layer

	result, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(result.Content, head); err != nil {
		t.Fatalf("reading the first bytes: %v", err)
	}
	if err := result.Content.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if stored := env.storedBlobs(t); len(stored) != 0 {
		t.Errorf("cache holds %v after an abandoned read, want nothing", stored)
	}
	if _, err := env.meta.GetCachedBlob(fillCtx(), env.target.Repository,
		meta.Digest(layer.Digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedBlob = %v, want no row", err)
	}
}

// A row whose bytes are gone is a cache miss, not a failure: cached content is
// recoverable by definition, so the fill simply runs again.
func TestFillBlobRefillsWhenTheBytesAreGone(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	layer := env.fixture.Layer

	first, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if _, err := io.ReadAll(first.Content); err != nil {
		t.Fatalf("reading the fill: %v", err)
	}
	_ = first.Content.Close()

	// Evict the bytes behind the row's back, which is what a partially
	// completed eviction sweep leaves (C-013).
	if err := env.blobs.Delete(fillCtx(), layer.Digest); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	second, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
	if err != nil {
		t.Fatalf("Blob after the bytes were evicted: %v", err)
	}
	if second.Hit {
		t.Error("a row without bytes reported a cache hit")
	}
	got, err := io.ReadAll(second.Content)
	if err != nil {
		t.Fatalf("reading the refill: %v", err)
	}
	_ = second.Content.Close()
	if !bytes.Equal(got, layer.Bytes) {
		t.Error("the refill did not serve the layer's bytes")
	}
	if stored := env.storedBlobs(t); len(stored) != 1 {
		t.Errorf("cache holds %v, want the refilled layer", stored)
	}
}

// Concurrent fills of one digest are safe: the blob store is content-addressed
// so the first commit wins and the rest are identical by definition, and every
// caller still gets the whole layer. Run under the race detector, this is also
// what proves the sessions do not share state.
func TestFillBlobConcurrentFills(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	layer := env.fixture.Layer

	const fillers = 8
	var wg sync.WaitGroup
	errs := make([]error, fillers)
	for i := range fillers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			result, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
			if err != nil {
				errs[i] = err
				return
			}
			got, err := io.ReadAll(result.Content)
			_ = result.Content.Close()
			switch {
			case err != nil:
				errs[i] = err
			case !bytes.Equal(got, layer.Bytes):
				errs[i] = errors.New("served bytes differ from the layer")
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("filler %d: %v", i, err)
		}
	}
	if stored := env.storedBlobs(t); len(stored) != 1 || stored[0] != layer.Digest {
		t.Errorf("cache holds %v, want exactly the layer once", stored)
	}
	if _, err := env.meta.GetCachedBlob(fillCtx(), env.target.Repository,
		meta.Digest(layer.Digest)); err != nil {
		t.Errorf("GetCachedBlob: %v", err)
	}
}

// A cache the filler cannot open a session in serves the content anyway. The
// upstream fetch has already happened and the client is waiting for it.
func TestFillBlobServesWhenTheCacheCannotBeOpened(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(fillCtx(), meta.Repository{
		Name: fillEntity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: &fillBrokenBlobs{
			CacheBlobStore: blobmemory.New(blobmemory.Options{}),
			uploads:        errors.New("read-only filesystem"),
		},
		Meta: store,
		Now:  fixedNow,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	result, err := filler.Blob(fillCtx(), proxy.Target{
		Repository: fillEntity + "/" + seed.Repository,
		Upstream:   seed.Repository,
		Client:     client,
	}, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("Blob with an unwritable cache: %v, want it served anyway", err)
	}
	got, err := io.ReadAll(result.Content)
	if err != nil {
		t.Fatalf("reading the uncached stream: %v", err)
	}
	_ = result.Content.Close()
	if !bytes.Equal(got, seed.Layer.Bytes) {
		t.Error("the uncached stream did not serve the layer's bytes")
	}
	if _, err := store.GetCachedBlob(fillCtx(), fillEntity+"/"+seed.Repository,
		meta.Digest(seed.Layer.Digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedBlob = %v, want no row for content that was never stored", err)
	}
}

func TestNewFillerRequiresACache(t *testing.T) {
	t.Parallel()

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })

	if _, err := proxy.NewFiller(proxy.FillerOptions{Meta: store}); !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("NewFiller without a blob store = %v, want ErrInvalidReference", err)
	}
	if _, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobmemory.New(blobmemory.Options{}),
	}); !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("NewFiller without a metadata store = %v, want ErrInvalidReference", err)
	}

	// Defaults fill in for what is optional: a filler with no event sink and
	// no clock is a working filler, because a deployment that has not wired
	// the event system yet still has to serve pulls.
	if _, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobmemory.New(blobmemory.Options{}), Meta: store,
	}); err != nil {
		t.Errorf("NewFiller with only the required stores: %v", err)
	}
}

func TestFillValidatesItsArguments(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{}, clienttest.DefaultFixture())
	good := env.target
	digest := env.fixture.Layer.Digest

	cases := []struct {
		name   string
		target proxy.Target
		digest blob.Digest
	}{
		{"no repository", proxy.Target{Upstream: "library/nginx", Client: good.Client}, digest},
		{"no upstream", proxy.Target{Repository: good.Repository, Client: good.Client}, digest},
		{"no client", proxy.Target{Repository: good.Repository, Upstream: "library/nginx"}, digest},
		{"unparseable digest", good, "not-a-digest"},
		{"empty digest", good, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := env.filler.Manifest(fillCtx(), tc.target, tc.digest); !errors.Is(err, proxy.ErrInvalidReference) {
				t.Errorf("Manifest = %v, want ErrInvalidReference", err)
			}
			if _, err := env.filler.Blob(fillCtx(), tc.target, tc.digest); !errors.Is(err, proxy.ErrInvalidReference) {
				t.Errorf("Blob = %v, want ErrInvalidReference", err)
			}
		})
	}
}

// A cached write into a repository that is not a proxy is refused by the store,
// which is the wall that keeps cached rows off hosted entities (ADR 0009). The
// filler surfaces the refusal as a degraded fill rather than a failed pull,
// which is the same shape every other cache-write failure takes.
func TestFillRefusesToCacheUnderAHostedEntity(t *testing.T) {
	t.Parallel()

	env := newFillEnvOverFake(t, 0, false)
	if _, err := env.meta.CreateRepository(fillCtx(), meta.Repository{
		Name: "shop", Type: meta.Hosted, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	target := env.target
	target.Repository = "shop/library/nginx"

	got, err := env.filler.Manifest(fillCtx(), target, env.fixture.Manifest.Digest)
	if err != nil {
		t.Fatalf("Manifest into a hosted entity: %v, want it served uncached", err)
	}
	if got.Cached {
		t.Error("Cached = true for a write the store refused")
	}
	if _, err := env.meta.GetCachedManifest(fillCtx(), target.Repository,
		meta.Digest(env.fixture.Manifest.Digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedManifest = %v, want nothing cached under a hosted entity", err)
	}
}

// The edges a fill records cover every shape a manifest can reference: an
// index's children, a referrer's subject, and -- by omission -- a foreign
// layer, whose bytes this registry never holds and therefore never accounts
// for.
func TestFillManifestRecordsEveryEdgeShape(t *testing.T) {
	t.Parallel()

	index := []byte(`{"schemaVersion":2,` +
		`"mediaType":"application/vnd.oci.image.index.v1+json",` +
		`"manifests":[` +
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` +
		"1111111111111111111111111111111111111111111111111111111111111111" + `","size":10},` +
		`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` +
		"2222222222222222222222222222222222222222222222222222222222222222" + `","size":20}]}`)

	sbom := []byte(`{"schemaVersion":2,` +
		`"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
		`"artifactType":"application/vnd.example.sbom",` +
		`"config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:` +
		"3333333333333333333333333333333333333333333333333333333333333333" + `","size":2},` +
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:` +
		"4444444444444444444444444444444444444444444444444444444444444444" + `","size":30},` +
		`{"mediaType":"application/vnd.oci.image.layer.nondistributable.v1.tar","digest":"sha256:` +
		"5555555555555555555555555555555555555555555555555555555555555555" + `","size":40,` +
		`"urls":["https://example.invalid/layer"]}],` +
		`"subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` +
		"6666666666666666666666666666666666666666666666666666666666666666" + `","size":50}}`)

	cases := []struct {
		name      string
		payload   []byte
		mediaType string
		want      []meta.RefKind
	}{
		{
			"index", index, "application/vnd.oci.image.index.v1+json",
			[]meta.RefKind{meta.RefChild, meta.RefChild},
		},
		{
			// The foreign layer contributes no edge: the registry neither
			// stores nor reclaims content it does not hold.
			"referrer", sbom, "application/vnd.oci.image.manifest.v1+json",
			[]meta.RefKind{meta.RefConfig, meta.RefLayer, meta.RefSubject},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			digest := blob.FromBytes(blob.SHA256, tc.payload)
			env := newFillEnv(t, &fillStubClient{manifest: tc.payload, mediaType: tc.mediaType},
				clienttest.DefaultFixture())

			if _, err := env.filler.Manifest(fillCtx(), env.target, digest); err != nil {
				t.Fatalf("Manifest: %v", err)
			}
			edges, err := env.meta.ListCachedManifestRefs(fillCtx(), env.target.Repository, meta.Digest(digest))
			if err != nil {
				t.Fatalf("ListCachedManifestRefs: %v", err)
			}
			if len(edges) != len(tc.want) {
				t.Fatalf("edges = %+v, want %d of them", edges, len(tc.want))
			}
			for i, kind := range tc.want {
				if edges[i].Kind != kind {
					t.Errorf("edge %d kind = %q, want %q", i, edges[i].Kind, kind)
				}
			}

			record, err := env.meta.GetCachedManifest(fillCtx(), env.target.Repository, meta.Digest(digest))
			if err != nil {
				t.Fatalf("GetCachedManifest: %v", err)
			}
			if tc.name == "referrer" && record.Subject == "" {
				// The subject is a column as well as an edge: the referrers
				// API is one indexed query over it (ADR 0006).
				t.Error("the cached row recorded no subject")
			}
		})
	}
}

// An upstream failure on the fetch itself, before any bytes stream, is
// returned as it came: the sentinel set is closed, and a caller classifies a
// fill exactly as it classifies a fetch.
func TestFillBlobSurfacesFetchFailures(t *testing.T) {
	t.Parallel()

	env := newFillEnv(t, &fillStubClient{blobErr: proxy.ErrNotFound}, clienttest.DefaultFixture())
	if _, err := env.filler.Blob(fillCtx(), env.target, env.fixture.Layer.Digest); !errors.Is(err, proxy.ErrNotFound) {
		t.Errorf("Blob = %v, want ErrNotFound", err)
	}
	if len(env.events.ofType(event.BlobCorrupt)) != 0 {
		t.Error("a missing blob published blob.corrupt")
	}

	// An upstream that answers a digest request with something that is not
	// that digest is reported, whether the mismatch surfaces at the fetch or
	// mid-stream.
	mismatch := newFillEnv(t, &fillStubClient{blobErr: proxy.ErrDigestMismatch}, clienttest.DefaultFixture())
	if _, err := mismatch.filler.Blob(fillCtx(), mismatch.target, mismatch.fixture.Layer.Digest); !errors.Is(err, proxy.ErrDigestMismatch) {
		t.Errorf("Blob = %v, want ErrDigestMismatch", err)
	}
	if len(mismatch.events.ofType(event.BlobCorrupt)) != 1 {
		t.Error("a mismatched fetch published no blob.corrupt")
	}
}

// Every way the cache itself can fail, and what the client sees in each: the
// content, every time.
func TestFillBlobDegradesRatherThanFailing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// broken builds the cache stores for this case.
		blobs func(proxy.CacheBlobStore) proxy.CacheBlobStore
		meta  func(proxy.CacheStore) proxy.CacheStore
		// cached reports whether the bytes should end up in the store anyway.
		cached bool
	}{
		{
			name: "the session refuses writes",
			blobs: func(s proxy.CacheBlobStore) proxy.CacheBlobStore {
				return &fillBrokenBlobs{CacheBlobStore: s, writes: errors.New("no space left on device")}
			},
			cached: false,
		},
		{
			name: "the commit fails",
			blobs: func(s proxy.CacheBlobStore) proxy.CacheBlobStore {
				return &fillBrokenBlobs{CacheBlobStore: s, commits: errors.New("rename failed")}
			},
			cached: false,
		},
		{
			// The bytes land and the row does not. They are invisible to this
			// proxy and are reclaimed by the eviction sweep's orphan pass:
			// leaking recoverable bytes is the cheaper of the two failure
			// modes, and it is the one chosen deliberately.
			name: "the row cannot be written",
			meta: func(s proxy.CacheStore) proxy.CacheStore {
				return &fillBrokenCache{CacheStore: s, writes: errors.New("disk full")}
			},
			cached: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			seed := clienttest.DefaultFixture()
			server := newUpstream(t, seed)
			client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

			store := metamemory.New()
			t.Cleanup(func() { _ = store.Close() })
			if _, err := store.CreateRepository(fillCtx(), meta.Repository{
				Name: fillEntity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
			}); err != nil {
				t.Fatalf("CreateRepository: %v", err)
			}

			var blobs proxy.CacheBlobStore = blobmemory.New(blobmemory.Options{})
			inner := blobs
			if tc.blobs != nil {
				blobs = tc.blobs(blobs)
			}
			var cache proxy.CacheStore = store
			if tc.meta != nil {
				cache = tc.meta(cache)
			}

			events := &fillEvents{}
			filler, err := proxy.NewFiller(proxy.FillerOptions{
				Blobs: blobs, Meta: cache, Events: events, Now: fixedNow,
			})
			if err != nil {
				t.Fatalf("NewFiller: %v", err)
			}

			result, err := filler.Blob(fillCtx(), proxy.Target{
				Repository: fillEntity + "/" + seed.Repository,
				Upstream:   seed.Repository,
				Client:     client,
			}, seed.Layer.Digest)
			if err != nil {
				t.Fatalf("Blob: %v, want the content served anyway", err)
			}
			got, err := io.ReadAll(result.Content)
			if err != nil {
				t.Fatalf("reading through a failing cache: %v", err)
			}
			_ = result.Content.Close()
			if !bytes.Equal(got, seed.Layer.Bytes) {
				t.Error("the client did not receive the whole layer")
			}

			if _, err := store.GetCachedBlob(fillCtx(), fillEntity+"/"+seed.Repository,
				meta.Digest(seed.Layer.Digest)); !errors.Is(err, meta.ErrNotFound) {
				t.Errorf("GetCachedBlob = %v, want no row for a failed fill", err)
			}
			if len(events.ofType(event.CacheFilled)) != 0 {
				t.Error("a failed fill published cache.filled")
			}

			_, err = inner.Stat(fillCtx(), seed.Layer.Digest)
			if tc.cached && err != nil {
				t.Errorf("Stat = %v, want the committed bytes present", err)
			}
			if !tc.cached && !errors.Is(err, blob.ErrNotFound) {
				t.Errorf("Stat = %v, want nothing published", err)
			}
		})
	}
}

// Reading the cache can fail in three ways and each has its own answer: a
// broken metadata store fails the pull, unusable bytes refill, and anything
// else the blob store cannot explain fails the pull too.
func TestFillBlobHandlesUnreadableCacheState(t *testing.T) {
	t.Parallel()

	t.Run("the row cannot be read", func(t *testing.T) {
		t.Parallel()

		env := newFillEnvOverFake(t, 0, false)
		filler, err := proxy.NewFiller(proxy.FillerOptions{
			Blobs: env.blobs,
			Meta:  &fillBrokenCache{CacheStore: env.meta, reads: errors.New("connection reset")},
			Now:   fixedNow,
		})
		if err != nil {
			t.Fatalf("NewFiller: %v", err)
		}
		if _, err := filler.Blob(fillCtx(), env.target, env.fixture.Layer.Digest); err == nil {
			t.Error("Blob with an unreadable cache succeeded, want the failure surfaced")
		}
	})

	t.Run("the cached bytes no longer verify", func(t *testing.T) {
		t.Parallel()

		env := newFillEnvOverFake(t, 0, false)
		layer := env.fixture.Layer

		first, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
		if err != nil {
			t.Fatalf("Blob: %v", err)
		}
		if _, err := io.ReadAll(first.Content); err != nil {
			t.Fatalf("reading the fill: %v", err)
		}
		_ = first.Content.Close()

		// The store finds the row, opens the bytes, and they are corrupt --
		// which a real driver reports after quarantining them (F-009).
		corrupt, err := proxy.NewFiller(proxy.FillerOptions{
			Blobs: &fillBrokenBlobs{CacheBlobStore: env.blobs, gets: blob.ErrDigestMismatch},
			Meta:  env.meta,
			Now:   fixedNow,
		})
		if err != nil {
			t.Fatalf("NewFiller: %v", err)
		}
		result, err := corrupt.Blob(fillCtx(), env.target, layer.Digest)
		if err != nil {
			t.Fatalf("Blob over corrupt cached bytes: %v, want a refill", err)
		}
		if result.Hit {
			t.Error("corrupt cached bytes reported a cache hit")
		}
		got, err := io.ReadAll(result.Content)
		if err != nil {
			t.Fatalf("reading the refill: %v", err)
		}
		_ = result.Content.Close()
		if !bytes.Equal(got, layer.Bytes) {
			t.Error("the refill did not serve the layer's bytes")
		}
	})

	t.Run("the store fails for another reason", func(t *testing.T) {
		t.Parallel()

		env := newFillEnvOverFake(t, 0, false)
		layer := env.fixture.Layer

		first, err := env.filler.Blob(fillCtx(), env.target, layer.Digest)
		if err != nil {
			t.Fatalf("Blob: %v", err)
		}
		if _, err := io.ReadAll(first.Content); err != nil {
			t.Fatalf("reading the fill: %v", err)
		}
		_ = first.Content.Close()

		broken, err := proxy.NewFiller(proxy.FillerOptions{
			Blobs: &fillBrokenBlobs{CacheBlobStore: env.blobs, gets: errors.New("permission denied")},
			Meta:  env.meta,
			Now:   fixedNow,
		})
		if err != nil {
			t.Fatalf("NewFiller: %v", err)
		}
		if _, err := broken.Blob(fillCtx(), env.target, layer.Digest); err == nil {
			t.Error("Blob over an unreadable cache store succeeded, want the failure surfaced")
		}
	})
}

// A filler with no event sink is a working filler: a deployment that has not
// wired the event system yet still serves pulls, and still refuses content that
// did not verify.
func TestFillWithoutAnEventSink(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newFaultyUpstream(t, seed, clienttest.FaultManifestDigestMismatch)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(fillCtx(), meta.Repository{
		Name: fillEntity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobmemory.New(blobmemory.Options{}), Meta: store, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	_, err = filler.Manifest(fillCtx(), proxy.Target{
		Repository: fillEntity + "/" + seed.Repository,
		Upstream:   seed.Repository,
		Client:     client,
	}, seed.Manifest.Digest)
	if !errors.Is(err, proxy.ErrDigestMismatch) {
		t.Errorf("Manifest against a lying upstream = %v, want ErrDigestMismatch", err)
	}
}

// A session that will not cancel is logged and otherwise ignored. There is
// nothing else to do about it: the client has what it asked for, and an
// abandoned session is reaped later.
func TestFillBlobSurvivesAnUncancellableSession(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(fillCtx(), meta.Repository{
		Name: fillEntity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: &fillBrokenBlobs{
			CacheBlobStore: blobmemory.New(blobmemory.Options{}),
			cancels:        errors.New("directory removed"),
		},
		Meta: store,
		Now:  fixedNow,
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	result, err := filler.Blob(fillCtx(), proxy.Target{
		Repository: fillEntity + "/" + seed.Repository,
		Upstream:   seed.Repository,
		Client:     client,
	}, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(result.Content, head); err != nil {
		t.Fatalf("reading the first bytes: %v", err)
	}
	if err := result.Content.Close(); err != nil {
		t.Errorf("Close = %v, want the cancel failure kept out of the client's way", err)
	}
	if _, err := store.GetCachedBlob(fillCtx(), fillEntity+"/"+seed.Repository,
		meta.Digest(seed.Layer.Digest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedBlob = %v, want no row", err)
	}
}

func TestUnusableContentErrorNamesTheContent(t *testing.T) {
	t.Parallel()

	err := &proxy.UnusableContentError{
		Repository: "library/nginx",
		Digest:     blob.FromBytes(blob.SHA256, []byte("x")),
		Reason:     "schema 1 manifests are not supported",
	}
	message := err.Error()
	switch {
	case !strings.Contains(message, "library/nginx"):
		t.Errorf("message %q does not name the repository", message)
	case !strings.Contains(message, err.Digest.String()):
		t.Errorf("message %q does not name the digest", message)
	case !strings.Contains(message, "schema 1"):
		t.Errorf("message %q does not carry the reason", message)
	}
}

// --- stubs -----------------------------------------------------------------

// fillStubClient answers with fixed content. It is for the cases the fake
// upstream cannot produce, such as a manifest media type this registry does
// not implement.
type fillStubClient struct {
	manifest   []byte
	mediaType  string
	blobErr    error
	resolution proxy.Resolution
	resolveErr error
}

func (c *fillStubClient) ResolveTag(context.Context, string, string, proxy.Conditional) (proxy.Resolution, error) {
	if c.resolveErr != nil {
		return proxy.Resolution{}, c.resolveErr
	}
	if c.resolution.Digest == "" {
		return proxy.Resolution{}, proxy.ErrNotFound
	}
	return c.resolution, nil
}

func (c *fillStubClient) FetchManifest(context.Context, string, blob.Digest) ([]byte, string, error) {
	if c.manifest == nil {
		return nil, "", proxy.ErrNotFound
	}
	return c.manifest, c.mediaType, nil
}

func (c *fillStubClient) FetchBlob(context.Context, string, blob.Digest) (io.ReadCloser, int64, error) {
	if c.blobErr != nil {
		return nil, 0, c.blobErr
	}
	return nil, 0, proxy.ErrNotFound
}

func (c *fillStubClient) RateLimit() proxy.RateLimitState { return proxy.RateLimitState{} }

// fillBrokenCache fails the cached-content reads or writes it is told to.
type fillBrokenCache struct {
	proxy.CacheStore

	reads   error
	writes  error
	deletes error
}

func (c *fillBrokenCache) GetTagLease(ctx context.Context, repo, tag string) (meta.TagLease, error) {
	if c.reads != nil {
		return meta.TagLease{}, c.reads
	}
	return c.CacheStore.GetTagLease(ctx, repo, tag)
}

func (c *fillBrokenCache) PutTagLease(ctx context.Context, lease meta.TagLease) error {
	if c.writes != nil {
		return c.writes
	}
	return c.CacheStore.PutTagLease(ctx, lease)
}

func (c *fillBrokenCache) DeleteTagLease(ctx context.Context, repo, tag string) error {
	if c.deletes != nil {
		return c.deletes
	}
	return c.CacheStore.DeleteTagLease(ctx, repo, tag)
}

func (c *fillBrokenCache) GetCachedManifest(ctx context.Context, repo string, d meta.Digest) (meta.CachedManifest, error) {
	if c.reads != nil {
		return meta.CachedManifest{}, c.reads
	}
	return c.CacheStore.GetCachedManifest(ctx, repo, d)
}

func (c *fillBrokenCache) PutCachedManifest(ctx context.Context, m meta.CachedManifest, refs []meta.CachedManifestRef) error {
	if c.writes != nil {
		return c.writes
	}
	return c.CacheStore.PutCachedManifest(ctx, m, refs)
}

func (c *fillBrokenCache) GetCachedBlob(ctx context.Context, repo string, d meta.Digest) (meta.CachedBlob, error) {
	if c.reads != nil {
		return meta.CachedBlob{}, c.reads
	}
	return c.CacheStore.GetCachedBlob(ctx, repo, d)
}

func (c *fillBrokenCache) PutCachedBlob(ctx context.Context, b meta.CachedBlob) error {
	if c.writes != nil {
		return c.writes
	}
	return c.CacheStore.PutCachedBlob(ctx, b)
}

// fillBrokenBlobs fails the cache-store operation it is told to.
type fillBrokenBlobs struct {
	proxy.CacheBlobStore

	uploads error
	writes  error
	commits error
	cancels error
	gets    error
}

func (s *fillBrokenBlobs) CreateUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if s.uploads != nil {
		return nil, s.uploads
	}
	session, err := s.CacheBlobStore.CreateUpload(ctx, id)
	if err != nil || (s.writes == nil && s.commits == nil && s.cancels == nil) {
		return session, err
	}
	return &fillBrokenSession{
		UploadSession: session, writes: s.writes, commits: s.commits, cancels: s.cancels,
	}, nil
}

func (s *fillBrokenBlobs) Get(ctx context.Context, digest blob.Digest) (blob.VerifiedReader, error) {
	if s.gets != nil {
		return nil, s.gets
	}
	return s.CacheBlobStore.Get(ctx, digest)
}

// fillBrokenSession is an upload session that fails where it is told to. It
// stands in for a full disk, which is the failure the fill path has to survive
// without failing anybody's pull.
type fillBrokenSession struct {
	blob.UploadSession

	writes  error
	commits error
	cancels error
}

func (s *fillBrokenSession) Cancel(ctx context.Context) error {
	if s.cancels != nil {
		return s.cancels
	}
	return s.UploadSession.Cancel(ctx)
}

func (s *fillBrokenSession) Write(ctx context.Context, r io.Reader) (int64, error) {
	if s.writes != nil {
		return 0, s.writes
	}
	return s.UploadSession.Write(ctx, r)
}

func (s *fillBrokenSession) Commit(ctx context.Context, expected blob.Digest) (blob.Descriptor, error) {
	if s.commits != nil {
		return blob.Descriptor{}, s.commits
	}
	return s.UploadSession.Commit(ctx, expected)
}
