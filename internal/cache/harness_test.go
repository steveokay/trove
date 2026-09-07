package cache_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmemory "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
)

// testTime is the instant every fixture is built at. Nothing here reads the
// wall clock: last-access times are values the test chose, so an LRU order is
// asserted rather than raced (§7).
var testTime = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

// discardLogger keeps the sweeps' failure logging out of the test output. The
// failures themselves are asserted through the results, which is where a
// caller sees them.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// captureLogger returns a logger and a reader for everything written to it,
// for the assertions that are about what an operator is told.
func captureLogger() (*slog.Logger, func() string) {
	var mu sync.Mutex
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&syncWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(handler), func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// syncWriter serialises writes from the sweep goroutine and reads from the
// test's.
type syncWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// env is a cache: a metadata store, a cache-rooted blob store, and an event
// recorder. There is no hosted store in it at all -- the separation these
// tests are about is that the evictor is never handed one (ADR 0009 wall 2).
type env struct {
	t      *testing.T
	meta   *metamemory.Store
	blobs  *blobmemory.Store
	events *recorder
}

func newEnv(t *testing.T, proxies ...string) *env {
	t.Helper()

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	for _, name := range proxies {
		if _, err := store.CreateRepository(context.Background(), meta.Repository{
			Name: name, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
		}); err != nil {
			t.Fatalf("CreateRepository(%q): %v", name, err)
		}
	}

	return &env{t: t, meta: store, blobs: blobmemory.New(blobmemory.Options{}), events: &recorder{}}
}

// evictor builds an evictor over the env with a budget and any option
// overrides the test needs.
func (e *env) evictor(budget cache.Budget, tweak ...func(*cache.Options)) *cache.Evictor {
	e.t.Helper()

	opts := cache.Options{
		Meta:   e.meta,
		Blobs:  e.blobs,
		Events: e.events,
		Budget: budget,
		Log:    discardLogger(),
	}
	for _, apply := range tweak {
		apply(&opts)
	}
	evictor, err := cache.New(opts)
	if err != nil {
		e.t.Fatalf("cache.New: %v", err)
	}
	return evictor
}

// putBlob caches a blob: the bytes in the cache store and a row under repo,
// last accessed at the given time.
func (e *env) putBlob(repo, content string, accessed time.Time) blob.Digest {
	e.t.Helper()

	data := []byte(content)
	digest := blob.FromBytes(blob.SHA256, data)
	ctx := context.Background()
	if err := e.blobs.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		e.t.Fatalf("blobs.Put: %v", err)
	}
	if err := e.meta.PutCachedBlob(ctx, meta.CachedBlob{
		Repository: repo, Digest: meta.Digest(digest), Size: int64(len(data)),
		CachedAt: testTime, LastAccessAt: accessed,
	}); err != nil {
		e.t.Fatalf("PutCachedBlob: %v", err)
	}
	return digest
}

// putManifest caches a manifest. Its payload is the row, so nothing is written
// to the blob store -- which is what makes the manifest cases prove that
// eviction does not touch the store when it has no reason to.
func (e *env) putManifest(repo, content string, accessed time.Time) blob.Digest {
	e.t.Helper()

	payload := []byte(content)
	digest := blob.FromBytes(blob.SHA256, payload)
	if err := e.meta.PutCachedManifest(context.Background(), meta.CachedManifest{
		Repository: repo, Digest: meta.Digest(digest), MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload: payload, Size: int64(len(payload)), CachedAt: testTime, LastAccessAt: accessed,
	}, nil); err != nil {
		e.t.Fatalf("PutCachedManifest: %v", err)
	}
	return digest
}

// usage reports what the cache holds under an entity ("" for all of it).
func (e *env) usage(entity string) meta.CacheUsage {
	e.t.Helper()

	usage, err := e.meta.CachedUsage(context.Background(), entity)
	if err != nil {
		e.t.Fatalf("CachedUsage(%q): %v", entity, err)
	}
	return usage
}

// hasBlobRow reports whether a proxy still claims a cached blob.
func (e *env) hasBlobRow(repo string, digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.meta.GetCachedBlob(context.Background(), repo, meta.Digest(digest))
	return err == nil
}

// hasManifestRow reports whether a cached manifest is still recorded.
func (e *env) hasManifestRow(repo string, digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.meta.GetCachedManifest(context.Background(), repo, meta.Digest(digest))
	return err == nil
}

// hasBytes reports whether the cache store still holds a blob's bytes.
func (e *env) hasBytes(digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.blobs.Stat(context.Background(), digest)
	return err == nil
}

// storedBlobs counts what the cache blob store holds.
func (e *env) storedBlobs() int {
	e.t.Helper()

	var count int
	if err := e.blobs.Walk(context.Background(), func(blob.Descriptor) error {
		count++
		return nil
	}); err != nil {
		e.t.Fatalf("Walk: %v", err)
	}
	return count
}

// recorder collects published events.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Publish(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) all() []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event.Event(nil), r.events...)
}

// evictedPayloads returns the cache.evicted payloads, failing on any other
// event type: this package publishes one type, and publishing an
// artifact.deleted from an eviction path would be exactly the confusion the
// separate event types exist to prevent (ADR 0009).
func (r *recorder) evictedPayloads(t *testing.T) []event.CacheEvictedPayload {
	t.Helper()

	var out []event.CacheEvictedPayload
	for _, e := range r.all() {
		if e.Type != event.CacheEvicted {
			t.Fatalf("published %q; the cache may only publish %q", e.Type, event.CacheEvicted)
		}
		payload, ok := e.Payload.(event.CacheEvictedPayload)
		if !ok {
			t.Fatalf("payload is %T, want event.CacheEvictedPayload", e.Payload)
		}
		out = append(out, payload)
	}
	return out
}

// stubStore wraps a cache.Store so a test can fail one method at one moment.
// Every field left nil delegates, so a test names only the failure it is about.
type stubStore struct {
	inner cache.Store

	usage    func(ctx context.Context, entity string) (meta.CacheUsage, error)
	list     func(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error)
	delMan   func(ctx context.Context, repo string, digest meta.Digest) error
	delBlob  func(ctx context.Context, repo string, digest meta.Digest) (int64, error)
	claims   func(ctx context.Context, digest meta.Digest) (int64, error)
	calls    sync.Map
	callsMu  sync.Mutex
	callList []string
}

func (s *stubStore) note(method string) {
	s.calls.Store(method, true)
	s.callsMu.Lock()
	defer s.callsMu.Unlock()
	s.callList = append(s.callList, method)
}

func (s *stubStore) called(method string) bool {
	_, ok := s.calls.Load(method)
	return ok
}

func (s *stubStore) CachedUsage(ctx context.Context, entity string) (meta.CacheUsage, error) {
	s.note("CachedUsage")
	if s.usage != nil {
		return s.usage(ctx, entity)
	}
	return s.inner.CachedUsage(ctx, entity)
}

func (s *stubStore) ListEvictable(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error) {
	s.note("ListEvictable")
	if s.list != nil {
		return s.list(ctx, entity, limit)
	}
	return s.inner.ListEvictable(ctx, entity, limit)
}

func (s *stubStore) DeleteCachedManifest(ctx context.Context, repo string, digest meta.Digest) error {
	s.note("DeleteCachedManifest")
	if s.delMan != nil {
		return s.delMan(ctx, repo, digest)
	}
	return s.inner.DeleteCachedManifest(ctx, repo, digest)
}

func (s *stubStore) DeleteCachedBlob(ctx context.Context, repo string, digest meta.Digest) (int64, error) {
	s.note("DeleteCachedBlob")
	if s.delBlob != nil {
		return s.delBlob(ctx, repo, digest)
	}
	return s.inner.DeleteCachedBlob(ctx, repo, digest)
}

func (s *stubStore) CachedBlobClaims(ctx context.Context, digest meta.Digest) (int64, error) {
	s.note("CachedBlobClaims")
	if s.claims != nil {
		return s.claims(ctx, digest)
	}
	return s.inner.CachedBlobClaims(ctx, digest)
}

// stubBlobs wraps a cache.BlobStore the same way.
type stubBlobs struct {
	inner cache.BlobStore

	del  func(ctx context.Context, digest blob.Digest) error
	walk func(ctx context.Context, fn func(blob.Descriptor) error) error

	mu      sync.Mutex
	deleted []blob.Digest
}

func (s *stubBlobs) Delete(ctx context.Context, digest blob.Digest) error {
	s.mu.Lock()
	s.deleted = append(s.deleted, digest)
	s.mu.Unlock()
	if s.del != nil {
		return s.del(ctx, digest)
	}
	return s.inner.Delete(ctx, digest)
}

func (s *stubBlobs) Walk(ctx context.Context, fn func(blob.Descriptor) error) error {
	if s.walk != nil {
		return s.walk(ctx, fn)
	}
	return s.inner.Walk(ctx, fn)
}

func (s *stubBlobs) deletions() []blob.Digest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]blob.Digest(nil), s.deleted...)
}

// errFailed is the failure a stub returns when the test only cares that it
// failed.
var errFailed = fmt.Errorf("store is not answering")
