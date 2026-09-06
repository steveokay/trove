package metatest

import (
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// The eviction contract (C-013): what the cache costs, what is coldest, and
// what happens when a claim on shared bytes goes away.
//
// It is part of the cached family and never touches a hosted table, which is
// the same wall the rest of that family keeps (ADR 0009) -- the assertions here
// are about the queries eviction runs, not about anything it could reach.

// evictionTests are the cases, registered by cachedTests.
func evictionTests() []suiteCase {
	return []suiteCase{
		{"CachedUsageCountsBothFamilies", testCachedUsageCountsBothFamilies},
		{"ListEvictableIsLeastRecentlyUsedFirst", testListEvictableIsLeastRecentlyUsedFirst},
		{"DeleteCachedBlobCountsRemainingClaims", testDeleteCachedBlobCountsRemainingClaims},
		{"DeleteCachedManifestTakesItsEdges", testDeleteCachedManifestTakesItsEdges},
		{"TouchCachedOnlyMovesForward", testTouchCachedOnlyMovesForward},
		{"TouchCachedValidation", testTouchCachedValidation},
	}
}

// mustPutSizedBlob caches a blob of a given size with a given access time.
func mustPutSizedBlob(t *testing.T, s meta.Store, repo string, d meta.Digest, size int64, at time.Time) {
	t.Helper()

	if err := s.PutCachedBlob(ctx(), meta.CachedBlob{
		Repository: repo, Digest: d, Size: size, CachedAt: testTime, LastAccessAt: at,
	}); err != nil {
		t.Fatalf("PutCachedBlob(%q, %q): %v", repo, d, err)
	}
}

func testCachedUsageCountsBothFamilies(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "quay", meta.Proxy)

	empty, err := s.CachedUsage(ctx(), "")
	if err != nil {
		t.Fatalf("CachedUsage: %v", err)
	}
	if empty.Bytes != 0 || empty.Manifests != 0 || empty.Blobs != 0 {
		// An empty cache is an ordinary state, not an error and not a NULL.
		t.Errorf("usage of an empty cache = %+v, want zeroes", empty)
	}

	mustPutCachedManifest(t, s, "dockerhub/library/nginx", digest("m1"))
	mustPutSizedBlob(t, s, "dockerhub/library/nginx", digest("b1"), 100, testTime)
	mustPutSizedBlob(t, s, "quay/library/nginx", digest("b2"), 250, testTime)

	global, err := s.CachedUsage(ctx(), "")
	if err != nil {
		t.Fatalf("CachedUsage: %v", err)
	}
	switch {
	case global.Blobs != 2 || global.BlobBytes != 350:
		t.Errorf("blob usage = %d rows / %d bytes, want 2 / 350", global.Blobs, global.BlobBytes)
	case global.Manifests != 1 || global.ManifestBytes != 19:
		t.Errorf("manifest usage = %d rows / %d bytes, want 1 / 19", global.Manifests, global.ManifestBytes)
	case global.Bytes != global.ManifestBytes+global.BlobBytes:
		t.Errorf("total = %d, want the two halves to add up", global.Bytes)
	}

	// Per entity, so a carve-out can be accounted for separately.
	scoped, err := s.CachedUsage(ctx(), "quay")
	if err != nil {
		t.Fatalf("CachedUsage(quay): %v", err)
	}
	if scoped.Bytes != 250 || scoped.Manifests != 0 {
		t.Errorf("quay usage = %+v, want only its own blob", scoped)
	}

	// A neighbour whose name merely starts the same way is not in scope: the
	// range is over path segments, not a prefix.
	mustCreateRepo(t, s, "quay2", meta.Proxy)
	mustPutSizedBlob(t, s, "quay2/library/nginx", digest("b3"), 500, testTime)
	if again, err := s.CachedUsage(ctx(), "quay"); err != nil || again.Bytes != 250 {
		t.Errorf("quay usage = %+v (%v), want the neighbour excluded", again, err)
	}
}

func testListEvictableIsLeastRecentlyUsedFirst(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	// Written out of order, so the ordering under test cannot be the insertion
	// one. The manifest is the coldest of the three.
	mustPutSizedBlob(t, s, repo, digest("warm"), 10, testTime.Add(2*time.Hour))
	mustPutSizedBlob(t, s, repo, digest("cool"), 20, testTime.Add(time.Hour))
	cold := cachedManifest(repo, digest("cold"))
	cold.LastAccessAt = testTime
	if err := s.PutCachedManifest(ctx(), cold, nil); err != nil {
		t.Fatalf("PutCachedManifest: %v", err)
	}

	items, err := s.ListEvictable(ctx(), "", 10)
	if err != nil {
		t.Fatalf("ListEvictable: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("items = %+v, want three", items)
	}
	// Manifests and blobs are ranked together: they compete for one budget.
	want := []meta.Digest{digest("cold"), digest("cool"), digest("warm")}
	for i, d := range want {
		if items[i].Digest != d {
			t.Errorf("item %d = %q, want %q", i, items[i].Digest, d)
		}
	}
	if items[0].Kind != meta.CachedManifestKind || items[1].Kind != meta.CachedBlobKind {
		t.Errorf("kinds = %q, %q, want the manifest first", items[0].Kind, items[1].Kind)
	}
	if items[1].Size != 20 {
		t.Errorf("size = %d, want the blob's 20", items[1].Size)
	}
	if !items[0].LastAccessAt.Equal(testTime) {
		t.Errorf("last access = %s, want %s", items[0].LastAccessAt, testTime)
	}

	// The limit bounds the page, and the page is still the coldest end.
	page, err := s.ListEvictable(ctx(), "", 1)
	if err != nil {
		t.Fatalf("ListEvictable(limit 1): %v", err)
	}
	if len(page) != 1 || page[0].Digest != digest("cold") {
		t.Errorf("page = %+v, want just the coldest row", page)
	}
	if none, err := s.ListEvictable(ctx(), "", 0); err != nil || len(none) != 0 {
		t.Errorf("ListEvictable(limit 0) = %+v (%v), want nothing", none, err)
	}

	// Scoped to an entity that has nothing cached: an empty page, not
	// everybody else's rows.
	mustCreateRepo(t, s, "quay", meta.Proxy)
	if other, err := s.ListEvictable(ctx(), "quay", 10); err != nil || len(other) != 0 {
		t.Errorf("ListEvictable(quay) = %+v (%v), want nothing", other, err)
	}
}

// Cached bytes are content-addressed and stored once, so two proxies that
// fetched the same layer hold one copy between them. The count is what tells
// eviction whether the bytes may go.
func testDeleteCachedBlobCountsRemainingClaims(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "quay", meta.Proxy)
	shared := digest("shared-layer")

	mustPutSizedBlob(t, s, "dockerhub/library/nginx", shared, 100, testTime)
	mustPutSizedBlob(t, s, "quay/library/nginx", shared, 100, testTime)

	claims, err := s.CachedBlobClaims(ctx(), shared)
	if err != nil {
		t.Fatalf("CachedBlobClaims: %v", err)
	}
	if claims != 2 {
		t.Fatalf("claims = %d, want 2", claims)
	}

	remaining, err := s.DeleteCachedBlob(ctx(), "dockerhub/library/nginx", shared)
	if err != nil {
		t.Fatalf("DeleteCachedBlob: %v", err)
	}
	if remaining != 1 {
		// Reclaiming the bytes here would break the other proxy's cache.
		t.Errorf("remaining = %d, want the other proxy's claim to survive", remaining)
	}

	remaining, err = s.DeleteCachedBlob(ctx(), "quay/library/nginx", shared)
	if err != nil {
		t.Fatalf("DeleteCachedBlob: %v", err)
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want nothing holding the bytes", remaining)
	}
	if claims, err := s.CachedBlobClaims(ctx(), shared); err != nil || claims != 0 {
		t.Errorf("claims = %d (%v), want none", claims, err)
	}

	_, err = s.DeleteCachedBlob(ctx(), "dockerhub/library/nginx", digest("never-cached"))
	requireErrIs(t, err, meta.ErrNotFound, "DeleteCachedBlob for an uncached digest")
}

func testDeleteCachedManifestTakesItsEdges(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"
	d := digest("evicted-manifest")

	mustPutCachedManifest(t, s, repo, d,
		meta.CachedManifestRef{Child: digest("layer"), Kind: meta.RefLayer})
	// A blob the manifest referenced stays: eviction reclaims rows, and the
	// layer is its own row with its own access time.
	mustPutSizedBlob(t, s, repo, digest("layer"), 10, testTime)

	if err := s.DeleteCachedManifest(ctx(), repo, d); err != nil {
		t.Fatalf("DeleteCachedManifest: %v", err)
	}
	requireErrIs(t, s.DeleteCachedManifest(ctx(), repo, d), meta.ErrNotFound, "DeleteCachedManifest twice")

	if _, err := s.GetCachedManifest(ctx(), repo, d); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedManifest = %v, want it gone", err)
	}
	if _, err := s.ListCachedManifestRefs(ctx(), repo, d); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("ListCachedManifestRefs = %v, want the edges gone with it", err)
	}
	if _, err := s.GetCachedBlob(ctx(), repo, digest("layer")); err != nil {
		t.Errorf("GetCachedBlob = %v, want the layer untouched", err)
	}
}

// The LRU key only ever moves forward, so a flush that arrives late cannot make
// hot content look cold, and an access for content that has since been evicted
// records nothing rather than resurrecting a row.
func testTouchCachedOnlyMovesForward(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"
	later := testTime.Add(3 * time.Hour)

	mustPutCachedManifest(t, s, repo, digest("m"))
	mustPutSizedBlob(t, s, repo, digest("b"), 10, testTime)

	if err := s.TouchCached(ctx(), nil); err != nil {
		t.Errorf("TouchCached(nil) = %v, want an empty batch to be a no-op", err)
	}
	if err := s.TouchCached(ctx(), []meta.CacheAccess{
		{Repository: repo, Digest: digest("b"), Kind: meta.CachedBlobKind, At: later},
		{Repository: repo, Digest: digest("m"), Kind: meta.CachedManifestKind, At: later},
		{Repository: repo, Digest: digest("gone"), Kind: meta.CachedBlobKind, At: later},
	}); err != nil {
		t.Fatalf("TouchCached: %v", err)
	}

	blob, err := s.GetCachedBlob(ctx(), repo, digest("b"))
	if err != nil {
		t.Fatalf("GetCachedBlob: %v", err)
	}
	if !blob.LastAccessAt.Equal(later) {
		t.Errorf("blob last access = %s, want %s", blob.LastAccessAt, later)
	}
	manifest, err := s.GetCachedManifest(ctx(), repo, digest("m"))
	if err != nil {
		t.Fatalf("GetCachedManifest: %v", err)
	}
	if !manifest.LastAccessAt.Equal(later) {
		t.Errorf("manifest last access = %s, want %s", manifest.LastAccessAt, later)
	}
	// The access for content that is not cached recorded nothing.
	if _, err := s.GetCachedBlob(ctx(), repo, digest("gone")); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedBlob = %v, want an access not to create a row", err)
	}

	// An earlier observation is ignored however the batch is ordered.
	if err := s.TouchCached(ctx(), []meta.CacheAccess{
		{Repository: repo, Digest: digest("b"), Kind: meta.CachedBlobKind, At: testTime},
	}); err != nil {
		t.Fatalf("TouchCached with a stale observation: %v", err)
	}
	blob, err = s.GetCachedBlob(ctx(), repo, digest("b"))
	if err != nil {
		t.Fatalf("GetCachedBlob: %v", err)
	}
	if !blob.LastAccessAt.Equal(later) {
		t.Errorf("blob last access = %s, want the later time to stand", blob.LastAccessAt)
	}
}

func testTouchCachedValidation(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"
	mustPutSizedBlob(t, s, repo, digest("b"), 10, testTime)

	requireErrIs(t, s.TouchCached(ctx(), []meta.CacheAccess{
		{Repository: repo, Digest: digest("b"), Kind: "invented", At: testTime},
	}), meta.ErrInvalid, "TouchCached with an unknown kind")

	requireErrIs(t, s.TouchCached(ctx(), []meta.CacheAccess{
		{Repository: repo, Kind: meta.CachedBlobKind, At: testTime},
	}), meta.ErrInvalid, "TouchCached without a digest")

	// The whole batch is rejected before anything is written, so a bad record
	// cannot half-apply an otherwise good flush.
	requireErrIs(t, s.TouchCached(ctx(), []meta.CacheAccess{
		{Repository: repo, Digest: digest("b"), Kind: meta.CachedBlobKind, At: testTime.Add(time.Hour)},
		{Repository: repo, Digest: digest("b"), Kind: "invented", At: testTime.Add(time.Hour)},
	}), meta.ErrInvalid, "TouchCached with one bad record")
	blob, err := s.GetCachedBlob(ctx(), repo, digest("b"))
	if err != nil {
		t.Fatalf("GetCachedBlob: %v", err)
	}
	if !blob.LastAccessAt.Equal(testTime) {
		t.Errorf("last access = %s, want the refused batch to have written nothing", blob.LastAccessAt)
	}
}
