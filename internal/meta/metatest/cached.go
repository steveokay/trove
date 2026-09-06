package metatest

import (
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// The cached-content contract (C-004). It is the other half of the content
// suite and it never touches a hosted method except to prove that the two
// families cannot see each other -- which is the assertion ADR 0009 turns into
// a type-system obligation, checked here at the store level as well because a
// shared table would defeat the types.

// cachedTests are the cached-content cases, kept in their own file for the
// reason the store keeps them in their own interface.
func cachedTests() []suiteCase {
	return []suiteCase{
		{"CachedManifestRoundTrip", testCachedManifestRoundTrip},
		{"CachedManifestEdges", testCachedManifestEdges},
		{"CachedWritesRequireAProxyEntity", testCachedWritesRequireAProxyEntity},
		{"CachedWritesValidate", testCachedWritesValidate},
		{"CachedRefillReplacesAndRefreshes", testCachedRefillReplacesAndRefreshes},
		{"CachedBlobsAreScopedToTheirRepository", testCachedBlobsAreScopedToTheirRepository},
		{"CachedAndHostedContentAreInvisibleToEachOther", testCachedAndHostedContentAreInvisibleToEachOther},
		{"CachedContentDiesWithTheRepository", testCachedContentDiesWithTheRepository},
	}
}

// accessTime is when cached content was last served: after it was fetched, so
// a store that wrote one timestamp into both columns is visible.
var accessTime = testTime.Add(90 * time.Minute)

func cachedManifest(repo string, d meta.Digest) meta.CachedManifest {
	return meta.CachedManifest{
		Repository:   repo,
		Digest:       d,
		MediaType:    "application/vnd.oci.image.manifest.v1+json",
		ArtifactType: "application/vnd.example.sbom",
		Subject:      digest("cached-subject"),
		Payload:      []byte(`{"schemaVersion":2}`),
		Size:         19,
		CachedAt:     testTime,
		LastAccessAt: accessTime,
	}
}

func mustPutCachedManifest(t *testing.T, s meta.Store, repo string, d meta.Digest, refs ...meta.CachedManifestRef) {
	t.Helper()

	if err := s.PutCachedManifest(ctx(), cachedManifest(repo, d), refs); err != nil {
		t.Fatalf("PutCachedManifest(%q, %q): %v", repo, d, err)
	}
}

func mustPutCachedBlob(t *testing.T, s meta.Store, repo string, d meta.Digest) {
	t.Helper()

	if err := s.PutCachedBlob(ctx(), meta.CachedBlob{
		Repository: repo, Digest: d, Size: 512, CachedAt: testTime, LastAccessAt: accessTime,
	}); err != nil {
		t.Fatalf("PutCachedBlob(%q, %q): %v", repo, d, err)
	}
}

func testCachedManifestRoundTrip(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	d := digest("cached-manifest")

	// Content is keyed by the full name and the row it needs is the entity, so
	// the upstream's own namespace comes along untouched.
	mustPutCachedManifest(t, s, "dockerhub/library/nginx", d)

	got, err := s.GetCachedManifest(ctx(), "dockerhub/library/nginx", d)
	if err != nil {
		t.Fatalf("GetCachedManifest: %v", err)
	}
	want := cachedManifest("dockerhub/library/nginx", d)
	switch {
	case got.Digest != want.Digest:
		t.Errorf("digest = %q, want %q", got.Digest, want.Digest)
	case got.MediaType != want.MediaType || got.ArtifactType != want.ArtifactType:
		t.Errorf("media types = %q/%q, want %q/%q",
			got.MediaType, got.ArtifactType, want.MediaType, want.ArtifactType)
	case got.Subject != want.Subject:
		t.Errorf("subject = %q, want %q", got.Subject, want.Subject)
	case string(got.Payload) != string(want.Payload):
		t.Errorf("payload = %q, want %q", got.Payload, want.Payload)
	case got.Size != want.Size:
		t.Errorf("size = %d, want %d", got.Size, want.Size)
	case !got.CachedAt.Equal(testTime):
		t.Errorf("cached at %s, want %s", got.CachedAt, testTime)
	case !got.LastAccessAt.Equal(accessTime):
		// The two timestamps are separate columns because eviction ranks by
		// the second one (Q11); a store that folded them together would rank
		// by when content arrived rather than by when it was last wanted.
		t.Errorf("last access at %s, want %s", got.LastAccessAt, accessTime)
	}

	// Cached content is per repository, exactly as hosted content is: another
	// proxy that has not fetched this digest is a miss, not a hit through a
	// shared table.
	mustCreateRepo(t, s, "quay", meta.Proxy)
	_, err = s.GetCachedManifest(ctx(), "quay/library/nginx", d)
	requireErrIs(t, err, meta.ErrNotFound, "GetCachedManifest in another proxy")

	_, err = s.GetCachedManifest(ctx(), "dockerhub/library/nginx", digest("never-fetched"))
	requireErrIs(t, err, meta.ErrNotFound, "GetCachedManifest for a digest nobody fetched")
}

func testCachedManifestEdges(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	d := digest("cached-index")

	edges := []meta.CachedManifestRef{
		{Child: digest("cached-config"), Kind: meta.RefConfig},
		{Child: digest("cached-layer-1"), Kind: meta.RefLayer},
		{Child: digest("cached-layer-2"), Kind: meta.RefLayer},
	}
	mustPutCachedManifest(t, s, "dockerhub/library/nginx", d, edges...)

	got, err := s.ListCachedManifestRefs(ctx(), "dockerhub/library/nginx", d)
	if err != nil {
		t.Fatalf("ListCachedManifestRefs: %v", err)
	}
	if len(got) != len(edges) {
		t.Fatalf("edges = %d, want %d", len(got), len(edges))
	}
	// Write order is contract: a manifest's layers come back as the manifest
	// listed them, so a caller accounting for a fill sees what it fetched.
	for i, want := range edges {
		if got[i] != want {
			t.Errorf("edge %d = %+v, want %+v", i, got[i], want)
		}
	}

	_, err = s.ListCachedManifestRefs(ctx(), "dockerhub/library/nginx", digest("never-fetched"))
	requireErrIs(t, err, meta.ErrNotFound, "ListCachedManifestRefs for an uncached manifest")
}

// Cached rows may only exist under a proxy. Cached content is defined by being
// refillable from an upstream; a hosted or group entity has none, so a row
// under one would claim recoverability the deployment cannot deliver.
func testCachedWritesRequireAProxyEntity(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "shop", meta.Hosted)
	mustCreateRepo(t, s, "everything", meta.Group)
	d := digest("misplaced")

	for _, name := range []string{"shop", "shop/api", "everything", "everything/api"} {
		err := s.PutCachedManifest(ctx(), cachedManifest(name, d), nil)
		requireErrIs(t, err, meta.ErrInvalid, "PutCachedManifest under "+name)

		err = s.PutCachedBlob(ctx(), meta.CachedBlob{
			Repository: name, Digest: d, Size: 1, CachedAt: testTime, LastAccessAt: testTime,
		})
		requireErrIs(t, err, meta.ErrInvalid, "PutCachedBlob under "+name)
	}

	// A missing entity is the other answer: nothing was refused, there was
	// nothing to refuse for.
	err := s.PutCachedManifest(ctx(), cachedManifest("nothing-here/x", d), nil)
	requireErrIs(t, err, meta.ErrNotFound, "PutCachedManifest under an absent entity")

	err = s.PutCachedBlob(ctx(), meta.CachedBlob{Repository: "nothing-here/x", Digest: d, Size: 1})
	requireErrIs(t, err, meta.ErrNotFound, "PutCachedBlob under an absent entity")
}

func testCachedWritesValidate(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	m := cachedManifest(repo, "")
	requireErrIs(t, s.PutCachedManifest(ctx(), m, nil), meta.ErrInvalid,
		"PutCachedManifest without a digest")

	requireErrIs(t, s.PutCachedBlob(ctx(), meta.CachedBlob{Repository: repo}), meta.ErrInvalid,
		"PutCachedBlob without a digest")

	d := digest("cached-validate")
	requireErrIs(t, s.PutCachedManifest(ctx(), cachedManifest(repo, d),
		[]meta.CachedManifestRef{{Child: digest("child"), Kind: "invented"}}),
		meta.ErrInvalid, "PutCachedManifest with an unknown edge kind")

	requireErrIs(t, s.PutCachedManifest(ctx(), cachedManifest(repo, d),
		[]meta.CachedManifestRef{{Kind: meta.RefLayer}}),
		meta.ErrInvalid, "PutCachedManifest with an empty edge digest")

	// A rejected write stores nothing, edges included: a manifest whose edge
	// set was refused must not be left recorded with no edges at all.
	_, err := s.GetCachedManifest(ctx(), repo, d)
	requireErrIs(t, err, meta.ErrNotFound, "GetCachedManifest after a refused write")
}

// A refill of content already cached is the normal case rather than a
// conflict, and it is how the access time moves: this is what eviction ranks
// by, so a store that ignored the second write would rank every blob by the
// day it first arrived.
func testCachedRefillReplacesAndRefreshes(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"
	d := digest("refilled")

	mustPutCachedManifest(t, s, repo, d,
		meta.CachedManifestRef{Child: digest("first-layer"), Kind: meta.RefLayer})
	mustPutCachedBlob(t, s, repo, digest("refilled-blob"))

	refreshed := cachedManifest(repo, d)
	refreshed.LastAccessAt = updateTime
	if err := s.PutCachedManifest(ctx(), refreshed, []meta.CachedManifestRef{
		{Child: digest("second-layer"), Kind: meta.RefLayer},
	}); err != nil {
		t.Fatalf("PutCachedManifest again: %v", err)
	}
	if err := s.PutCachedBlob(ctx(), meta.CachedBlob{
		Repository: repo, Digest: digest("refilled-blob"), Size: 512,
		CachedAt: testTime, LastAccessAt: updateTime,
	}); err != nil {
		t.Fatalf("PutCachedBlob again: %v", err)
	}

	got, err := s.GetCachedManifest(ctx(), repo, d)
	if err != nil {
		t.Fatalf("GetCachedManifest: %v", err)
	}
	if !got.LastAccessAt.Equal(updateTime) {
		t.Errorf("manifest last access at %s, want the refreshed %s", got.LastAccessAt, updateTime)
	}

	blob, err := s.GetCachedBlob(ctx(), repo, digest("refilled-blob"))
	if err != nil {
		t.Fatalf("GetCachedBlob: %v", err)
	}
	if !blob.LastAccessAt.Equal(updateTime) {
		t.Errorf("blob last access at %s, want the refreshed %s", blob.LastAccessAt, updateTime)
	}

	// The edge set is replaced wholesale, not merged: what a manifest brought
	// in is a property of the manifest, and an accumulated set would report
	// layers this digest never listed.
	edges, err := s.ListCachedManifestRefs(ctx(), repo, d)
	if err != nil {
		t.Fatalf("ListCachedManifestRefs: %v", err)
	}
	if len(edges) != 1 || edges[0].Child != digest("second-layer") {
		t.Errorf("edges = %+v, want only the second layer", edges)
	}
}

// Whether a layer is cached is a per-proxy question. One proxy having fetched
// it says nothing about whether another may serve it, and a global answer
// would let a proxy serve content its own routing rules never admitted (C-010).
func testCachedBlobsAreScopedToTheirRepository(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "quay", meta.Proxy)
	d := digest("shared-layer")

	mustPutCachedBlob(t, s, "dockerhub/library/nginx", d)

	got, err := s.GetCachedBlob(ctx(), "dockerhub/library/nginx", d)
	if err != nil {
		t.Fatalf("GetCachedBlob: %v", err)
	}
	if got.Digest != d || got.Size != 512 {
		t.Errorf("blob = %+v, want the stored digest and size", got)
	}

	_, err = s.GetCachedBlob(ctx(), "quay/library/nginx", d)
	requireErrIs(t, err, meta.ErrNotFound, "GetCachedBlob under another proxy")
}

// The two families share no rows, which the store proves by answering for each
// only through its own methods. This is the storage-layer half of ADR 0009:
// the Go types make the crossing uncompilable, and this makes it unreachable
// even from a statement that named the wrong table.
func testCachedAndHostedContentAreInvisibleToEachOther(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "shop", meta.Hosted)
	d := digest("same-digest-both-sides")

	mustPutCachedManifest(t, s, "dockerhub/library/nginx", d)
	mustPutCachedBlob(t, s, "dockerhub/library/nginx", d)
	mustPutManifest(t, s, "shop", d)
	if err := s.PutBlob(ctx(), meta.Blob{Digest: d, Size: 7, CreatedAt: testTime}); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	// A hosted read cannot find cached content...
	_, err := s.GetManifest(ctx(), "dockerhub/library/nginx", d)
	requireErrIs(t, err, meta.ErrNotFound, "GetManifest against a cached manifest")

	// ...and a cached read cannot find hosted content, which is the direction
	// that matters most: it is the one where a cache sweep would otherwise
	// find something irreplaceable.
	_, err = s.GetCachedManifest(ctx(), "shop", d)
	requireErrIs(t, err, meta.ErrNotFound, "GetCachedManifest against a hosted manifest")

	_, err = s.GetCachedBlob(ctx(), "shop", d)
	requireErrIs(t, err, meta.ErrNotFound, "GetCachedBlob against a hosted blob")

	// Deleting the hosted manifest leaves the cached one, and the reverse
	// would too: they are different rows about different bytes that happen to
	// hash the same.
	if err := s.DeleteManifest(ctx(), "shop", d); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if _, err := s.GetCachedManifest(ctx(), "dockerhub/library/nginx", d); err != nil {
		t.Errorf("GetCachedManifest after a hosted delete: %v, want it untouched", err)
	}
}

func testCachedContentDiesWithTheRepository(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	// A neighbour whose name merely starts the same way, so the sweep cannot
	// be a prefix match: `dockerhub2/...` is somebody else's cache.
	mustCreateRepo(t, s, "dockerhub2", meta.Proxy)
	d := digest("evicted-with-the-entity")

	mustPutCachedManifest(t, s, "dockerhub/library/nginx", d,
		meta.CachedManifestRef{Child: digest("layer"), Kind: meta.RefLayer})
	mustPutCachedBlob(t, s, "dockerhub/library/nginx", digest("layer"))
	mustPutCachedManifest(t, s, "dockerhub2/library/nginx", d)
	mustPutCachedBlob(t, s, "dockerhub2/library/nginx", digest("layer"))

	if err := s.DeleteRepository(ctx(), "dockerhub"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	// A proxy created at this name afterwards points at whatever upstream its
	// own operator chose; serving a predecessor's cached bytes from it would
	// answer for a remote nobody configured.
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	if _, err := s.GetCachedManifest(ctx(), "dockerhub/library/nginx", d); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedManifest after recreation = %v, want ErrNotFound", err)
	}
	if _, err := s.GetCachedBlob(ctx(), "dockerhub/library/nginx", digest("layer")); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetCachedBlob after recreation = %v, want ErrNotFound", err)
	}
	if _, err := s.ListCachedManifestRefs(ctx(), "dockerhub/library/nginx", d); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("ListCachedManifestRefs after recreation = %v, want ErrNotFound", err)
	}

	// The neighbour is untouched: the sweep is over a name range, and
	// `dockerhub2` is not under `dockerhub`.
	if _, err := s.GetCachedManifest(ctx(), "dockerhub2/library/nginx", d); err != nil {
		t.Errorf("GetCachedManifest for the neighbour: %v, want it untouched", err)
	}
	if _, err := s.GetCachedBlob(ctx(), "dockerhub2/library/nginx", digest("layer")); err != nil {
		t.Errorf("GetCachedBlob for the neighbour: %v, want it untouched", err)
	}
}
