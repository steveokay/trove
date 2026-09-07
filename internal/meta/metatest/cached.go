package metatest

import (
	"errors"
	"fmt"
	"sort"
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
	cases := []suiteCase{
		{"CachedManifestRoundTrip", testCachedManifestRoundTrip},
		{"CachedManifestEdges", testCachedManifestEdges},
		{"CachedWritesRequireAProxyEntity", testCachedWritesRequireAProxyEntity},
		{"CachedWritesValidate", testCachedWritesValidate},
		{"CachedRefillReplacesAndRefreshes", testCachedRefillReplacesAndRefreshes},
		{"CachedBlobsAreScopedToTheirRepository", testCachedBlobsAreScopedToTheirRepository},
		{"CachedAndHostedContentAreInvisibleToEachOther", testCachedAndHostedContentAreInvisibleToEachOther},
		{"CachedContentDiesWithTheRepository", testCachedContentDiesWithTheRepository},
		{"TagLeaseRoundTrip", testTagLeaseRoundTrip},
		{"TagLeaseRevalidationReplaces", testTagLeaseRevalidationReplaces},
		{"TagLeaseRequiresAProxyEntity", testTagLeaseRequiresAProxyEntity},
		{"TagLeaseValidation", testTagLeaseValidation},
		{"TagLeaseDelete", testTagLeaseDelete},
		{"TagLeasesDieWithTheRepository", testTagLeasesDieWithTheRepository},
		{"NegativeEntryRoundTrip", testNegativeEntryRoundTrip},
		{"NegativeEntryRefreshAndDelete", testNegativeEntryRefreshAndDelete},
		{"NegativeEntryRequiresAProxyEntity", testNegativeEntryRequiresAProxyEntity},
		{"NegativeEntriesDieWithTheRepository", testNegativeEntriesDieWithTheRepository},
	}
	return append(cases, evictionTests()...)
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

// --- tag leases (C-005) ----------------------------------------------------

// A lease is somebody else's fact, borrowed for a while: the mapping from a tag
// to a digest, with when it was last confirmed and whether the last attempt to
// confirm it failed. It is deliberately not a hosted Tag, and the store keeps
// them in different tables reached by different methods.

func tagLease(repo, tag string, d meta.Digest) meta.TagLease {
	return meta.TagLease{
		Repository: repo,
		Tag:        tag,
		Digest:     d,
		ETag:       `W/"abc123"`,
		FetchedAt:  testTime,
		TTL:        15 * time.Minute,
	}
}

func testTagLeaseRoundTrip(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"
	want := tagLease(repo, "latest", digest("leased"))

	if err := s.PutTagLease(ctx(), want); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}
	got, err := s.GetTagLease(ctx(), repo, "latest")
	if err != nil {
		t.Fatalf("GetTagLease: %v", err)
	}
	switch {
	case got.Digest != want.Digest:
		t.Errorf("digest = %q, want %q", got.Digest, want.Digest)
	case got.ETag != want.ETag:
		// The entity tag goes back upstream as If-None-Match, so a store that
		// dropped it would make every revalidation transfer a manifest body.
		t.Errorf("etag = %q, want %q", got.ETag, want.ETag)
	case !got.FetchedAt.Equal(testTime):
		t.Errorf("fetched at %s, want %s", got.FetchedAt, testTime)
	case got.TTL != want.TTL:
		t.Errorf("ttl = %s, want %s", got.TTL, want.TTL)
	case got.Stale:
		t.Error("a freshly written lease came back stale")
	}

	// Leases are per repository and per tag, like every other cached row.
	mustCreateRepo(t, s, "quay", meta.Proxy)
	if _, err := s.GetTagLease(ctx(), "quay/library/nginx", "latest"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetTagLease under another proxy = %v, want ErrNotFound", err)
	}
	if _, err := s.GetTagLease(ctx(), repo, "never-resolved"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetTagLease for an unresolved tag = %v, want ErrNotFound", err)
	}

	// A zero TTL is a real setting -- revalidate on every pull (Q11) -- and
	// must survive the round trip as itself rather than as "unset".
	always := tagLease(repo, "always", digest("always"))
	always.TTL = 0
	if err := s.PutTagLease(ctx(), always); err != nil {
		t.Fatalf("PutTagLease with a zero TTL: %v", err)
	}
	stored, err := s.GetTagLease(ctx(), repo, "always")
	if err != nil {
		t.Fatalf("GetTagLease: %v", err)
	}
	if stored.TTL != 0 {
		t.Errorf("ttl = %s, want 0", stored.TTL)
	}
}

// Every revalidation writes a lease, whether the tag moved or not, so
// replacement is the normal case rather than a conflict.
func testTagLeaseRevalidationReplaces(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	if err := s.PutTagLease(ctx(), tagLease(repo, "latest", digest("first"))); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}

	moved := tagLease(repo, "latest", digest("second"))
	moved.ETag = `W/"def456"`
	moved.FetchedAt = updateTime
	moved.Stale = true
	if err := s.PutTagLease(ctx(), moved); err != nil {
		t.Fatalf("PutTagLease again: %v", err)
	}

	got, err := s.GetTagLease(ctx(), repo, "latest")
	if err != nil {
		t.Fatalf("GetTagLease: %v", err)
	}
	switch {
	case got.Digest != digest("second"):
		t.Errorf("digest = %q, want the tag's new target", got.Digest)
	case got.ETag != `W/"def456"`:
		t.Errorf("etag = %q, want the new one", got.ETag)
	case !got.FetchedAt.Equal(updateTime):
		t.Errorf("fetched at %s, want %s", got.FetchedAt, updateTime)
	case !got.Stale:
		// Degraded mode is a fact about the last attempt, and an operator
		// asking why a cluster is pulling yesterday's image reads it here.
		t.Error("stale did not survive the write")
	}
}

func testTagLeaseRequiresAProxyEntity(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "shop", meta.Hosted)
	mustCreateRepo(t, s, "everything", meta.Group)

	for _, name := range []string{"shop", "shop/api", "everything", "everything/api"} {
		err := s.PutTagLease(ctx(), tagLease(name, "latest", digest("misplaced")))
		requireErrIs(t, err, meta.ErrInvalid, "PutTagLease under "+name)
	}

	err := s.PutTagLease(ctx(), tagLease("nothing-here/x", "latest", digest("misplaced")))
	requireErrIs(t, err, meta.ErrNotFound, "PutTagLease under an absent entity")
}

func testTagLeaseValidation(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	requireErrIs(t, s.PutTagLease(ctx(), tagLease(repo, "", digest("no-tag"))),
		meta.ErrInvalid, "PutTagLease without a tag")
	requireErrIs(t, s.PutTagLease(ctx(), tagLease(repo, "latest", "")),
		meta.ErrInvalid, "PutTagLease without a digest")
}

func testTagLeaseDelete(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	if err := s.PutTagLease(ctx(), tagLease(repo, "latest", digest("leased"))); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}
	if err := s.DeleteTagLease(ctx(), repo, "latest"); err != nil {
		t.Fatalf("DeleteTagLease: %v", err)
	}
	requireErrIs(t, s.DeleteTagLease(ctx(), repo, "latest"), meta.ErrNotFound, "DeleteTagLease twice")

	// The manifest the lease pointed at stays cached: a tag that vanished
	// upstream does not make the content it named unreachable by digest, which
	// is what keeps images pinned by digest working (ADR 0008).
	mustPutCachedManifest(t, s, repo, digest("leased"))
	if err := s.PutTagLease(ctx(), tagLease(repo, "latest", digest("leased"))); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}
	if err := s.DeleteTagLease(ctx(), repo, "latest"); err != nil {
		t.Fatalf("DeleteTagLease: %v", err)
	}
	if _, err := s.GetCachedManifest(ctx(), repo, digest("leased")); err != nil {
		t.Errorf("GetCachedManifest after the lease went: %v, want it untouched", err)
	}
}

func testTagLeasesDieWithTheRepository(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "dockerhub2", meta.Proxy)

	if err := s.PutTagLease(ctx(), tagLease("dockerhub/library/nginx", "latest", digest("leased"))); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}
	if err := s.PutTagLease(ctx(), tagLease("dockerhub2/library/nginx", "latest", digest("leased"))); err != nil {
		t.Fatalf("PutTagLease: %v", err)
	}

	if err := s.DeleteRepository(ctx(), "dockerhub"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	if _, err := s.GetTagLease(ctx(), "dockerhub/library/nginx", "latest"); !errors.Is(err, meta.ErrNotFound) {
		// A proxy recreated at this name points at whatever upstream its own
		// operator chose; a inherited lease would answer for a remote nobody
		// configured.
		t.Errorf("GetTagLease after recreation = %v, want ErrNotFound", err)
	}
	if _, err := s.GetTagLease(ctx(), "dockerhub2/library/nginx", "latest"); err != nil {
		t.Errorf("GetTagLease for the neighbour: %v, want it untouched", err)
	}
}

// --- negative cache (C-007) ------------------------------------------------

// A recorded absence: what an upstream did not have, so a typo does not hammer
// it. Names only -- the rule that a digest is never recorded lives with the
// resolver, because this store cannot tell one from the other.

func negativeEntry(repo, reference string) meta.NegativeEntry {
	return meta.NegativeEntry{
		Repository: repo,
		Reference:  reference,
		ObservedAt: testTime,
		TTL:        60 * time.Second,
	}
}

func testNegativeEntryRoundTrip(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	if err := s.PutNegativeEntry(ctx(), negativeEntry(repo, "no-such-tag")); err != nil {
		t.Fatalf("PutNegativeEntry: %v", err)
	}
	got, err := s.GetNegativeEntry(ctx(), repo, "no-such-tag")
	if err != nil {
		t.Fatalf("GetNegativeEntry: %v", err)
	}
	switch {
	case got.Reference != "no-such-tag":
		t.Errorf("reference = %q, want %q", got.Reference, "no-such-tag")
	case !got.ObservedAt.Equal(testTime):
		t.Errorf("observed at %s, want %s", got.ObservedAt, testTime)
	case got.TTL != 60*time.Second:
		t.Errorf("ttl = %s, want 60s", got.TTL)
	}

	// Per repository and per reference, like everything else in this family.
	mustCreateRepo(t, s, "quay", meta.Proxy)
	if _, err := s.GetNegativeEntry(ctx(), "quay/library/nginx", "no-such-tag"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetNegativeEntry under another proxy = %v, want ErrNotFound", err)
	}
	if _, err := s.GetNegativeEntry(ctx(), repo, "another-tag"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetNegativeEntry for an unrecorded name = %v, want ErrNotFound", err)
	}

	entry := negativeEntry(repo, "")
	requireErrIs(t, s.PutNegativeEntry(ctx(), entry), meta.ErrInvalid, "PutNegativeEntry without a reference")
}

func testNegativeEntryRefreshAndDelete(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	repo := "dockerhub/library/nginx"

	if err := s.PutNegativeEntry(ctx(), negativeEntry(repo, "typo")); err != nil {
		t.Fatalf("PutNegativeEntry: %v", err)
	}

	// Missing the same name again is a refresh, not a conflict: the entry says
	// when the upstream last said no.
	refreshed := negativeEntry(repo, "typo")
	refreshed.ObservedAt = updateTime
	refreshed.TTL = 30 * time.Second
	if err := s.PutNegativeEntry(ctx(), refreshed); err != nil {
		t.Fatalf("PutNegativeEntry again: %v", err)
	}
	got, err := s.GetNegativeEntry(ctx(), repo, "typo")
	if err != nil {
		t.Fatalf("GetNegativeEntry: %v", err)
	}
	if !got.ObservedAt.Equal(updateTime) || got.TTL != 30*time.Second {
		t.Errorf("entry = %+v, want the refreshed observation", got)
	}

	if err := s.DeleteNegativeEntry(ctx(), repo, "typo"); err != nil {
		t.Fatalf("DeleteNegativeEntry: %v", err)
	}
	requireErrIs(t, s.DeleteNegativeEntry(ctx(), repo, "typo"), meta.ErrNotFound, "DeleteNegativeEntry twice")
}

func testNegativeEntryRequiresAProxyEntity(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "shop", meta.Hosted)
	mustCreateRepo(t, s, "everything", meta.Group)

	for _, name := range []string{"shop", "shop/api", "everything", "everything/api"} {
		err := s.PutNegativeEntry(ctx(), negativeEntry(name, "no-such-tag"))
		requireErrIs(t, err, meta.ErrInvalid, "PutNegativeEntry under "+name)
	}

	err := s.PutNegativeEntry(ctx(), negativeEntry("nothing-here/x", "no-such-tag"))
	requireErrIs(t, err, meta.ErrNotFound, "PutNegativeEntry under an absent entity")
}

func testNegativeEntriesDieWithTheRepository(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "dockerhub2", meta.Proxy)

	if err := s.PutNegativeEntry(ctx(), negativeEntry("dockerhub/library/nginx", "typo")); err != nil {
		t.Fatalf("PutNegativeEntry: %v", err)
	}
	if err := s.PutNegativeEntry(ctx(), negativeEntry("dockerhub2/library/nginx", "typo")); err != nil {
		t.Fatalf("PutNegativeEntry: %v", err)
	}

	if err := s.DeleteRepository(ctx(), "dockerhub"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}

	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	if _, err := s.GetNegativeEntry(ctx(), "dockerhub/library/nginx", "typo"); !errors.Is(err, meta.ErrNotFound) {
		// A proxy recreated at this name points somewhere else entirely; an
		// inherited absence would refuse a pull the new upstream would serve.
		t.Errorf("GetNegativeEntry after recreation = %v, want ErrNotFound", err)
	}
	if _, err := s.GetNegativeEntry(ctx(), "dockerhub2/library/nginx", "typo"); err != nil {
		t.Errorf("GetNegativeEntry for the neighbour: %v, want it untouched", err)
	}
}

// The catalog is the union of hosted and cached content (C-021, ADR 0008
// clarification). A proxy contributes what it has actually cached, which is
// also why these cases live beside the cached-content contract rather than
// with the hosted listing ones: the union is a property of both halves, and an
// engine that implements one and forgets the other fails here.

func testListContentNamesIncludesCachedContent(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustSeedContent(t, s, "team-a/api")
	mustPutCachedManifest(t, s, "dockerhub/library/nginx", digest("cached-nginx"))
	mustPutCachedManifest(t, s, "dockerhub/library/redis", digest("cached-redis"))

	// An entity that has cached nothing contributes nothing: a proxy's catalog
	// is what it holds, not what its upstream offers.
	mustCreateRepo(t, s, "quay", meta.Proxy)

	got := contentNames(t, s, meta.Unrestricted(), 0)
	want := []string{"dockerhub/library/nginx", "dockerhub/library/redis", "team-a/api"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("names = %v, want %v", got, want)
	}
}

// testListContentNamesFiltersCachedContent: the visibility filter guards both
// halves of the union. A proxy the subject cannot see must be as absent from
// the catalog as a hosted repository is -- the disclosure rule does not care
// which table a name came out of (ADR 0003).
func testListContentNamesFiltersCachedContent(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	mustCreateRepo(t, s, "dockerhub", meta.Proxy)
	mustCreateRepo(t, s, "secret", meta.Proxy)
	mustSeedContent(t, s, "team-a/api")
	mustPutCachedManifest(t, s, "dockerhub/library/nginx", digest("cached-nginx"))
	mustPutCachedManifest(t, s, "secret/internal/tool", digest("cached-secret"))

	got := contentNames(t, s, meta.VisibleTo(meta.ScopeFilter{Prefix: "team-a/"}, meta.ScopeFilter{Prefix: "dockerhub/"}), 0)
	want := []string{"dockerhub/library/nginx", "team-a/api"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("names = %v, want %v -- a cached name leaked past the filter", got, want)
	}
}

// testListContentNamesPaginateAcrossTheUnion is the case a union most easily
// gets wrong. Hosted and cached names interleave lexically, so a page boundary
// falls in the middle of the merge; an implementation that paged each half
// separately, or that applied the cursor to only one of them, returns
// duplicates or drops names here. Hidden names are interleaved too, so a
// cursor that names one is caught by contentNames as it walks.
func testListContentNamesPaginateAcrossTheUnion(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "a", meta.Hosted)
	mustCreateRepo(t, s, "b", meta.Proxy)
	mustCreateRepo(t, s, "hidden", meta.Proxy)

	// Interleaved by name: a/1 b/1 a/2 b/2 ... with hidden/N between them.
	var want []string
	for i := 1; i <= 5; i++ {
		hosted := fmt.Sprintf("a/%d", i)
		cached := fmt.Sprintf("b/%d", i)
		mustSeedContent(t, s, hosted)
		mustPutCachedManifest(t, s, cached, digest(cached))
		mustPutCachedManifest(t, s, fmt.Sprintf("hidden/%d", i), digest("hidden"+cached))
		want = append(want, hosted, cached)
	}
	sort.Strings(want)

	for _, limit := range []int{1, 2, 3, 7} {
		got := contentNames(t, s, meta.VisibleTo(meta.ScopeFilter{Prefix: "a/"}, meta.ScopeFilter{Prefix: "b/"}), limit)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("limit %d: names = %v, want %v", limit, got, want)
		}
	}
}

// testListContentNamesListsANameHoldingBothKindsOnce. A name cannot normally
// hold hosted and cached content at once -- the entity is one type -- but the
// two tables have no constraint tying them together, so a converted or
// half-migrated entity can produce it. The catalog is a set of names, and a
// client that saw one twice would page it twice.
func testListContentNamesListsANameHoldingBothKindsOnce(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "both", meta.Proxy)
	mustPutCachedManifest(t, s, "both/thing", digest("cached-thing"))
	mustSeedContent(t, s, "both/thing")

	got := contentNames(t, s, meta.Unrestricted(), 0)
	if fmt.Sprint(got) != fmt.Sprint([]string{"both/thing"}) {
		t.Errorf("names = %v, want the name exactly once", got)
	}
}
