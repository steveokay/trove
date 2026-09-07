// Package separation is ADR 0009's proving test: cache eviction and hosted
// deletion are separate systems, and crossing between them is unwritable.
//
// The ADR names four walls -- distinct types, distinct store wiring, import
// boundaries, distinct schema families -- and describes one test asserting
// four things:
//
//	(a) the wiring passes disjoint instances;
//	(b) the import allowlist holds;
//	(c) a retention plan built over a fixture containing both families selects
//	    only hosted manifests;
//	(d) an eviction pass over the same fixture touches only cached rows and
//	    cache-store paths.
//
// All four are here, over one fixture that holds hosted and cached content
// with the *same digests*, because a proof that eviction takes the right rows
// is worth nothing if the two families are distinguishable by digest alone.
//
// It lives in the top-level test tree rather than in either package because it
// is the one test that has to see both sides at once. internal/cache may not
// import internal/policy and vice versa (wall 3), so no package that is
// constrained by the wall can host the test that checks it.
package separation_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/archtest"
	"github.com/steveokay/trove/internal/blob"
	blobfs "github.com/steveokay/trove/internal/blob/fs"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/policy"
)

const (
	hostedRepo = "team-a/api"
	cachedRepo = "dockerhub/library/nginx"
)

var evaluatedAt = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

// fixture is one deployment holding both families: a hosted repository with a
// manifest and a layer, and a proxy repository whose cache holds a manifest and
// a layer with the very same digests.
type fixture struct {
	meta *metamemory.Store

	hostedBlobs *blobfs.Store
	cacheBlobs  *blobfs.Store

	// hostedRoot and cacheRoot are disjoint directories. Wall 2 is what makes
	// them disjoint; these are what the test looks at to prove it.
	hostedRoot string
	cacheRoot  string

	manifest blob.Digest
	layer    blob.Digest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	ctx := context.Background()
	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })

	for _, repo := range []meta.Repository{
		{Name: "team-a", Type: meta.Hosted, CreatedAt: evaluatedAt, UpdatedAt: evaluatedAt},
		{Name: "dockerhub", Type: meta.Proxy, CreatedAt: evaluatedAt, UpdatedAt: evaluatedAt},
	} {
		if _, err := store.CreateRepository(ctx, repo); err != nil {
			t.Fatalf("CreateRepository(%q): %v", repo.Name, err)
		}
	}

	hostedRoot := filepath.Join(t.TempDir(), "hosted")
	cacheRoot := filepath.Join(t.TempDir(), "cache")
	hostedBlobs, err := blobfs.New(blobfs.Options{Root: hostedRoot})
	if err != nil {
		t.Fatalf("hosted blob store: %v", err)
	}
	cacheBlobs, err := blobfs.New(blobfs.Options{Root: cacheRoot})
	if err != nil {
		t.Fatalf("cache blob store: %v", err)
	}

	manifestPayload := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	layerBytes := []byte("a layer both families happen to hold")
	manifestDigest := blob.FromBytes(blob.SHA256, manifestPayload)
	layerDigest := blob.FromBytes(blob.SHA256, layerBytes)

	// The hosted half: a manifest, a tag, a blob row, and the bytes under the
	// hosted root.
	if err := store.PutManifest(ctx, meta.Manifest{
		Repository: hostedRepo, Digest: meta.Digest(manifestDigest),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   manifestPayload, Size: int64(len(manifestPayload)), CreatedAt: evaluatedAt.Add(-90 * 24 * time.Hour),
	}, []meta.ManifestRef{{Child: meta.Digest(layerDigest), Kind: meta.RefLayer}}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if err := store.PutTag(ctx, meta.Tag{
		Repository: hostedRepo, Name: "v1", Digest: meta.Digest(manifestDigest),
		CreatedAt: evaluatedAt, UpdatedAt: evaluatedAt,
	}); err != nil {
		t.Fatalf("PutTag: %v", err)
	}
	if err := store.PutBlob(ctx, meta.Blob{
		Digest: meta.Digest(layerDigest), Size: int64(len(layerBytes)), CreatedAt: evaluatedAt,
	}); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	if err := hostedBlobs.Put(ctx, layerDigest, bytes.NewReader(layerBytes)); err != nil {
		t.Fatalf("hosted Put: %v", err)
	}

	// The cached half: the same two digests, in the other family's tables and
	// under the other root.
	if err := store.PutCachedManifest(ctx, meta.CachedManifest{
		Repository: cachedRepo, Digest: meta.Digest(manifestDigest),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   manifestPayload, Size: int64(len(manifestPayload)),
		CachedAt: evaluatedAt, LastAccessAt: evaluatedAt,
	}, []meta.CachedManifestRef{{Child: meta.Digest(layerDigest), Kind: meta.RefLayer}}); err != nil {
		t.Fatalf("PutCachedManifest: %v", err)
	}
	if err := store.PutCachedBlob(ctx, meta.CachedBlob{
		Repository: cachedRepo, Digest: meta.Digest(layerDigest), Size: int64(len(layerBytes)),
		CachedAt: evaluatedAt, LastAccessAt: evaluatedAt,
	}); err != nil {
		t.Fatalf("PutCachedBlob: %v", err)
	}
	if err := cacheBlobs.Put(ctx, layerDigest, bytes.NewReader(layerBytes)); err != nil {
		t.Fatalf("cache Put: %v", err)
	}

	return &fixture{
		meta: store, hostedBlobs: hostedBlobs, cacheBlobs: cacheBlobs,
		hostedRoot: hostedRoot, cacheRoot: cacheRoot,
		manifest: manifestDigest, layer: layerDigest,
	}
}

// TestEvictionTouchesOnlyTheCachedFamily is assertions (a) and (d): an
// eviction pass over a fixture holding both families removes every cached row
// and every cache-store byte, and leaves the hosted rows, the hosted tag, and
// the hosted bytes exactly as they were -- while holding digests that name
// content in both.
func TestEvictionTouchesOnlyTheCachedFamily(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	ctx := context.Background()

	// Wall 2 made literal before anything runs: the two blob stores are rooted
	// at directories neither of which contains the other, so "the cache store
	// cannot name a hosted blob" is a fact about the filesystem and not only
	// about the types above it.
	if within(f.cacheRoot, f.hostedRoot) || within(f.hostedRoot, f.cacheRoot) {
		t.Fatalf("the blob stores share a root: hosted %q, cache %q", f.hostedRoot, f.cacheRoot)
	}

	// The wiring is the assertion: the evictor is constructed with the cached
	// half of the metadata store and the cache-rooted blob store, and there is
	// no argument through which the hosted ones could arrive (wall 2). The
	// recorders sit in between so the test can say what was reached rather
	// than only what survived.
	rows := &recordingStore{inner: f.meta}
	bytesStore := &recordingBlobs{inner: f.cacheBlobs}
	evictor, err := cache.New(cache.Options{
		Meta: rows, Blobs: bytesStore,
		// A budget of one byte: everything cached is over it.
		Budget: cache.Budget{Global: 1},
		Log:    quietLogger(),
	})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}

	result, err := evictor.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Manifests != 1 || result.Blobs != 1 {
		t.Fatalf("swept %d manifests / %d blobs, want 1 / 1", result.Manifests, result.Blobs)
	}

	// The cached family is empty.
	if _, err := f.meta.GetCachedManifest(ctx, cachedRepo, meta.Digest(f.manifest)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("the cached manifest survived: %v", err)
	}
	if _, err := f.meta.GetCachedBlob(ctx, cachedRepo, meta.Digest(f.layer)); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("the cached blob row survived: %v", err)
	}
	if _, err := f.cacheBlobs.Stat(ctx, f.layer); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("the cached bytes survived: %v", err)
	}

	// The hosted family is untouched -- same digests, other tables, other root.
	if _, err := f.meta.GetManifest(ctx, hostedRepo, meta.Digest(f.manifest)); err != nil {
		t.Errorf("the hosted manifest is gone: %v", err)
	}
	if _, err := f.meta.GetBlob(ctx, meta.Digest(f.layer)); err != nil {
		t.Errorf("the hosted blob row is gone: %v", err)
	}
	if _, err := f.meta.GetTag(ctx, hostedRepo, "v1"); err != nil {
		t.Errorf("the hosted tag is gone: %v", err)
	}
	desc, err := f.hostedBlobs.Stat(ctx, f.layer)
	if err != nil {
		t.Fatalf("the hosted bytes are gone: %v", err)
	}
	if desc.Digest != f.layer {
		t.Errorf("hosted bytes changed identity: %s", desc.Digest)
	}

	// And what the pass reached, rather than only what survived: every store
	// call named the cached family, and every byte deleted was named through
	// the cache-rooted store.
	for _, method := range rows.methods() {
		if !slices.Contains(cachedMethods, method) {
			t.Errorf("the eviction pass called %q, which is not part of the cached family", method)
		}
	}
	if deleted := bytesStore.deletions(); len(deleted) != 1 || deleted[0] != f.layer {
		t.Errorf("deleted %v from the cache store, want exactly the cached layer", deleted)
	}
}

// TestRetentionPlansOverBothFamiliesSelectOnlyHosted is assertion (c): a
// retention inventory built over the same fixture reaches the hosted rows and
// nothing else, so the plan an operator applies cannot name cached content --
// even though the cached content has the same digest as the hosted content.
func TestRetentionPlansOverBothFamiliesSelectOnlyHosted(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	ctx := context.Background()

	// The inventory is built the way the apply path builds one: from the
	// hosted store's own methods. Asking those methods for the proxy
	// repository's content is what proves the families do not answer for each
	// other -- a hosted read of a cached row is ErrNotFound, not a hit.
	if _, err := f.meta.GetManifest(ctx, cachedRepo, meta.Digest(f.manifest)); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("a hosted read reached a cached row: %v", err)
	}

	hosted, err := f.meta.GetManifest(ctx, hostedRepo, meta.Digest(f.manifest))
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	inventory, err := policy.NewInventory(hostedRepo, []policy.Manifest{{
		Digest:   policy.Digest(hosted.Digest),
		Tags:     []policy.Tag{{Name: "v1"}},
		PushedAt: hosted.CreatedAt,
		Size:     hosted.Size,
	}})
	if err != nil {
		t.Fatalf("NewInventory: %v", err)
	}

	// A rule that keeps nothing: the widest plan the evaluator can produce, so
	// anything it *could* reach, it does.
	rules, err := policy.CompileRules(policy.Rule{
		Name: "sweep-everything", Priority: 1, Kind: policy.SelectMatched,
	})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	plan, err := policy.Evaluate(inventory, rules, evaluatedAt)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if plan.Repository != hostedRepo {
		t.Errorf("plan repository = %q, want %q", plan.Repository, hostedRepo)
	}
	if len(plan.Selected) != 1 {
		t.Fatalf("plan selected %d manifests, want 1", len(plan.Selected))
	}

	// The cached rows are still there afterwards, which is the other half of
	// the same statement: a retention plan is not a thing that can reach them.
	if _, err := f.meta.GetCachedManifest(ctx, cachedRepo, meta.Digest(f.manifest)); err != nil {
		t.Errorf("the cached manifest went missing during a retention evaluation: %v", err)
	}
	if _, err := f.cacheBlobs.Stat(ctx, f.layer); err != nil {
		t.Errorf("the cached bytes went missing during a retention evaluation: %v", err)
	}
}

// TestTheImportWallIsDeclaredAndHolds is assertion (b). The archtest suite
// checks every rule in the repository; this checks that the two rules ADR 0009
// depends on still exist and still pass, so deleting one of them fails the
// ADR's own test rather than quietly passing everything that remains.
func TestTheImportWallIsDeclaredAndHolds(t *testing.T) {
	t.Parallel()

	want := []string{"cache-reaches-no-hosted-deletion", "hosted-deletion-reaches-no-cache"}
	var walls []archtest.Rule
	for _, rule := range archtest.Rules() {
		if slices.Contains(want, rule.Name) {
			walls = append(walls, rule)
		}
	}
	if len(walls) != len(want) {
		t.Fatalf("found %d of the ADR 0009 import rules, want %d (%v)", len(walls), len(want), want)
	}

	graph, err := archtest.Load(t.Context(), archtest.Options{
		Patterns: []string{"github.com/steveokay/trove/..."},
	})
	if err != nil {
		t.Fatalf("loading the import graph: %v", err)
	}
	if !slices.Contains(graph.Packages(), "github.com/steveokay/trove/internal/cache") {
		t.Fatal("internal/cache is missing from the graph; the rules would pass vacuously")
	}
	if violations := graph.Check(walls); len(violations) > 0 {
		t.Fatalf("ADR 0009's import wall is broken:\n\n%s", archtest.FormatViolations(violations))
	}
}

// cachedMethods is the cached-content family's eviction half. A call to
// anything else from an eviction pass is a wall breach, whatever it did.
var cachedMethods = []string{
	"CachedUsage", "ListEvictable", "DeleteCachedManifest", "DeleteCachedBlob", "CachedBlobClaims",
}

// recordingStore is the instrumented fake the ADR calls for: it satisfies
// cache.Store and records which methods an eviction pass reached for.
type recordingStore struct {
	inner *metamemory.Store
	calls []string
}

func (s *recordingStore) methods() []string { return slices.Clone(s.calls) }

func (s *recordingStore) CachedUsage(ctx context.Context, entity string) (meta.CacheUsage, error) {
	s.calls = append(s.calls, "CachedUsage")
	return s.inner.CachedUsage(ctx, entity)
}

func (s *recordingStore) ListEvictable(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error) {
	s.calls = append(s.calls, "ListEvictable")
	return s.inner.ListEvictable(ctx, entity, limit)
}

func (s *recordingStore) DeleteCachedManifest(ctx context.Context, repo string, digest meta.Digest) error {
	s.calls = append(s.calls, "DeleteCachedManifest")
	return s.inner.DeleteCachedManifest(ctx, repo, digest)
}

func (s *recordingStore) DeleteCachedBlob(ctx context.Context, repo string, digest meta.Digest) (int64, error) {
	s.calls = append(s.calls, "DeleteCachedBlob")
	return s.inner.DeleteCachedBlob(ctx, repo, digest)
}

func (s *recordingStore) CachedBlobClaims(ctx context.Context, digest meta.Digest) (int64, error) {
	s.calls = append(s.calls, "CachedBlobClaims")
	return s.inner.CachedBlobClaims(ctx, digest)
}

// recordingBlobs records what an eviction pass deleted from the cache store.
type recordingBlobs struct {
	inner   blob.Store
	deleted []blob.Digest
}

func (b *recordingBlobs) deletions() []blob.Digest { return slices.Clone(b.deleted) }

func (b *recordingBlobs) Delete(ctx context.Context, digest blob.Digest) error {
	b.deleted = append(b.deleted, digest)
	return b.inner.Delete(ctx, digest)
}

func (b *recordingBlobs) Walk(ctx context.Context, fn func(blob.Descriptor) error) error {
	return b.inner.Walk(ctx, fn)
}

// within reports whether one path is inside another, so the disjointness of
// the two roots is checked rather than assumed from how they were built.
func within(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
