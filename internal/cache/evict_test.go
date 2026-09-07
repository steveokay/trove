package cache_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/meta"
)

func TestNewRefusesUnusableOptions(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	for _, tc := range []struct {
		name string
		opts cache.Options
	}{
		{
			name: "no metadata store",
			opts: cache.Options{Blobs: env.blobs},
		},
		{
			name: "no blob store",
			opts: cache.Options{Meta: env.meta},
		},
		{
			name: "negative global budget",
			opts: cache.Options{Meta: env.meta, Blobs: env.blobs, Budget: cache.Budget{Global: -1}},
		},
		{
			name: "negative carve-out",
			opts: cache.Options{Meta: env.meta, Blobs: env.blobs,
				Budget: cache.Budget{PerEntity: map[string]int64{"dockerhub": -1}}},
		},
		{
			name: "headroom past the cap",
			opts: cache.Options{Meta: env.meta, Blobs: env.blobs, Headroom: 0.9},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			evictor, err := cache.New(tc.opts)
			if !errors.Is(err, cache.ErrInvalidOptions) {
				t.Fatalf("New error = %v, want ErrInvalidOptions", err)
			}
			if evictor != nil {
				t.Error("New returned an evictor alongside an error")
			}
		})
	}
}

func TestSweepLeavesACacheInsideItsBudgetAlone(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	digest := env.putBlob("dockerhub/library/nginx", "layer-one", testTime)

	// A store that fails every listing: reaching one would mean the sweep
	// looked for something to evict from a cache that is inside its budget.
	store := &stubStore{inner: env.meta, list: func(context.Context, string, int) ([]meta.CachedItem, error) {
		return nil, errFailed
	}}
	evictor := env.evictor(cache.Budget{Global: 1024}, func(o *cache.Options) { o.Meta = store })

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Manifests+result.Blobs != 0 {
		t.Errorf("evicted %d rows from a cache inside its budget", result.Manifests+result.Blobs)
	}
	if store.called("ListEvictable") {
		t.Error("listed evictable content for a cache inside its budget")
	}
	if !env.hasBlobRow("dockerhub/library/nginx", digest) {
		t.Error("the row is gone")
	}
	if len(result.Scopes) != 1 || result.Scopes[0].Before != result.Scopes[0].After {
		t.Errorf("scopes = %+v, want one untouched global scope", result.Scopes)
	}
}

func TestSweepEvictsLeastRecentlyUsedFirst(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	// Nine bytes each, five rows, forty-five bytes held.
	coldest := env.putBlob(repo, "layer-one", testTime.Add(-4*time.Hour))
	colder := env.putBlob(repo, "layer-two", testTime.Add(-3*time.Hour))
	warm := env.putBlob(repo, "layer-fiv", testTime.Add(-time.Hour))
	hot := env.putBlob(repo, "layer-six", testTime)

	// A budget of 20 with no headroom leaves room for two rows.
	evictor := env.evictor(cache.Budget{Global: 20}, func(o *cache.Options) { o.Headroom = -1 })
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if result.Blobs != 2 || result.Bytes != 18 {
		t.Errorf("evicted %d blobs / %d bytes, want 2 / 18", result.Blobs, result.Bytes)
	}
	for _, gone := range []blob.Digest{coldest, colder} {
		if env.hasBlobRow(repo, gone) {
			t.Errorf("%s survived; the coldest rows go first", gone)
		}
		if env.hasBytes(gone) {
			t.Errorf("%s kept its bytes; the last claim went with the row", gone)
		}
	}
	for _, kept := range []blob.Digest{warm, hot} {
		if !env.hasBlobRow(repo, kept) {
			t.Errorf("%s was evicted; it is warmer than what remained", kept)
		}
	}
	if usage := env.usage(""); usage.Bytes != 18 {
		t.Errorf("usage after the sweep = %d bytes, want 18", usage.Bytes)
	}
}

func TestSweepGoesUnderTheBudgetByItsHeadroom(t *testing.T) {
	t.Parallel()

	// Ten rows of nine bytes, a budget of 90 exceeded by one row, and the
	// default 5% headroom: stopping at the budget would evict one row and
	// leave the cache one byte from being swept again.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	for i := range 11 {
		env.putBlob(repo, string(rune('a'+i))+"-cache-x", testTime.Add(time.Duration(i)*time.Minute))
	}
	if usage := env.usage(""); usage.Bytes != 99 {
		t.Fatalf("fixture usage = %d bytes, want 99", usage.Bytes)
	}

	evictor := env.evictor(cache.Budget{Global: 90})
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// Target is 90 - 4 (5% truncated) = 86, so two rows go, not one.
	if result.Blobs != 2 {
		t.Errorf("evicted %d rows, want 2 (one for the breach, one for the headroom)", result.Blobs)
	}
	if got, want := env.usage("").Bytes, int64(81); got != want {
		t.Errorf("usage after the sweep = %d, want %d", got, want)
	}
	scope := result.Scopes[len(result.Scopes)-1]
	if scope.Target != 86 || scope.Before != 99 || scope.After != 81 {
		t.Errorf("scope = %+v, want target 86, before 99, after 81", scope)
	}
}

func TestSweepReclaimsBytesOnlyWhenTheLastClaimGoes(t *testing.T) {
	t.Parallel()

	// Two proxies that both cached the same layer. The bytes are stored once,
	// content-addressed, and the rows are what the budget counts.
	env := newEnv(t, "dockerhub", "quay")
	shared := env.putBlob("dockerhub/library/nginx", "shared-layer", testTime.Add(-time.Hour))
	if got := env.putBlob("quay/other/app", "shared-layer", testTime); got != shared {
		t.Fatalf("the fixture did not share a digest: %s != %s", got, shared)
	}

	// A carve-out that only dockerhub breaches: its claim goes, quay's stays,
	// and the bytes must survive because quay can still serve them.
	evictor := env.evictor(cache.Budget{PerEntity: map[string]int64{"dockerhub": 1}})
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if result.Blobs != 1 || result.Shared != 1 {
		t.Errorf("result = %d blobs / %d shared, want 1 / 1", result.Blobs, result.Shared)
	}
	if env.hasBlobRow("dockerhub/library/nginx", shared) {
		t.Error("dockerhub kept its claim")
	}
	if !env.hasBlobRow("quay/other/app", shared) {
		t.Error("quay lost its claim to another proxy's eviction")
	}
	if !env.hasBytes(shared) {
		t.Fatal("the shared bytes were reclaimed while another proxy still claimed them")
	}

	// Now take quay's claim too: the last one out reclaims the bytes.
	last := env.evictor(cache.Budget{PerEntity: map[string]int64{"quay": 1}})
	if _, err := last.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if env.hasBytes(shared) {
		t.Error("the bytes outlived their last claim")
	}
}

func TestSweepEvictsManifestsWithoutTouchingTheBlobStore(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	cold := env.putManifest(repo, "manifest-cold", testTime.Add(-time.Hour))
	hot := env.putManifest(repo, "manifest-hot!", testTime)
	blobs := &stubBlobs{inner: env.blobs}

	evictor := env.evictor(cache.Budget{Global: 13}, func(o *cache.Options) {
		o.Blobs = blobs
		o.Headroom = -1
	})
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if result.Manifests != 1 || result.Blobs != 0 {
		t.Errorf("result = %d manifests / %d blobs, want 1 / 0", result.Manifests, result.Blobs)
	}
	if deletions := blobs.deletions(); len(deletions) != 0 {
		// A manifest's payload is its row. Deleting a blob for one would mean
		// the digest was looked up in a store that never held it.
		t.Errorf("deleted %v from the blob store for a manifest eviction", deletions)
	}
	if env.hasManifestRow(repo, cold) {
		t.Error("the colder manifest survived")
	}
	if !env.hasManifestRow(repo, hot) {
		t.Error("the hotter manifest was evicted")
	}
}

func TestSweepRanksManifestsAndBlobsInOneOrder(t *testing.T) {
	t.Parallel()

	// They compete for one budget, so the coldest thing goes whichever kind it
	// is -- a cache that always evicted blobs first would keep a stale
	// manifest ahead of a layer somebody is pulling.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	coldManifest := env.putManifest(repo, "manifest!!", testTime.Add(-2*time.Hour))
	coldBlob := env.putBlob(repo, "layer-one!", testTime.Add(-time.Hour))
	hotBlob := env.putBlob(repo, "layer-two!", testTime)

	evictor := env.evictor(cache.Budget{Global: 10}, func(o *cache.Options) { o.Headroom = -1 })
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if result.Manifests != 1 || result.Blobs != 1 {
		t.Errorf("result = %d manifests / %d blobs, want 1 / 1", result.Manifests, result.Blobs)
	}
	if env.hasManifestRow(repo, coldManifest) {
		t.Error("the coldest row was a manifest and it survived")
	}
	if env.hasBlobRow(repo, coldBlob) {
		t.Error("the second-coldest row survived")
	}
	if !env.hasBlobRow(repo, hotBlob) {
		t.Error("the hottest row was evicted")
	}
}

func TestSweepEnforcesCarveOutsBeforeTheGlobalBudget(t *testing.T) {
	t.Parallel()

	// dockerhub is over its own carve-out; quay is not. A global-first sweep
	// would rank both together and take quay's older content, leaving the
	// greedy proxy over the ceiling its operator set for it.
	env := newEnv(t, "dockerhub", "quay")
	greedy := env.putBlob("dockerhub/library/nginx", "greedy-la", testTime)
	polite := env.putBlob("quay/other/app", "polite-la", testTime.Add(-10*time.Hour))

	evictor := env.evictor(cache.Budget{
		Global:    1000,
		PerEntity: map[string]int64{"dockerhub": 1, "quay": 1000},
	})
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if env.hasBlobRow("dockerhub/library/nginx", greedy) {
		t.Error("the proxy over its carve-out kept its content")
	}
	if !env.hasBlobRow("quay/other/app", polite) {
		t.Error("a proxy inside its carve-out lost older content to another's breach")
	}

	var order []string
	for _, scope := range result.Scopes {
		order = append(order, scope.Entity)
	}
	if len(order) != 3 || order[0] != "dockerhub" || order[1] != "quay" || order[2] != "" {
		t.Errorf("scope order = %v, want [dockerhub quay <global>]", order)
	}
}

func TestSweepCarveOutsDoNotExemptFromTheGlobalBudget(t *testing.T) {
	t.Parallel()

	// The carve-out is a ceiling, not an allocation: the disk is finite
	// whatever the per-proxy configuration says.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	cold := env.putBlob(repo, "layer-one", testTime.Add(-time.Hour))
	hot := env.putBlob(repo, "layer-two", testTime)

	evictor := env.evictor(cache.Budget{
		Global:    9,
		PerEntity: map[string]int64{"dockerhub": 1000},
	}, func(o *cache.Options) { o.Headroom = -1 })
	if _, err := evictor.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if env.hasBlobRow(repo, cold) {
		t.Error("the global budget did not reach a proxy that was inside its carve-out")
	}
	if !env.hasBlobRow(repo, hot) {
		t.Error("the global pass took more than it needed")
	}
}

func TestSweepIsUnboundedWhenNoBudgetIsSet(t *testing.T) {
	t.Parallel()

	// A deployment that configured nothing gets a cache that grows -- visible
	// in the storage metrics -- rather than one that empties itself because a
	// config key was missing.
	env := newEnv(t, "dockerhub")
	digest := env.putBlob("dockerhub/library/nginx", "layer-one", testTime)
	store := &stubStore{inner: env.meta}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Meta = store })
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if len(result.Scopes) != 0 {
		t.Errorf("scopes = %+v, want none: an unbounded scope is not swept", result.Scopes)
	}
	if store.called("CachedUsage") {
		t.Error("read usage for an unbounded cache; the answer could not have changed anything")
	}
	if !env.hasBlobRow("dockerhub/library/nginx", digest) {
		t.Error("evicted from an unbounded cache")
	}
}

func TestSweepPublishesOneEvictionEventPerRow(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime.Add(-time.Hour))
	env.putBlob(repo, "layer-two", testTime)

	evictor := env.evictor(cache.Budget{Global: 9}, func(o *cache.Options) { o.Headroom = -1 })
	if _, err := evictor.Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	payloads := env.events.evictedPayloads(t)
	if len(payloads) != 1 {
		t.Fatalf("published %d events, want 1", len(payloads))
	}
	want := payloads[0]
	if want.Repository != repo || want.Digest != digest.String() || want.Size != 9 || want.Reason != "budget" {
		t.Errorf("payload = %+v, want %s / %s / 9 / budget", want, repo, digest)
	}
}

func TestSweepSurvivesAFailedDelete(t *testing.T) {
	t.Parallel()

	// One row the store refuses, one it does not. The sweep reports the
	// failure and reclaims what it can: a broken row must not stop a cache
	// from staying inside its budget.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	stuck := env.putBlob(repo, "layer-one", testTime.Add(-2*time.Hour))
	next := env.putBlob(repo, "layer-two", testTime.Add(-time.Hour))
	env.putBlob(repo, "layer-six", testTime)

	store := &stubStore{inner: env.meta, delBlob: func(ctx context.Context, repo string, digest meta.Digest) (int64, error) {
		if digest == meta.Digest(stuck) {
			return 0, errFailed
		}
		return env.meta.DeleteCachedBlob(ctx, repo, digest)
	}}
	evictor := env.evictor(cache.Budget{Global: 18}, func(o *cache.Options) {
		o.Meta = store
		o.Headroom = -1
	})

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep returned an error for a row it could not delete: %v", err)
	}
	if result.Failed != 1 || result.Blobs != 1 {
		t.Errorf("result = %d failed / %d evicted, want 1 / 1", result.Failed, result.Blobs)
	}
	if !env.hasBlobRow(repo, stuck) {
		t.Error("the refused row went anyway")
	}
	if env.hasBlobRow(repo, next) {
		t.Error("the sweep stopped at the first failure instead of continuing")
	}
}

func TestSweepStopsWhenAWholePageFails(t *testing.T) {
	t.Parallel()

	// Every delete failing means the next listing returns the same rows in the
	// same order for the same reasons. Stopping is what keeps a broken store
	// from becoming a spin.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	env.putBlob(repo, "layer-one", testTime.Add(-time.Hour))
	env.putBlob(repo, "layer-two", testTime)

	var listings int
	store := &stubStore{
		inner: env.meta,
		list: func(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error) {
			listings++
			if listings > 4 {
				t.Fatal("the sweep kept listing after a page it could not evict from")
			}
			return env.meta.ListEvictable(ctx, entity, limit)
		},
		delBlob: func(context.Context, string, meta.Digest) (int64, error) { return 0, errFailed },
	}
	evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) { o.Meta = store })

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if listings != 1 {
		t.Errorf("listed %d pages, want 1", listings)
	}
	if result.Failed != 2 {
		t.Errorf("failed = %d, want 2 (the whole page)", result.Failed)
	}
}

func TestSweepStopsWhenNothingIsEvictable(t *testing.T) {
	t.Parallel()

	// Usage says over budget and the listing is empty: a concurrent delete
	// beat the sweep to everything. The next sweep reads a usage that agrees
	// again; this one must not loop waiting for it.
	env := newEnv(t, "dockerhub")
	store := &stubStore{
		inner: env.meta,
		usage: func(context.Context, string) (meta.CacheUsage, error) {
			return meta.CacheUsage{Bytes: 1 << 30}, nil
		},
	}
	evictor := env.evictor(cache.Budget{Global: 10}, func(o *cache.Options) { o.Meta = store })

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Manifests+result.Blobs+result.Failed != 0 {
		t.Errorf("result = %+v, want nothing evicted and nothing failed", result)
	}
}

func TestSweepCountsRowsAnotherWriterAlreadyRemoved(t *testing.T) {
	t.Parallel()

	// A repository deletion, or a concurrent sweep, got there first. The space
	// is reclaimed either way, so it is not a failure -- but it is not an
	// eviction this sweep can claim, and no event is published for content it
	// did not remove.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	env.putBlob(repo, "layer-one", testTime.Add(-time.Hour))
	env.putManifest(repo, "manifest!", testTime.Add(-2*time.Hour))

	store := &stubStore{
		inner: env.meta,
		delBlob: func(context.Context, string, meta.Digest) (int64, error) {
			return 0, meta.NotFound("cached blob", "gone")
		},
		delMan: func(context.Context, string, meta.Digest) error { return meta.NotFound("cached manifest", "gone") },
	}
	evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) { o.Meta = store })

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Skipped != 2 || result.Failed != 0 || result.Blobs != 0 || result.Manifests != 0 {
		t.Errorf("result = %+v, want 2 skipped and nothing else", result)
	}
	if events := env.events.all(); len(events) != 0 {
		t.Errorf("published %d events for rows it did not remove", len(events))
	}
}

func TestSweepLeavesUnreclaimableBytesToTheOrphanPass(t *testing.T) {
	t.Parallel()

	// The row is gone and the bytes would not delete. The budget is right --
	// usage counts rows -- and the disk catches up on the orphan pass's
	// schedule, so this is not a sweep failure.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)
	blobs := &stubBlobs{inner: env.blobs, del: func(context.Context, blob.Digest) error { return errFailed }}

	evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) { o.Blobs = blobs })
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if result.Blobs != 1 || result.Failed != 0 {
		t.Errorf("result = %d evicted / %d failed, want 1 / 0", result.Blobs, result.Failed)
	}
	if env.hasBlobRow(repo, digest) {
		t.Error("the row survived a successful delete")
	}
	if !env.hasBytes(digest) {
		t.Error("the fixture did not leave the bytes behind")
	}
}

func TestSweepIgnoresABlobStoreThatHasAlreadyForgottenTheBytes(t *testing.T) {
	t.Parallel()

	// Bytes an earlier orphan pass took, or a driver that lost them. Already
	// gone is the outcome the eviction asked for.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)
	if err := env.blobs.Delete(context.Background(), digest); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	evictor := env.evictor(cache.Budget{Global: 1})
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Blobs != 1 || result.Failed != 0 {
		t.Errorf("result = %d evicted / %d failed, want 1 / 0", result.Blobs, result.Failed)
	}
}

func TestSweepSkipsARowOfAnUnknownKind(t *testing.T) {
	t.Parallel()

	// A store that invented a kind. Counting it as evicted would make the
	// sweep's arithmetic drift from the usage it re-reads next time, so it is
	// a failure and the page-level guard stops the pass.
	env := newEnv(t, "dockerhub")
	store := &stubStore{
		inner: env.meta,
		usage: func(context.Context, string) (meta.CacheUsage, error) {
			return meta.CacheUsage{Bytes: 100}, nil
		},
		list: func(context.Context, string, int) ([]meta.CachedItem, error) {
			return []meta.CachedItem{{
				Repository: "dockerhub/library/nginx", Digest: "sha256:whatever",
				Kind: meta.CachedKind("lease"), Size: 10,
			}}, nil
		},
	}
	evictor := env.evictor(cache.Budget{Global: 10}, func(o *cache.Options) { o.Meta = store })

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Failed != 1 || result.Blobs != 0 || result.Manifests != 0 {
		t.Errorf("result = %+v, want one failure and nothing evicted", result)
	}
}

func TestSweepSkipsAnUnparseableDigest(t *testing.T) {
	t.Parallel()

	// The row goes -- the store is authoritative about its own rows -- but
	// nothing is handed to the blob store, because a digest that will not
	// parse is not a path anything may be built from.
	env := newEnv(t, "dockerhub")
	blobs := &stubBlobs{inner: env.blobs}
	store := &stubStore{
		inner: env.meta,
		usage: func(context.Context, string) (meta.CacheUsage, error) {
			return meta.CacheUsage{Bytes: 100}, nil
		},
		list: func(context.Context, string, int) ([]meta.CachedItem, error) {
			return []meta.CachedItem{{
				Repository: "dockerhub/library/nginx", Digest: "../../etc/passwd",
				Kind: meta.CachedBlobKind, Size: 100,
			}}, nil
		},
		delBlob: func(context.Context, string, meta.Digest) (int64, error) { return 0, nil },
	}
	evictor := env.evictor(cache.Budget{Global: 10}, func(o *cache.Options) {
		o.Meta = store
		o.Blobs = blobs
	})

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Blobs != 1 {
		t.Errorf("evicted %d rows, want 1", result.Blobs)
	}
	if deletions := blobs.deletions(); len(deletions) != 0 {
		t.Errorf("handed %v to the blob store; an unparseable digest never reaches storage", deletions)
	}
}

func TestSweepReportsAStoreItCannotRead(t *testing.T) {
	t.Parallel()

	// The distinction the caller needs: a sweep that does not know what it is
	// looking at is an error, and content it could not evict is a count.
	env := newEnv(t, "dockerhub")
	env.putBlob("dockerhub/library/nginx", "layer-one", testTime)

	for _, tc := range []struct {
		name  string
		store *stubStore
	}{
		{
			name: "usage",
			store: &stubStore{inner: env.meta, usage: func(context.Context, string) (meta.CacheUsage, error) {
				return meta.CacheUsage{}, errFailed
			}},
		},
		{
			name: "listing",
			store: &stubStore{inner: env.meta, list: func(context.Context, string, int) ([]meta.CachedItem, error) {
				return nil, errFailed
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) { o.Meta = tc.store })
			if _, err := evictor.Sweep(context.Background()); !errors.Is(err, errFailed) {
				t.Fatalf("Sweep error = %v, want the store's failure", err)
			}
		})
	}
}

func TestSweepReportsACarveOutItCannotRead(t *testing.T) {
	t.Parallel()

	// A carve-out pass that cannot read its scope stops the whole sweep. The
	// global pass that would follow reads the same store, so continuing would
	// be asking a broken store the same question with a wider scope.
	env := newEnv(t, "dockerhub")
	env.putBlob("dockerhub/library/nginx", "layer-one", testTime)
	store := &stubStore{inner: env.meta, usage: func(_ context.Context, entity string) (meta.CacheUsage, error) {
		if entity == "dockerhub" {
			return meta.CacheUsage{}, errFailed
		}
		return meta.CacheUsage{}, nil
	}}

	evictor := env.evictor(cache.Budget{
		Global:    1000,
		PerEntity: map[string]int64{"dockerhub": 1},
	}, func(o *cache.Options) { o.Meta = store })

	result, err := evictor.Sweep(context.Background())
	if !errors.Is(err, errFailed) {
		t.Fatalf("Sweep error = %v, want the store's failure", err)
	}
	if len(result.Scopes) != 0 {
		t.Errorf("scopes = %+v, want none: the pass never got past its usage read", result.Scopes)
	}
}

func TestSweepSurvivesAFailedManifestDelete(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	stuck := env.putManifest(repo, "manifest-a", testTime.Add(-2*time.Hour))
	env.putManifest(repo, "manifest-b", testTime.Add(-time.Hour))
	env.putManifest(repo, "manifest-c", testTime)

	store := &stubStore{inner: env.meta, delMan: func(ctx context.Context, repo string, digest meta.Digest) error {
		if digest == meta.Digest(stuck) {
			return errFailed
		}
		return env.meta.DeleteCachedManifest(ctx, repo, digest)
	}}
	evictor := env.evictor(cache.Budget{Global: 20}, func(o *cache.Options) {
		o.Meta = store
		o.Headroom = -1
	})

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Failed != 1 || result.Manifests != 1 {
		t.Errorf("result = %d failed / %d evicted, want 1 / 1", result.Failed, result.Manifests)
	}
	if !env.hasManifestRow(repo, stuck) {
		t.Error("the refused row went anyway")
	}
}

func TestSweepRunsWithoutAPublisherOrALogger(t *testing.T) {
	t.Parallel()

	// A deployment whose event system is not wired yet, and the package
	// defaults for the logger. Neither is a reason for eviction not to work.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	digest := env.putBlob(repo, "layer-one", testTime)

	evictor, err := cache.New(cache.Options{
		Meta: env.meta, Blobs: env.blobs, Budget: cache.Budget{Global: 1},
	})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Blobs != 1 {
		t.Errorf("evicted %d rows, want 1", result.Blobs)
	}
	if env.hasBlobRow(repo, digest) {
		t.Error("the row survived")
	}

	// The orphan pass publishes through the same nil sink.
	if _, err := evictor.SweepOrphans(context.Background()); err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
}

func TestSweepStopsOnACancelledContext(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	env.putBlob(repo, "layer-one", testTime.Add(-time.Hour))
	env.putBlob(repo, "layer-two", testTime)

	ctx, cancel := context.WithCancel(context.Background())
	store := &stubStore{inner: env.meta, delBlob: func(c context.Context, repo string, digest meta.Digest) (int64, error) {
		// Cancelled between rows: the sweep must notice before the next one.
		cancel()
		return env.meta.DeleteCachedBlob(context.WithoutCancel(c), repo, digest)
	}}
	evictor := env.evictor(cache.Budget{Global: 1}, func(o *cache.Options) { o.Meta = store })

	if _, err := evictor.Sweep(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sweep error = %v, want context.Canceled", err)
	}
	if got := env.usage("").Blobs; got != 1 {
		t.Errorf("%d rows left, want 1: the sweep continued past cancellation", got)
	}
}

func TestSweepPagesThroughALargeCache(t *testing.T) {
	t.Parallel()

	// More rows over budget than one page holds. The sweep takes a page,
	// evicts from it, and comes back -- the listing is a bound on memory, not
	// on how much a sweep may reclaim.
	env := newEnv(t, "dockerhub")
	repo := "dockerhub/library/nginx"
	for i := range 20 {
		env.putBlob(repo, "cache-row-"+string(rune('a'+i)), testTime.Add(time.Duration(i)*time.Minute))
	}

	var listings int
	store := &stubStore{inner: env.meta, list: func(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error) {
		listings++
		return env.meta.ListEvictable(ctx, entity, limit)
	}}
	evictor := env.evictor(cache.Budget{Global: 44}, func(o *cache.Options) {
		o.Meta = store
		o.PageSize = 3
		o.Headroom = -1
	})

	result, err := evictor.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Blobs != 16 {
		t.Errorf("evicted %d rows, want 16", result.Blobs)
	}
	if listings < 6 {
		t.Errorf("listed %d pages for 16 evictions at a page size of 3, want at least 6", listings)
	}
	if got := env.usage("").Bytes; got > 44 {
		t.Errorf("usage after the sweep = %d, want at most 44", got)
	}
}
