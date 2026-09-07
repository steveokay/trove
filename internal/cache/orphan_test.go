package cache_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/meta"
)

// orphan writes bytes into the cache store with no row naming them: what a
// fill that committed and then died leaves behind (C-004).
func (e *env) orphan(content string) blob.Digest {
	e.t.Helper()

	data := []byte(content)
	digest := blob.FromBytes(blob.SHA256, data)
	if err := e.blobs.Put(context.Background(), digest, bytes.NewReader(data)); err != nil {
		e.t.Fatalf("blobs.Put: %v", err)
	}
	return digest
}

func TestOrphanPassReclaimsBytesNothingClaims(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	claimed := env.putBlob("dockerhub/library/nginx", "claimed-layer", testTime)
	stray := env.orphan("interrupted-fill")

	evictor := env.evictor(cache.Budget{})
	result, err := evictor.SweepOrphans(context.Background())
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}

	if result.Scanned != 2 || result.Reclaimed != 1 || result.Failed != 0 {
		t.Errorf("result = %+v, want 2 scanned / 1 reclaimed / 0 failed", result)
	}
	if result.Bytes != int64(len("interrupted-fill")) {
		t.Errorf("bytes = %d, want %d", result.Bytes, len("interrupted-fill"))
	}
	if env.hasBytes(stray) {
		t.Error("the orphan survived")
	}
	if !env.hasBytes(claimed) {
		t.Error("bytes a proxy still claims were reclaimed")
	}
	if result.Truncated {
		t.Error("reported truncation for a pass that finished")
	}
}

func TestOrphanPassPublishesAnEvictionWithNoRepository(t *testing.T) {
	t.Parallel()

	// An orphan has no owner -- that is what made it collectable -- so naming
	// one would be inventing a claim that nothing held.
	env := newEnv(t, "dockerhub")
	stray := env.orphan("interrupted-fill")

	evictor := env.evictor(cache.Budget{})
	if _, err := evictor.SweepOrphans(context.Background()); err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}

	payloads := env.events.evictedPayloads(t)
	if len(payloads) != 1 {
		t.Fatalf("published %d events, want 1", len(payloads))
	}
	got := payloads[0]
	if got.Repository != "" || got.Digest != stray.String() || got.Reason != "orphan" {
		t.Errorf("payload = %+v, want an empty repository, %s, reason orphan", got, stray)
	}
	if got.Size != int64(len("interrupted-fill")) {
		t.Errorf("size = %d, want %d", got.Size, len("interrupted-fill"))
	}
}

func TestOrphanPassKeepsEverythingWhenItCannotCountClaims(t *testing.T) {
	t.Parallel()

	// Without an answer there is no telling an orphan from a layer somebody is
	// serving, and the safe reading of "I do not know" is to keep the bytes.
	env := newEnv(t, "dockerhub")
	stray := env.orphan("interrupted-fill")
	blobs := &stubBlobs{inner: env.blobs}
	store := &stubStore{inner: env.meta, claims: func(context.Context, meta.Digest) (int64, error) {
		return 0, errFailed
	}}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) {
		o.Meta = store
		o.Blobs = blobs
	})
	if _, err := evictor.SweepOrphans(context.Background()); !errors.Is(err, errFailed) {
		t.Fatalf("SweepOrphans error = %v, want the store's failure", err)
	}
	if deletions := blobs.deletions(); len(deletions) != 0 {
		t.Errorf("deleted %v without knowing whether anything claimed them", deletions)
	}
	if !env.hasBytes(stray) {
		t.Error("the bytes are gone")
	}
}

func TestOrphanPassCountsBytesItCouldNotDelete(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	env.orphan("interrupted-fill")
	blobs := &stubBlobs{inner: env.blobs, del: func(context.Context, blob.Digest) error { return errFailed }}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Blobs = blobs })
	result, err := evictor.SweepOrphans(context.Background())
	if err != nil {
		t.Fatalf("SweepOrphans returned an error for bytes it could not delete: %v", err)
	}
	if result.Failed != 1 || result.Reclaimed != 0 || result.Bytes != 0 {
		t.Errorf("result = %+v, want 1 failed and nothing reclaimed", result)
	}
	if events := env.events.all(); len(events) != 0 {
		t.Errorf("published %d events for bytes that are still there", len(events))
	}
}

func TestOrphanPassTreatsAlreadyGoneAsReclaimed(t *testing.T) {
	t.Parallel()

	// Another pass, or an eviction, got there between the walk and the delete.
	// Already gone is the outcome this pass asked for.
	env := newEnv(t, "dockerhub")
	env.orphan("interrupted-fill")
	blobs := &stubBlobs{inner: env.blobs, del: func(context.Context, blob.Digest) error { return blob.ErrNotFound }}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Blobs = blobs })
	result, err := evictor.SweepOrphans(context.Background())
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if result.Reclaimed != 1 || result.Failed != 0 {
		t.Errorf("result = %+v, want 1 reclaimed", result)
	}
}

func TestOrphanPassStopsAtItsBoundAndSaysSo(t *testing.T) {
	t.Parallel()

	// The bound keeps one pass from holding a large digest list. What it left
	// behind is a number, not a silence (§9).
	env := newEnv(t, "dockerhub")
	for i := range 5 {
		env.orphan("interrupted-fill-" + string(rune('a'+i)))
	}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.MaxOrphans = 2 })
	result, err := evictor.SweepOrphans(context.Background())
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if !result.Truncated {
		t.Error("stopped at the bound without reporting it")
	}
	if result.Reclaimed != 2 {
		t.Errorf("reclaimed %d, want 2", result.Reclaimed)
	}
	if got := env.storedBlobs(); got != 3 {
		t.Errorf("%d blobs left in the store, want 3", got)
	}

	// The next pass continues where this one stopped.
	again, err := evictor.SweepOrphans(context.Background())
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if again.Reclaimed != 2 || !again.Truncated {
		t.Errorf("second pass = %+v, want 2 more reclaimed and truncated again", again)
	}
}

func TestOrphanPassReportsAStoreItCannotWalk(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	blobs := &stubBlobs{inner: env.blobs, walk: func(context.Context, func(blob.Descriptor) error) error {
		return errFailed
	}}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Blobs = blobs })
	if _, err := evictor.SweepOrphans(context.Background()); !errors.Is(err, errFailed) {
		t.Fatalf("SweepOrphans error = %v, want the store's failure", err)
	}
}

func TestOrphanPassStopsOnACancelledContext(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "dockerhub")
	for i := range 3 {
		env.orphan("interrupted-fill-" + string(rune('a'+i)))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	evictor := env.evictor(cache.Budget{})
	if _, err := evictor.SweepOrphans(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("SweepOrphans error = %v, want context.Canceled", err)
	}
	if got := env.storedBlobs(); got != 3 {
		t.Errorf("%d blobs left, want 3: a cancelled pass reclaimed something", got)
	}
}

func TestOrphanPassStopsBetweenDeletesOnCancellation(t *testing.T) {
	t.Parallel()

	// Cancelled after the walk, during the deletes: the pass stops where it is
	// rather than finishing a list it built before the caller changed its mind.
	env := newEnv(t, "dockerhub")
	for i := range 4 {
		env.orphan("interrupted-fill-" + string(rune('a'+i)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	blobs := &stubBlobs{inner: env.blobs, del: func(c context.Context, digest blob.Digest) error {
		cancel()
		return env.blobs.Delete(context.WithoutCancel(c), digest)
	}}
	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Blobs = blobs })

	if _, err := evictor.SweepOrphans(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("SweepOrphans error = %v, want context.Canceled", err)
	}
	if got := env.storedBlobs(); got != 3 {
		t.Errorf("%d blobs left, want 3: the pass kept deleting after cancellation", got)
	}
}

func TestOrphanPassStopsMidWalkOnCancellation(t *testing.T) {
	t.Parallel()

	// A driver that keeps enumerating after its context went. The pass stops
	// at the next descriptor rather than collecting a list nobody asked for.
	env := newEnv(t, "dockerhub")
	ctx, cancel := context.WithCancel(context.Background())
	var offered int
	blobs := &stubBlobs{inner: env.blobs, walk: func(_ context.Context, fn func(blob.Descriptor) error) error {
		cancel()
		for range 3 {
			offered++
			if err := fn(blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, []byte("x")), Size: 1}); err != nil {
				return err
			}
		}
		return nil
	}}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Blobs = blobs })
	if _, err := evictor.SweepOrphans(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("SweepOrphans error = %v, want context.Canceled", err)
	}
	if offered != 1 {
		t.Errorf("the walk offered %d descriptors, want 1: the pass kept scanning after cancellation", offered)
	}
}

func TestOrphanPassSkipsAnUnparseableDigest(t *testing.T) {
	t.Parallel()

	// A store that enumerated something that cannot be a digest. It cannot
	// have arrived through a fill, and this pass is not the place to decide
	// what to do about it -- but it must not become a path either.
	env := newEnv(t, "dockerhub")
	blobs := &stubBlobs{inner: env.blobs, walk: func(_ context.Context, fn func(blob.Descriptor) error) error {
		return fn(blob.Descriptor{Digest: "../../etc/passwd", Size: 7})
	}}

	evictor := env.evictor(cache.Budget{}, func(o *cache.Options) { o.Blobs = blobs })
	result, err := evictor.SweepOrphans(context.Background())
	if err != nil {
		t.Fatalf("SweepOrphans: %v", err)
	}
	if result.Failed != 1 || result.Reclaimed != 0 {
		t.Errorf("result = %+v, want 1 failed and nothing reclaimed", result)
	}
	if deletions := blobs.deletions(); len(deletions) != 0 {
		t.Errorf("handed %v to the blob store", deletions)
	}
}
