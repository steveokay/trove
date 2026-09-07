// Package gcrace runs garbage collection against real pushes, concurrently,
// over the real SQLite store and a real filesystem blob store (P-008).
//
// The deterministic matrix lives in internal/gc's race_test.go: it places a
// push at an exact point in a sweep and asserts the outcome. This is the other
// half — nobody chooses the interleaving, the store is the one a deployment
// runs, and the assertion is the invariant rather than a sequence:
//
//	**every blob a live manifest references still has its row and its bytes.**
//
// That is the property whose violation is silent. A pull fails weeks later with
// a 404 on a layer, and nothing in the logs says which sweep took it.
//
// It is bounded to a second or two and runs in the normal suite. The plan asked
// for a nightly job; a chaos test nobody watches nightly is worth less than a
// bounded one that runs on every commit, and the bound is what keeps it from
// being the flaky test §9 forbids.
package gcrace_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobfs "github.com/steveokay/trove/internal/blob/fs"
	"github.com/steveokay/trove/internal/gc"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlite"
)

const (
	entity = "team-a"
	repo   = "team-a/api"

	// pushers is how many clients push at once, and pushesEach how many images
	// each of them completes. Small enough to stay under a second, large
	// enough that the sweep and the pushes genuinely overlap.
	pushers    = 8
	pushesEach = 12

	// grace is the window a pushed blob is protected by. The real default is
	// 24h; a short one here makes the sweep actually reach the content this
	// test creates, which is the only way the race is live.
	grace = 250 * time.Millisecond
)

// TestPushesSurviveConcurrentCollection is the invariant test.
//
// Eight clients push complete images -- upload session, blob, manifest, and
// the session released, in the order the registry does it -- while a collector
// sweeps continuously with a short grace window. Afterwards every manifest's
// layers must still be there, rows and bytes both.
func TestPushesSurviveConcurrentCollection(t *testing.T) {
	env := newEnv(t)

	// Garbage to give the sweep real work: unreferenced blobs, old enough to
	// be collectable immediately.
	for i := range 40 {
		env.putGarbage(t, fmt.Sprintf("garbage-%d", i))
	}

	ctx, cancel := context.WithCancel(context.Background())
	var sweeps atomic.Int64
	var sweepErr atomic.Pointer[error]

	var collectors sync.WaitGroup
	collectors.Add(1)
	go func() {
		defer collectors.Done()
		for ctx.Err() == nil {
			if _, err := env.collector.Run(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				sweepErr.Store(&err)
				return
			}
			sweeps.Add(1)
		}
	}()

	var clients sync.WaitGroup
	for p := range pushers {
		clients.Add(1)
		go func() {
			defer clients.Done()
			for i := range pushesEach {
				env.push(t, fmt.Sprintf("p%d-i%d", p, i))
			}
		}()
	}
	clients.Wait()
	deletedDuringPushes := env.counted.deletes.Load()

	// One more full sweep after the pushes stop, past the grace window, so the
	// collector has had every chance to take something it should not have.
	time.Sleep(2 * grace)
	if _, err := env.collector.Run(context.Background()); err != nil {
		t.Fatalf("final sweep: %v", err)
	}
	cancel()
	collectors.Wait()

	if err := sweepErr.Load(); err != nil {
		t.Fatalf("a sweep failed: %v", *err)
	}
	// Deletes performed *while clients were still pushing* are what make this
	// a race rather than a sequence. Without this the test could pass by
	// collecting nothing until everything was safely written.
	if deletedDuringPushes == 0 {
		t.Fatal("the collector deleted nothing while the pushes ran; nothing was actually raced")
	}
	if sweeps.Load() == 0 {
		t.Fatal("no sweep ever completed")
	}

	env.assertEveryReferencedBlobIsIntact(t)
	env.assertGarbageWasCollected(t)
}

// countingStore records the deletes the collector actually performs, so the
// test can prove the sweep was doing work *while* clients pushed rather than
// only afterwards. Counting completed sweeps is too coarse: a full pass over
// the fixture takes longer than the pushes do, and a sweep that deleted forty
// blobs mid-push is overlap whether or not it finished.
type countingStore struct {
	inner   gc.Store
	deletes atomic.Int64
}

func (s *countingStore) ListSweepCandidates(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
	return s.inner.ListSweepCandidates(ctx, before, after, limit)
}

func (s *countingStore) DeleteBlobIfUnreferenced(ctx context.Context, digest meta.Digest, before time.Time) (bool, error) {
	deleted, err := s.inner.DeleteBlobIfUnreferenced(ctx, digest, before)
	if deleted {
		s.deletes.Add(1)
	}
	return deleted, err
}

func (s *countingStore) StartGCRun(ctx context.Context, run meta.GCRun) error {
	return s.inner.StartGCRun(ctx, run)
}

func (s *countingStore) SaveGCProgress(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freed int64) error {
	return s.inner.SaveGCProgress(ctx, id, cursor, scanned, deleted, freed)
}

func (s *countingStore) FinishGCRun(ctx context.Context, id string, at time.Time, failure string) error {
	return s.inner.FinishGCRun(ctx, id, at, failure)
}

func (s *countingStore) ResumableGCRun(ctx context.Context) (meta.GCRun, error) {
	return s.inner.ResumableGCRun(ctx)
}

// env is the deployment under test: a real SQLite store and a real filesystem
// blob store, with a collector over them.
type env struct {
	meta      *sqlite.Store
	blobs     *blobfs.Store
	collector *gc.Collector
	counted   *countingStore

	// pushed records every (manifest, layer) a client completed, so the
	// invariant can be checked against what was actually pushed rather than
	// against what the store happens to contain.
	mu     sync.Mutex
	pushed map[blob.Digest]blob.Digest

	garbage []blob.Digest
	ids     atomic.Int64
}

func newEnv(t *testing.T) *env {
	t.Helper()

	dir := t.TempDir()
	store, err := sqlite.Open(context.Background(), sqlite.Options{Path: filepath.Join(dir, "trove.db")})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: entity, Type: meta.Hosted, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	blobs, err := blobfs.New(blobfs.Options{Root: filepath.Join(dir, "hosted")})
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}

	e := &env{meta: store, blobs: blobs, pushed: map[blob.Digest]blob.Digest{}}
	e.counted = &countingStore{inner: store}
	collector, err := gc.New(gc.Options{
		Meta: e.counted, Blobs: blobs, Grace: grace, BatchSize: 4,
		NewID: func() string { return fmt.Sprintf("gcrace-%d", e.ids.Add(1)) },
		Log:   slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1})),
	})
	if err != nil {
		t.Fatalf("gc.New: %v", err)
	}
	e.collector = collector
	return e
}

// push completes one image the way the registry does: a session that pins the
// digest, the bytes, the blob row, the session released, and only then the
// manifest.
//
// The order is the point. Between releasing the session and writing the
// manifest there is a window where the blob is unreferenced and unpinned, and
// the only thing protecting it is the grace window -- which is exactly the
// claim ADR 0010 makes and exactly what this test is trying to break.
func (e *env) push(t *testing.T, seed string) {
	t.Helper()

	ctx := context.Background()
	layer := []byte("layer bytes for " + seed)
	layerDigest := blob.FromBytes(blob.SHA256, layer)
	sessionID := "upload-" + seed

	if err := e.meta.CreateUpload(ctx, meta.UploadSession{
		ID: sessionID, Repository: repo, Digest: meta.Digest(layerDigest),
		StartedAt: time.Now(), LastChunkAt: time.Now(),
	}); err != nil {
		t.Errorf("CreateUpload(%s): %v", seed, err)
		return
	}
	if err := e.blobs.Put(ctx, layerDigest, bytes.NewReader(layer)); err != nil {
		t.Errorf("blobs.Put(%s): %v", seed, err)
		return
	}
	if err := e.meta.PutBlob(ctx, meta.Blob{
		Digest: meta.Digest(layerDigest), Size: int64(len(layer)), CreatedAt: time.Now(),
	}); err != nil {
		t.Errorf("PutBlob(%s): %v", seed, err)
		return
	}
	if err := e.meta.DeleteUpload(ctx, sessionID); err != nil {
		t.Errorf("DeleteUpload(%s): %v", seed, err)
		return
	}

	payload := []byte(`{"schemaVersion":2,"seed":"` + seed + `"}`)
	manifestDigest := blob.FromBytes(blob.SHA256, payload)
	if err := e.meta.PutManifest(ctx, meta.Manifest{
		Repository: repo, Digest: meta.Digest(manifestDigest),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   payload, Size: int64(len(payload)), CreatedAt: time.Now(),
	}, []meta.ManifestRef{{Child: meta.Digest(layerDigest), Kind: meta.RefLayer}}); err != nil {
		t.Errorf("PutManifest(%s): %v", seed, err)
		return
	}

	e.mu.Lock()
	e.pushed[manifestDigest] = layerDigest
	e.mu.Unlock()
}

// putGarbage stores a blob nothing will ever reference, old enough to collect.
func (e *env) putGarbage(t *testing.T, seed string) {
	t.Helper()

	data := []byte("garbage " + seed)
	digest := blob.FromBytes(blob.SHA256, data)
	ctx := context.Background()
	if err := e.blobs.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := e.meta.PutBlob(ctx, meta.Blob{
		Digest: meta.Digest(digest), Size: int64(len(data)), CreatedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	e.garbage = append(e.garbage, digest)
}

// assertEveryReferencedBlobIsIntact is the invariant: for every manifest a
// client completed, the layer it names still has a row and bytes.
func (e *env) assertEveryReferencedBlobIsIntact(t *testing.T) {
	t.Helper()

	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.pushed) != pushers*pushesEach {
		t.Fatalf("%d pushes completed, want %d", len(e.pushed), pushers*pushesEach)
	}

	ctx := context.Background()
	for manifest, layer := range e.pushed {
		if _, err := e.meta.GetManifest(ctx, repo, meta.Digest(manifest)); err != nil {
			t.Fatalf("manifest %s went missing: %v", manifest, err)
		}
		if _, err := e.meta.GetBlob(ctx, meta.Digest(layer)); err != nil {
			t.Errorf("garbage collection took the row of layer %s, referenced by %s: %v", layer, manifest, err)
			continue
		}
		if _, err := e.blobs.Stat(ctx, layer); err != nil {
			t.Errorf("garbage collection took the bytes of layer %s, referenced by %s: %v", layer, manifest, err)
		}
	}
}

// assertGarbageWasCollected keeps the test honest. An invariant about what
// survived proves nothing if the collector never deleted anything.
func (e *env) assertGarbageWasCollected(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	var left int
	for _, digest := range e.garbage {
		if _, err := e.meta.GetBlob(ctx, meta.Digest(digest)); err == nil {
			left++
		}
	}
	if left > 0 {
		t.Errorf("%d of %d unreferenced blobs survived; the sweeps were not doing their job",
			left, len(e.garbage))
	}
}
