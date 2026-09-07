package gc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmemory "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/gc"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
)

// testTime is the instant every fixture is built at. The clock is injected
// (§7), so a grace window expiring is a value a test chose.
var testTime = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// env is a registry with hosted content: a metadata store, the hosted blob
// store, and the collector between them. There is no cached store in it --
// the separation this package keeps is that it is never handed one.
type env struct {
	t      *testing.T
	meta   *metamemory.Store
	blobs  *blobmemory.Store
	events *recorder
	clock  *clock
	ids    *ids
}

func newEnv(t *testing.T) *env {
	t.Helper()

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: "team-a", Type: meta.Hosted, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	return &env{
		t: t, meta: store, blobs: blobmemory.New(blobmemory.Options{}),
		events: &recorder{}, clock: &clock{now: testTime}, ids: &ids{},
	}
}

// collector builds one over the env, with whatever a test needs different.
func (e *env) collector(tweak ...func(*gc.Options)) *gc.Collector {
	e.t.Helper()

	opts := gc.Options{
		Meta: e.meta, Blobs: e.blobs, Events: e.events,
		NewID: e.ids.next, Now: e.clock.Now, Log: discardLogger(),
	}
	for _, apply := range tweak {
		apply(&opts)
	}
	collector, err := gc.New(opts)
	if err != nil {
		e.t.Fatalf("gc.New: %v", err)
	}
	return collector
}

// putBlob stores a hosted blob: the bytes and the row, as a push does.
func (e *env) putBlob(content string, createdAt time.Time) blob.Digest {
	e.t.Helper()

	data := []byte(content)
	digest := blob.FromBytes(blob.SHA256, data)
	ctx := context.Background()
	if err := e.blobs.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		e.t.Fatalf("blobs.Put: %v", err)
	}
	if err := e.meta.PutBlob(ctx, meta.Blob{
		Digest: meta.Digest(digest), Size: int64(len(data)), CreatedAt: createdAt,
	}); err != nil {
		e.t.Fatalf("PutBlob: %v", err)
	}
	return digest
}

// putManifest stores a manifest referencing the given blobs as layers, which
// is what makes them unreachable to a sweep.
func (e *env) putManifest(name string, layers ...blob.Digest) blob.Digest {
	e.t.Helper()

	payload := []byte(`{"schemaVersion":2,"name":"` + name + `"}`)
	digest := blob.FromBytes(blob.SHA256, payload)
	refs := make([]meta.ManifestRef, 0, len(layers))
	for _, layer := range layers {
		refs = append(refs, meta.ManifestRef{Child: meta.Digest(layer), Kind: meta.RefLayer})
	}
	if err := e.meta.PutManifest(context.Background(), meta.Manifest{
		Repository: "team-a/api", Digest: meta.Digest(digest),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   payload, Size: int64(len(payload)), CreatedAt: testTime,
	}, refs); err != nil {
		e.t.Fatalf("PutManifest: %v", err)
	}
	return digest
}

// hasRow reports whether the blob's metadata row survives.
func (e *env) hasRow(digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.meta.GetBlob(context.Background(), meta.Digest(digest))
	return err == nil
}

// hasBytes reports whether the hosted blob store still holds the content.
func (e *env) hasBytes(digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.blobs.Stat(context.Background(), digest)
	return err == nil
}

// survives asserts that both halves of a blob are intact. Losing either is a
// failure: bytes without a row are a leak, and a row without bytes is the
// corruption this design refuses to create.
func (e *env) survives(digest blob.Digest, what string) {
	e.t.Helper()

	if !e.hasRow(digest) {
		e.t.Errorf("%s: the metadata row was deleted", what)
	}
	if !e.hasBytes(digest) {
		e.t.Errorf("%s: the bytes were deleted", what)
	}
}

// gone asserts that both halves went.
func (e *env) gone(digest blob.Digest, what string) {
	e.t.Helper()

	if e.hasRow(digest) {
		e.t.Errorf("%s: the metadata row survived", what)
	}
	if e.hasBytes(digest) {
		e.t.Errorf("%s: the bytes survived", what)
	}
}

// clock is the injected time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ids hands out run identifiers a test can predict.
type ids struct {
	mu sync.Mutex
	n  int
}

func (i *ids) next() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.n++
	return "gc-run-" + strconv.Itoa(i.n)
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

// errFailed is the failure a stub returns when a test only cares that it
// failed.
var errFailed = errors.New("store is not answering")

// stubStore wraps a gc.Store so a test can fail or intercept one method.
// Fields left nil delegate, so a test names only the behaviour it is about.
type stubStore struct {
	inner gc.Store

	list     func(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error)
	del      func(ctx context.Context, digest meta.Digest, before time.Time) (bool, error)
	save     func(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freed int64) error
	finish   func(ctx context.Context, id string, at time.Time, failure string) error
	resume   func(ctx context.Context) (meta.GCRun, error)
	startRun func(ctx context.Context, run meta.GCRun) error
}

func (s *stubStore) ListSweepCandidates(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
	if s.list != nil {
		return s.list(ctx, before, after, limit)
	}
	return s.inner.ListSweepCandidates(ctx, before, after, limit)
}

func (s *stubStore) DeleteBlobIfUnreferenced(ctx context.Context, digest meta.Digest, before time.Time) (bool, error) {
	if s.del != nil {
		return s.del(ctx, digest, before)
	}
	return s.inner.DeleteBlobIfUnreferenced(ctx, digest, before)
}

func (s *stubStore) StartGCRun(ctx context.Context, run meta.GCRun) error {
	if s.startRun != nil {
		return s.startRun(ctx, run)
	}
	return s.inner.StartGCRun(ctx, run)
}

func (s *stubStore) SaveGCProgress(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freed int64) error {
	if s.save != nil {
		return s.save(ctx, id, cursor, scanned, deleted, freed)
	}
	return s.inner.SaveGCProgress(ctx, id, cursor, scanned, deleted, freed)
}

func (s *stubStore) FinishGCRun(ctx context.Context, id string, at time.Time, failure string) error {
	if s.finish != nil {
		return s.finish(ctx, id, at, failure)
	}
	return s.inner.FinishGCRun(ctx, id, at, failure)
}

func (s *stubStore) ResumableGCRun(ctx context.Context) (meta.GCRun, error) {
	if s.resume != nil {
		return s.resume(ctx)
	}
	return s.inner.ResumableGCRun(ctx)
}

// stubBlobs wraps the hosted blob store the same way.
type stubBlobs struct {
	inner gc.BlobStore
	del   func(ctx context.Context, digest blob.Digest) error

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

func (s *stubBlobs) deletions() []blob.Digest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]blob.Digest(nil), s.deleted...)
}

func TestNewRefusesUnusableOptions(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	for _, tc := range []struct {
		name string
		opts gc.Options
	}{
		{name: "no metadata store", opts: gc.Options{Blobs: env.blobs, NewID: env.ids.next}},
		{name: "no blob store", opts: gc.Options{Meta: env.meta, NewID: env.ids.next}},
		{name: "no identifier source", opts: gc.Options{Meta: env.meta, Blobs: env.blobs}},
		{
			// Not read as "no protection": a negative grace is a typo, and
			// treating it as zero would turn one into data loss.
			name: "negative grace",
			opts: gc.Options{Meta: env.meta, Blobs: env.blobs, NewID: env.ids.next, Grace: -time.Hour},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			collector, err := gc.New(tc.opts)
			if !errors.Is(err, gc.ErrInvalidOptions) {
				t.Fatalf("New error = %v, want ErrInvalidOptions", err)
			}
			if collector != nil {
				t.Error("New returned a collector alongside an error")
			}
		})
	}
}

// TestSweepDeletesOnlyWhatNothingReferences is the whole task in one case: a
// layer a manifest names survives, an orphan does not, and both halves of each
// blob agree.
func TestSweepDeletesOnlyWhatNothingReferences(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	referenced := env.putBlob("referenced layer", old)
	orphan := env.putBlob("orphaned layer", old)
	env.putManifest("live", referenced)

	result, err := env.collector().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	env.survives(referenced, "a layer a live manifest references")
	env.gone(orphan, "an unreferenced layer")

	if result.Deleted != 1 || result.Scanned != 1 {
		t.Errorf("result = %d scanned / %d deleted, want 1 / 1", result.Scanned, result.Deleted)
	}
	if result.Bytes != int64(len("orphaned layer")) {
		t.Errorf("bytes = %d, want %d", result.Bytes, len("orphaned layer"))
	}
	if !result.Complete || result.Resumed {
		t.Errorf("result = %+v, want a complete first run", result)
	}
}

// TestSweepProtectsBlobsInsideTheGraceWindow: the window between a push's blob
// upload and its manifest PUT is exactly when a blob looks orphaned and is
// not.
func TestSweepProtectsBlobsInsideTheGraceWindow(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	justUploaded := env.putBlob("uploaded a minute ago", testTime.Add(-time.Minute))
	longOrphaned := env.putBlob("orphaned for days", testTime.Add(-72*time.Hour))

	result, err := env.collector().Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	env.survives(justUploaded, "a blob uploaded a minute ago")
	env.gone(longOrphaned, "a blob orphaned for days")
	if result.Deleted != 1 {
		t.Errorf("deleted %d blobs, want 1", result.Deleted)
	}
}

// TestSweepProtectsBlobsAnUploadPins: a session that has not committed its
// manifest yet holds its digest, and the sweep must see the pin.
func TestSweepProtectsBlobsAnUploadPins(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	pinned := env.putBlob("half-pushed layer", old)
	if err := env.meta.CreateUpload(context.Background(), meta.UploadSession{
		ID: "upload-1", Repository: "team-a/api", Digest: meta.Digest(pinned),
		StartedAt: testTime, LastChunkAt: testTime,
	}); err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	if _, err := env.collector().Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	env.survives(pinned, "a blob an upload session pins")
}

// TestSweepDeletesTheRowBeforeTheBytes pins the order by making the bytes
// refuse to go: the row is gone, the bytes remain, and the sweep reports a
// leak rather than an error. The reverse order would produce a row whose
// content is missing, which is the one corruption class this design refuses.
func TestSweepDeletesTheRowBeforeTheBytes(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	orphan := env.putBlob("stubborn bytes", testTime.Add(-48*time.Hour))
	blobs := &stubBlobs{inner: env.blobs, del: func(context.Context, blob.Digest) error {
		return errFailed
	}}

	result, err := env.collector(func(o *gc.Options) { o.Blobs = blobs }).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error for bytes it could not delete: %v", err)
	}

	if env.hasRow(orphan) {
		t.Error("the row survived a successful metadata delete")
	}
	if !env.hasBytes(orphan) {
		t.Error("the fixture did not leave the bytes behind")
	}
	if result.Deleted != 1 || result.Leaked != 1 {
		t.Errorf("result = %d deleted / %d leaked, want 1 / 1", result.Deleted, result.Leaked)
	}
	if got := blobs.deletions(); len(got) != 1 || got[0] != orphan {
		t.Errorf("byte deletions = %v, want exactly the orphan", got)
	}
}

// TestSweepSkipsWhatTheRecheckRefuses: between the listing and the delete,
// something referenced the blob. The re-check refusing is the safety property
// working, so it is counted and not logged as a failure.
func TestSweepSkipsWhatTheRecheckRefuses(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	orphan := env.putBlob("claimed mid-sweep", testTime.Add(-48*time.Hour))
	blobs := &stubBlobs{inner: env.blobs}
	store := &stubStore{inner: env.meta, del: func(context.Context, meta.Digest, time.Time) (bool, error) {
		return false, nil
	}}

	result, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.Blobs = blobs
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	env.survives(orphan, "a blob the re-check protected")
	if result.Skipped != 1 || result.Deleted != 0 {
		t.Errorf("result = %d skipped / %d deleted, want 1 / 0", result.Skipped, result.Deleted)
	}
	if got := blobs.deletions(); len(got) != 0 {
		t.Errorf("deleted %v from the blob store for a row that did not go", got)
	}
}

// TestSweepKeepsBytesWhenTheStoreCannotAnswer: an unknown answer is not a
// licence to delete.
func TestSweepKeepsBytesWhenTheStoreCannotAnswer(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	orphan := env.putBlob("unanswerable", testTime.Add(-48*time.Hour))
	blobs := &stubBlobs{inner: env.blobs}
	store := &stubStore{inner: env.meta, del: func(context.Context, meta.Digest, time.Time) (bool, error) {
		return false, errFailed
	}}

	result, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.Blobs = blobs
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	env.survives(orphan, "a blob whose re-check failed")
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", result.Skipped)
	}
	if got := blobs.deletions(); len(got) != 0 {
		t.Errorf("deleted %v after a failed re-check", got)
	}
}

// TestSweepResumesAnInterruptedRun: the cursor is persisted, the run stays
// open, and the next sweep continues it rather than starting over.
func TestSweepResumesAnInterruptedRun(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	for i := range 6 {
		env.putBlob(fmt.Sprintf("orphan-%d", i), old)
	}

	// Cancelled after the first batch: one page is deleted, the rest are not.
	ctx, cancel := context.WithCancel(context.Background())
	var batches int
	store := &stubStore{inner: env.meta, list: func(c context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
		batches++
		if batches == 2 {
			cancel()
		}
		return env.meta.ListSweepCandidates(context.WithoutCancel(c), before, after, limit)
	}}

	first, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.BatchSize = 2
	}).Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted Run error = %v, want context.Canceled", err)
	}
	if first.Complete {
		t.Error("an interrupted sweep reported itself complete")
	}
	if first.Deleted == 0 {
		t.Fatal("the interrupted sweep deleted nothing; there is no progress to resume from")
	}

	// The run is still open, and it remembers where it stopped.
	open, err := env.meta.ResumableGCRun(context.Background())
	if err != nil {
		t.Fatalf("ResumableGCRun: %v", err)
	}
	if open.Cursor == "" {
		t.Error("the interrupted run saved no cursor")
	}

	second, err := env.collector().Run(context.Background())
	if err != nil {
		t.Fatalf("resumed Run: %v", err)
	}
	if !second.Resumed {
		t.Error("the second sweep did not report itself a resume")
	}
	if second.RunID != open.ID {
		t.Errorf("resumed run = %q, want the open one %q", second.RunID, open.ID)
	}
	if !second.Complete {
		t.Error("the resumed sweep did not finish")
	}

	// Together they swept everything exactly once: the counters continue
	// rather than restarting.
	if second.Deleted != 6 {
		t.Errorf("total deleted = %d, want 6", second.Deleted)
	}
	left, err := env.meta.ListSweepCandidates(context.Background(), testTime, "", 100)
	if err != nil {
		t.Fatalf("ListSweepCandidates: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("%d candidates left after a complete sweep", len(left))
	}
}

// TestResumeKeepsTheOriginalWindow: a resumed sweep must not widen what it may
// delete. A blob uploaded after the run began is protected by the run's own
// deadline even though it is older than the grace window by the time the sweep
// resumes.
func TestResumeKeepsTheOriginalWindow(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	env.putBlob("orphan-a", old)
	env.putBlob("orphan-b", old)

	// Interrupted mid-sweep, so a run exists to resume. A context that was
	// already dead would fail before the run was even opened, which is
	// correct but is not this case.
	ctx, cancel := context.WithCancel(context.Background())
	var batches int
	interrupting := &stubStore{inner: env.meta, list: func(c context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
		batches++
		if batches == 2 {
			cancel()
		}
		return env.meta.ListSweepCandidates(context.WithoutCancel(c), before, after, limit)
	}}
	if _, err := env.collector(func(o *gc.Options) {
		o.Meta = interrupting
		o.BatchSize = 1
	}).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted Run error = %v, want context.Canceled", err)
	}

	// A blob uploaded now -- after the run started -- and then a long wait, so
	// that by the time the sweep resumes it is older than the grace window.
	arrivedAfterTheRunBegan := env.putBlob("uploaded during the sweep", env.clock.Now())
	env.clock.advance(72 * time.Hour)

	result, err := env.collector().Run(context.Background())
	if err != nil {
		t.Fatalf("resumed Run: %v", err)
	}
	if !result.Resumed {
		t.Fatal("the sweep did not resume the open run")
	}
	env.survives(arrivedAfterTheRunBegan, "a blob that arrived after the run's deadline")
}

// TestSweepPublishesCompletion: gc.completed carries what the operator's
// automation waits on.
func TestSweepPublishesCompletion(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	orphan := env.putBlob("collectable", testTime.Add(-48*time.Hour))
	if _, err := env.collector().Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	events := env.events.all()
	if len(events) != 1 || events[0].Type != event.GCCompleted {
		t.Fatalf("published %v, want one gc.completed", events)
	}
	payload, ok := events[0].Payload.(event.GCCompletedPayload)
	if !ok {
		t.Fatalf("payload is %T, want GCCompletedPayload", events[0].Payload)
	}
	if payload.BlobsDeleted != 1 || payload.BytesReclaimed != int64(len("collectable")) {
		t.Errorf("payload = %+v, want one blob of %d bytes", payload, len("collectable"))
	}
	if payload.RunID == "" || events[0].Resource != payload.RunID {
		t.Errorf("event names run %q / resource %q; they must agree and be set", payload.RunID, events[0].Resource)
	}
	if payload.Resumed {
		t.Error("a first sweep reported itself resumed")
	}
	if env.hasBytes(orphan) {
		t.Error("the sweep published completion without doing the work")
	}
}

// TestInterruptedSweepPublishesNothing: gc.completed means the collection ran,
// and a sweep that stopped halfway did not.
func TestInterruptedSweepPublishesNothing(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	env.putBlob("collectable-a", old)
	env.putBlob("collectable-b", old)

	// Cancelled after the sweep has started and deleted something, which is
	// the case worth asserting: work happened, and it still does not count as
	// a completed collection.
	ctx, cancel := context.WithCancel(context.Background())
	var batches int
	store := &stubStore{inner: env.meta, list: func(c context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
		batches++
		if batches == 2 {
			cancel()
		}
		return env.meta.ListSweepCandidates(context.WithoutCancel(c), before, after, limit)
	}}

	result, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.BatchSize = 1
	}).Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if result.Deleted == 0 {
		t.Fatal("the sweep deleted nothing; the assertion below would be vacuous")
	}
	if events := env.events.all(); len(events) != 0 {
		t.Errorf("an interrupted sweep published %v", events)
	}
}

// TestSweepReportsAStoreItCannotList: the distinction a caller needs. A sweep
// that cannot see the candidates is an error; content it could not delete is a
// count.
func TestSweepReportsAStoreItCannotList(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.putBlob("collectable", testTime.Add(-48*time.Hour))
	store := &stubStore{inner: env.meta, list: func(context.Context, time.Time, meta.Digest, int) ([]meta.Blob, error) {
		return nil, errFailed
	}}

	_, err := env.collector(func(o *gc.Options) { o.Meta = store }).Run(context.Background())
	if !errors.Is(err, errFailed) {
		t.Fatalf("Run error = %v, want the store's failure", err)
	}

	// The run is closed with the reason, so the next sweep starts fresh rather
	// than resuming a run that failed for a reason it cannot see.
	if _, err := env.meta.ResumableGCRun(context.Background()); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("ResumableGCRun after a listing failure = %v, want ErrNotFound", err)
	}
}

// TestSweepReportsARunItCannotStart covers the other end: a store that will
// not open a run at all.
func TestSweepReportsARunItCannotStart(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	for _, tc := range []struct {
		name  string
		store *stubStore
	}{
		{
			name: "cannot look for a run to resume",
			store: &stubStore{inner: env.meta, resume: func(context.Context) (meta.GCRun, error) {
				return meta.GCRun{}, errFailed
			}},
		},
		{
			name: "cannot start one",
			store: &stubStore{inner: env.meta, startRun: func(context.Context, meta.GCRun) error {
				return errFailed
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := env.collector(func(o *gc.Options) { o.Meta = tc.store }).Run(context.Background())
			if !errors.Is(err, errFailed) {
				t.Fatalf("Run error = %v, want the store's failure", err)
			}
		})
	}
}

// TestSweepSurvivesAProgressWriteFailure: the sweep has already deleted what
// it deleted, and stopping would neither undo that nor make the next run
// safer. The cost is re-listing from an older cursor, which is wasted work
// rather than lost data.
func TestSweepSurvivesAProgressWriteFailure(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	orphan := env.putBlob("collectable", testTime.Add(-48*time.Hour))
	store := &stubStore{inner: env.meta, save: func(context.Context, string, meta.Digest, int64, int64, int64) error {
		return errFailed
	}}

	result, err := env.collector(func(o *gc.Options) { o.Meta = store }).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Deleted != 1 {
		t.Errorf("deleted = %d, want 1", result.Deleted)
	}
	env.gone(orphan, "an unreferenced blob whose progress write failed")
}

// TestSweepSurvivesACloseFailure: a run that cannot be closed is logged, not
// returned. The bytes are already reclaimed and the caller cannot act on it.
func TestSweepSurvivesACloseFailure(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	env.putBlob("collectable", testTime.Add(-48*time.Hour))
	store := &stubStore{inner: env.meta, finish: func(context.Context, string, time.Time, string) error {
		return errFailed
	}}

	if _, err := env.collector(func(o *gc.Options) { o.Meta = store }).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestSweepSkipsAnUnparseableDigest: a row naming something that is not a
// digest has no addressable bytes, so nothing is handed to the blob store.
func TestSweepSkipsAnUnparseableDigest(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	blobs := &stubBlobs{inner: env.blobs}
	store := &stubStore{
		inner: env.meta,
		list: func(_ context.Context, _ time.Time, after meta.Digest, _ int) ([]meta.Blob, error) {
			if after != "" {
				return nil, nil
			}
			return []meta.Blob{{Digest: "../../etc/passwd", Size: 10}}, nil
		},
		del: func(context.Context, meta.Digest, time.Time) (bool, error) { return true, nil },
	}

	result, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.Blobs = blobs
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := blobs.deletions(); len(got) != 0 {
		t.Errorf("handed %v to the blob store; an unparseable digest never reaches storage", got)
	}
	if result.Leaked != 1 {
		t.Errorf("leaked = %d, want 1: the row went and no bytes could be addressed", result.Leaked)
	}
}

// TestSweepRunsWithoutAPublisherOrALogger: a deployment whose event system is
// not wired yet still collects.
func TestSweepRunsWithoutAPublisherOrALogger(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	orphan := env.putBlob("collectable", testTime.Add(-48*time.Hour))

	collector, err := gc.New(gc.Options{Meta: env.meta, Blobs: env.blobs, NewID: env.ids.next, Now: env.clock.Now})
	if err != nil {
		t.Fatalf("gc.New: %v", err)
	}
	if _, err := collector.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	env.gone(orphan, "an unreferenced blob")
}

// TestSweepPagesThroughALargeRegistry: more candidates than one batch holds,
// and the cursor is what carries the sweep across them.
func TestSweepPagesThroughALargeRegistry(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	for i := range 20 {
		env.putBlob(fmt.Sprintf("orphan-%02d", i), old)
	}

	var listings int
	store := &stubStore{inner: env.meta, list: func(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
		listings++
		return env.meta.ListSweepCandidates(ctx, before, after, limit)
	}}

	result, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.BatchSize = 3
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Deleted != 20 {
		t.Errorf("deleted %d blobs, want 20", result.Deleted)
	}
	if listings < 7 {
		t.Errorf("made %d listings for 20 blobs at a batch of 3, want at least 7", listings)
	}
}

// TestSweepStopsBetweenBatches covers the other cancellation point: the sweep
// is asked to stop after a batch has been written rather than partway through
// one. The run is still open and its cursor still names where it stopped.
func TestSweepStopsBetweenBatches(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	for i := range 4 {
		env.putBlob(fmt.Sprintf("orphan-%d", i), old)
	}

	ctx, cancel := context.WithCancel(context.Background())
	store := &stubStore{inner: env.meta, save: func(c context.Context, id string, cursor meta.Digest, scanned, deleted, freed int64) error {
		// The batch is done and its progress is being written: cancelling here
		// lands on the loop's own check rather than the per-candidate one.
		cancel()
		return env.meta.SaveGCProgress(c, id, cursor, scanned, deleted, freed)
	}}

	result, err := env.collector(func(o *gc.Options) {
		o.Meta = store
		o.BatchSize = 2
	}).Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if result.Deleted != 2 {
		t.Errorf("deleted = %d, want the one completed batch's 2", result.Deleted)
	}

	open, err := env.meta.ResumableGCRun(context.Background())
	if err != nil {
		t.Fatalf("ResumableGCRun: %v", err)
	}
	if open.Cursor == "" {
		t.Error("the run stopped between batches without recording a cursor")
	}
}

// TestCollectorRunsOnTheDefaultClock: nothing but the three required options,
// so the package's own clock is what decides the grace deadline. The store is
// empty, which keeps the assertion about construction rather than about what
// the wall clock happens to say.
func TestCollectorRunsOnTheDefaultClock(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	collector, err := gc.New(gc.Options{Meta: env.meta, Blobs: env.blobs, NewID: env.ids.next})
	if err != nil {
		t.Fatalf("gc.New: %v", err)
	}

	result, err := collector.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !result.Complete || result.Deleted != 0 {
		t.Errorf("result = %+v, want a complete sweep over an empty store", result)
	}
}
