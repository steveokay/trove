package metatest

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// The garbage-collection contract (ADR 0010, P-007): which blobs a sweep may
// consider, whether one is still safe at the moment of deleting it, and what a
// run remembers so an interrupted sweep resumes rather than restarting.
//
// These are the assertions that decide whether trove loses data. Every case
// here is about a blob that must survive; the ones about a blob that must go
// exist only so the survivors are not survivors by accident.

// gcTests are the cases, registered by Run.
func gcTests() []suiteCase {
	return []suiteCase{
		{"SweepCandidatesSkipReferencedBlobs", testSweepCandidatesSkipReferencedBlobs},
		{"SweepCandidatesSkipTheGraceWindow", testSweepCandidatesSkipTheGraceWindow},
		{"SweepCandidatesSkipUploadPinnedBlobs", testSweepCandidatesSkipUploadPinnedBlobs},
		{"SweepCandidatesPageByDigest", testSweepCandidatesPageByDigest},
		{"SweepCandidatesIgnoreManifestOnlyEdges", testSweepCandidatesIgnoreManifestOnlyEdges},
		{"DeleteBlobIfUnreferencedRechecks", testDeleteBlobIfUnreferencedRechecks},
		{"GCRunLifecycle", testGCRunLifecycle},
		{"GCRunResume", testGCRunResume},
		{"GCRunValidation", testGCRunValidation},
	}
}

// gcGrace is the deadline sweeps in these cases use: everything seeded at
// testTime is older than it.
var gcGrace = testTime.Add(time.Hour)

// mustPutSweepableBlob records a hosted blob old enough to be swept.
func mustPutSweepableBlob(t *testing.T, s meta.Store, d meta.Digest, size int64) {
	t.Helper()

	if err := s.PutBlob(ctx(), meta.Blob{Digest: d, Size: size, CreatedAt: testTime}); err != nil {
		t.Fatalf("PutBlob(%s): %v", d, err)
	}
}

// candidateDigests lists what a sweep would consider, in order.
func candidateDigests(t *testing.T, s meta.Store, before time.Time) []meta.Digest {
	t.Helper()

	blobs, err := s.ListSweepCandidates(ctx(), before, "", 100)
	if err != nil {
		t.Fatalf("ListSweepCandidates: %v", err)
	}
	out := make([]meta.Digest, 0, len(blobs))
	for _, blob := range blobs {
		out = append(out, blob.Digest)
	}
	return out
}

// testSweepCandidatesSkipReferencedBlobs is the central one: a blob a live
// manifest names as a config or a layer is never offered, and the same blob
// becomes a candidate the moment that manifest goes.
func testSweepCandidatesSkipReferencedBlobs(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	config, layer, orphan := digest("gc-config"), digest("gc-layer"), digest("gc-orphan")
	for _, d := range []meta.Digest{config, layer, orphan} {
		mustPutSweepableBlob(t, s, d, 512)
	}

	manifest := digest("gc-manifest")
	mustPutManifest(t, s, "team-a/api", manifest,
		meta.ManifestRef{Child: config, Kind: meta.RefConfig},
		meta.ManifestRef{Child: layer, Kind: meta.RefLayer})

	got := candidateDigests(t, s, gcGrace)
	if slices.Contains(got, config) || slices.Contains(got, layer) {
		t.Fatalf("a referenced blob was offered for sweeping: %v", got)
	}
	if !slices.Contains(got, orphan) {
		t.Fatalf("an unreferenced blob was not offered: %v", got)
	}

	// Deleting the manifest takes its edges, which is what makes its blobs
	// collectable -- the whole point of deferring blob deletion to GC (Q16).
	if err := s.DeleteManifest(ctx(), "team-a/api", manifest); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	after := candidateDigests(t, s, gcGrace)
	for _, d := range []meta.Digest{config, layer, orphan} {
		if !slices.Contains(after, d) {
			t.Errorf("%s is still protected after its manifest went: %v", d, after)
		}
	}
}

// testSweepCandidatesSkipTheGraceWindow: a blob newer than the deadline is
// never a candidate, however unreferenced it looks. This is what protects the
// window between a push's blob upload and its manifest PUT.
func testSweepCandidatesSkipTheGraceWindow(t *testing.T, s meta.Store) {
	old, fresh := digest("gc-old"), digest("gc-fresh")
	mustPutSweepableBlob(t, s, old, 128)
	if err := s.PutBlob(ctx(), meta.Blob{Digest: fresh, Size: 128, CreatedAt: gcGrace.Add(time.Minute)}); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	got := candidateDigests(t, s, gcGrace)
	if slices.Contains(got, fresh) {
		t.Errorf("a blob inside the grace window was offered: %v", got)
	}
	if !slices.Contains(got, old) {
		t.Errorf("a blob older than the window was not offered: %v", got)
	}

	// The deadline is the caller's, so moving it forward brings the newer
	// blob into scope. Nothing here reads a clock.
	later := candidateDigests(t, s, gcGrace.Add(time.Hour))
	if !slices.Contains(later, fresh) {
		t.Errorf("a later deadline did not admit the newer blob: %v", later)
	}
}

// testSweepCandidatesSkipUploadPinnedBlobs: an upload session pins its digest.
// A client that uploaded a layer and has not yet committed the manifest must
// not have that layer swept out from under it.
func testSweepCandidatesSkipUploadPinnedBlobs(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	pinned, loose := digest("gc-pinned"), digest("gc-loose")
	mustPutSweepableBlob(t, s, pinned, 256)
	mustPutSweepableBlob(t, s, loose, 256)

	if err := s.CreateUpload(ctx(), meta.UploadSession{
		ID: "upload-1", Repository: "team-a/api", Digest: pinned,
		StartedAt: testTime, LastChunkAt: testTime,
	}); err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	got := candidateDigests(t, s, gcGrace)
	if slices.Contains(got, pinned) {
		t.Fatalf("a blob an upload session pins was offered: %v", got)
	}
	if !slices.Contains(got, loose) {
		t.Fatalf("an unpinned blob was not offered: %v", got)
	}

	// And the pin is released with the session, not left behind.
	if err := s.DeleteUpload(ctx(), "upload-1"); err != nil {
		t.Fatalf("DeleteUpload: %v", err)
	}
	if !slices.Contains(candidateDigests(t, s, gcGrace), pinned) {
		t.Error("the pin outlived its upload session")
	}
}

// testSweepCandidatesPageByDigest: the listing is a keyset page, and the
// cursor is what a resumed sweep continues from. An order that varied between
// calls would let a resume skip a blob -- which is a leak -- or revisit one,
// which is merely wasteful.
func testSweepCandidatesPageByDigest(t *testing.T, s meta.Store) {
	seeded := make([]meta.Digest, 0, 5)
	for _, seed := range []string{"gc-a", "gc-b", "gc-c", "gc-d", "gc-e"} {
		d := digest(seed)
		mustPutSweepableBlob(t, s, d, 64)
		seeded = append(seeded, d)
	}

	first, err := s.ListSweepCandidates(ctx(), gcGrace, "", 2)
	if err != nil {
		t.Fatalf("ListSweepCandidates: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first page has %d rows, want 2", len(first))
	}
	if first[0].Digest >= first[1].Digest {
		t.Errorf("page is not in digest order: %v", first)
	}
	if first[0].Size != 64 {
		t.Errorf("size = %d, want 64: the sweep counts what it frees", first[0].Size)
	}

	second, err := s.ListSweepCandidates(ctx(), gcGrace, first[1].Digest, 100)
	if err != nil {
		t.Fatalf("ListSweepCandidates (page 2): %v", err)
	}
	if len(second) != len(seeded)-2 {
		t.Fatalf("second page has %d rows, want %d", len(second), len(seeded)-2)
	}
	for _, blob := range second {
		if blob.Digest <= first[1].Digest {
			t.Errorf("the cursor was not exclusive: %s came back after %s", blob.Digest, first[1].Digest)
		}
	}

	// A limit of zero returns nothing rather than everything, the rule
	// ListEvictable keeps for the same reason.
	empty, err := s.ListSweepCandidates(ctx(), gcGrace, "", 0)
	if err != nil {
		t.Fatalf("ListSweepCandidates (limit 0): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("a limit of zero returned %d rows", len(empty))
	}
}

// testSweepCandidatesIgnoreManifestOnlyEdges: child-manifest and subject edges
// name manifests, whose payloads live in their own rows. A blob that happens
// to share a digest with one is still collectable, and a sweep that protected
// it would be protecting content nothing stores.
func testSweepCandidatesIgnoreManifestOnlyEdges(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	child := digest("gc-child")
	mustPutManifest(t, s, "team-a/api", child)
	mustPutSweepableBlob(t, s, child, 32)

	index := digest("gc-index")
	mustPutManifest(t, s, "team-a/api", index,
		meta.ManifestRef{Child: child, Kind: meta.RefChild})

	if !slices.Contains(candidateDigests(t, s, gcGrace), child) {
		t.Error("a blob referenced only by a child-manifest edge was protected")
	}
}

// testDeleteBlobIfUnreferencedRechecks is the safety property: the delete
// re-evaluates every condition inside its own transaction, so a reference that
// appeared since the listing stops it.
func testDeleteBlobIfUnreferencedRechecks(t *testing.T, s meta.Store) {
	mustCreateRepo(t, s, "team-a", meta.Hosted)
	collectable, claimed := digest("gc-collectable"), digest("gc-claimed")
	mustPutSweepableBlob(t, s, collectable, 100)
	mustPutSweepableBlob(t, s, claimed, 100)

	// Both were candidates a moment ago; now something references one of them,
	// which is exactly the race the re-check exists for.
	mustPutManifest(t, s, "team-a/api", digest("gc-late-manifest"),
		meta.ManifestRef{Child: claimed, Kind: meta.RefLayer})

	deleted, err := s.DeleteBlobIfUnreferenced(ctx(), claimed, gcGrace)
	if err != nil {
		t.Fatalf("DeleteBlobIfUnreferenced: %v", err)
	}
	if deleted {
		t.Fatal("deleted a blob a manifest references")
	}
	if _, err := s.GetBlob(ctx(), claimed); err != nil {
		t.Fatalf("the referenced blob's row is gone: %v", err)
	}

	deleted, err = s.DeleteBlobIfUnreferenced(ctx(), collectable, gcGrace)
	if err != nil {
		t.Fatalf("DeleteBlobIfUnreferenced: %v", err)
	}
	if !deleted {
		t.Fatal("refused to delete an unreferenced blob")
	}
	if _, err := s.GetBlob(ctx(), collectable); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetBlob after delete = %v, want ErrNotFound", err)
	}

	// Deleting what is already gone is false and no error: another sweep, or
	// a repository deletion, got there first.
	deleted, err = s.DeleteBlobIfUnreferenced(ctx(), collectable, gcGrace)
	if err != nil || deleted {
		t.Errorf("second delete = (%t, %v), want (false, nil)", deleted, err)
	}

	// The grace window is re-checked too: a deadline before the blob's
	// creation protects it even when nothing references it.
	fresh := digest("gc-fresh-recheck")
	mustPutSweepableBlob(t, s, fresh, 100)
	deleted, err = s.DeleteBlobIfUnreferenced(ctx(), fresh, testTime.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteBlobIfUnreferenced: %v", err)
	}
	if deleted {
		t.Error("deleted a blob newer than the sweep's deadline")
	}
}

// testGCRunLifecycle: a run is started, advanced, and closed, and what it
// remembers survives the round trip.
func testGCRunLifecycle(t *testing.T, s meta.Store) {
	run := meta.GCRun{
		ID: "gc-1", StartedAt: testTime, SweepBefore: gcGrace,
	}
	if err := s.StartGCRun(ctx(), run); err != nil {
		t.Fatalf("StartGCRun: %v", err)
	}
	requireErrIs(t, s.StartGCRun(ctx(), run), meta.ErrConflict, "StartGCRun twice")

	stored, err := s.GetGCRun(ctx(), "gc-1")
	if err != nil {
		t.Fatalf("GetGCRun: %v", err)
	}
	if !stored.StartedAt.Equal(testTime) || !stored.SweepBefore.Equal(gcGrace) {
		t.Errorf("run = %+v, want the times it was started with", stored)
	}
	if !stored.FinishedAt.IsZero() {
		t.Errorf("a fresh run reports FinishedAt %v, want zero", stored.FinishedAt)
	}

	if err := s.SaveGCProgress(ctx(), "gc-1", digest("gc-cursor"), 40, 7, 4096); err != nil {
		t.Fatalf("SaveGCProgress: %v", err)
	}
	stored, err = s.GetGCRun(ctx(), "gc-1")
	if err != nil {
		t.Fatalf("GetGCRun: %v", err)
	}
	if stored.Cursor != digest("gc-cursor") || stored.Scanned != 40 || stored.Deleted != 7 || stored.FreedBytes != 4096 {
		t.Errorf("progress = %+v, want the cursor and counters just saved", stored)
	}

	finished := testTime.Add(2 * time.Hour)
	if err := s.FinishGCRun(ctx(), "gc-1", finished, ""); err != nil {
		t.Fatalf("FinishGCRun: %v", err)
	}
	stored, err = s.GetGCRun(ctx(), "gc-1")
	if err != nil {
		t.Fatalf("GetGCRun: %v", err)
	}
	if !stored.FinishedAt.Equal(finished) || stored.Failure != "" {
		t.Errorf("finished run = %+v, want %v and no failure", stored, finished)
	}
}

// testGCRunResume: the resumable run is the most recent unfinished one, and a
// closed run is not resumable however recent it is.
func testGCRunResume(t *testing.T, s meta.Store) {
	_, err := s.ResumableGCRun(ctx())
	requireErrIs(t, err, meta.ErrNotFound, "ResumableGCRun with no runs")

	older := meta.GCRun{ID: "gc-older", StartedAt: testTime, SweepBefore: gcGrace}
	newer := meta.GCRun{ID: "gc-newer", StartedAt: testTime.Add(time.Hour), SweepBefore: gcGrace}
	for _, run := range []meta.GCRun{older, newer} {
		if err := s.StartGCRun(ctx(), run); err != nil {
			t.Fatalf("StartGCRun(%s): %v", run.ID, err)
		}
	}

	got, err := s.ResumableGCRun(ctx())
	if err != nil {
		t.Fatalf("ResumableGCRun: %v", err)
	}
	if got.ID != "gc-newer" {
		t.Errorf("resumable run = %q, want the most recently started", got.ID)
	}
	// The window it carries is the one it started with: recomputing on resume
	// would widen what the sweep may delete.
	if !got.SweepBefore.Equal(gcGrace) {
		t.Errorf("resumed sweep window = %v, want %v", got.SweepBefore, gcGrace)
	}

	if err := s.FinishGCRun(ctx(), "gc-newer", testTime.Add(2*time.Hour), "interrupted"); err != nil {
		t.Fatalf("FinishGCRun: %v", err)
	}
	got, err = s.ResumableGCRun(ctx())
	if err != nil {
		t.Fatalf("ResumableGCRun: %v", err)
	}
	if got.ID != "gc-older" {
		t.Errorf("resumable run = %q, want the remaining unfinished one", got.ID)
	}

	if err := s.FinishGCRun(ctx(), "gc-older", testTime.Add(3*time.Hour), ""); err != nil {
		t.Fatalf("FinishGCRun: %v", err)
	}
	_, err = s.ResumableGCRun(ctx())
	requireErrIs(t, err, meta.ErrNotFound, "ResumableGCRun with every run finished")
}

// testGCRunValidation: the refusals a caller can provoke.
func testGCRunValidation(t *testing.T, s meta.Store) {
	requireErrIs(t, s.StartGCRun(ctx(), meta.GCRun{}), meta.ErrInvalid, "StartGCRun without an id")
	requireErrIs(t, s.SaveGCProgress(ctx(), "nope", "", 0, 0, 0), meta.ErrNotFound, "SaveGCProgress on a missing run")
	requireErrIs(t, s.FinishGCRun(ctx(), "nope", testTime, ""), meta.ErrNotFound, "FinishGCRun on a missing run")

	_, err := s.GetGCRun(ctx(), "nope")
	requireErrIs(t, err, meta.ErrNotFound, "GetGCRun on a missing run")
}
