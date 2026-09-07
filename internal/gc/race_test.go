package gc_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/gc"
	"github.com/steveokay/trove/internal/meta"
)

// ADR 0010's race matrix (P-008), as deterministic interleavings.
//
// The sync points are the sweep's own store calls. A collector's observable
// steps are exactly "list candidates", "delete this one if it is still
// collectable", and "save progress", so a stub that acts *inside* one of them
// places a concurrent operation at a precise point in the sweep -- without a
// hook in production code that exists only for tests, and without a sleep.
//
// Every cell asserts the same thing in the end: a blob something references
// still has both its row and its bytes. That is the property the whole design
// exists to keep, and the failure it is defending against is silent.

// racingStore runs a test's action inside one of the sweep's steps.
type racingStore struct {
	inner gc.Store

	// beforeDelete runs inside DeleteBlobIfUnreferenced, before the real store
	// sees it: the moment between "this blob was listed as collectable" and
	// "the delete transaction opens".
	beforeDelete func(digest meta.Digest)

	// afterList runs once the candidates are in hand but before any of them
	// has been deleted.
	afterList func(candidates []meta.Blob)
}

func (s *racingStore) ListSweepCandidates(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
	candidates, err := s.inner.ListSweepCandidates(ctx, before, after, limit)
	if err == nil && s.afterList != nil {
		s.afterList(candidates)
	}
	return candidates, err
}

func (s *racingStore) DeleteBlobIfUnreferenced(ctx context.Context, digest meta.Digest, before time.Time) (bool, error) {
	if s.beforeDelete != nil {
		s.beforeDelete(digest)
	}
	return s.inner.DeleteBlobIfUnreferenced(ctx, digest, before)
}

func (s *racingStore) StartGCRun(ctx context.Context, run meta.GCRun) error {
	return s.inner.StartGCRun(ctx, run)
}

func (s *racingStore) SaveGCProgress(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freed int64) error {
	return s.inner.SaveGCProgress(ctx, id, cursor, scanned, deleted, freed)
}

func (s *racingStore) FinishGCRun(ctx context.Context, id string, at time.Time, failure string) error {
	return s.inner.FinishGCRun(ctx, id, at, failure)
}

func (s *racingStore) ResumableGCRun(ctx context.Context) (meta.GCRun, error) {
	return s.inner.ResumableGCRun(ctx)
}

// TestGCLosesToAManifestPushedMidSweep is the central race: a blob is listed as
// collectable, and before the delete transaction opens, a manifest PUT
// references it.
//
// The push wins, always. ADR 0010's argument is that a reference created before
// the delete transaction commits is seen by the re-check; this places the
// reference exactly there and asserts the blob survives whole.
func TestGCLosesToAManifestPushedMidSweep(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	racer := env.putBlob("layer pushed against", old)
	bystander := env.putBlob("nobody wants this", old)

	var pushed bool
	store := &racingStore{inner: env.meta, beforeDelete: func(digest meta.Digest) {
		if digest != meta.Digest(racer) || pushed {
			return
		}
		// The instant between listing and deleting: a client completes a push
		// that references the very blob the sweep is about to take.
		pushed = true
		env.putManifest("pushed-mid-sweep", racer)
	}}

	result, err := env.collector(func(o *gc.Options) { o.Meta = store }).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !pushed {
		t.Fatal("the racing push never happened; the assertion below would be vacuous")
	}

	env.survives(racer, "a blob referenced between the listing and the delete")
	env.gone(bystander, "a blob nothing referenced")
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1: the re-check is what refused", result.Skipped)
	}
}

// TestGCLosesToAnUploadStartedMidSweep: the same race one step earlier in a
// push. The client has not committed a manifest yet -- it has only opened an
// upload session -- and that pin is enough.
func TestGCLosesToAnUploadStartedMidSweep(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	racer := env.putBlob("layer being re-uploaded", old)

	var pinned bool
	store := &racingStore{inner: env.meta, beforeDelete: func(digest meta.Digest) {
		if digest != meta.Digest(racer) || pinned {
			return
		}
		pinned = true
		if err := env.meta.CreateUpload(context.Background(), meta.UploadSession{
			ID: "racing-upload", Repository: "team-a/api", Digest: digest,
			StartedAt: testTime, LastChunkAt: testTime,
		}); err != nil {
			t.Errorf("CreateUpload: %v", err)
		}
	}}

	result, err := env.collector(func(o *gc.Options) { o.Meta = store }).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !pinned {
		t.Fatal("the racing upload never happened")
	}

	env.survives(racer, "a blob an upload session pinned mid-sweep")
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", result.Skipped)
	}
}

// TestGCSurvivesAManifestDeletedMidSweep: the other direction. A manifest is
// deleted while the sweep runs, so blobs become collectable *after* the
// listing that would have offered them.
//
// The sweep must not fail, and must not delete them on the strength of a
// listing that predates their becoming collectable -- it simply does not see
// them this pass. The next one does, which is what makes GC eventually
// complete rather than exactly complete.
func TestGCSurvivesAManifestDeletedMidSweep(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	old := testTime.Add(-48 * time.Hour)
	orphan := env.putBlob("already collectable", old)
	stillReferenced := env.putBlob("referenced until mid-sweep", old)
	manifest := env.putManifest("doomed", stillReferenced)

	var deleted bool
	store := &racingStore{inner: env.meta, beforeDelete: func(meta.Digest) {
		if deleted {
			return
		}
		deleted = true
		if err := env.meta.DeleteManifest(context.Background(), "team-a/api", meta.Digest(manifest)); err != nil {
			t.Errorf("DeleteManifest: %v", err)
		}
	}}

	first, err := env.collector(func(o *gc.Options) { o.Meta = store }).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !deleted {
		t.Fatal("the racing delete never happened")
	}
	env.gone(orphan, "a blob that was already collectable")

	// Whether this pass reached the newly orphaned blob depends on where the
	// cursor was, and either answer is correct. What must be true is that a
	// following sweep collects it and nothing was lost in the meantime.
	if !first.Complete {
		t.Error("the sweep did not finish")
	}
	if _, err := env.collector().Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	env.gone(stillReferenced, "a blob whose manifest was deleted")
}

// TestGCAtTheGraceBoundary pins the comparison itself. The condition is
// strictly "older than the deadline", so a blob created *at* it is protected:
// the boundary belongs to the side that keeps data.
func TestGCAtTheGraceBoundary(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	// The collector's deadline is now-grace. These three straddle it.
	deadline := testTime.Add(-24 * time.Hour)
	atTheBoundary := env.putBlob("created exactly at the deadline", deadline)
	justInside := env.putBlob("created a nanosecond later", deadline.Add(time.Nanosecond))
	justOutside := env.putBlob("created a nanosecond earlier", deadline.Add(-time.Nanosecond))

	if _, err := env.collector(func(o *gc.Options) { o.Grace = 24 * time.Hour }).Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	env.survives(atTheBoundary, "a blob created exactly at the deadline")
	env.survives(justInside, "a blob created inside the window")
	env.gone(justOutside, "a blob created before the window")
}

// TestGCInterruptedAtEveryPhaseBoundary walks the boundaries a sweep can be
// stopped at and asserts the same two things at each: nothing referenced is
// lost, and the sweep can be resumed to completion.
//
// The boundaries are where the collector's own loop can yield: before it has
// listed anything, once it holds a page, between two deletes, and after a
// page's progress has been written.
func TestGCInterruptedAtEveryPhaseBoundary(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// stop installs the cancellation at one boundary. It returns the store
		// the collector should use.
		stop func(env *env, cancel context.CancelFunc) gc.Store
	}{
		{
			name: "before the first listing",
			stop: func(env *env, cancel context.CancelFunc) gc.Store {
				return &stubStore{inner: env.meta, list: func(c context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
					cancel()
					return env.meta.ListSweepCandidates(context.WithoutCancel(c), before, after, limit)
				}}
			},
		},
		{
			name: "holding a page, before any delete",
			stop: func(env *env, cancel context.CancelFunc) gc.Store {
				return &racingStore{inner: env.meta, afterList: func([]meta.Blob) { cancel() }}
			},
		},
		{
			name: "between two deletes",
			stop: func(env *env, cancel context.CancelFunc) gc.Store {
				var deletes int
				return &racingStore{inner: env.meta, beforeDelete: func(meta.Digest) {
					deletes++
					if deletes == 2 {
						cancel()
					}
				}}
			},
		},
		{
			name: "after a page's progress is written",
			stop: func(env *env, cancel context.CancelFunc) gc.Store {
				return &stubStore{inner: env.meta, save: func(c context.Context, id string, cursor meta.Digest, scanned, deleted, freed int64) error {
					err := env.meta.SaveGCProgress(c, id, cursor, scanned, deleted, freed)
					cancel()
					return err
				}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t)
			old := testTime.Add(-48 * time.Hour)
			referenced := env.putBlob("referenced throughout", old)
			env.putManifest("live", referenced)

			orphans := make([]blob.Digest, 0, 6)
			for i := range 6 {
				orphans = append(orphans, env.putBlob(fmt.Sprintf("orphan-%d", i), old))
			}

			ctx, cancel := context.WithCancel(context.Background())
			interrupted, err := env.collector(func(o *gc.Options) {
				o.Meta = tc.stop(env, cancel)
				o.BatchSize = 2
			}).Run(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted Run error = %v, want context.Canceled", err)
			}
			if interrupted.Complete {
				t.Error("an interrupted sweep reported itself complete")
			}
			env.survives(referenced, "a referenced blob, across an interruption")

			// Resume with a healthy store: the run is still open, and the
			// sweep finishes what it started.
			resumed, err := env.collector().Run(context.Background())
			if err != nil {
				t.Fatalf("resumed Run: %v", err)
			}
			if !resumed.Resumed {
				t.Error("the second sweep did not continue the interrupted run")
			}
			if !resumed.Complete {
				t.Error("the resumed sweep did not finish")
			}

			env.survives(referenced, "a referenced blob, after the resume")

			// A candidate whose re-check was interrupted mid-call is counted
			// as skipped, and the cursor still advances past it -- it must, or
			// a permanently failing blob would make the sweep loop on it
			// forever. So the resumed run may leave one behind, which is the
			// design's "prefer leaking" in its smallest form. The next *fresh*
			// sweep starts from the beginning and collects it.
			if _, err := env.collector().Run(context.Background()); err != nil {
				t.Fatalf("following Run: %v", err)
			}
			for _, orphan := range orphans {
				env.gone(orphan, "an unreferenced blob after an interrupted sweep, a resume, and a fresh pass")
			}
			env.survives(referenced, "a referenced blob, after three sweeps")
		})
	}
}

// TestCancellationIsReportedAsCancellation: a store need not report a
// cancelled context as context.Canceled -- SQLite surfaces its own
// "interrupted" -- and the collector must classify it by what was asked
// rather than by what the driver called it.
//
// The alternative is what the concurrent suite in test/gcrace found: every
// shutdown logged as a failed collection, which is how an operator learns to
// ignore the message that matters.
func TestCancellationIsReportedAsCancellation(t *testing.T) {
	t.Parallel()

	// errDriver stands in for a store that reports its own interruption.
	errDriver := errors.New("interrupted (9)")

	for _, tc := range []struct {
		name  string
		store func(env *env, cancel context.CancelFunc) gc.Store
	}{
		{
			name: "while looking for a run to resume",
			store: func(env *env, cancel context.CancelFunc) gc.Store {
				return &stubStore{inner: env.meta, resume: func(context.Context) (meta.GCRun, error) {
					cancel()
					return meta.GCRun{}, errDriver
				}}
			},
		},
		{
			name: "while starting one",
			store: func(env *env, cancel context.CancelFunc) gc.Store {
				return &stubStore{inner: env.meta, startRun: func(context.Context, meta.GCRun) error {
					cancel()
					return errDriver
				}}
			},
		},
		{
			name: "while listing candidates",
			store: func(env *env, cancel context.CancelFunc) gc.Store {
				return &stubStore{inner: env.meta, list: func(context.Context, time.Time, meta.Digest, int) ([]meta.Blob, error) {
					cancel()
					return nil, errDriver
				}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t)
			env.putBlob("collectable", testTime.Add(-48*time.Hour))

			ctx, cancel := context.WithCancel(context.Background())
			_, err := env.collector(func(o *gc.Options) { o.Meta = tc.store(env, cancel) }).Run(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run error = %v, want context.Canceled", err)
			}
			if errors.Is(err, errDriver) {
				t.Error("the driver's own wording reached the caller instead of the cancellation")
			}
		})
	}
}
