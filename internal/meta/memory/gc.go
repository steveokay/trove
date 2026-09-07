package memory

import (
	"context"
	"sort"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// The garbage-collection half of the hosted family (ADR 0010, P-007). Nothing
// here touches cached content: a sweep is the one operation whose mistakes are
// unrecoverable, and the tables it can name are the ones whose bytes this
// registry is the origin of.

// referencedAsBlob reports whether any live manifest names the digest as a
// config or a layer. The lock is held by the caller.
//
// Child-manifest and subject edges are deliberately not consulted. They name
// manifests, whose payloads live in their own rows rather than in the blob
// store, so a blob is referenced only as a config or a layer -- and a sweep
// that also marked those digests would protect content nothing stores while
// reading as though it understood the difference.
func (s *Store) referencedAsBlob(digest meta.Digest) bool {
	for _, manifests := range s.refs {
		for _, refs := range manifests {
			for _, ref := range refs {
				if ref.Child != digest {
					continue
				}
				if ref.Kind == meta.RefConfig || ref.Kind == meta.RefLayer {
					return true
				}
			}
		}
	}
	return false
}

// pinnedByUpload reports whether an upload session holds the digest. The lock
// is held by the caller.
func (s *Store) pinnedByUpload(digest meta.Digest) bool {
	for _, session := range s.uploads {
		if session.Digest == digest {
			return true
		}
	}
	return false
}

// sweepable reports whether a blob satisfies every ADR 0010 condition. The
// lock is held by the caller.
func (s *Store) sweepable(blob meta.Blob, before time.Time) bool {
	return blob.CreatedAt.Before(before) &&
		!s.referencedAsBlob(blob.Digest) &&
		!s.pinnedByUpload(blob.Digest)
}

// ListSweepCandidates returns reclaimable-looking blobs in digest order.
func (s *Store) ListSweepCandidates(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}

	var candidates []meta.Blob
	for _, blob := range s.blobs {
		if blob.Digest <= after {
			continue
		}
		if s.sweepable(blob, before) {
			candidates = append(candidates, blob)
		}
	}

	// Digest order, which is what makes the cursor a cursor: a resumed sweep
	// continues after the last digest it saw, and an order that varied between
	// calls would let it skip rows.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Digest < candidates[j].Digest })
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates, nil
}

// DeleteBlobIfUnreferenced removes a blob row only if it is still sweepable.
//
// The write lock is what makes the re-check and the delete one operation here,
// standing in for the transaction the SQL engines take. A candidate that
// stopped being one reports false rather than an error: the re-check refusing
// is the system working.
func (s *Store) DeleteBlobIfUnreferenced(ctx context.Context, digest meta.Digest, before time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return false, err
	}

	blob, ok := s.blobs[digest]
	if !ok {
		// Already gone -- another sweep, or a repository deletion. Not an
		// error, and not a deletion this caller may count.
		return false, nil
	}
	if !s.sweepable(blob, before) {
		return false, nil
	}

	delete(s.blobs, digest)
	return true, nil
}

// StartGCRun records a sweep beginning.
func (s *Store) StartGCRun(ctx context.Context, run meta.GCRun) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if run.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if _, exists := s.gcRuns[run.ID]; exists {
		return meta.Conflict("gc run", run.ID)
	}
	s.gcRuns[run.ID] = run
	return nil
}

// SaveGCProgress advances a run's cursor and counters.
func (s *Store) SaveGCProgress(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freedBytes int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	run, ok := s.gcRuns[id]
	if !ok {
		return meta.NotFound("gc run", id)
	}
	run.Cursor = cursor
	run.Scanned = scanned
	run.Deleted = deleted
	run.FreedBytes = freedBytes
	s.gcRuns[id] = run
	return nil
}

// FinishGCRun closes a run.
func (s *Store) FinishGCRun(ctx context.Context, id string, at time.Time, failure string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	run, ok := s.gcRuns[id]
	if !ok {
		return meta.NotFound("gc run", id)
	}
	run.FinishedAt = at
	run.Failure = failure
	s.gcRuns[id] = run
	return nil
}

// GetGCRun returns one run.
func (s *Store) GetGCRun(ctx context.Context, id string) (meta.GCRun, error) {
	if err := ctx.Err(); err != nil {
		return meta.GCRun{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.GCRun{}, err
	}

	run, ok := s.gcRuns[id]
	if !ok {
		return meta.GCRun{}, meta.NotFound("gc run", id)
	}
	return run, nil
}

// ResumableGCRun returns the most recently started unfinished run.
func (s *Store) ResumableGCRun(ctx context.Context) (meta.GCRun, error) {
	if err := ctx.Err(); err != nil {
		return meta.GCRun{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.GCRun{}, err
	}

	var newest meta.GCRun
	var found bool
	for _, run := range s.gcRuns {
		if !run.FinishedAt.IsZero() {
			continue
		}
		// Ties break on the identifier so two runs started in the same
		// millisecond resolve the same way every time.
		if !found || run.StartedAt.After(newest.StartedAt) ||
			(run.StartedAt.Equal(newest.StartedAt) && run.ID > newest.ID) {
			newest, found = run, true
		}
	}
	if !found {
		return meta.GCRun{}, meta.NotFound("gc run", "unfinished")
	}
	return newest, nil
}
