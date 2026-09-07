package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
)

// The garbage-collection half of the hosted family (ADR 0010, P-007).
//
// Every statement here names hosted tables only. A sweep is the one operation
// whose mistakes cannot be undone, so the separation from the cached family is
// carried by there being no cached table it can reach (ADR 0009 wall 4).

// sweepConditions is the WHERE clause shared by the listing and the re-check,
// written once so the two cannot drift.
//
// Drift between them would be the worst kind of bug this file could have: the
// listing would offer a blob the re-check was supposed to protect, or the
// re-check would refuse everything and the sweep would silently stop
// reclaiming. The parameters are (created-before, then the digest).
//
// Child-manifest and subject edges are excluded because they name manifests,
// whose payloads live in their own rows rather than in the blob store.
const sweepConditions = `
	blobs.created_at IS NOT NULL
	AND blobs.created_at < ?
	AND NOT EXISTS (
		SELECT 1 FROM manifest_refs
		WHERE manifest_refs.child_digest = blobs.digest
		  AND manifest_refs.kind IN ('config', 'layer')
	)
	AND NOT EXISTS (
		SELECT 1 FROM upload_sessions
		WHERE upload_sessions.digest = blobs.digest
	)`

// ListSweepCandidates returns reclaimable-looking blobs in digest order.
func (s *Store) ListSweepCandidates(ctx context.Context, before time.Time, after meta.Digest, limit int) ([]meta.Blob, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT digest, size, created_at FROM blobs
		 WHERE digest > ? AND`+sweepConditions+`
		 ORDER BY digest LIMIT ?`,
		[]any{string(after), before.UTC().UnixMilli(), limit},
		func(rows *sql.Rows) (meta.Blob, error) {
			var (
				blob    meta.Blob
				digest  string
				created sql.NullInt64
			)
			if err := rows.Scan(&digest, &blob.Size, &created); err != nil {
				return meta.Blob{}, fmt.Errorf("scan blob: %w", err)
			}
			blob.Digest = meta.Digest(digest)
			blob.CreatedAt = sqlutil.AsTime(created)
			return blob, nil
		})
}

// DeleteBlobIfUnreferenced removes a blob row only if it is still sweepable,
// re-checked inside the delete's own transaction.
//
// The delete is a single statement carrying the conditions, which is what
// makes the check and the delete atomic under SQLite's single writer: nothing
// can insert a manifest_refs row between the two, because there is no between.
// A candidate that stopped being one affects no rows and reports false.
func (s *Store) DeleteBlobIfUnreferenced(ctx context.Context, digest meta.Digest, before time.Time) (bool, error) {
	if err := s.ready(ctx); err != nil {
		return false, err
	}

	var deleted bool
	err := sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		affected, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM blobs WHERE digest = ? AND`+sweepConditions,
			string(digest), before.UTC().UnixMilli())
		if err != nil {
			return err
		}
		deleted = affected > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return deleted, nil
}

// StartGCRun records a sweep beginning.
func (s *Store) StartGCRun(ctx context.Context, run meta.GCRun) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if run.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM gc_runs WHERE id = ?`, run.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("gc run", run.ID)
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO gc_runs (id, started_at, finished_at, sweep_before, cursor, scanned, deleted, freed_bytes, failure)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			run.ID, sqlutil.Millis(run.StartedAt), sqlutil.Millis(run.FinishedAt), sqlutil.Millis(run.SweepBefore),
			string(run.Cursor), run.Scanned, run.Deleted, run.FreedBytes, run.Failure)
		return err
	})
}

// SaveGCProgress advances a run's cursor and counters.
func (s *Store) SaveGCProgress(ctx context.Context, id string, cursor meta.Digest, scanned, deleted, freedBytes int64) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db,
		`UPDATE gc_runs SET cursor = ?, scanned = ?, deleted = ?, freed_bytes = ? WHERE id = ?`,
		string(cursor), scanned, deleted, freedBytes, id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("gc run", id)
	}
	return nil
}

// FinishGCRun closes a run.
func (s *Store) FinishGCRun(ctx context.Context, id string, at time.Time, failure string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db,
		`UPDATE gc_runs SET finished_at = ?, failure = ? WHERE id = ?`,
		sqlutil.Millis(at), failure, id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("gc run", id)
	}
	return nil
}

// GetGCRun returns one run.
func (s *Store) GetGCRun(ctx context.Context, id string) (meta.GCRun, error) {
	if err := s.ready(ctx); err != nil {
		return meta.GCRun{}, err
	}

	runs, err := sqlutil.Collect(ctx, s.db,
		`SELECT id, started_at, finished_at, sweep_before, cursor, scanned, deleted, freed_bytes, failure
		 FROM gc_runs WHERE id = ?`,
		[]any{id},
		func(rows *sql.Rows) (meta.GCRun, error) { return scanGCRun(rows) })
	if err != nil {
		return meta.GCRun{}, err
	}
	if len(runs) == 0 {
		return meta.GCRun{}, meta.NotFound("gc run", id)
	}
	return runs[0], nil
}

// ResumableGCRun returns the most recently started unfinished run.
func (s *Store) ResumableGCRun(ctx context.Context) (meta.GCRun, error) {
	if err := s.ready(ctx); err != nil {
		return meta.GCRun{}, err
	}

	runs, err := sqlutil.Collect(ctx, s.db,
		`SELECT id, started_at, finished_at, sweep_before, cursor, scanned, deleted, freed_bytes, failure
		 FROM gc_runs WHERE finished_at IS NULL
		 ORDER BY started_at DESC, id DESC LIMIT 1`,
		nil,
		func(rows *sql.Rows) (meta.GCRun, error) { return scanGCRun(rows) })
	if err != nil {
		return meta.GCRun{}, err
	}
	if len(runs) == 0 {
		return meta.GCRun{}, meta.NotFound("gc run", "unfinished")
	}
	return runs[0], nil
}

// scanGCRun reads one run row.
func scanGCRun(rows *sql.Rows) (meta.GCRun, error) {
	var (
		run        meta.GCRun
		started    sql.NullInt64
		finished   sql.NullInt64
		before     sql.NullInt64
		cursor     string
		scanned    int64
		deleted    int64
		freedBytes int64
	)
	if err := rows.Scan(&run.ID, &started, &finished, &before,
		&cursor, &scanned, &deleted, &freedBytes, &run.Failure); err != nil {
		return meta.GCRun{}, fmt.Errorf("scan gc run: %w", err)
	}
	run.StartedAt = sqlutil.AsTime(started)
	run.FinishedAt = sqlutil.AsTime(finished)
	run.SweepBefore = sqlutil.AsTime(before)
	run.Cursor = meta.Digest(cursor)
	run.Scanned, run.Deleted, run.FreedBytes = scanned, deleted, freedBytes
	return run, nil
}
