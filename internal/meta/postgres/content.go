package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
)

const manifestColumns = `repo_name, digest, media_type, artifact_type, subject_digest, payload, size, created_at`

func scanManifest(sc sqlutil.Scanner) (meta.Manifest, error) {
	var (
		m       meta.Manifest
		digest  string
		subject string
		payload []byte
		created sql.NullInt64
	)
	if err := sc.Scan(&m.Repository, &digest, &m.MediaType, &m.ArtifactType, &subject, &payload, &m.Size, &created); err != nil {
		return meta.Manifest{}, err
	}
	m.Digest = meta.Digest(digest)
	m.Subject = meta.Digest(subject)
	m.Payload = payload
	m.CreatedAt = sqlutil.AsTime(created)
	return m, nil
}

// PutManifest stores a manifest and its reference edges in one transaction.
// The edges are what garbage collection walks, so a manifest that existed
// without them would be a blob-loss bug (ADR 0010).
func (s *Store) PutManifest(ctx context.Context, m meta.Manifest, refs []meta.ManifestRef) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if m.Digest == "" {
		return meta.Invalid("digest", "must not be empty")
	}
	for _, r := range refs {
		if !r.Kind.Valid() {
			return meta.Invalid("refs", fmt.Sprintf("unknown reference kind %q", r.Kind))
		}
		if r.Child == "" {
			return meta.Invalid("refs", "reference digest must not be empty")
		}
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := s.repository(ctx, tx, m.Repository); err != nil {
			return err
		}
		if _, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO manifests (`+manifestColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT (repo_name, digest) DO UPDATE SET
			     media_type = excluded.media_type,
			     artifact_type = excluded.artifact_type,
			     subject_digest = excluded.subject_digest,
			     payload = excluded.payload,
			     size = excluded.size,
			     created_at = excluded.created_at`,
			m.Repository, string(m.Digest), m.MediaType, m.ArtifactType, string(m.Subject),
			m.Payload, m.Size, sqlutil.Millis(m.CreatedAt)); err != nil {
			return err
		}

		// The edge set is replaced wholesale: a re-push with fewer layers must
		// not leave the old ones marked reachable.
		if _, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM manifest_refs WHERE repo_name = $1 AND manifest_digest = $2`,
			m.Repository, string(m.Digest)); err != nil {
			return err
		}
		for i, r := range refs {
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO manifest_refs (repo_name, manifest_digest, ordinal, child_digest, kind)
				 VALUES ($1, $2, $3, $4, $5)`,
				m.Repository, string(m.Digest), i, string(r.Child), string(r.Kind)); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetManifest returns one manifest by digest.
func (s *Store) GetManifest(ctx context.Context, repo string, digest meta.Digest) (meta.Manifest, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Manifest{}, err
	}
	return s.manifest(ctx, s.db, repo, digest)
}

func (s *Store) manifest(ctx context.Context, q sqlutil.Querier, repo string, digest meta.Digest) (meta.Manifest, error) {
	m, err := scanManifest(q.QueryRowContext(ctx,
		`SELECT `+manifestColumns+` FROM manifests WHERE repo_name = $1 AND digest = $2`,
		repo, string(digest)))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Manifest{}, meta.NotFound("manifest", string(digest))
	case err != nil:
		return meta.Manifest{}, fmt.Errorf("scan manifest: %w", err)
	default:
		return m, nil
	}
}

// DeleteManifest removes a manifest, its reference edges, and any tags
// pointing at it. It refuses while a live index still lists the manifest as a
// child, naming the parents so an operator knows what to delete first (Q10).
func (s *Store) DeleteManifest(ctx context.Context, repo string, digest meta.Digest) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := s.manifest(ctx, tx, repo, digest); err != nil {
			return err
		}

		parents, err := sqlutil.Collect(ctx, tx,
			`SELECT DISTINCT manifest_digest FROM manifest_refs
			 WHERE repo_name = $1 AND child_digest = $2 AND kind = $3 AND manifest_digest <> $4
			 ORDER BY manifest_digest`,
			[]any{repo, string(digest), string(meta.RefChild), string(digest)},
			func(rows *sql.Rows) (string, error) {
				var parent string
				return parent, rows.Scan(&parent)
			})
		if err != nil {
			return err
		}
		if len(parents) > 0 {
			return meta.Referenced("manifest", string(digest), parents)
		}

		_, err = sqlutil.Execute(ctx, tx, `DELETE FROM manifests WHERE repo_name = $1 AND digest = $2`,
			repo, string(digest))
		return err
	})
}

// ListManifestRefs returns the manifest's outgoing reference edges.
func (s *Store) ListManifestRefs(ctx context.Context, repo string, digest meta.Digest) ([]meta.ManifestRef, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := s.manifest(ctx, s.db, repo, digest); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT child_digest, kind FROM manifest_refs
		 WHERE repo_name = $1 AND manifest_digest = $2 ORDER BY ordinal`,
		[]any{repo, string(digest)},
		func(rows *sql.Rows) (meta.ManifestRef, error) {
			var (
				ref   meta.ManifestRef
				child string
				kind  string
			)
			if err := rows.Scan(&child, &kind); err != nil {
				return meta.ManifestRef{}, err
			}
			ref.Child = meta.Digest(child)
			ref.Kind = meta.RefKind(kind)
			return ref, nil
		})
}

// ListIndexParents returns the digests of manifests that reference the given
// digest as a child.
func (s *Store) ListIndexParents(ctx context.Context, repo string, child meta.Digest) ([]meta.Digest, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT DISTINCT manifest_digest FROM manifest_refs
		 WHERE repo_name = $1 AND child_digest = $2 AND kind = $3 ORDER BY manifest_digest`,
		[]any{repo, string(child), string(meta.RefChild)},
		func(rows *sql.Rows) (meta.Digest, error) {
			var parent string
			if err := rows.Scan(&parent); err != nil {
				return "", err
			}
			return meta.Digest(parent), nil
		})
}

// ListReferrers returns manifests whose subject is the given digest. Callers
// must check read permission on the subject first: a referrer inherits the
// subject's permission (ADR 0001), and this query does not know the subject.
func (s *Store) ListReferrers(ctx context.Context, repo string, subject meta.Digest, artifactType string) ([]meta.Manifest, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT `+manifestColumns+` FROM manifests
		 WHERE repo_name = $1 AND subject_digest = $2 AND ($3 = '' OR artifact_type = $4)
		 ORDER BY digest`,
		[]any{repo, string(subject), artifactType, artifactType},
		func(rows *sql.Rows) (meta.Manifest, error) { return scanManifest(rows) })
}

// PutTag creates or repoints a tag. The manifest must already exist.
func (s *Store) PutTag(ctx context.Context, tag meta.Tag) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if tag.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := s.repository(ctx, tx, tag.Repository); err != nil {
			return err
		}
		if _, err := s.manifest(ctx, tx, tag.Repository, tag.Digest); err != nil {
			return err
		}
		// Repointing keeps the original creation time: the tag is the same
		// tag, pointing somewhere new.
		_, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO tags (repo_name, name, manifest_digest, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (repo_name, name) DO UPDATE SET
			     manifest_digest = excluded.manifest_digest,
			     updated_at = excluded.updated_at`,
			tag.Repository, tag.Name, string(tag.Digest), sqlutil.Millis(tag.CreatedAt), sqlutil.Millis(tag.UpdatedAt))
		return err
	})
}

// GetTag resolves a tag to its manifest.
func (s *Store) GetTag(ctx context.Context, repo, name string) (meta.Tag, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Tag{}, err
	}

	tag, err := scanTag(s.db.QueryRowContext(ctx,
		`SELECT repo_name, name, manifest_digest, created_at, updated_at
		 FROM tags WHERE repo_name = $1 AND name = $2`, repo, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Tag{}, meta.NotFound("tag", name)
	case err != nil:
		return meta.Tag{}, fmt.Errorf("scan tag: %w", err)
	default:
		return tag, nil
	}
}

func scanTag(sc sqlutil.Scanner) (meta.Tag, error) {
	var (
		tag     meta.Tag
		digest  string
		created sql.NullInt64
		updated sql.NullInt64
	)
	if err := sc.Scan(&tag.Repository, &tag.Name, &digest, &created, &updated); err != nil {
		return meta.Tag{}, err
	}
	tag.Digest = meta.Digest(digest)
	tag.CreatedAt = sqlutil.AsTime(created)
	tag.UpdatedAt = sqlutil.AsTime(updated)
	return tag, nil
}

// ListTags returns a page of tags ordered by name. An invisible repository is
// indistinguishable from a missing one (ADR 0003).
func (s *Store) ListTags(ctx context.Context, repo string, opts meta.ListOptions) (meta.TagPage, error) {
	if err := s.ready(ctx); err != nil {
		return meta.TagPage{}, err
	}
	if _, err := s.repository(ctx, s.db, repo); err != nil {
		return meta.TagPage{}, err
	}
	if !opts.Visibility.Allows(repo) {
		return meta.TagPage{}, meta.NotFound("repository", repo)
	}

	limit := opts.EffectiveLimit()
	tags, err := sqlutil.Collect(ctx, s.db,
		`SELECT repo_name, name, manifest_digest, created_at, updated_at
		 FROM tags WHERE repo_name = $1 AND name > $2 ORDER BY name LIMIT $3`,
		[]any{repo, opts.Cursor, limit + 1},
		func(rows *sql.Rows) (meta.Tag, error) { return scanTag(rows) })
	if err != nil {
		return meta.TagPage{}, err
	}

	page := meta.TagPage{Tags: tags}
	if len(tags) > limit {
		page.Tags = tags[:limit]
		page.NextCursor = tags[limit-1].Name
	}
	return page, nil
}

// DeleteTag removes one tag, leaving the manifest in place.
func (s *Store) DeleteTag(ctx context.Context, repo, name string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db, `DELETE FROM tags WHERE repo_name = $1 AND name = $2`, repo, name)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("tag", name)
	}
	return nil
}

// PutBlob records a hosted blob. Storing an existing digest again is not an
// error: blobs are content-addressed and identical by definition.
func (s *Store) PutBlob(ctx context.Context, blob meta.Blob) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if blob.Digest == "" {
		return meta.Invalid("digest", "must not be empty")
	}
	if blob.Size < 0 {
		return meta.Invalid("size", "must not be negative")
	}

	_, err := sqlutil.Execute(ctx, s.db,
		`INSERT INTO blobs (digest, size, created_at) VALUES ($1, $2, $3)
		 ON CONFLICT (digest) DO NOTHING`,
		string(blob.Digest), blob.Size, sqlutil.Millis(blob.CreatedAt))
	return err
}

// GetBlob returns a blob record.
func (s *Store) GetBlob(ctx context.Context, digest meta.Digest) (meta.Blob, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Blob{}, err
	}

	var (
		blob    meta.Blob
		stored  string
		created sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT digest, size, created_at FROM blobs WHERE digest = $1`, string(digest)).
		Scan(&stored, &blob.Size, &created)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Blob{}, meta.NotFound("blob", string(digest))
	case err != nil:
		return meta.Blob{}, fmt.Errorf("scan blob: %w", err)
	}
	blob.Digest = meta.Digest(stored)
	blob.CreatedAt = sqlutil.AsTime(created)
	return blob, nil
}

// DeleteBlob removes a blob record. Garbage collection calls it only after
// re-checking reachability in the same transaction (ADR 0010).
func (s *Store) DeleteBlob(ctx context.Context, digest meta.Digest) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db, `DELETE FROM blobs WHERE digest = $1`, string(digest))
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("blob", string(digest))
	}
	return nil
}

// CreateUpload starts an upload session. Its existence pins the digest against
// garbage collection, which is why it is stored rather than held in memory.
func (s *Store) CreateUpload(ctx context.Context, session meta.UploadSession) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if session.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := s.repository(ctx, tx, session.Repository); err != nil {
			return err
		}
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM upload_sessions WHERE id = $1`, session.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("upload", session.ID)
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO upload_sessions (id, repo_name, digest, bytes, started_at, last_chunk_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			session.ID, session.Repository, string(session.Digest), session.Bytes,
			sqlutil.Millis(session.StartedAt), sqlutil.Millis(session.LastChunkAt))
		return asConflict(err, "upload", session.ID)
	})
}

// GetUpload returns a session.
func (s *Store) GetUpload(ctx context.Context, id string) (meta.UploadSession, error) {
	if err := s.ready(ctx); err != nil {
		return meta.UploadSession{}, err
	}

	session, err := scanUpload(s.db.QueryRowContext(ctx,
		`SELECT id, repo_name, digest, bytes, started_at, last_chunk_at
		 FROM upload_sessions WHERE id = $1`, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.UploadSession{}, meta.NotFound("upload", id)
	case err != nil:
		return meta.UploadSession{}, fmt.Errorf("scan upload: %w", err)
	default:
		return session, nil
	}
}

func scanUpload(sc sqlutil.Scanner) (meta.UploadSession, error) {
	var (
		session meta.UploadSession
		digest  string
		started sql.NullInt64
		last    sql.NullInt64
	)
	if err := sc.Scan(&session.ID, &session.Repository, &digest, &session.Bytes, &started, &last); err != nil {
		return meta.UploadSession{}, err
	}
	session.Digest = meta.Digest(digest)
	session.StartedAt = sqlutil.AsTime(started)
	session.LastChunkAt = sqlutil.AsTime(last)
	return session, nil
}

// UpdateUpload records progress and refreshes the activity timestamp, so an
// active upload is never reaped. The caller supplies the time: no store calls
// time.Now (§7).
func (s *Store) UpdateUpload(ctx context.Context, id string, bytes int64, at time.Time) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if bytes < 0 {
		return meta.Invalid("bytes", "must not be negative")
	}

	affected, err := sqlutil.Execute(ctx, s.db,
		`UPDATE upload_sessions SET bytes = $1, last_chunk_at = $2 WHERE id = $3`,
		bytes, sqlutil.Millis(at), id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("upload", id)
	}
	return nil
}

// DeleteUpload removes a session on completion or cancellation.
func (s *Store) DeleteUpload(ctx context.Context, id string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db, `DELETE FROM upload_sessions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("upload", id)
	}
	return nil
}

// ListStaleUploads returns sessions untouched since the cutoff, oldest first,
// for the upload reaper (R-011).
func (s *Store) ListStaleUploads(ctx context.Context, before time.Time, limit int) ([]meta.UploadSession, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	// A session with no recorded activity is as stale as one can be, so a NULL
	// timestamp is included rather than swallowed by the comparison. NULLs sort
	// first in ascending order here, which is where the oldest belong.
	//
	// Postgres reads a NULL limit as "no limit"; it rejects a negative one.
	rowLimit := sql.NullInt64{}
	if limit > 0 {
		rowLimit = sql.NullInt64{Int64: int64(limit), Valid: true}
	}
	return sqlutil.Collect(ctx, s.db,
		`SELECT id, repo_name, digest, bytes, started_at, last_chunk_at
		 FROM upload_sessions
		 WHERE last_chunk_at IS NULL OR last_chunk_at < $1
		 ORDER BY last_chunk_at NULLS FIRST, id LIMIT $2`,
		[]any{before.UTC().UnixMilli(), rowLimit},
		func(rows *sql.Rows) (meta.UploadSession, error) { return scanUpload(rows) })
}

// validPullRecord rejects a record the store cannot account for. A zero or
// negative count is a caller bug rather than an empty batch, and it would
// corrupt a total nothing else can reconstruct.
func validPullRecord(r meta.PullRecord) error {
	switch {
	case r.Repository == "":
		return meta.Invalid("repository", "must not be empty")
	case r.Reference == "":
		return meta.Invalid("reference", "must not be empty")
	case r.Count <= 0:
		return meta.Invalid("count", "must be positive")
	default:
		return nil
	}
}

// RecordPulls accumulates a batch of pull observations in one transaction. The
// whole batch is validated first, so a bad record rejects it rather than
// leaving half of it written.
func (s *Store) RecordPulls(ctx context.Context, records []meta.PullRecord) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	for _, record := range records {
		if err := validPullRecord(record); err != nil {
			return err
		}
	}
	if len(records) == 0 {
		return nil
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		for _, record := range records {
			// The count adds and the timestamp only moves forward, so a batch
			// that arrives out of order still lands on the same row. GREATEST
			// is the right comparison here rather than a CASE: it ignores a
			// NULL argument instead of propagating it, so an unknown timestamp
			// cannot erase a known one.
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO pull_stats (repo_name, tag, last_pulled_at, count) VALUES ($1, $2, $3, $4)
				 ON CONFLICT (repo_name, tag) DO UPDATE SET
				     count = pull_stats.count + excluded.count,
				     last_pulled_at = GREATEST(pull_stats.last_pulled_at, excluded.last_pulled_at)`,
				record.Repository, record.Reference, sqlutil.Millis(record.At), record.Count); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetPullStats returns one reference's accumulated statistics. The caller
// checks read permission on the repository first: this query does not know the
// subject.
func (s *Store) GetPullStats(ctx context.Context, repo, reference string) (meta.PullStats, error) {
	if err := s.ready(ctx); err != nil {
		return meta.PullStats{}, err
	}

	var (
		stats  meta.PullStats
		pulled sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT repo_name, tag, last_pulled_at, count FROM pull_stats
		 WHERE repo_name = $1 AND tag = $2`, repo, reference).
		Scan(&stats.Repository, &stats.Reference, &pulled, &stats.Count)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.PullStats{}, meta.NotFound("pull stats", repo+"@"+reference)
	case err != nil:
		return meta.PullStats{}, fmt.Errorf("scan pull stats: %w", err)
	}
	stats.LastPulledAt = sqlutil.AsTime(pulled)
	return stats, nil
}
