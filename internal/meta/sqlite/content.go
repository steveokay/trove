package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

const manifestColumns = `repo_name, digest, media_type, artifact_type, subject_digest, payload, size, created_at`

func scanManifest(sc scanner) (meta.Manifest, error) {
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
	m.CreatedAt = asTime(created)
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

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.repository(ctx, tx, m.Repository); err != nil {
			return err
		}
		if _, err := execute(ctx, tx,
			`INSERT INTO manifests (`+manifestColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (repo_name, digest) DO UPDATE SET
			     media_type = excluded.media_type,
			     artifact_type = excluded.artifact_type,
			     subject_digest = excluded.subject_digest,
			     payload = excluded.payload,
			     size = excluded.size,
			     created_at = excluded.created_at`,
			m.Repository, string(m.Digest), m.MediaType, m.ArtifactType, string(m.Subject),
			m.Payload, m.Size, millis(m.CreatedAt)); err != nil {
			return err
		}

		// The edge set is replaced wholesale: a re-push with fewer layers must
		// not leave the old ones marked reachable.
		if _, err := execute(ctx, tx,
			`DELETE FROM manifest_refs WHERE repo_name = ? AND manifest_digest = ?`,
			m.Repository, string(m.Digest)); err != nil {
			return err
		}
		for i, r := range refs {
			if _, err := execute(ctx, tx,
				`INSERT INTO manifest_refs (repo_name, manifest_digest, ordinal, child_digest, kind)
				 VALUES (?, ?, ?, ?, ?)`,
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

func (s *Store) manifest(ctx context.Context, q querier, repo string, digest meta.Digest) (meta.Manifest, error) {
	m, err := scanManifest(q.QueryRowContext(ctx,
		`SELECT `+manifestColumns+` FROM manifests WHERE repo_name = ? AND digest = ?`,
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

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.manifest(ctx, tx, repo, digest); err != nil {
			return err
		}

		parents, err := collect(ctx, tx,
			`SELECT DISTINCT manifest_digest FROM manifest_refs
			 WHERE repo_name = ? AND child_digest = ? AND kind = ? AND manifest_digest <> ?
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

		_, err = execute(ctx, tx, `DELETE FROM manifests WHERE repo_name = ? AND digest = ?`,
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

	return collect(ctx, s.db,
		`SELECT child_digest, kind FROM manifest_refs
		 WHERE repo_name = ? AND manifest_digest = ? ORDER BY ordinal`,
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

	return collect(ctx, s.db,
		`SELECT DISTINCT manifest_digest FROM manifest_refs
		 WHERE repo_name = ? AND child_digest = ? AND kind = ? ORDER BY manifest_digest`,
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

	return collect(ctx, s.db,
		`SELECT `+manifestColumns+` FROM manifests
		 WHERE repo_name = ? AND subject_digest = ? AND (? = '' OR artifact_type = ?)
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

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.repository(ctx, tx, tag.Repository); err != nil {
			return err
		}
		if _, err := s.manifest(ctx, tx, tag.Repository, tag.Digest); err != nil {
			return err
		}
		// Repointing keeps the original creation time: the tag is the same
		// tag, pointing somewhere new.
		_, err := execute(ctx, tx,
			`INSERT INTO tags (repo_name, name, manifest_digest, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT (repo_name, name) DO UPDATE SET
			     manifest_digest = excluded.manifest_digest,
			     updated_at = excluded.updated_at`,
			tag.Repository, tag.Name, string(tag.Digest), millis(tag.CreatedAt), millis(tag.UpdatedAt))
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
		 FROM tags WHERE repo_name = ? AND name = ?`, repo, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Tag{}, meta.NotFound("tag", name)
	case err != nil:
		return meta.Tag{}, fmt.Errorf("scan tag: %w", err)
	default:
		return tag, nil
	}
}

func scanTag(sc scanner) (meta.Tag, error) {
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
	tag.CreatedAt = asTime(created)
	tag.UpdatedAt = asTime(updated)
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
	tags, err := collect(ctx, s.db,
		`SELECT repo_name, name, manifest_digest, created_at, updated_at
		 FROM tags WHERE repo_name = ? AND name > ? ORDER BY name LIMIT ?`,
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

	affected, err := execute(ctx, s.db, `DELETE FROM tags WHERE repo_name = ? AND name = ?`, repo, name)
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

	_, err := execute(ctx, s.db,
		`INSERT INTO blobs (digest, size, created_at) VALUES (?, ?, ?)
		 ON CONFLICT (digest) DO NOTHING`,
		string(blob.Digest), blob.Size, millis(blob.CreatedAt))
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
		`SELECT digest, size, created_at FROM blobs WHERE digest = ?`, string(digest)).
		Scan(&stored, &blob.Size, &created)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Blob{}, meta.NotFound("blob", string(digest))
	case err != nil:
		return meta.Blob{}, fmt.Errorf("scan blob: %w", err)
	}
	blob.Digest = meta.Digest(stored)
	blob.CreatedAt = asTime(created)
	return blob, nil
}

// DeleteBlob removes a blob record. Garbage collection calls it only after
// re-checking reachability in the same transaction (ADR 0010).
func (s *Store) DeleteBlob(ctx context.Context, digest meta.Digest) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := execute(ctx, s.db, `DELETE FROM blobs WHERE digest = ?`, string(digest))
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

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.repository(ctx, tx, session.Repository); err != nil {
			return err
		}
		taken, err := exists(ctx, tx, `SELECT 1 FROM upload_sessions WHERE id = ?`, session.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("upload", session.ID)
		}
		_, err = execute(ctx, tx,
			`INSERT INTO upload_sessions (id, repo_name, digest, bytes, started_at, last_chunk_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			session.ID, session.Repository, string(session.Digest), session.Bytes,
			millis(session.StartedAt), millis(session.LastChunkAt))
		return err
	})
}

// GetUpload returns a session.
func (s *Store) GetUpload(ctx context.Context, id string) (meta.UploadSession, error) {
	if err := s.ready(ctx); err != nil {
		return meta.UploadSession{}, err
	}

	session, err := scanUpload(s.db.QueryRowContext(ctx,
		`SELECT id, repo_name, digest, bytes, started_at, last_chunk_at
		 FROM upload_sessions WHERE id = ?`, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.UploadSession{}, meta.NotFound("upload", id)
	case err != nil:
		return meta.UploadSession{}, fmt.Errorf("scan upload: %w", err)
	default:
		return session, nil
	}
}

func scanUpload(sc scanner) (meta.UploadSession, error) {
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
	session.StartedAt = asTime(started)
	session.LastChunkAt = asTime(last)
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

	affected, err := execute(ctx, s.db,
		`UPDATE upload_sessions SET bytes = ?, last_chunk_at = ? WHERE id = ?`,
		bytes, millis(at), id)
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

	affected, err := execute(ctx, s.db, `DELETE FROM upload_sessions WHERE id = ?`, id)
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
	// timestamp is included rather than swallowed by the comparison.
	rowLimit := -1
	if limit > 0 {
		rowLimit = limit
	}
	return collect(ctx, s.db,
		`SELECT id, repo_name, digest, bytes, started_at, last_chunk_at
		 FROM upload_sessions
		 WHERE last_chunk_at IS NULL OR last_chunk_at < ?
		 ORDER BY last_chunk_at, id LIMIT ?`,
		[]any{before.UTC().UnixMilli(), rowLimit},
		func(rows *sql.Rows) (meta.UploadSession, error) { return scanUpload(rows) })
}
