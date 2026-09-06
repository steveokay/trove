package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
	"github.com/steveokay/trove/internal/reponame"
)

// The cached-content family (ADR 0006, C-004). Every statement in this file
// names a `cached_` table, and every statement in content.go names a hosted
// one; neither set of names exists in the other file, which is the fourth of
// ADR 0009's walls in the one place a raw statement could cross it.

const cachedManifestColumns = `repo_name, digest, media_type, artifact_type, subject_digest, payload, size, cached_at, last_access_at`

const cachedBlobColumns = `repo_name, digest, size, cached_at, last_access_at`

// requireProxyEntity checks that a cached write's content name belongs to an
// entity that exists and is a proxy. See meta.CachedContentStore for why the
// type is checked and not only the existence.
func (s *Store) requireProxyEntity(ctx context.Context, q sqlutil.Querier, name string) error {
	entity := reponame.Prefix(name)
	repo, err := s.repository(ctx, q, entity)
	if err != nil {
		return err
	}
	if repo.Type != meta.Proxy {
		return meta.Invalid("repository",
			fmt.Sprintf("repository %q is a %s, not a proxy", entity, repo.Type))
	}
	return nil
}

func scanCachedManifest(sc sqlutil.Scanner) (meta.CachedManifest, error) {
	var (
		m          meta.CachedManifest
		digest     string
		subject    string
		payload    []byte
		cached     sql.NullInt64
		lastAccess sql.NullInt64
	)
	if err := sc.Scan(&m.Repository, &digest, &m.MediaType, &m.ArtifactType, &subject,
		&payload, &m.Size, &cached, &lastAccess); err != nil {
		return meta.CachedManifest{}, err
	}
	m.Digest = meta.Digest(digest)
	m.Subject = meta.Digest(subject)
	m.Payload = payload
	m.CachedAt = sqlutil.AsTime(cached)
	m.LastAccessAt = sqlutil.AsTime(lastAccess)
	return m, nil
}

// PutCachedManifest stores a cached manifest and its edges in one transaction.
func (s *Store) PutCachedManifest(ctx context.Context, m meta.CachedManifest, refs []meta.CachedManifestRef) error {
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
		if err := s.requireProxyEntity(ctx, tx, m.Repository); err != nil {
			return err
		}
		if _, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO cached_manifests (`+cachedManifestColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (repo_name, digest) DO UPDATE SET
			     media_type = excluded.media_type,
			     artifact_type = excluded.artifact_type,
			     subject_digest = excluded.subject_digest,
			     payload = excluded.payload,
			     size = excluded.size,
			     cached_at = excluded.cached_at,
			     last_access_at = excluded.last_access_at`,
			m.Repository, string(m.Digest), m.MediaType, m.ArtifactType, string(m.Subject),
			m.Payload, m.Size, sqlutil.Millis(m.CachedAt), sqlutil.Millis(m.LastAccessAt)); err != nil {
			return err
		}

		// The edge set is replaced wholesale, as the hosted path does: a refill
		// of a digest is the same bytes by definition, but a row rewritten with
		// a stale edge set would misreport what the fill brought in.
		if _, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM cached_manifest_refs WHERE repo_name = ? AND manifest_digest = ?`,
			m.Repository, string(m.Digest)); err != nil {
			return err
		}
		for i, r := range refs {
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO cached_manifest_refs (repo_name, manifest_digest, ordinal, child_digest, kind)
				 VALUES (?, ?, ?, ?, ?)`,
				m.Repository, string(m.Digest), i, string(r.Child), string(r.Kind)); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetCachedManifest returns one cached manifest by digest.
func (s *Store) GetCachedManifest(ctx context.Context, repo string, digest meta.Digest) (meta.CachedManifest, error) {
	if err := s.ready(ctx); err != nil {
		return meta.CachedManifest{}, err
	}
	return s.cachedManifest(ctx, s.db, repo, digest)
}

func (s *Store) cachedManifest(ctx context.Context, q sqlutil.Querier, repo string, digest meta.Digest) (meta.CachedManifest, error) {
	m, err := scanCachedManifest(q.QueryRowContext(ctx,
		`SELECT `+cachedManifestColumns+` FROM cached_manifests WHERE repo_name = ? AND digest = ?`,
		repo, string(digest)))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.CachedManifest{}, meta.NotFound("cached manifest", string(digest))
	case err != nil:
		return meta.CachedManifest{}, fmt.Errorf("scan cached manifest: %w", err)
	default:
		return m, nil
	}
}

// ListCachedManifestRefs returns a cached manifest's edges in write order.
func (s *Store) ListCachedManifestRefs(ctx context.Context, repo string, digest meta.Digest) ([]meta.CachedManifestRef, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := s.cachedManifest(ctx, s.db, repo, digest); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT child_digest, kind FROM cached_manifest_refs
		 WHERE repo_name = ? AND manifest_digest = ? ORDER BY ordinal`,
		[]any{repo, string(digest)},
		func(rows *sql.Rows) (meta.CachedManifestRef, error) {
			var (
				ref   meta.CachedManifestRef
				child string
				kind  string
			)
			if err := rows.Scan(&child, &kind); err != nil {
				return meta.CachedManifestRef{}, err
			}
			ref.Child = meta.Digest(child)
			ref.Kind = meta.RefKind(kind)
			return ref, nil
		})
}

// PutCachedBlob records a blob cached under a proxy repository.
func (s *Store) PutCachedBlob(ctx context.Context, b meta.CachedBlob) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if b.Digest == "" {
		return meta.Invalid("digest", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.requireProxyEntity(ctx, tx, b.Repository); err != nil {
			return err
		}
		_, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO cached_blobs (`+cachedBlobColumns+`) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT (repo_name, digest) DO UPDATE SET
			     size = excluded.size,
			     cached_at = excluded.cached_at,
			     last_access_at = excluded.last_access_at`,
			b.Repository, string(b.Digest), b.Size,
			sqlutil.Millis(b.CachedAt), sqlutil.Millis(b.LastAccessAt))
		return err
	})
}

const tagLeaseColumns = `repo_name, tag, digest, etag, fetched_at, ttl_s, stale`

// PutTagLease stores or replaces a tag's lease.
func (s *Store) PutTagLease(ctx context.Context, lease meta.TagLease) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	switch {
	case lease.Tag == "":
		return meta.Invalid("tag", "must not be empty")
	case lease.Digest == "":
		return meta.Invalid("digest", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.requireProxyEntity(ctx, tx, lease.Repository); err != nil {
			return err
		}
		_, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO tag_leases (`+tagLeaseColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (repo_name, tag) DO UPDATE SET
			     digest = excluded.digest,
			     etag = excluded.etag,
			     fetched_at = excluded.fetched_at,
			     ttl_s = excluded.ttl_s,
			     stale = excluded.stale`,
			lease.Repository, lease.Tag, string(lease.Digest), lease.ETag,
			sqlutil.Millis(lease.FetchedAt), int64(lease.TTL/time.Second), lease.Stale)
		return err
	})
}

// GetTagLease returns a tag's lease.
func (s *Store) GetTagLease(ctx context.Context, repo, tag string) (meta.TagLease, error) {
	if err := s.ready(ctx); err != nil {
		return meta.TagLease{}, err
	}

	var (
		lease   meta.TagLease
		digest  string
		fetched sql.NullInt64
		ttl     int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT `+tagLeaseColumns+` FROM tag_leases WHERE repo_name = ? AND tag = ?`,
		repo, tag).Scan(&lease.Repository, &lease.Tag, &digest, &lease.ETag,
		&fetched, &ttl, &lease.Stale)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.TagLease{}, meta.NotFound("tag lease", tag)
	case err != nil:
		return meta.TagLease{}, fmt.Errorf("scan tag lease: %w", err)
	}
	lease.Digest = meta.Digest(digest)
	lease.FetchedAt = sqlutil.AsTime(fetched)
	lease.TTL = time.Duration(ttl) * time.Second
	return lease, nil
}

// DeleteTagLease removes a lease.
func (s *Store) DeleteTagLease(ctx context.Context, repo, tag string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db,
		`DELETE FROM tag_leases WHERE repo_name = ? AND tag = ?`, repo, tag)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("tag lease", tag)
	}
	return nil
}

// GetCachedBlob returns one cached blob record.
func (s *Store) GetCachedBlob(ctx context.Context, repo string, digest meta.Digest) (meta.CachedBlob, error) {
	if err := s.ready(ctx); err != nil {
		return meta.CachedBlob{}, err
	}

	var (
		b          meta.CachedBlob
		stored     string
		cached     sql.NullInt64
		lastAccess sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT `+cachedBlobColumns+` FROM cached_blobs WHERE repo_name = ? AND digest = ?`,
		repo, string(digest)).Scan(&b.Repository, &stored, &b.Size, &cached, &lastAccess)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.CachedBlob{}, meta.NotFound("cached blob", string(digest))
	case err != nil:
		return meta.CachedBlob{}, fmt.Errorf("scan cached blob: %w", err)
	}
	b.Digest = meta.Digest(stored)
	b.CachedAt = sqlutil.AsTime(cached)
	b.LastAccessAt = sqlutil.AsTime(lastAccess)
	return b, nil
}
