package postgres

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

// The cached-content family (ADR 0006, C-004): the SQLite file's twin, and the
// same separation. Every statement here names a `cached_` table and none of
// them names a hosted one.

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
			`INSERT INTO cached_manifests (`+cachedManifestColumns+`)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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

		if _, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM cached_manifest_refs WHERE repo_name = $1 AND manifest_digest = $2`,
			m.Repository, string(m.Digest)); err != nil {
			return err
		}
		for i, r := range refs {
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO cached_manifest_refs (repo_name, manifest_digest, ordinal, child_digest, kind)
				 VALUES ($1, $2, $3, $4, $5)`,
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
		`SELECT `+cachedManifestColumns+` FROM cached_manifests WHERE repo_name = $1 AND digest = $2`,
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
		 WHERE repo_name = $1 AND manifest_digest = $2 ORDER BY ordinal`,
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
			`INSERT INTO cached_blobs (`+cachedBlobColumns+`) VALUES ($1, $2, $3, $4, $5)
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
			`INSERT INTO tag_leases (`+tagLeaseColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)
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
		`SELECT `+tagLeaseColumns+` FROM tag_leases WHERE repo_name = $1 AND tag = $2`,
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
		`DELETE FROM tag_leases WHERE repo_name = $1 AND tag = $2`, repo, tag)
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
		`SELECT `+cachedBlobColumns+` FROM cached_blobs WHERE repo_name = $1 AND digest = $2`,
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

const negativeEntryColumns = `repo_name, reference, observed_at, ttl_s`

// PutNegativeEntry records that an upstream did not have a name.
func (s *Store) PutNegativeEntry(ctx context.Context, entry meta.NegativeEntry) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if entry.Reference == "" {
		return meta.Invalid("reference", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.requireProxyEntity(ctx, tx, entry.Repository); err != nil {
			return err
		}
		_, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO negative_cache (`+negativeEntryColumns+`) VALUES ($1, $2, $3, $4)
			 ON CONFLICT (repo_name, reference) DO UPDATE SET
			     observed_at = excluded.observed_at,
			     ttl_s = excluded.ttl_s`,
			entry.Repository, entry.Reference,
			sqlutil.Millis(entry.ObservedAt), int64(entry.TTL/time.Second))
		return err
	})
}

// GetNegativeEntry returns a recorded absence.
func (s *Store) GetNegativeEntry(ctx context.Context, repo, reference string) (meta.NegativeEntry, error) {
	if err := s.ready(ctx); err != nil {
		return meta.NegativeEntry{}, err
	}

	var (
		entry    meta.NegativeEntry
		observed sql.NullInt64
		ttl      int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT `+negativeEntryColumns+` FROM negative_cache WHERE repo_name = $1 AND reference = $2`,
		repo, reference).Scan(&entry.Repository, &entry.Reference, &observed, &ttl)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.NegativeEntry{}, meta.NotFound("negative cache entry", reference)
	case err != nil:
		return meta.NegativeEntry{}, fmt.Errorf("scan negative cache entry: %w", err)
	}
	entry.ObservedAt = sqlutil.AsTime(observed)
	entry.TTL = time.Duration(ttl) * time.Second
	return entry, nil
}

// DeleteNegativeEntry removes a recorded absence.
func (s *Store) DeleteNegativeEntry(ctx context.Context, repo, reference string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db,
		`DELETE FROM negative_cache WHERE repo_name = $1 AND reference = $2`, repo, reference)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("negative cache entry", reference)
	}
	return nil
}

// --- eviction (C-013) ------------------------------------------------------

// cacheScope compiles an eviction scope into a WHERE fragment and its
// arguments: an entity's own name plus everything beneath it, or the whole
// cache when the entity is empty.
//
// It is a name range rather than a LIKE for the reason DeleteRepository uses
// one: `_` is a LIKE wildcard and a legal name character at once, so
// `LIKE 'team_a/%'` would reach into `teamXa`.
func cacheScope(entity string, ph sqlutil.Placeholder, from int) (string, []any) {
	if entity == "" {
		return "1 = 1", nil
	}
	low, high := sqlutil.EntityContentRange(entity)
	return fmt.Sprintf("(repo_name = %s OR (repo_name >= %s AND repo_name < %s))",
			ph(from), ph(from+1), ph(from+2)),
		[]any{entity, low, high}
}

// CachedUsage reports what cached content occupies.
func (s *Store) CachedUsage(ctx context.Context, entity string) (meta.CacheUsage, error) {
	if err := s.ready(ctx); err != nil {
		return meta.CacheUsage{}, err
	}

	where, args := cacheScope(entity, sqlutil.Dollar, 1)
	var usage meta.CacheUsage
	// COALESCE because SUM over no rows is NULL, and an empty cache is a
	// perfectly ordinary state rather than an error.
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size), 0), COUNT(*) FROM cached_manifests WHERE `+where,
		args...).Scan(&usage.ManifestBytes, &usage.Manifests); err != nil {
		return meta.CacheUsage{}, fmt.Errorf("sum cached manifests: %w", err)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size), 0), COUNT(*) FROM cached_blobs WHERE `+where,
		args...).Scan(&usage.BlobBytes, &usage.Blobs); err != nil {
		return meta.CacheUsage{}, fmt.Errorf("sum cached blobs: %w", err)
	}
	usage.Bytes = usage.ManifestBytes + usage.BlobBytes
	return usage, nil
}

// ListEvictable returns cached rows least-recently-used first.
func (s *Store) ListEvictable(ctx context.Context, entity string, limit int) ([]meta.CachedItem, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}

	manifestWhere, args := cacheScope(entity, sqlutil.Dollar, 1)
	blobWhere, blobArgs := cacheScope(entity, sqlutil.Dollar, len(args)+1)
	args = append(args, blobArgs...)
	args = append(args, limit)

	// COALESCE on the sort key so both engines agree about a row whose access
	// time was never written: SQLite sorts NULL first and Postgres sorts it
	// last, and the safe reading is "coldest", which epoch gives on both.
	// The tie-breakers make the order total, so a second page cannot skip a
	// row the first page passed.
	// The UNION is wrapped rather than ordered directly: neither engine allows
	// an expression in an ORDER BY over a union, and the sort key has to be an
	// expression because a row whose access time was never written must sort as
	// the coldest -- SQLite puts NULL first and Postgres puts it last, and only
	// COALESCE makes the two agree.
	//
	// The tie-breakers after it make the order total, so a second page cannot
	// skip a row the first page passed.
	query := `SELECT repo_name, digest, kind, size, last_access_at FROM (
		    SELECT repo_name, digest, ` + quoteKind(meta.CachedManifestKind) + ` AS kind, size,
		           last_access_at, COALESCE(last_access_at, 0) AS sort_key
		    FROM cached_manifests WHERE ` + manifestWhere + `
		    UNION ALL
		    SELECT repo_name, digest, ` + quoteKind(meta.CachedBlobKind) + ` AS kind, size,
		           last_access_at, COALESCE(last_access_at, 0) AS sort_key
		    FROM cached_blobs WHERE ` + blobWhere + `
		  ) AS evictable
		  ORDER BY sort_key, repo_name, digest, kind
		  LIMIT ` + sqlutil.Dollar(len(args))

	return sqlutil.Collect(ctx, s.db, query, args, func(rows *sql.Rows) (meta.CachedItem, error) {
		var (
			item       meta.CachedItem
			digest     string
			kind       string
			lastAccess sql.NullInt64
		)
		if err := rows.Scan(&item.Repository, &digest, &kind, &item.Size, &lastAccess); err != nil {
			return meta.CachedItem{}, err
		}
		item.Digest = meta.Digest(digest)
		item.Kind = meta.CachedKind(kind)
		item.LastAccessAt = sqlutil.AsTime(lastAccess)
		return item, nil
	})
}

// quoteKind renders a cached kind as a SQL literal. The values are this
// package's own constants, never anything a request supplies.
func quoteKind(kind meta.CachedKind) string { return "'" + string(kind) + "'" }

// DeleteCachedManifest removes a cached manifest and its edges.
func (s *Store) DeleteCachedManifest(ctx context.Context, repo string, digest meta.Digest) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db,
		`DELETE FROM cached_manifests WHERE repo_name = $1 AND digest = $2`,
		repo, string(digest))
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("cached manifest", string(digest))
	}
	return nil
}

// DeleteCachedBlob removes one proxy's claim and reports the claims remaining.
func (s *Store) DeleteCachedBlob(ctx context.Context, repo string, digest meta.Digest) (int64, error) {
	if err := s.ready(ctx); err != nil {
		return 0, err
	}

	var remaining int64
	err := sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		affected, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM cached_blobs WHERE repo_name = $1 AND digest = $2`,
			repo, string(digest))
		if err != nil {
			return err
		}
		if affected == 0 {
			return meta.NotFound("cached blob", string(digest))
		}
		// In the same transaction as the delete: a claim added between the two
		// would otherwise let the caller reclaim bytes somebody is about to
		// serve.
		return tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM cached_blobs WHERE digest = $1`, string(digest)).Scan(&remaining)
	})
	if err != nil {
		return 0, err
	}
	return remaining, nil
}

// CachedBlobClaims reports how many proxies hold a cached blob.
func (s *Store) CachedBlobClaims(ctx context.Context, digest meta.Digest) (int64, error) {
	if err := s.ready(ctx); err != nil {
		return 0, err
	}

	var claims int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cached_blobs WHERE digest = $1`, string(digest)).Scan(&claims); err != nil {
		return 0, fmt.Errorf("count cached blob claims: %w", err)
	}
	return claims, nil
}

// TouchCached advances the LRU key of content that was served.
func (s *Store) TouchCached(ctx context.Context, accesses []meta.CacheAccess) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if len(accesses) == 0 {
		return nil
	}
	for _, access := range accesses {
		if !access.Kind.Valid() {
			return meta.Invalid("kind", fmt.Sprintf("unknown cached kind %q", access.Kind))
		}
		if access.Digest == "" {
			return meta.Invalid("digest", "must not be empty")
		}
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		for _, access := range accesses {
			table := "cached_blobs"
			if access.Kind == meta.CachedManifestKind {
				table = "cached_manifests"
			}
			// The guard keeps the time monotonic: a flush that arrives late
			// must not make hot content look cold. A row that is gone updates
			// nothing, which is the point -- an access is an observation about
			// a row, not a reason to resurrect one.
			if _, err := sqlutil.Execute(ctx, tx,
				`UPDATE `+table+` SET last_access_at = $1
				 WHERE repo_name = $2 AND digest = $3
				   AND (last_access_at IS NULL OR last_access_at < $4)`,
				sqlutil.Millis(access.At), access.Repository, string(access.Digest),
				sqlutil.Millis(access.At)); err != nil {
				return err
			}
		}
		return nil
	})
}
