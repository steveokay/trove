package memory

import (
	"context"
	"fmt"

	"github.com/steveokay/trove/internal/meta"
)

// The cached-content family. It shares no map with the hosted one above, which
// is the in-memory version of ADR 0006's separate tables: a cache path that
// went looking for hosted manifests here would find a map it has no name for.

// requireProxyEntity checks that a cached write's content name belongs to an
// entity that exists and is a proxy.
//
// The type check is the wall, not a nicety. Cached content is defined by being
// refillable from an upstream, and a hosted or group entity has none; a row
// under one would be content that reports itself recoverable while the only
// copy of its bytes sits in the cache store, where eviction is free to take it
// (ADR 0009).
func (s *Store) requireProxyEntity(name string) error {
	entity := entityOf(name)
	repo, ok := s.repos[entity]
	if !ok {
		return meta.NotFound("repository", entity)
	}
	if repo.Type != meta.Proxy {
		return meta.Invalid("repository",
			fmt.Sprintf("repository %q is a %s, not a proxy", entity, repo.Type))
	}
	return nil
}

// PutCachedManifest stores a cached manifest and its edges.
func (s *Store) PutCachedManifest(ctx context.Context, m meta.CachedManifest, refs []meta.CachedManifestRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if err := s.requireProxyEntity(m.Repository); err != nil {
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

	stored := m
	stored.Payload = append([]byte(nil), m.Payload...)

	if s.cachedManifests[m.Repository] == nil {
		s.cachedManifests[m.Repository] = make(map[meta.Digest]meta.CachedManifest)
		s.cachedRefs[m.Repository] = make(map[meta.Digest][]meta.CachedManifestRef)
	}
	s.cachedManifests[m.Repository][m.Digest] = stored

	edges := make([]meta.CachedManifestRef, len(refs))
	copy(edges, refs)
	s.cachedRefs[m.Repository][m.Digest] = edges
	return nil
}

// GetCachedManifest returns one cached manifest.
func (s *Store) GetCachedManifest(ctx context.Context, repo string, digest meta.Digest) (meta.CachedManifest, error) {
	if err := ctx.Err(); err != nil {
		return meta.CachedManifest{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.CachedManifest{}, err
	}

	m, ok := s.cachedManifests[repo][digest]
	if !ok {
		return meta.CachedManifest{}, meta.NotFound("cached manifest", string(digest))
	}
	m.Payload = append([]byte(nil), m.Payload...)
	return m, nil
}

// ListCachedManifestRefs returns a cached manifest's edges in write order.
func (s *Store) ListCachedManifestRefs(ctx context.Context, repo string, digest meta.Digest) ([]meta.CachedManifestRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	if _, ok := s.cachedManifests[repo][digest]; !ok {
		return nil, meta.NotFound("cached manifest", string(digest))
	}
	edges := s.cachedRefs[repo][digest]
	out := make([]meta.CachedManifestRef, len(edges))
	copy(out, edges)
	return out, nil
}

// PutCachedBlob records a blob cached under a proxy repository.
func (s *Store) PutCachedBlob(ctx context.Context, b meta.CachedBlob) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if err := s.requireProxyEntity(b.Repository); err != nil {
		return err
	}
	if b.Digest == "" {
		return meta.Invalid("digest", "must not be empty")
	}

	if s.cachedBlobs[b.Repository] == nil {
		s.cachedBlobs[b.Repository] = make(map[meta.Digest]meta.CachedBlob)
	}
	s.cachedBlobs[b.Repository][b.Digest] = b
	return nil
}

// GetCachedBlob returns one cached blob record.
func (s *Store) GetCachedBlob(ctx context.Context, repo string, digest meta.Digest) (meta.CachedBlob, error) {
	if err := ctx.Err(); err != nil {
		return meta.CachedBlob{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.CachedBlob{}, err
	}

	b, ok := s.cachedBlobs[repo][digest]
	if !ok {
		return meta.CachedBlob{}, meta.NotFound("cached blob", string(digest))
	}
	return b, nil
}

// PutTagLease stores or replaces a tag's lease.
func (s *Store) PutTagLease(ctx context.Context, lease meta.TagLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if err := s.requireProxyEntity(lease.Repository); err != nil {
		return err
	}
	switch {
	case lease.Tag == "":
		return meta.Invalid("tag", "must not be empty")
	case lease.Digest == "":
		return meta.Invalid("digest", "must not be empty")
	}

	if s.tagLeases[lease.Repository] == nil {
		s.tagLeases[lease.Repository] = make(map[string]meta.TagLease)
	}
	s.tagLeases[lease.Repository][lease.Tag] = lease
	return nil
}

// GetTagLease returns a tag's lease.
func (s *Store) GetTagLease(ctx context.Context, repo, tag string) (meta.TagLease, error) {
	if err := ctx.Err(); err != nil {
		return meta.TagLease{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.TagLease{}, err
	}

	lease, ok := s.tagLeases[repo][tag]
	if !ok {
		return meta.TagLease{}, meta.NotFound("tag lease", tag)
	}
	return lease, nil
}

// DeleteTagLease removes a lease.
func (s *Store) DeleteTagLease(ctx context.Context, repo, tag string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.tagLeases[repo][tag]; !ok {
		return meta.NotFound("tag lease", tag)
	}
	delete(s.tagLeases[repo], tag)
	return nil
}

// PutNegativeEntry records that an upstream did not have a name.
func (s *Store) PutNegativeEntry(ctx context.Context, entry meta.NegativeEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if err := s.requireProxyEntity(entry.Repository); err != nil {
		return err
	}
	if entry.Reference == "" {
		return meta.Invalid("reference", "must not be empty")
	}

	if s.negativeCache[entry.Repository] == nil {
		s.negativeCache[entry.Repository] = make(map[string]meta.NegativeEntry)
	}
	s.negativeCache[entry.Repository][entry.Reference] = entry
	return nil
}

// GetNegativeEntry returns a recorded absence.
func (s *Store) GetNegativeEntry(ctx context.Context, repo, reference string) (meta.NegativeEntry, error) {
	if err := ctx.Err(); err != nil {
		return meta.NegativeEntry{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.NegativeEntry{}, err
	}

	entry, ok := s.negativeCache[repo][reference]
	if !ok {
		return meta.NegativeEntry{}, meta.NotFound("negative cache entry", reference)
	}
	return entry, nil
}

// DeleteNegativeEntry removes a recorded absence.
func (s *Store) DeleteNegativeEntry(ctx context.Context, repo, reference string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.negativeCache[repo][reference]; !ok {
		return meta.NotFound("negative cache entry", reference)
	}
	delete(s.negativeCache[repo], reference)
	return nil
}

// deleteCachedContent drops every cached row stored under an entity. It is
// called from DeleteRepository, with the lock held.
//
// Cached rows go with the entity for the same reason hosted content does: the
// name is free afterwards, and a proxy created at it points at whatever
// upstream its own operator chose. Serving a predecessor's cached bytes from
// the new name would answer for a remote nobody configured.
func (s *Store) deleteCachedContent(entity string) {
	for content := range s.cachedManifests {
		if belongsTo(content, entity) {
			delete(s.cachedManifests, content)
			delete(s.cachedRefs, content)
		}
	}
	for content := range s.cachedBlobs {
		if belongsTo(content, entity) {
			delete(s.cachedBlobs, content)
		}
	}
	for content := range s.tagLeases {
		if belongsTo(content, entity) {
			delete(s.tagLeases, content)
		}
	}
	for content := range s.negativeCache {
		if belongsTo(content, entity) {
			delete(s.negativeCache, content)
		}
	}
}
