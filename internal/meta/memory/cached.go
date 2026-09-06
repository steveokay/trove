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
}
