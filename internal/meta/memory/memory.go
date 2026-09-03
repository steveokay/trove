// Package memory is an in-memory meta.Store. It is the reference
// implementation: it defines the behaviour the contract suite pins down, and it
// lets packages above the storage layer be tested without a database.
//
// It is not a production store. Nothing is persisted, and it holds one global
// lock rather than modelling transaction isolation.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// Store is an in-memory meta.Store.
type Store struct {
	mu sync.RWMutex

	repos   map[string]meta.Repository
	members map[string][]meta.GroupMember

	// Content is keyed by repository, so deleting a repository cannot
	// accidentally reach another's manifests.
	manifests map[string]map[meta.Digest]meta.Manifest
	refs      map[string]map[meta.Digest][]meta.ManifestRef
	tags      map[string]map[string]meta.Tag

	blobs   map[meta.Digest]meta.Blob
	uploads map[string]meta.UploadSession

	// Identity is keyed by name, the handle operators use; ids are the
	// stable reference bindings point at.
	subjects      map[string]meta.Subject
	subjectGroups map[string]meta.SubjectGroup
	groupMembers  map[string]map[string]bool // group name -> subject names
	roles         map[string]meta.Role
	bindings      map[string]meta.Binding

	userCredentials  map[string]meta.UserCredential
	robotCredentials map[string]meta.RobotCredential
	accessTokens     map[string]meta.AccessToken
	sessions         map[string]meta.Session

	closed bool
}

// New returns a store holding only the built-in anonymous subject.
//
// Not quite empty, because the database-backed stores are not either: their
// migrations seed that row (ADR 0001), and every request with no credentials
// resolves to it. A reference implementation that started without it would let
// a caller work against a store no real deployment can have.
func New() *Store {
	store := newEmpty()
	store.subjects[meta.AnonymousSubjectName] = meta.Subject{
		ID:   meta.AnonymousSubjectID,
		Kind: meta.Anonymous,
		Name: meta.AnonymousSubjectName,
	}
	return store
}

// newEmpty returns a store with nothing in it at all.
func newEmpty() *Store {
	return &Store{
		repos:     make(map[string]meta.Repository),
		members:   make(map[string][]meta.GroupMember),
		manifests: make(map[string]map[meta.Digest]meta.Manifest),
		refs:      make(map[string]map[meta.Digest][]meta.ManifestRef),
		tags:      make(map[string]map[string]meta.Tag),
		blobs:     make(map[meta.Digest]meta.Blob),
		uploads:   make(map[string]meta.UploadSession),

		subjects:      make(map[string]meta.Subject),
		subjectGroups: make(map[string]meta.SubjectGroup),
		groupMembers:  make(map[string]map[string]bool),
		roles:         make(map[string]meta.Role),
		bindings:      make(map[string]meta.Binding),

		userCredentials:  make(map[string]meta.UserCredential),
		robotCredentials: make(map[string]meta.RobotCredential),
		accessTokens:     make(map[string]meta.AccessToken),
		sessions:         make(map[string]meta.Session),
	}
}

// Close marks the store unusable. It is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

var errClosed = fmt.Errorf("%w: store is closed", meta.ErrInvalid)

func (s *Store) checkOpen() error {
	if s.closed {
		return errClosed
	}
	return nil
}

// --- repositories ---

// CreateRepository stores a new repository.
func (s *Store) CreateRepository(ctx context.Context, repo meta.Repository) (meta.Repository, error) {
	if err := ctx.Err(); err != nil {
		return meta.Repository{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return meta.Repository{}, err
	}

	if repo.Name == "" {
		return meta.Repository{}, meta.Invalid("name", "must not be empty")
	}
	if !repo.Type.Valid() {
		return meta.Repository{}, meta.Invalid("type", fmt.Sprintf("unknown repository type %q", repo.Type))
	}
	if _, exists := s.repos[repo.Name]; exists {
		return meta.Repository{}, meta.Conflict("repository", repo.Name)
	}

	stored := repo
	stored.ConfigVersion = 1
	stored.Config = cloneJSON(repo.Config)
	s.repos[repo.Name] = stored

	return cloneRepo(stored), nil
}

// GetRepository returns one repository by name.
func (s *Store) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if err := ctx.Err(); err != nil {
		return meta.Repository{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Repository{}, err
	}

	repo, ok := s.repos[name]
	if !ok {
		return meta.Repository{}, meta.NotFound("repository", name)
	}
	return cloneRepo(repo), nil
}

// ListRepositories returns a permission-filtered page ordered by name.
func (s *Store) ListRepositories(ctx context.Context, opts meta.ListOptions) (meta.RepositoryPage, error) {
	if err := ctx.Err(); err != nil {
		return meta.RepositoryPage{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.RepositoryPage{}, err
	}

	names := make([]string, 0, len(s.repos))
	for name := range s.repos {
		// Filtering happens here, while building the result set -- never
		// after (ADR 0003). Counts and cursors must reflect the filter.
		if opts.Visibility.Allows(name) && name > opts.Cursor {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	limit := opts.EffectiveLimit()
	page := meta.RepositoryPage{}
	for i, name := range names {
		if i == limit {
			page.NextCursor = names[i-1]
			break
		}
		page.Repositories = append(page.Repositories, cloneRepo(s.repos[name]))
	}
	return page, nil
}

// UpdateRepositoryConfig replaces configuration under an optimistic version check.
func (s *Store) UpdateRepositoryConfig(ctx context.Context, name string, config []byte, expectedVersion int64) (meta.Repository, error) {
	if err := ctx.Err(); err != nil {
		return meta.Repository{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return meta.Repository{}, err
	}

	repo, ok := s.repos[name]
	if !ok {
		return meta.Repository{}, meta.NotFound("repository", name)
	}
	if repo.ConfigVersion != expectedVersion {
		return meta.Repository{}, fmt.Errorf("%w: repository %q is at version %d, not %d",
			meta.ErrStale, name, repo.ConfigVersion, expectedVersion)
	}

	repo.Config = cloneJSON(config)
	repo.ConfigVersion++
	s.repos[name] = repo

	return cloneRepo(repo), nil
}

// DeleteRepository removes a repository and its membership rows.
func (s *Store) DeleteRepository(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.repos[name]; !ok {
		return meta.NotFound("repository", name)
	}

	delete(s.repos, name)
	delete(s.members, name)
	delete(s.manifests, name)
	delete(s.refs, name)
	delete(s.tags, name)

	// An upload into a repository that no longer exists can never complete,
	// and while it survives it pins its digest against garbage collection.
	for id, session := range s.uploads {
		if session.Repository == name {
			delete(s.uploads, id)
		}
	}

	// Drop the repository from any group that listed it, so a stale member
	// can never resolve.
	for group, members := range s.members {
		kept := members[:0]
		for _, m := range members {
			if m.Repository != name {
				kept = append(kept, m)
			}
		}
		s.members[group] = kept
	}
	return nil
}

// SetGroupMembers replaces a group's ordered member list.
func (s *Store) SetGroupMembers(ctx context.Context, group string, members []meta.GroupMember) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	repo, ok := s.repos[group]
	if !ok {
		return meta.NotFound("repository", group)
	}
	if repo.Type != meta.Group {
		return meta.Invalid("group", fmt.Sprintf("repository %q is a %s, not a group", group, repo.Type))
	}

	seenPosition := make(map[int]bool, len(members))
	writeTargets := 0
	for _, m := range members {
		if _, ok := s.repos[m.Repository]; !ok {
			return meta.NotFound("repository", m.Repository)
		}
		if m.Repository == group {
			return meta.Invalid("members", "a group cannot contain itself")
		}
		if s.repos[m.Repository].Type == meta.Group {
			return meta.Invalid("members", fmt.Sprintf("member %q is a group; groups do not nest (ADR 0005)", m.Repository))
		}
		if seenPosition[m.Position] {
			return meta.Invalid("members", fmt.Sprintf("duplicate position %d: member order must be unambiguous", m.Position))
		}
		seenPosition[m.Position] = true
		if m.WriteTarget {
			writeTargets++
		}
	}
	if writeTargets > 1 {
		return meta.Invalid("members", "at most one member may be the write target (ADR 0005)")
	}

	stored := make([]meta.GroupMember, len(members))
	copy(stored, members)
	sort.Slice(stored, func(i, j int) bool { return stored[i].Position < stored[j].Position })
	s.members[group] = stored
	return nil
}

// ListGroupMembers returns members in resolution order.
func (s *Store) ListGroupMembers(ctx context.Context, group string) ([]meta.GroupMember, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	if _, ok := s.repos[group]; !ok {
		return nil, meta.NotFound("repository", group)
	}

	out := make([]meta.GroupMember, len(s.members[group]))
	copy(out, s.members[group])
	return out, nil
}

// --- content ---

// PutManifest stores a manifest and its reference edges together.
func (s *Store) PutManifest(ctx context.Context, m meta.Manifest, refs []meta.ManifestRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.repos[m.Repository]; !ok {
		return meta.NotFound("repository", m.Repository)
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

	if s.manifests[m.Repository] == nil {
		s.manifests[m.Repository] = make(map[meta.Digest]meta.Manifest)
		s.refs[m.Repository] = make(map[meta.Digest][]meta.ManifestRef)
	}
	s.manifests[m.Repository][m.Digest] = stored

	edges := make([]meta.ManifestRef, len(refs))
	copy(edges, refs)
	s.refs[m.Repository][m.Digest] = edges
	return nil
}

// GetManifest returns one manifest.
func (s *Store) GetManifest(ctx context.Context, repo string, digest meta.Digest) (meta.Manifest, error) {
	if err := ctx.Err(); err != nil {
		return meta.Manifest{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Manifest{}, err
	}

	m, ok := s.manifests[repo][digest]
	if !ok {
		return meta.Manifest{}, meta.NotFound("manifest", string(digest))
	}
	return cloneManifest(m), nil
}

// DeleteManifest removes a manifest unless a live index still lists it.
func (s *Store) DeleteManifest(ctx context.Context, repo string, digest meta.Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.manifests[repo][digest]; !ok {
		return meta.NotFound("manifest", string(digest))
	}

	// Q10: refuse while a live index references this manifest as a child, and
	// name the parents so the operator knows what to delete first.
	var parents []string
	for parent, edges := range s.refs[repo] {
		if parent == digest {
			continue
		}
		for _, e := range edges {
			if e.Child == digest && e.Kind == meta.RefChild {
				parents = append(parents, string(parent))
				break
			}
		}
	}
	if len(parents) > 0 {
		sort.Strings(parents)
		return meta.Referenced("manifest", string(digest), parents)
	}

	delete(s.manifests[repo], digest)
	delete(s.refs[repo], digest)

	for name, tag := range s.tags[repo] {
		if tag.Digest == digest {
			delete(s.tags[repo], name)
		}
	}
	return nil
}

// ListManifestRefs returns a manifest's outgoing edges.
func (s *Store) ListManifestRefs(ctx context.Context, repo string, digest meta.Digest) ([]meta.ManifestRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	if _, ok := s.manifests[repo][digest]; !ok {
		return nil, meta.NotFound("manifest", string(digest))
	}
	edges := s.refs[repo][digest]
	out := make([]meta.ManifestRef, len(edges))
	copy(out, edges)
	return out, nil
}

// ListIndexParents returns manifests referencing the digest as a child.
func (s *Store) ListIndexParents(ctx context.Context, repo string, child meta.Digest) ([]meta.Digest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	var parents []meta.Digest
	for parent, edges := range s.refs[repo] {
		for _, e := range edges {
			if e.Child == child && e.Kind == meta.RefChild {
				parents = append(parents, parent)
				break
			}
		}
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i] < parents[j] })
	return parents, nil
}

// ListReferrers returns manifests attached to the given subject.
func (s *Store) ListReferrers(ctx context.Context, repo string, subject meta.Digest, artifactType string) ([]meta.Manifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	var out []meta.Manifest
	for _, m := range s.manifests[repo] {
		if m.Subject != subject {
			continue
		}
		if artifactType != "" && m.ArtifactType != artifactType {
			continue
		}
		out = append(out, cloneManifest(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, nil
}

// PutTag creates or repoints a tag.
func (s *Store) PutTag(ctx context.Context, tag meta.Tag) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if tag.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}
	if _, ok := s.repos[tag.Repository]; !ok {
		return meta.NotFound("repository", tag.Repository)
	}
	if _, ok := s.manifests[tag.Repository][tag.Digest]; !ok {
		return meta.NotFound("manifest", string(tag.Digest))
	}

	if s.tags[tag.Repository] == nil {
		s.tags[tag.Repository] = make(map[string]meta.Tag)
	}
	if existing, ok := s.tags[tag.Repository][tag.Name]; ok {
		tag.CreatedAt = existing.CreatedAt
	}
	s.tags[tag.Repository][tag.Name] = tag
	return nil
}

// GetTag resolves one tag.
func (s *Store) GetTag(ctx context.Context, repo, name string) (meta.Tag, error) {
	if err := ctx.Err(); err != nil {
		return meta.Tag{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Tag{}, err
	}

	tag, ok := s.tags[repo][name]
	if !ok {
		return meta.Tag{}, meta.NotFound("tag", name)
	}
	return tag, nil
}

// ListTags returns a page of tags ordered by name.
func (s *Store) ListTags(ctx context.Context, repo string, opts meta.ListOptions) (meta.TagPage, error) {
	if err := ctx.Err(); err != nil {
		return meta.TagPage{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.TagPage{}, err
	}

	if _, ok := s.repos[repo]; !ok {
		return meta.TagPage{}, meta.NotFound("repository", repo)
	}
	// The repository itself must be visible; an invisible repository has no
	// tags as far as the caller is concerned.
	if !opts.Visibility.Allows(repo) {
		return meta.TagPage{}, meta.NotFound("repository", repo)
	}

	names := make([]string, 0, len(s.tags[repo]))
	for name := range s.tags[repo] {
		if name > opts.Cursor {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	limit := opts.EffectiveLimit()
	page := meta.TagPage{}
	for i, name := range names {
		if i == limit {
			page.NextCursor = names[i-1]
			break
		}
		page.Tags = append(page.Tags, s.tags[repo][name])
	}
	return page, nil
}

// DeleteTag removes a tag, leaving its manifest in place.
func (s *Store) DeleteTag(ctx context.Context, repo, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.tags[repo][name]; !ok {
		return meta.NotFound("tag", name)
	}
	delete(s.tags[repo], name)
	return nil
}

// PutBlob records a hosted blob; re-storing the same digest is a no-op.
func (s *Store) PutBlob(ctx context.Context, blob meta.Blob) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if blob.Digest == "" {
		return meta.Invalid("digest", "must not be empty")
	}
	if blob.Size < 0 {
		return meta.Invalid("size", "must not be negative")
	}
	if _, exists := s.blobs[blob.Digest]; exists {
		return nil // content-addressed: identical by definition
	}
	s.blobs[blob.Digest] = blob
	return nil
}

// GetBlob returns a blob record.
func (s *Store) GetBlob(ctx context.Context, digest meta.Digest) (meta.Blob, error) {
	if err := ctx.Err(); err != nil {
		return meta.Blob{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Blob{}, err
	}

	blob, ok := s.blobs[digest]
	if !ok {
		return meta.Blob{}, meta.NotFound("blob", string(digest))
	}
	return blob, nil
}

// DeleteBlob removes a blob record.
func (s *Store) DeleteBlob(ctx context.Context, digest meta.Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.blobs[digest]; !ok {
		return meta.NotFound("blob", string(digest))
	}
	delete(s.blobs, digest)
	return nil
}

// CreateUpload starts an upload session.
func (s *Store) CreateUpload(ctx context.Context, session meta.UploadSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if session.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if _, ok := s.repos[session.Repository]; !ok {
		return meta.NotFound("repository", session.Repository)
	}
	if _, exists := s.uploads[session.ID]; exists {
		return meta.Conflict("upload", session.ID)
	}
	s.uploads[session.ID] = session
	return nil
}

// GetUpload returns a session.
func (s *Store) GetUpload(ctx context.Context, id string) (meta.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return meta.UploadSession{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.UploadSession{}, err
	}

	session, ok := s.uploads[id]
	if !ok {
		return meta.UploadSession{}, meta.NotFound("upload", id)
	}
	return session, nil
}

// UpdateUpload records progress and refreshes the activity timestamp.
func (s *Store) UpdateUpload(ctx context.Context, id string, bytes int64, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	session, ok := s.uploads[id]
	if !ok {
		return meta.NotFound("upload", id)
	}
	if bytes < 0 {
		return meta.Invalid("bytes", "must not be negative")
	}
	session.Bytes = bytes
	session.LastChunkAt = at
	s.uploads[id] = session
	return nil
}

// DeleteUpload removes a session.
func (s *Store) DeleteUpload(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.uploads[id]; !ok {
		return meta.NotFound("upload", id)
	}
	delete(s.uploads, id)
	return nil
}

// ListStaleUploads returns sessions untouched since the cutoff, oldest first.
func (s *Store) ListStaleUploads(ctx context.Context, before time.Time, limit int) ([]meta.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	var out []meta.UploadSession
	for _, session := range s.uploads {
		if session.LastChunkAt.Before(before) {
			out = append(out, session)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastChunkAt.Equal(out[j].LastChunkAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].LastChunkAt.Before(out[j].LastChunkAt)
	})

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- helpers ---

func cloneRepo(r meta.Repository) meta.Repository {
	r.Config = cloneJSON(r.Config)
	return r
}

func cloneManifest(m meta.Manifest) meta.Manifest {
	m.Payload = append([]byte(nil), m.Payload...)
	return m
}

// cloneJSON copies configuration so callers cannot mutate stored state through
// a returned slice -- a real database hands back a fresh copy, and the
// reference implementation must not be more forgiving than the thing it models.
func cloneJSON(raw []byte) json.RawMessage {
	if raw == nil {
		return nil
	}
	out := make(json.RawMessage, len(raw))
	copy(out, raw)
	return out
}

// assert the interface is satisfied at compile time.
var _ meta.Store = (*Store)(nil)
