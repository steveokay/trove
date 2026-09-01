package meta

import (
	"context"
	"time"
)

// Store is the metadata store. It is composed from the entity groups of
// ADR 0006 so implementations and tests can be organised the same way, while
// callers see one interface.
//
// Two rules hold across every method:
//
//   - Listings take a Visibility and filter inside the query. Fetching
//     everything and filtering afterwards leaks through counts and pagination
//     (ADR 0003), so no method offers an unfiltered listing.
//   - Hosted and cached content never share a method. The cached-content group
//     is a separate interface with separate types, which is what makes it
//     impossible for a cache path to reach hosted content (ADR 0009).
type Store interface {
	RepositoryStore
	ContentStore

	// Close releases the store's resources. It is safe to call twice.
	Close() error
}

// RepositoryStore manages repository entities and group membership.
type RepositoryStore interface {
	// CreateRepository stores a new repository. It returns ErrConflict if the
	// name is taken.
	CreateRepository(ctx context.Context, repo Repository) (Repository, error)

	// GetRepository returns one repository by name, or ErrNotFound.
	GetRepository(ctx context.Context, name string) (Repository, error)

	// ListRepositories returns a permission-filtered page of repositories
	// ordered by name.
	ListRepositories(ctx context.Context, opts ListOptions) (RepositoryPage, error)

	// UpdateRepositoryConfig replaces a repository's configuration. The write
	// fails with ErrStale unless expectedVersion matches the stored version,
	// so concurrent edits cannot silently overwrite each other. The returned
	// repository carries the new version.
	UpdateRepositoryConfig(ctx context.Context, name string, config []byte, expectedVersion int64) (Repository, error)

	// DeleteRepository removes a repository and its group membership rows. It
	// does not delete content: callers sequence that explicitly, because
	// deleting hosted content is irreversible (ADR 0009).
	DeleteRepository(ctx context.Context, name string) error

	// SetGroupMembers replaces a group's ordered member list atomically.
	// Positions must be unique and members must exist.
	SetGroupMembers(ctx context.Context, group string, members []GroupMember) error

	// ListGroupMembers returns a group's members in resolution order.
	ListGroupMembers(ctx context.Context, group string) ([]GroupMember, error)
}

// ContentStore manages hosted manifests, tags, blobs, and upload sessions.
// Nothing here touches cached proxy content.
type ContentStore interface {
	// PutManifest stores a manifest and its reference edges in one
	// transaction. The edges are what garbage collection walks, so a manifest
	// that exists without them would be a blob-loss bug (ADR 0010).
	PutManifest(ctx context.Context, m Manifest, refs []ManifestRef) error

	// GetManifest returns one manifest by digest, or ErrNotFound.
	GetManifest(ctx context.Context, repo string, digest Digest) (Manifest, error)

	// DeleteManifest removes a manifest, its reference edges, and any tags
	// pointing at it. It returns ErrReferenced, naming the parents, when a live
	// index still lists the manifest as a child (Q10).
	DeleteManifest(ctx context.Context, repo string, digest Digest) error

	// ListManifestRefs returns the manifest's outgoing reference edges.
	ListManifestRefs(ctx context.Context, repo string, digest Digest) ([]ManifestRef, error)

	// ListIndexParents returns the digests of manifests that reference the
	// given digest as a child. It is what makes the Q10 refusal possible.
	ListIndexParents(ctx context.Context, repo string, child Digest) ([]Digest, error)

	// ListReferrers returns manifests whose subject is the given digest,
	// optionally filtered by artifact type. Callers must check read permission
	// on the subject first: a referrer inherits the subject's permission
	// (ADR 0001), and this method does not know the subject.
	ListReferrers(ctx context.Context, repo string, subject Digest, artifactType string) ([]Manifest, error)

	// PutTag creates or repoints a tag. The manifest must already exist.
	PutTag(ctx context.Context, tag Tag) error

	// GetTag resolves a tag to its manifest, or ErrNotFound.
	GetTag(ctx context.Context, repo, name string) (Tag, error)

	// ListTags returns a page of tags ordered by name. The repository itself
	// must be visible to the caller.
	ListTags(ctx context.Context, repo string, opts ListOptions) (TagPage, error)

	// DeleteTag removes one tag, leaving the manifest in place.
	DeleteTag(ctx context.Context, repo, name string) error

	// PutBlob records a hosted blob. Storing an existing digest again is not
	// an error: blobs are content-addressed and identical by definition.
	PutBlob(ctx context.Context, blob Blob) error

	// GetBlob returns a blob record, or ErrNotFound.
	GetBlob(ctx context.Context, digest Digest) (Blob, error)

	// DeleteBlob removes a blob record. Garbage collection calls it only after
	// re-checking reachability inside the same transaction (ADR 0010).
	DeleteBlob(ctx context.Context, digest Digest) error

	// CreateUpload starts an upload session.
	CreateUpload(ctx context.Context, session UploadSession) error

	// GetUpload returns a session, or ErrNotFound.
	GetUpload(ctx context.Context, id string) (UploadSession, error)

	// UpdateUpload records progress on a session, refreshing its activity
	// timestamp so an active upload is never reaped. The caller supplies the
	// time: no store calls time.Now, which is what keeps reaping and retention
	// testable against an injected clock (§7).
	UpdateUpload(ctx context.Context, id string, bytes int64, at time.Time) error

	// DeleteUpload removes a session on completion or cancellation.
	DeleteUpload(ctx context.Context, id string) error

	// ListStaleUploads returns sessions untouched since the cutoff, oldest
	// first, for the upload reaper (R-011).
	ListStaleUploads(ctx context.Context, before time.Time, limit int) ([]UploadSession, error)
}
