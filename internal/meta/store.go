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
	IdentityStore
	CredentialStore

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

// IdentityStore manages subjects, groups, roles, and bindings: everything the
// authorization decision needs, and nothing that decides anything itself. The
// decision function is pure and lives in authz (ADR 0001); this interface only
// supplies it with values.
type IdentityStore interface {
	// CreateSubject stores a user, robot, or the anonymous subject. Names are
	// unique across all kinds.
	CreateSubject(ctx context.Context, subject Subject) error

	// GetSubject returns a subject by name, or ErrNotFound.
	GetSubject(ctx context.Context, name string) (Subject, error)

	// ListSubjects returns a page of subjects ordered by name.
	ListSubjects(ctx context.Context, opts ListOptions) (SubjectPage, error)

	// SetSubjectDisabled enables or disables a subject. Disabling is
	// reversible and keeps bindings intact; deletion does not.
	SetSubjectDisabled(ctx context.Context, name string, disabled bool) error

	// DeleteSubject removes a subject along with its group memberships and
	// bindings. It refuses to remove the built-in anonymous subject, which
	// every unauthenticated request resolves to.
	DeleteSubject(ctx context.Context, name string) error

	// CreateGroup stores a local group.
	CreateGroup(ctx context.Context, group SubjectGroup) error

	// GetGroup returns a group by name, or ErrNotFound.
	GetGroup(ctx context.Context, name string) (SubjectGroup, error)

	// ListGroups returns every group, ordered by name.
	ListGroups(ctx context.Context) ([]SubjectGroup, error)

	// DeleteGroup removes a group, its memberships, and its bindings.
	DeleteGroup(ctx context.Context, name string) error

	// AddGroupMember puts a subject in a group. Adding twice is not an error:
	// membership is a set.
	AddGroupMember(ctx context.Context, group, subject string) error

	// RemoveGroupMember takes a subject out of a group.
	RemoveGroupMember(ctx context.Context, group, subject string) error

	// ListGroupMemberSubjects returns a group's members, ordered by name.
	ListGroupMemberSubjects(ctx context.Context, group string) ([]Subject, error)

	// ListSubjectGroups returns the groups a subject belongs to, ordered by
	// name.
	ListSubjectGroups(ctx context.Context, subject string) ([]SubjectGroup, error)

	// CreateRole stores a role. Verbs are stored as given, expanded.
	CreateRole(ctx context.Context, role Role) error

	// GetRole returns a role by name, or ErrNotFound.
	GetRole(ctx context.Context, name string) (Role, error)

	// ListRoles returns every role, ordered by name.
	ListRoles(ctx context.Context) ([]Role, error)

	// UpdateRoleVerbs replaces a custom role's verb set. Built-in roles are
	// read-only and the store returns ErrInvalid for them.
	UpdateRoleVerbs(ctx context.Context, name string, verbs []string) error

	// DeleteRole removes a custom role and every binding that granted it.
	// Built-in roles cannot be deleted.
	DeleteRole(ctx context.Context, name string) error

	// CreateBinding grants a role to a subject or group within a scope. The
	// principal and the role must exist. Re-creating an identical binding is
	// a conflict: bindings are a set, and a duplicate would double-count in
	// the explainer.
	CreateBinding(ctx context.Context, binding Binding) error

	// GetBinding returns one binding by id, or ErrNotFound.
	GetBinding(ctx context.Context, id string) (Binding, error)

	// ListBindings returns every binding, ordered by id.
	ListBindings(ctx context.Context) ([]Binding, error)

	// DeleteBinding removes one binding by id.
	DeleteBinding(ctx context.Context, id string) error

	// ListEffectiveBindings returns every binding that applies to a subject:
	// those bound to it directly and those reaching it through a group, each
	// tagged with how it arrived. This is the single query authorization runs
	// per request, and the same data the effective-permission explainer
	// renders, so the two can never disagree.
	//
	// A disabled subject has no effective bindings: disabling must take
	// effect everywhere at once, not only where someone remembered to check.
	ListEffectiveBindings(ctx context.Context, subject string) ([]EffectiveBinding, error)
}

// CredentialStore holds secrets at rest: password verifiers, robot secrets,
// personal access tokens, and browser sessions. It stores hashes, never
// plaintext, and enforces expiry on read rather than trusting callers to check
// afterwards (ADR 0004).
type CredentialStore interface {
	// PutUserCredential stores or replaces a user's password verifier.
	PutUserCredential(ctx context.Context, cred UserCredential) error

	// GetUserCredential returns a user's verifier, or ErrNotFound. Password
	// verification happens in authn; the store only supplies the hash.
	GetUserCredential(ctx context.Context, subject string) (UserCredential, error)

	// DeleteUserCredential removes a password verifier, leaving the subject.
	DeleteUserCredential(ctx context.Context, subject string) error

	// PutRobotCredential stores or replaces a robot's secret digest. The
	// expiry is mandatory; a robot without one is rejected.
	PutRobotCredential(ctx context.Context, cred RobotCredential) error

	// GetRobotCredential returns a robot's secret digest, or ErrNotFound if
	// there is none or it has expired at the given time. Expired and absent
	// are the same answer on purpose: an authentication path should not
	// reveal which robots used to exist.
	GetRobotCredential(ctx context.Context, subject string, now time.Time) (RobotCredential, error)

	// DeleteRobotCredential revokes a robot's secret. The next use fails,
	// regardless of any token minted while it was valid.
	DeleteRobotCredential(ctx context.Context, subject string) error

	// CreateAccessToken stores a personal access token.
	CreateAccessToken(ctx context.Context, token AccessToken) error

	// GetAccessTokenByHash resolves a presented token to its record, or
	// ErrNotFound if unknown or expired at the given time. Lookup is by hash
	// because that is all the store holds.
	GetAccessTokenByHash(ctx context.Context, hash []byte, now time.Time) (AccessToken, error)

	// ListAccessTokens returns a subject's tokens, ordered by name, including
	// expired ones so an operator can see and clean them up.
	ListAccessTokens(ctx context.Context, subject string) ([]AccessToken, error)

	// TouchAccessToken records that a token was used.
	TouchAccessToken(ctx context.Context, id string, at time.Time) error

	// DeleteAccessToken revokes one token by id.
	DeleteAccessToken(ctx context.Context, id string) error

	// CreateSession stores a browser session.
	CreateSession(ctx context.Context, session Session) error

	// GetSession returns a live session, or ErrNotFound if unknown or expired
	// at the given time by either the idle or the absolute bound.
	GetSession(ctx context.Context, id string, now time.Time) (Session, error)

	// RefreshSession extends a session's idle bound. It cannot extend the
	// absolute bound: that is what stops a session living forever.
	RefreshSession(ctx context.Context, id string, idleExpiresAt time.Time) error

	// DeleteSession ends one session.
	DeleteSession(ctx context.Context, id string) error

	// DeleteSubjectSessions ends every session belonging to a subject. It is
	// what a password change and a disable both call, so a compromised
	// session cannot outlive the credential it came from.
	DeleteSubjectSessions(ctx context.Context, subject string) (int, error)

	// DeleteExpiredSessions removes sessions that expired before the given
	// time, so the table does not grow without bound.
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int, error)
}
