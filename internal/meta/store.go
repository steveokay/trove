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
	EventStore

	// Close releases the store's resources. It is safe to call twice.
	Close() error
}

// EventStore is the durable half of the event system: the outbox that ADR 0012
// builds at-least-once webhook delivery on.
type EventStore interface {
	// WithinTx runs fn inside one transaction and commits it only if fn
	// returns nil. Everything fn wrote through tx is discarded otherwise, and
	// fn's error is returned unwrapped so the caller can still assert on it
	// with errors.Is.
	//
	// It exists for one rule: an event row must exist if and only if the
	// change that produced it committed (ADR 0012). A caller that appends its
	// event *after* its state change has a window in which a crash leaves a
	// change nobody was told about, and a caller that appends before has a
	// window in which it announces a change that never happened. Neither is
	// recoverable, because nothing downstream can tell the two apart.
	//
	// Tx is one method wide today, which is honest about what has a second
	// writer: events are the only rows that must join somebody else's
	// transaction, and every other write already owns its own. When a state
	// change needs to commit atomically with its event, that method moves onto
	// Tx as part of the task that needs it -- an additive change, since Tx is
	// an interface and callers name only what they use.
	//
	// fn may be called with a transaction that is already doomed if the
	// context is cancelled mid-way; the commit then fails and the error
	// surfaces. Implementations must not swallow it.
	WithinTx(ctx context.Context, fn func(tx Tx) error) error

	// ListEvents returns a permission-filtered page of events, oldest first,
	// paginated by the same keyset cursor every listing uses (ADR 0015). The
	// cursor is the last id of the previous page, which works because a ULID
	// sorts chronologically.
	//
	// The visibility applies to the event's repository, inside the query
	// (ADR 0003): an event naming a repository the subject cannot read must
	// not appear in a page, a count, or a cursor. System events -- those with
	// no repository -- are returned only to an unrestricted view, because
	// there is no repository to check them against. The verb a system event
	// really requires is per-type (an `authz.denied` event needs `audit:read`)
	// and belongs to the delivery worker that knows the subscription's owner
	// (E-004), not to a query that knows only names.
	ListEvents(ctx context.Context, opts ListOptions) (EventPage, error)
}

// Tx is the write surface available inside WithinTx. It is deliberately narrow:
// see WithinTx for why, and for how it grows.
//
// A Tx is valid only for the duration of the call it was handed to. Retaining
// one past the return of fn is a caller bug; implementations are free to fail
// such a call rather than write through a committed transaction.
type Tx interface {
	// AppendEvent records one event. The ID and Type must be set and the
	// timestamp must not be zero (ErrInvalid); an ID that has been used
	// before is ErrConflict, because the ID is the idempotency key and two
	// events sharing one would be indistinguishable to a receiver.
	AppendEvent(ctx context.Context, event Event) error
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
	// repository carries the new version and the given time as its UpdatedAt.
	//
	// In the same transaction it appends the *superseded* revision to the
	// configuration history: the version and document that were stored until
	// now, the actor replacing them, and when. Config changes are versioned so
	// a support bundle can show their lineage (ADR 0005), and writing the
	// history outside the transaction would let a crash leave a version nobody
	// can account for. Creation writes no history row: the current row is the
	// first revision, so the full lineage is the history plus the live row.
	//
	// The actor is the subject that made the change. It is recorded as given,
	// and an empty actor means the change came from inside the process --
	// seeding, a migration import -- rather than from a request; every admin
	// API path supplies a subject name.
	//
	// The caller supplies the time: no store calls time.Now (§7).
	UpdateRepositoryConfig(ctx context.Context, name string, config []byte, expectedVersion int64,
		actor string, at time.Time) (Repository, error)

	// ListConfigHistory returns a repository's superseded configurations,
	// oldest version first. A repository that was never reconfigured, and one
	// that does not exist, both return no revisions: history is a log rather
	// than a resource, and asking about a name nobody used is not an error.
	//
	// There is deliberately no HTTP endpoint for this yet. A proxy's stored
	// configuration is behind proxy:read (ADR 0002), and its history is the
	// same disclosure with a longer tail -- including upstreams an operator
	// has since removed. Deciding how that is exposed belongs with the
	// support-bundle task, which is the first caller that needs it; until
	// then the lineage is readable through the store, by tests and by that
	// task, and by nothing that answers a request.
	ListConfigHistory(ctx context.Context, name string) ([]ConfigRevision, error)

	// DeleteRepository removes a repository entity, its group membership rows,
	// its configuration history, and every piece of content stored under it --
	// the name itself and every name beneath it, since `team-a` is the entity
	// that holds `team-a/api` (ADR 0005). It all happens in one transaction: an
	// entity that was half deleted would leave content nothing routes to.
	//
	// The history goes with the entity deliberately. A name is free once it is
	// deleted, and a repository created at that name afterwards is a different
	// repository: inheriting a predecessor's lineage would attribute somebody
	// else's upstreams and settings to it.
	//
	// The deletion is immediate and irreversible for hosted content, which is
	// the decision rather than an oversight (Q16): there is no trash can, and
	// the lag before garbage collection reclaims the blobs is the only grace
	// window. Confirming that an operator means it belongs to the admin API
	// (C-016), not here.
	DeleteRepository(ctx context.Context, name string) error

	// SetGroupMembers replaces a group's ordered member list atomically.
	// Positions must be unique and members must exist.
	SetGroupMembers(ctx context.Context, group string, members []GroupMember) error

	// ListGroupMembers returns a group's members in resolution order.
	ListGroupMembers(ctx context.Context, group string) ([]GroupMember, error)
}

// ContentStore manages hosted manifests, tags, blobs, and upload sessions.
// Nothing here touches cached proxy content.
//
// Content is keyed by the full OCI repository name, and the repository row it
// belongs to is its *entity*: the first path segment of that name (ADR 0005).
// Storing a manifest under `team-a/api` therefore requires the entity `team-a`
// to exist, and nothing requires a row named `team-a/api` -- there is never one,
// because an entity is a single path segment. Every write below says which of
// the two it checks, and they all check the entity.
type ContentStore interface {
	// PutManifest stores a manifest and its reference edges in one
	// transaction. The edges are what garbage collection walks, so a manifest
	// that exists without them would be a blob-loss bug (ADR 0010).
	//
	// The manifest's entity must exist; ErrNotFound names the entity, not the
	// content name, because the entity is what an operator would have to
	// create.
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
	// optionally filtered by artifact type, ordered by digest -- the ordering
	// is contract, because the rendered referrers index is golden-tested and
	// a store-dependent order would make identical registries answer
	// differently. Callers must check read permission on the subject first: a
	// referrer inherits the subject's permission (ADR 0001), and this method
	// does not know the subject.
	ListReferrers(ctx context.Context, repo string, subject Digest, artifactType string) ([]Manifest, error)

	// PutTag creates or repoints a tag. The tag's entity and the manifest it
	// points at must both already exist.
	PutTag(ctx context.Context, tag Tag) error

	// GetTag resolves a tag to its manifest, or ErrNotFound.
	GetTag(ctx context.Context, repo, name string) (Tag, error)

	// ListTags returns a page of tags ordered by name. The repository itself
	// must be visible to the caller, and it must be a name this registry
	// knows: its entity exists, and either the name *is* that entity or it
	// holds content. A name nobody has ever pushed to is ErrNotFound rather
	// than an empty page -- a typo must not come back looking like a real
	// repository that happens to be empty, which is also what the distribution
	// spec's NAME_UNKNOWN says.
	//
	// An invisible repository is ErrNotFound too, and deliberately the same
	// answer: the two are indistinguishable (ADR 0003).
	ListTags(ctx context.Context, repo string, opts ListOptions) (TagPage, error)

	// ListContentNames returns a permission-filtered page of the distinct full
	// OCI repository names that hold hosted content, ordered lexically and
	// paginated by the same keyset cursor every listing uses (ADR 0015).
	//
	// It exists because a content name is not a repository entity. An entity
	// is mounted at the first path segment of a name, so `team-a` is the
	// entity and `team-a/api` is content inside it (ADR 0005); the catalog
	// lists what can be pulled, which is the names with content, not the
	// entities that route to them. ListRepositories answers the other
	// question -- which entities exist -- and the two are deliberately
	// separate methods rather than one with a flag.
	//
	// Only hosted content is enumerated, because only hosted content has rows
	// here: cached proxy content lives in its own table family (ADR 0009) and
	// joins this listing when that family exists, and a group contributes the
	// union of the members its subject may read (C-012). Neither is reachable
	// from this method, which is what keeps it a query over one table.
	//
	// The visibility is applied inside the query. A name the subject cannot
	// see must not appear in a page, in a count, or in a NextCursor -- a
	// cursor naming a hidden repository discloses it as surely as listing it
	// would (ADR 0003).
	ListContentNames(ctx context.Context, opts ListOptions) (ContentNamePage, error)

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

	// CreateUpload starts an upload session. Its entity must exist: an upload
	// into a repository that cannot be routed to could never be committed.
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

	// RecordPulls accumulates a batch of pull observations in one transaction:
	// each record adds its count to the reference's total and advances the
	// last-pulled time, which never moves backwards however the batch is
	// ordered. An empty batch is a no-op. A record with a non-positive count
	// or an empty repository or reference is ErrInvalid, and the whole batch
	// is rejected before anything is written.
	//
	// A record naming a repository or a reference that no longer exists still
	// upserts. Pull statistics are observations, not references: they hold no
	// foreign key, so a tag repointed or deleted between the pull and the
	// flush cannot fail the write, and retention joins them against live
	// content when it evaluates (§7).
	//
	// Callers batch off the hot path (R-010). A pull must never write here
	// itself: this is the only method in the interface whose latency is
	// deliberately nobody's request.
	RecordPulls(ctx context.Context, records []PullRecord) error

	// GetPullStats returns one reference's accumulated statistics, or
	// ErrNotFound. There is deliberately no listing yet: retention's rules
	// (the P tasks) will add one once they know the query shape they need, and
	// the caller checks read permission on the repository first -- this method,
	// like GetTag, does not know the subject.
	GetPullStats(ctx context.Context, repo, reference string) (PullStats, error)
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

	// PutBuiltinRole creates or replaces a built-in role's definition. It is
	// the seeding path (Z-014) and the only way a built-in changes: operators
	// cannot edit them, but startup must be able to bring "admin means every
	// verb" back to true after an upgrade -- or after a row was edited in the
	// database, which this heals. Replacement keeps bindings: it is an
	// upgrade, not a deletion. The role must carry the Builtin flag
	// (ErrInvalid), and an existing custom role of the same name is an
	// operator's and is refused (ErrConflict).
	PutBuiltinRole(ctx context.Context, role Role) error

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
