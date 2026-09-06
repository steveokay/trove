package meta

import (
	"encoding/json"
	"time"
)

// Digest is a content-addressed identifier in "algorithm:hex" form. The
// metadata store treats it as an opaque key: parsing and verification belong to
// the storage and registry layers (ADR 0007), which is what keeps this package
// free of storage dependencies.
type Digest string

// RepositoryType distinguishes the three repository kinds (ADR 0005). The
// distinction is load-bearing: proxies never accept writes, and groups never
// store content.
type RepositoryType string

// The repository kinds.
const (
	Hosted RepositoryType = "hosted"
	Proxy  RepositoryType = "proxy"
	Group  RepositoryType = "group"
)

// Valid reports whether t is a known repository type.
func (t RepositoryType) Valid() bool {
	switch t {
	case Hosted, Proxy, Group:
		return true
	default:
		return false
	}
}

// Repository is a hosted, proxy, or group repository. Config holds the
// type-specific settings as opaque JSON; the repo package owns its shape.
type Repository struct {
	Name          string
	Type          RepositoryType
	Config        json.RawMessage
	ConfigVersion int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ConfigRevision is one superseded repository configuration: the document that
// was stored at Version, the actor who replaced it, and when.
//
// Only replaced revisions are recorded. The live configuration is on the
// Repository row, so a repository's whole lineage is its history followed by
// its current row -- which is why creating one writes no revision, and why
// there is always exactly one more version than there are revisions.
type ConfigRevision struct {
	// Repository is the entity the revision belonged to.
	Repository string
	// Version is the config_version this document was stored at, before the
	// update that superseded it.
	Version int64
	// Config is the superseded document, byte for byte as it was stored.
	Config json.RawMessage
	// Actor is the subject that replaced it. Empty means the change came from
	// inside the process rather than from a request (ADR 0005).
	Actor string
	// At is when the replacement happened.
	At time.Time
}

// ProxyCredential is a proxy repository's upstream credential at rest.
//
// It is modelled the way the hashed credentials in credentials.go are: the
// field is named for what it actually holds, and what it holds is never a
// plaintext. Sealed is a complete secretbox value --
// "v1:<key-id>:<base64(nonce ‖ ciphertext)>" -- produced under the associated
// data secretbox.ProxyCredential(Repository), so a row lifted into another
// repository fails to open rather than decrypting into the wrong upstream
// (ADR 0016).
//
// The difference from a password verifier is that this one has to come back:
// the proxy client needs the username and password to authenticate upstream.
// That is why the value is sealed rather than hashed, and why exactly one
// method returns it -- see GetProxyCredential.
type ProxyCredential struct {
	// Repository is the proxy entity the credential belongs to. It is also
	// half of the associated data, which is what binds the ciphertext here.
	Repository string
	// Sealed is the encrypted credential, in secretbox's stored form. It is
	// opaque to the store: nothing in this package encrypts, decrypts, or
	// inspects it.
	Sealed string
	// RotatedAt is when the credential was last written. The caller supplies
	// it: no store calls time.Now (§7).
	RotatedAt time.Time
}

// ProxyCredentialStatus is everything a read path may learn about an upstream
// credential: whether one is set, and when it was last written.
//
// It is a separate type from ProxyCredential rather than the same type with
// the value blanked out, because a blanked field is one forgotten assignment
// away from being populated. There is no field here that could hold a secret,
// so a handler that renders this cannot leak one however it is written -- which
// is C-003's acceptance criterion made structural rather than remembered.
type ProxyCredentialStatus struct {
	// Repository is the entity the status is about.
	Repository string
	// Set reports whether a credential is stored.
	Set bool
	// RotatedAt is when it was last written, or the zero time when Set is
	// false.
	RotatedAt time.Time
}

// GroupMember is one entry in a group's ordered member list. Position is
// explicit because group resolution is first-match-wins and order must never
// be implicit (ADR 0005).
type GroupMember struct {
	Repository  string
	Position    int
	Required    bool
	WriteTarget bool
}

// Manifest is a stored manifest. Subject is set when the manifest attaches to
// another via the OCI referrers relationship; it is the index that makes the
// referrers API a single query (ADR 0006).
type Manifest struct {
	Repository   string
	Digest       Digest
	MediaType    string
	ArtifactType string
	Subject      Digest
	Payload      []byte
	Size         int64
	CreatedAt    time.Time
}

// RefKind describes why one manifest references another digest.
type RefKind string

// The reference kinds recorded for garbage collection.
const (
	RefConfig  RefKind = "config"
	RefLayer   RefKind = "layer"
	RefChild   RefKind = "child-manifest"
	RefSubject RefKind = "subject"
)

// Valid reports whether k is a known reference kind.
func (k RefKind) Valid() bool {
	switch k {
	case RefConfig, RefLayer, RefChild, RefSubject:
		return true
	default:
		return false
	}
}

// ManifestRef is one edge of the reachability graph garbage collection walks
// (ADR 0010). Every blob or child manifest a manifest depends on has a row.
type ManifestRef struct {
	Child Digest
	Kind  RefKind
}

// Tag is a mutable name pointing at a manifest digest.
type Tag struct {
	Repository string
	Name       string
	Digest     Digest
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Blob records the presence and size of hosted blob content. The bytes live in
// the blob store; this is the metadata half.
type Blob struct {
	Digest    Digest
	Size      int64
	CreatedAt time.Time
}

// CachedManifest is a manifest fetched from an upstream and kept, stored in the
// cached-content family (ADR 0006) that no hosted code path can reach.
//
// It is deliberately a different type from Manifest rather than the same one
// with a flag. The flag would be data, and data gets miswired; a function that
// evicts takes cached values and one that deletes hosted content takes hosted
// ones, so a cache sweep that reached an irreplaceable blob would not compile
// (ADR 0009 wall 1). The fields overlapping with Manifest are the manifest's
// own -- they describe the same bytes -- and the two that do not are what make
// this content recoverable: it was fetched at a moment, from somebody else, and
// its last use is what eviction ranks it by.
type CachedManifest struct {
	// Repository is the full trove content name the manifest was cached under,
	// e.g. `dockerhub/library/nginx`. Its entity -- the first path segment --
	// must exist and must be a proxy: cached rows under a hosted entity would
	// be content nothing could ever refill.
	Repository string

	// Digest is what the bytes hash to, verified on arrival (ADR 0007). A
	// cached manifest that did not verify is not stored, so a row here is a
	// claim that these bytes were correct when they landed.
	Digest Digest

	// MediaType, ArtifactType, and Subject describe the manifest the same way
	// they do for hosted content, so the referrers API can answer over cached
	// content without a second shape to read.
	MediaType    string
	ArtifactType string
	Subject      Digest

	// Payload is the manifest body. Manifests are small and are re-hashed on
	// read, so they live in the row rather than the blob store -- exactly as
	// hosted manifests do.
	Payload []byte

	// Size is the payload length in bytes. It is what the cache budget counts
	// (C-013).
	Size int64

	// CachedAt is when the fill happened, on the caller's clock. No store calls
	// time.Now (§7).
	CachedAt time.Time

	// LastAccessAt is when the content was last served. It is the LRU key
	// eviction ranks by (Q11), written on fill and refreshed on serve.
	LastAccessAt time.Time
}

// CachedManifestRef is one edge from a cached manifest to content it depends
// on: a layer, a config, a child manifest, or its subject.
//
// It exists separately from ManifestRef for the reason CachedManifest does. The
// edges of hosted content are the reachability graph garbage collection walks
// before it deletes something irreplaceable (ADR 0010); these edges answer a
// different question -- what else this fill brought in -- and a single type
// would be a seam through which one traversal could be handed the other's
// rows.
type CachedManifestRef struct {
	Child Digest
	Kind  RefKind
}

// CachedBlob records a blob fetched from an upstream and kept. The bytes live
// in the cache-rooted blob store (ADR 0007), which is a different store
// instance from the hosted one and shares no root with it.
//
// Unlike a hosted blob, which is recorded once globally, a cached blob is
// recorded per proxy repository. Two proxies that both cache the same layer
// hold one copy of the bytes and one row each: the bytes are content-addressed
// so a second copy would be waste, and the rows are what per-proxy accounting
// and per-proxy eviction are computed from.
type CachedBlob struct {
	// Repository is the full trove content name the blob was cached under.
	Repository string
	// Digest is what the bytes hash to.
	Digest Digest
	// Size is the blob length in bytes.
	Size int64
	// CachedAt is when the fill happened.
	CachedAt time.Time
	// LastAccessAt is the LRU key (Q11).
	LastAccessAt time.Time
}

// TagLease is a proxy repository's cached answer to "what does this tag point
// at right now" (ADR 0008, C-005).
//
// It is a lease and not a tag, which is the distinction the whole proxy
// subsystem turns on. A hosted Tag is a fact this registry decides; a lease is
// somebody else's fact, borrowed for a while. Digests are immutable so cached
// content never expires, but the mapping from a name to one does, and serving
// a week-old `:latest` is the failure that makes a pull-through cache worse
// than no cache at all.
type TagLease struct {
	// Repository is the full trove content name, e.g. `dockerhub/library/nginx`.
	Repository string

	// Tag is the tag as the client asked for it.
	Tag string

	// Digest is what the tag resolved to at FetchedAt.
	Digest Digest

	// ETag is what the upstream returned for that manifest, sent back as
	// If-None-Match on revalidation. Empty when the upstream sent none, which
	// is why the digest comparison exists alongside it rather than instead:
	// registries differ in whether they answer 304.
	ETag string

	// FetchedAt is when the mapping was last confirmed against the upstream --
	// on a fetch or on a revalidation that found it unchanged. Freshness is
	// computed from it and never stored, so a lease cannot claim to be fresh
	// while a clock says otherwise.
	FetchedAt time.Time

	// TTL is the revalidation interval that was in effect when the lease was
	// written. It is recorded for the operator, not consulted: the resolver
	// reads the repository's current TTL, so lowering it takes effect on the
	// next pull rather than after every lease happens to be rewritten.
	//
	// Zero means revalidate on every pull (Q11).
	TTL time.Duration

	// Stale marks a lease whose last revalidation could not be completed and
	// which was served anyway in degraded mode (ADR 0008). It is deliberately
	// not "past its TTL" -- that is derivable from FetchedAt and would drift
	// the moment it were stored -- but a record of a real event that nothing
	// else remembers: the upstream was unreachable and this answer is somebody
	// else's fact from before that.
	Stale bool
}

// CachedKind says which cached table a row lives in. Eviction ranks manifests
// and blobs in one order -- they compete for one budget -- so the kind travels
// with the row that came back.
type CachedKind string

// The two kinds of cached content.
const (
	// CachedManifestKind is a row in cached_manifests, whose bytes are the
	// payload column itself.
	CachedManifestKind CachedKind = "manifest"
	// CachedBlobKind is a row in cached_blobs, whose bytes are in the
	// cache-rooted blob store.
	CachedBlobKind CachedKind = "blob"
)

// Valid reports whether k is a known cached kind.
func (k CachedKind) Valid() bool {
	return k == CachedManifestKind || k == CachedBlobKind
}

// CachedItem is one cached row as eviction sees it: what it is, what it costs,
// and when it was last wanted (ADR 0008's LRU key).
type CachedItem struct {
	Repository   string
	Digest       Digest
	Kind         CachedKind
	Size         int64
	LastAccessAt time.Time
}

// CacheUsage is how much space cached content occupies. Manifests and blobs are
// counted separately because they are reclaimed differently -- a manifest's
// bytes go with its row, a blob's bytes are shared and outlive it -- and an
// operator looking at a full cache wants to know which it is.
type CacheUsage struct {
	// Bytes is the total, manifests plus blobs.
	Bytes int64
	// ManifestBytes and BlobBytes are the halves.
	ManifestBytes int64
	BlobBytes     int64
	// Manifests and Blobs are row counts.
	Manifests int64
	Blobs     int64
}

// CacheAccess is one observation that cached content was served, for the
// batched LRU touch (C-013).
//
// It is the cached twin of PullRecord and exists for the same reason: writing
// `last_access_at` on the pull path would put a database write in front of
// every byte served, and the LRU only needs to be approximately right.
type CacheAccess struct {
	Repository string
	Digest     Digest
	Kind       CachedKind
	// At is when it was served, on the caller's clock.
	At time.Time
}

// NegativeEntry records that an upstream did not have something, so a typo does
// not hammer it (ADR 0008, C-007).
//
// It is deliberately about *names* only. A digest that is absent upstream now
// may exist a moment later -- somebody is pushing it -- and caching that
// absence would break push-then-pull-through-a-group, so nothing keyed by
// digest is ever recorded here.
type NegativeEntry struct {
	// Repository is the full trove content name.
	Repository string

	// Reference is the tag, or the name itself when the whole repository is
	// absent upstream.
	Reference string

	// ObservedAt is when the upstream said no, on the caller's clock.
	ObservedAt time.Time

	// TTL is how long that answer may be reused. It is short by design
	// (60 seconds by default, Q11): the entry exists to absorb a retry loop,
	// not to remember a decision.
	TTL time.Duration
}

// UploadSession is an in-progress blob upload. Its existence pins the digest
// against garbage collection (ADR 0010), which is why it is stored rather than
// held in memory.
type UploadSession struct {
	ID          string
	Repository  string
	Digest      Digest
	Bytes       int64
	StartedAt   time.Time
	LastChunkAt time.Time
}

// PullRecord is one batch entry for RecordPulls: the pulls of a single
// reference observed since the last flush, already aggregated by the caller.
//
// Reference is the reference as the client asked for it. A manifest is pulled
// by tag or by digest and both count (R-010), so the column ADR 0006 named
// "tag" holds either; the Go field says Reference because that is what it is.
type PullRecord struct {
	Repository string
	Reference  string
	// At is when the most recent of these pulls happened. The caller supplies
	// it: no store calls time.Now (§7).
	At time.Time
	// Count is how many pulls this record accounts for. It must be positive --
	// a record of nothing is a caller bug, not an empty batch.
	Count int64
}

// PullStats is a reference's accumulated pull record: when it was last pulled
// and how many times. Retention's keep-if-pulled-since rule reads it, which is
// why the timestamp only ever moves forward.
type PullStats struct {
	Repository   string
	Reference    string
	LastPulledAt time.Time
	Count        int64
}

// Event is one durable record in the outbox: something that happened, what it
// happened to, and who caused it (ADR 0012). A row exists if and only if the
// transaction that produced it committed, which is what makes at-least-once
// delivery honest rather than aspirational -- see WithinTx.
//
// The store deliberately does not know the event vocabulary. The closed
// taxonomy is internal/event's, and holding it here would mean a migration
// every time a type was added and two places that could disagree about what a
// type is called.
type Event struct {
	// ID is a ULID. It orders events chronologically under plain byte
	// comparison, which is what lets a cursor be the last id seen, and it is
	// the idempotency key a webhook receiver deduplicates on (ADR 0012).
	ID string

	// Type names what happened, from internal/event's closed set.
	Type string

	// Repository is the repository the event concerns. It is empty for a
	// system event -- a garbage-collection run, a role change -- and stored as
	// NULL, which is the form ListEvents filters on.
	//
	// There is deliberately no foreign key. An event is an observation, not a
	// reference: `artifact.deleted` for a repository that was then deleted
	// must survive it, or the log would erase exactly the records an operator
	// asks for afterwards. This is the same reasoning pull statistics carry.
	Repository string

	// Resource is the digest, tag, or subject name the event names, as
	// applicable. Empty when the event is about the repository itself.
	Resource string

	// Actor is the subject that caused the event. Empty means the process did
	// -- a scheduled sweep, a cache fill -- rather than a request.
	Actor string

	// Payload is the type-specific body, byte for byte as the emitter
	// rendered it. It is stored opaquely and returned unchanged because it is
	// the webhook wire format: re-encoding it here would change a body that
	// has already been signed, and would silently reorder a contract that is
	// golden-tested upstream.
	Payload json.RawMessage

	// At is when it happened. The caller supplies it: no store calls
	// time.Now (§7).
	At time.Time
}

// EventPage is one page of events, oldest first. NextCursor is empty on the
// last page.
type EventPage struct {
	Events     []Event
	NextCursor string
}

// ScopeFilter matches repository names for permission-filtered queries. It is
// the compiled form of a binding scope (ADR 0001): authz produces these plain
// values, so the authorization engine never imports a storage package and the
// query layer never re-implements scope matching.
type ScopeFilter struct {
	// All matches every repository (scope "*").
	All bool
	// Exact matches one repository name exactly.
	Exact string
	// Prefix matches every name under a path, e.g. "team-a/" for "team-a/*".
	Prefix string
}

// Matches reports whether the filter selects the given repository name.
func (f ScopeFilter) Matches(name string) bool {
	switch {
	case f.All:
		return true
	case f.Exact != "":
		return name == f.Exact
	case f.Prefix != "":
		return len(name) > len(f.Prefix) && name[:len(f.Prefix)] == f.Prefix
	default:
		return false
	}
}

// Visibility bounds what a query may return. It is deliberately a struct
// rather than a slice: a nil slice reads as "no filters" and would silently
// mean "everything", which is the disclosure bug ADR 0003 exists to prevent.
// Callers must say which they mean.
type Visibility struct {
	unrestricted bool
	filters      []ScopeFilter
}

// Unrestricted returns a Visibility that sees everything. Use it only for
// internal callers with no subject: migrations, garbage collection, and
// maintenance tasks.
func Unrestricted() Visibility {
	return Visibility{unrestricted: true}
}

// VisibleTo returns a Visibility limited to the given filters. With no filters
// nothing is visible, which is the correct reading of a subject holding no
// bindings.
func VisibleTo(filters ...ScopeFilter) Visibility {
	return Visibility{filters: filters}
}

// IsUnrestricted reports whether the visibility bypasses filtering.
func (v Visibility) IsUnrestricted() bool { return v.unrestricted }

// Filters returns the scope filters. It is empty for an unrestricted view.
func (v Visibility) Filters() []ScopeFilter { return v.filters }

// Allows reports whether a repository name is visible.
func (v Visibility) Allows(name string) bool {
	if v.unrestricted {
		return true
	}
	for _, f := range v.filters {
		if f.Matches(name) {
			return true
		}
	}
	return false
}

// ListOptions bounds a listing. Every listing is permission-filtered and
// cursor-paginated (ADR 0015): offsets are unstable under writes and leak
// filtered totals.
type ListOptions struct {
	// Visibility is required. The zero value shows nothing.
	Visibility Visibility
	// Limit caps the page size. Zero means DefaultPageSize.
	Limit int
	// Cursor continues a previous page; empty starts at the beginning.
	Cursor string
}

// Page size bounds applied by every store implementation.
const (
	DefaultPageSize = 100
	MaxPageSize     = 1000
)

// EffectiveLimit returns the page size to use, applying the defaults and caps
// so no implementation has to repeat the clamping.
func (o ListOptions) EffectiveLimit() int {
	switch {
	case o.Limit <= 0:
		return DefaultPageSize
	case o.Limit > MaxPageSize:
		return MaxPageSize
	default:
		return o.Limit
	}
}

// RepositoryPage is one page of repositories. NextCursor is empty on the last
// page.
type RepositoryPage struct {
	Repositories []Repository
	NextCursor   string
}

// TagPage is one page of tag names within a repository.
type TagPage struct {
	Tags       []Tag
	NextCursor string
}

// ContentNamePage is one page of the full OCI repository names that hold
// hosted content. NextCursor is empty on the last page.
//
// It carries names rather than Repository rows because a content name is not
// a repository entity: an entity is mounted at the first path segment, and
// `team-a/api` is content inside the entity `team-a` (ADR 0005). The catalog
// answers with these names, so what a client pulls from is what it was told
// about.
type ContentNamePage struct {
	Names      []string
	NextCursor string
}
