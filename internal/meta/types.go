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
