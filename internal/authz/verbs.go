// Package authz is the authorization core: the permission vocabulary, the
// scope grammar, and the decision function.
//
// It holds no I/O and imports no registry, repository, or storage package. The
// decision is a pure function over values a caller has already fetched, which
// is what makes it exhaustively testable and what keeps the same answer from
// being computed two different ways in two different places (ADR 0001). An
// import-boundary test enforces the isolation (Z-009).
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Verb is one permission from the closed vocabulary of ADR 0002.
//
// The set is closed on purpose. Handlers reference these constants, a
// route-table test proves no route lacks one (Z-011), and an enumeration test
// fails if any verb lacks both a positive and a negative test (§9). Adding a
// verb is an ADR-level change, not a code change.
type Verb string

// The vocabulary. Verbs map to real operations rather than to HTTP methods,
// because a method cannot express the difference between pushing and purging,
// or between authoring a retention rule and executing it.
//
// Each group below is one section of ADR 0002's table.
const (
	// --- repository content (scope: repository pattern) ---

	// RepoList makes a repository appear in the catalog, in search results,
	// and in UI listings. It is separate from reading content because knowing
	// a repository exists is itself information (ADR 0003).
	RepoList Verb = "repo:list"
	// RepoRead permits pulling: blobs, manifests, and the tag list.
	RepoRead Verb = "repo:read"
	// RepoWrite permits pushing: blob uploads, manifest puts, and tag
	// creation or movement, subject to tag policy.
	RepoWrite Verb = "repo:write"
	// TagDelete permits deleting a tag reference, leaving the manifest.
	TagDelete Verb = "tag:delete"
	// ManifestDelete permits deleting a manifest, cascading to its referrers
	// (Q22).
	ManifestDelete Verb = "manifest:delete"
	// ReferrerRead permits listing and reading referrers. It grants nothing on
	// its own: the subject also needs RepoRead on the artifact the referrer
	// hangs from, or an SBOM would be readable for an image that is not.
	ReferrerRead Verb = "referrer:read"

	// --- repository lifecycle (scope: system to create, pattern otherwise) ---

	// RepoCreate permits creating a hosted, proxy, or group repository.
	RepoCreate Verb = "repo:create"
	// RepoConfigure permits changing a repository's settings: type-specific
	// config, TTLs, member order, routing rules, tag policy assignment. It
	// implies neither writing content nor deleting the repository.
	RepoConfigure Verb = "repo:configure"
	// RepoDelete permits deleting the repository itself, including all of its
	// content. Pushing is not purging, so RepoWrite never implies it.
	RepoDelete Verb = "repo:delete"

	// --- scanning and vulnerabilities (scope: repository pattern) ---

	// ScanRead permits reading scan results, CVE rollups, and SBOM-derived
	// reports.
	ScanRead Verb = "scan:read"
	// ScanTrigger permits requesting an on-demand rescan.
	ScanTrigger Verb = "scan:trigger"

	// --- policy (scope: repository pattern; policy:write also at system) ---

	// PolicyRead permits reading rules and dry-run plans.
	PolicyRead Verb = "policy:read"
	// PolicyWrite permits authoring or editing retention, tag, and gating
	// rules. Authoring a rule is not executing it.
	PolicyWrite Verb = "policy:write"
	// PolicyApply permits executing a destructive retention plan.
	PolicyApply Verb = "policy:apply"
	// GateOverride permits a break-glass pull past a vulnerability block. It
	// is implied by nothing and is always audited.
	GateOverride Verb = "gate:override"

	// --- proxy upstreams (scope: the proxy repository's pattern) ---

	// ProxyRead permits reading upstream configuration, with credentials
	// redacted.
	ProxyRead Verb = "proxy:read"
	// ProxyWrite permits changing an upstream URL, its TTLs, and its routing
	// rules. Changing a remote must not reveal its secret, so it never implies
	// ProxyCredentials.
	ProxyWrite Verb = "proxy:write"
	// ProxyCredentials permits setting or revealing upstream credentials.
	// #nosec G101 -- this is the name of a permission, not a credential.
	ProxyCredentials Verb = "proxy:credentials"

	// --- quotas, webhooks, search (scope: pattern; global quota at system) ---

	// QuotaRead permits reading storage limits and usage.
	QuotaRead Verb = "quota:read"
	// QuotaWrite permits setting storage limits.
	QuotaWrite Verb = "quota:write"
	// WebhookRead permits reading webhook subscriptions and their delivery
	// history.
	WebhookRead Verb = "webhook:read"
	// WebhookWrite permits managing webhook subscriptions. A subscription
	// still only receives events for resources its owner can read (E-004).
	WebhookWrite Verb = "webhook:write"
	// SearchRead permits cross-repository search. Results are still filtered
	// per repository by RepoList and RepoRead.
	SearchRead Verb = "search:read"

	// --- administration (scope: system only) ---

	// UserRead permits reading users, robot accounts, and groups.
	UserRead Verb = "user:read"
	// UserWrite permits managing users, robot accounts, and groups.
	UserWrite Verb = "user:write"
	// RoleRead permits reading roles and bindings.
	RoleRead Verb = "role:read"
	// RoleWrite permits managing roles and bindings. The last binding granting
	// it at system scope cannot be removed (ADR 0001).
	RoleWrite Verb = "role:write"
	// AuditRead permits querying and exporting the audit log.
	AuditRead Verb = "audit:read"
	// GCRun permits triggering garbage collection.
	GCRun Verb = "gc:run"
	// SystemMaintenance permits toggling read-only mode, importing or
	// updating the CVE database, and collecting a support bundle.
	SystemMaintenance Verb = "system:maintenance"
)

// verbs is the closed set, in the order ADR 0002 lists them.
var verbs = []Verb{
	RepoList, RepoRead, RepoWrite, TagDelete, ManifestDelete, ReferrerRead,
	RepoCreate, RepoConfigure, RepoDelete,
	ScanRead, ScanTrigger,
	PolicyRead, PolicyWrite, PolicyApply, GateOverride,
	ProxyRead, ProxyWrite, ProxyCredentials,
	QuotaRead, QuotaWrite, WebhookRead, WebhookWrite, SearchRead,
	UserRead, UserWrite, RoleRead, RoleWrite, AuditRead, GCRun, SystemMaintenance,
}

// verbSet is the membership lookup, built once.
var verbSet = func() map[Verb]bool {
	set := make(map[Verb]bool, len(verbs))
	for _, v := range verbs {
		set[v] = true
	}
	return set
}()

// AllVerbs returns every verb in the vocabulary, sorted, as a fresh slice.
//
// Sorted rather than in ADR order because callers compare and render it: a
// role's stored verb list, the enumeration test, and the admin API all want a
// stable order that does not change when the ADR's table is reorganised.
func AllVerbs() []Verb {
	out := make([]Verb, len(verbs))
	copy(out, verbs)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Valid reports whether v is part of the vocabulary.
func (v Verb) Valid() bool { return verbSet[v] }

// String renders the verb.
func (v Verb) String() string { return string(v) }

// ErrUnknownVerb reports a verb outside the vocabulary. Callers assert with
// errors.Is; the vocabulary is closed, so this is the only answer for anything
// not in it.
var ErrUnknownVerb = fmt.Errorf("unknown permission verb")

// UnknownVerbError names what was rejected while satisfying
// errors.Is(err, ErrUnknownVerb).
type UnknownVerbError struct {
	Verb string
}

func (e *UnknownVerbError) Error() string {
	return fmt.Sprintf("unknown permission verb %q", e.Verb)
}

// Is makes errors.Is(err, ErrUnknownVerb) true for this typed error.
func (e *UnknownVerbError) Is(target error) bool { return target == ErrUnknownVerb }

// ParseVerb turns a string into a Verb, rejecting anything outside the
// vocabulary.
//
// Every verb that reaches a role comes through here. A role holding a verb
// nothing enforces would look like a grant and be none, which is worse than a
// refusal at the point somebody typed it.
func ParseVerb(s string) (Verb, error) {
	v := Verb(s)
	if !v.Valid() {
		return "", &UnknownVerbError{Verb: s}
	}
	return v, nil
}

// ParseVerbs turns strings into verbs, reporting every unknown one rather than
// only the first: an operator pasting a role definition should see all of
// their typos at once.
func ParseVerbs(values []string) ([]Verb, error) {
	var (
		out     = make([]Verb, 0, len(values))
		unknown []string
	)
	for _, value := range values {
		v, err := ParseVerb(value)
		if err != nil {
			unknown = append(unknown, value)
			continue
		}
		out = append(out, v)
	}
	if len(unknown) > 0 {
		return nil, &UnknownVerbError{Verb: strings.Join(unknown, ", ")}
	}
	return out, nil
}
