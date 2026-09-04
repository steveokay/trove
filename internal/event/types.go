// Package event owns the registry's event taxonomy, the in-process bus that
// fans events out to consumers, and the outbox that makes them durable.
//
// Three pieces, deliberately separable (ADR 0012):
//
//   - The taxonomy is a closed set of types, each with a typed payload and a
//     stable JSON encoding. That encoding is the webhook wire format, so it is
//     contract and is golden-tested: an external system parses it, and a field
//     renamed here is a customer's broken integration.
//   - The bus fans an event out to in-process consumers -- metrics, the outbox,
//     later the scan queue. A consumer never affects the publisher: publishing
//     does not block, and a consumer that panics takes only itself down.
//   - The outbox writes the event to the metadata store, where webhook delivery
//     (E-002, E-003) picks it up. Durability lives there and not in the bus,
//     because a channel loses its contents when the process dies and
//     at-least-once delivery would then be a claim nobody could support.
package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// Type names one kind of event. The set is closed: extending it is a reviewable
// change, because every type needs a payload, a golden, and -- once E-004
// lands -- the permission verb a subscriber must hold to receive it.
type Type string

// The event taxonomy (§8, ADR 0012).
const (
	// ArtifactPushed reports a manifest stored in a hosted repository.
	ArtifactPushed Type = "artifact.pushed"

	// ArtifactPulled reports a manifest served. It is high-volume: it reaches
	// the bus for metrics and pull statistics, but is not written to the
	// outbox unless the operator sets events.persist_pulls (ADR 0012).
	ArtifactPulled Type = "artifact.pulled"

	// ArtifactDeleted reports a manifest removed, by an operator or by a
	// retention plan.
	ArtifactDeleted Type = "artifact.deleted"

	// CacheFilled reports content fetched from an upstream and cached.
	CacheFilled Type = "cache.filled"

	// CacheEvicted reports cached content reclaimed. It is never a hosted
	// blob: the two deletion paths do not share code, and they do not share an
	// event type either (ADR 0009).
	CacheEvicted Type = "cache.evicted"

	// CacheStaleServed reports cached content served past its revalidation
	// deadline because the upstream could not be reached. It is how an
	// operator learns the registry is running degraded rather than failing.
	CacheStaleServed Type = "cache.stale-served"

	// GroupMemberSkipped reports a group member left out of a resolution: down,
	// or invisible to the subject. A member being unusable must not fail the
	// group, so this is the only trace of it (§4).
	GroupMemberSkipped Type = "group.member.skipped"

	// ScanCompleted reports a finished vulnerability scan and its rollup.
	ScanCompleted Type = "scan.completed"

	// ScanRegressed reports an artifact that was clean and no longer is,
	// usually after a CVE database update rather than after a push (§6).
	ScanRegressed Type = "scan.regressed"

	// PolicyViolated reports an artifact that failed a gating policy.
	PolicyViolated Type = "policy.violated"

	// AuthzDenied reports a refused authorization. A spike in these is how an
	// operator notices a misconfiguration or an attack (§5).
	AuthzDenied Type = "authz.denied"

	// RoleChanged reports a role or binding edited, with what it was and what
	// it became.
	RoleChanged Type = "role.changed"

	// QuotaWarned reports usage crossing a soft threshold.
	QuotaWarned Type = "quota.warned"

	// QuotaExceeded reports a write refused by a hard quota.
	QuotaExceeded Type = "quota.exceeded"

	// GCCompleted reports a finished garbage-collection sweep.
	GCCompleted Type = "gc.completed"

	// BlobCorrupt reports content whose bytes did not match its digest. It is
	// the one event that means the storage layer is lying, so it is its own
	// type rather than a flavour of a scan or a pull failure.
	BlobCorrupt Type = "blob.corrupt"
)

// types is the closed set, in the order Types reports it: the order it is
// documented in, so a rendered list is stable.
var types = []Type{
	ArtifactPushed,
	ArtifactPulled,
	ArtifactDeleted,
	CacheFilled,
	CacheEvicted,
	CacheStaleServed,
	GroupMemberSkipped,
	ScanCompleted,
	ScanRegressed,
	PolicyViolated,
	AuthzDenied,
	RoleChanged,
	QuotaWarned,
	QuotaExceeded,
	GCCompleted,
	BlobCorrupt,
}

// Types returns the closed taxonomy. Callers that must handle every type --
// the webhook verb map (E-004), the subscription validator (E-002), the
// metrics registry (E-005) -- enumerate it rather than repeating it, so a type
// added here cannot be quietly missed by one of them.
func Types() []Type {
	out := make([]Type, len(types))
	copy(out, types)
	return out
}

// Valid reports whether t is in the taxonomy.
func (t Type) Valid() bool {
	for _, known := range types {
		if t == known {
			return true
		}
	}
	return false
}

// String returns the wire name.
func (t Type) String() string { return string(t) }

// ErrInvalidEvent reports an event that could not be built, encoded, or
// decoded. Callers assert with errors.Is; no caller may match on message text
// (§11).
var ErrInvalidEvent = errors.New("invalid event")

// Payload is the typed body of one event. Each type has exactly one payload
// struct, and the struct reports which type it belongs to, so an event whose
// body does not match its type cannot be constructed.
type Payload interface {
	// EventType reports the type this payload belongs to.
	EventType() Type
}

// SeverityCounts is a scan result rolled up by severity, with the fixable
// subset split out: "twelve criticals" and "twelve criticals, none fixable"
// call for different responses, and a consumer that only got the total would
// have to guess (§6).
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Fixable  int `json:"fixable"`
}

// ArtifactPushedPayload describes a manifest stored in a hosted repository.
type ArtifactPushedPayload struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	// Tag is the tag the push named, empty for a push by digest.
	Tag       string `json:"tag,omitempty"`
	MediaType string `json:"media_type"`
	// ArtifactType is the OCI artifactType for a non-image artifact: an SBOM,
	// a signature, a Helm chart.
	ArtifactType string `json:"artifact_type,omitempty"`
	// Subject is the digest this manifest attaches to as a referrer, empty for
	// a manifest that stands alone.
	Subject string `json:"subject,omitempty"`
	Size    int64  `json:"size"`
}

// EventType reports the type this payload belongs to.
func (ArtifactPushedPayload) EventType() Type { return ArtifactPushed }

// ArtifactPulledPayload describes a manifest served.
type ArtifactPulledPayload struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	// Reference is what the client asked for: a tag or a digest. Both count as
	// pulls, and which one was used is what pull statistics record.
	Reference string `json:"reference"`
	MediaType string `json:"media_type"`
}

// EventType reports the type this payload belongs to.
func (ArtifactPulledPayload) EventType() Type { return ArtifactPulled }

// ArtifactDeletedPayload describes a manifest removed.
type ArtifactDeletedPayload struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	// Tags are the tags that pointed at the manifest and went with it.
	Tags []string `json:"tags,omitempty"`
	// Cascaded marks a referrer deleted because its subject was (Q22), rather
	// than one an operator named.
	Cascaded bool `json:"cascaded"`
}

// EventType reports the type this payload belongs to.
func (ArtifactDeletedPayload) EventType() Type { return ArtifactDeleted }

// CacheFilledPayload describes content fetched from an upstream and cached.
type CacheFilledPayload struct {
	Repository string `json:"repository"`
	// Upstream is the remote the content came from, by name rather than by
	// URL: a URL can carry credentials, and this is a payload that leaves the
	// process (§4).
	Upstream  string `json:"upstream"`
	Digest    string `json:"digest"`
	Reference string `json:"reference,omitempty"`
	Size      int64  `json:"size"`
}

// EventType reports the type this payload belongs to.
func (CacheFilledPayload) EventType() Type { return CacheFilled }

// CacheEvictedPayload describes cached content reclaimed.
type CacheEvictedPayload struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	// Reason says which sweep took it: "budget" for the LRU bound, "ttl" for
	// expiry, "manual" for an operator.
	Reason string `json:"reason"`
}

// EventType reports the type this payload belongs to.
func (CacheEvictedPayload) EventType() Type { return CacheEvicted }

// CacheStaleServedPayload describes cached content served past its
// revalidation deadline.
type CacheStaleServedPayload struct {
	Repository string `json:"repository"`
	Upstream   string `json:"upstream"`
	Reference  string `json:"reference"`
	Digest     string `json:"digest,omitempty"`
	// StaleSeconds is how far past the revalidation deadline the cached
	// mapping was when it was served.
	StaleSeconds int64 `json:"stale_seconds"`
	// Reason is why revalidation did not happen: "unreachable", "timeout",
	// "rate-limited".
	Reason string `json:"reason"`
}

// EventType reports the type this payload belongs to.
func (CacheStaleServedPayload) EventType() Type { return CacheStaleServed }

// GroupMemberSkippedPayload describes a group member left out of a resolution.
//
// Reason distinguishes a member that was unusable from one the subject may not
// read, which is a distinction the *subscriber* may see and the *client* never
// may: a group must not let a subject infer that a member it cannot read
// exists (§4). Delivery re-checks the subscriber's permission on the group
// before this leaves the process (E-004).
type GroupMemberSkippedPayload struct {
	Group  string `json:"group"`
	Member string `json:"member"`
	// Reference is what was being resolved when the member was skipped.
	Reference string `json:"reference,omitempty"`
	// Reason is "unreachable", "unreadable", or "malformed".
	Reason string `json:"reason"`
}

// EventType reports the type this payload belongs to.
func (GroupMemberSkippedPayload) EventType() Type { return GroupMemberSkipped }

// ScanCompletedPayload describes a finished vulnerability scan.
type ScanCompletedPayload struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	// Scanner names the adapter that produced the result, and DatabaseVersion
	// the CVE database it used: a finding is only interpretable against the
	// data that found it, and air-gapped operators update that on their own
	// schedule (Q6).
	Scanner         string         `json:"scanner"`
	DatabaseVersion string         `json:"database_version"`
	Findings        SeverityCounts `json:"findings"`
}

// EventType reports the type this payload belongs to.
func (ScanCompletedPayload) EventType() Type { return ScanCompleted }

// ScanRegressedPayload describes an artifact that was clean and no longer is.
type ScanRegressedPayload struct {
	Repository      string         `json:"repository"`
	Digest          string         `json:"digest"`
	Scanner         string         `json:"scanner"`
	DatabaseVersion string         `json:"database_version"`
	Previous        SeverityCounts `json:"previous"`
	Current         SeverityCounts `json:"current"`
	// NewCVEs names what appeared, so a consumer does not have to diff two
	// rollups to find out what changed.
	NewCVEs []string `json:"new_cves,omitempty"`
}

// EventType reports the type this payload belongs to.
func (ScanRegressedPayload) EventType() Type { return ScanRegressed }

// PolicyViolatedPayload describes an artifact that failed a gating policy.
type PolicyViolatedPayload struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest,omitempty"`
	Reference  string `json:"reference,omitempty"`
	// Policy and Rule name what refused it, so an operator can find the rule
	// without reading the whole policy.
	Policy string `json:"policy"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	// Action is "blocked" or "warned": gating is off by default and operators
	// observe before they enforce (Q12), so both outcomes are reported.
	Action string `json:"action"`
	// Overridden marks a break-glass pass by a subject holding gate:override.
	Overridden bool `json:"overridden"`
}

// EventType reports the type this payload belongs to.
func (PolicyViolatedPayload) EventType() Type { return PolicyViolated }

// AuthzDeniedPayload describes a refused authorization.
type AuthzDeniedPayload struct {
	Subject string `json:"subject"`
	Verb    string `json:"verb"`
	// Resource is the repository pattern or the literal "system" scope the
	// verb was checked against.
	Resource string `json:"resource"`
	// Reason is why: "no-binding", "disabled-subject", "expired-credential".
	Reason string `json:"reason"`
}

// EventType reports the type this payload belongs to.
func (AuthzDeniedPayload) EventType() Type { return AuthzDenied }

// RoleChangedPayload describes a role or binding edited, with before and after.
type RoleChangedPayload struct {
	// Change is "created", "updated", or "deleted".
	Change string `json:"change"`
	// Role is the role edited, or the role a binding granted.
	Role string `json:"role"`
	// Binding, Principal, and Scope are set when the change was a binding
	// rather than the role itself.
	Binding   string `json:"binding,omitempty"`
	Principal string `json:"principal,omitempty"`
	Scope     string `json:"scope,omitempty"`
	// PreviousVerbs and Verbs are the role's verb set before and after. Role
	// changes are audited with before/after state (§5), and a consumer that
	// only got the new set could not tell what was taken away.
	PreviousVerbs []string `json:"previous_verbs,omitempty"`
	Verbs         []string `json:"verbs,omitempty"`
}

// EventType reports the type this payload belongs to.
func (RoleChangedPayload) EventType() Type { return RoleChanged }

// QuotaWarnedPayload describes usage crossing a soft threshold.
type QuotaWarnedPayload struct {
	// Scope is "repo", "global", or "cache". The cache budget is accounted
	// separately and breaching it evicts rather than refuses (Q8).
	Scope string `json:"scope"`
	// Key is the repository the quota applies to, empty for a global one.
	Key       string `json:"key,omitempty"`
	UsedBytes int64  `json:"used_bytes"`
	SoftBytes int64  `json:"soft_bytes"`
	HardBytes int64  `json:"hard_bytes"`
}

// EventType reports the type this payload belongs to.
func (QuotaWarnedPayload) EventType() Type { return QuotaWarned }

// QuotaExceededPayload describes a write refused by a hard quota.
type QuotaExceededPayload struct {
	Scope     string `json:"scope"`
	Key       string `json:"key,omitempty"`
	UsedBytes int64  `json:"used_bytes"`
	HardBytes int64  `json:"hard_bytes"`
	// RequestedBytes is what the refused write would have added.
	RequestedBytes int64 `json:"requested_bytes"`
}

// EventType reports the type this payload belongs to.
func (QuotaExceededPayload) EventType() Type { return QuotaExceeded }

// GCCompletedPayload describes a finished garbage-collection sweep.
type GCCompletedPayload struct {
	RunID            string `json:"run_id"`
	ManifestsScanned int64  `json:"manifests_scanned"`
	BlobsDeleted     int64  `json:"blobs_deleted"`
	BytesReclaimed   int64  `json:"bytes_reclaimed"`
	DurationSeconds  int64  `json:"duration_seconds"`
	// Resumed marks a sweep that picked up an interrupted run rather than
	// starting one (§7).
	Resumed bool `json:"resumed"`
}

// EventType reports the type this payload belongs to.
func (GCCompletedPayload) EventType() Type { return GCCompleted }

// BlobCorruptPayload describes content whose bytes did not match its digest.
type BlobCorruptPayload struct {
	Repository string `json:"repository,omitempty"`
	// Expected is the digest the content was stored or requested under;
	// Actual is what the bytes hash to. Both are reported because which one
	// is wrong is the operator's first question.
	Expected string `json:"expected"`
	Actual   string `json:"actual,omitempty"`
	// Source is "hosted", "cache", or "upstream": an upstream that answered
	// with the wrong bytes is somebody else's incident, and a hosted blob that
	// no longer matches is this deployment's.
	Source string `json:"source"`
}

// EventType reports the type this payload belongs to.
func (BlobCorruptPayload) EventType() Type { return BlobCorrupt }

// Event is one thing that happened: the envelope every consumer sees and the
// body every webhook receives.
//
// The envelope's fields are the ones the outbox stores as columns, so the row
// and the wire form hold the same information and neither has to be
// reconstructed from the other.
type Event struct {
	// ID is a ULID, minted by the bus. It orders events chronologically and is
	// the idempotency key a receiver deduplicates on (ADR 0012).
	ID string

	// Type names what happened.
	Type Type

	// Repository is the repository the event concerns, empty for a system
	// event. It is what delivery evaluates the subscriber's read permission
	// against (E-004), which is why it is on the envelope rather than only in
	// the payload.
	Repository string

	// Resource is the digest, tag, or subject name the event names.
	Resource string

	// Actor is the subject that caused it, empty when the process did.
	Actor string

	// Payload is the typed body. It must match Type: an event whose body
	// disagrees with its type is refused rather than encoded.
	Payload Payload

	// At is when it happened, from the bus's injected clock.
	At time.Time
}

// Validate reports whether the event is complete and self-consistent.
//
// The payload check is the one that matters: it makes an event whose type says
// one thing and whose body says another impossible to publish, so a consumer
// that switched on the type can decode the body without re-checking.
func (e Event) Validate() error {
	switch {
	case e.ID == "":
		return fmt.Errorf("%w: id must not be empty", ErrInvalidEvent)
	case !e.Type.Valid():
		return fmt.Errorf("%w: unknown type %q", ErrInvalidEvent, e.Type)
	case e.At.IsZero():
		return fmt.Errorf("%w: %s has no timestamp", ErrInvalidEvent, e.Type)
	case e.Payload == nil:
		return fmt.Errorf("%w: %s has no payload", ErrInvalidEvent, e.Type)
	case e.Payload.EventType() != e.Type:
		return fmt.Errorf("%w: %s carries a %s payload",
			ErrInvalidEvent, e.Type, e.Payload.EventType())
	default:
		return nil
	}
}

// envelope is the wire form. It exists separately from Event because Payload is
// an interface on the way out and raw JSON on the way in, and because the field
// order here is the contract: this is what an external system parses.
type envelope struct {
	ID         string          `json:"id"`
	Type       Type            `json:"type"`
	Repository string          `json:"repository,omitempty"`
	Resource   string          `json:"resource,omitempty"`
	Actor      string          `json:"actor,omitempty"`
	At         time.Time       `json:"at"`
	Payload    json.RawMessage `json:"payload"`
}

// MarshalJSON renders the event's wire form: the body a webhook receiver gets
// and the shape the goldens pin down. An event that does not validate is not
// encoded, so a malformed body cannot reach a subscriber.
//
// The timestamp is normalised to UTC first. An identical event must encode
// identically whatever zone the process happens to run in, or the same event
// would sign to two different HMACs.
func (e Event) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding the %s payload: %w", ErrInvalidEvent, e.Type, err)
	}
	return json.Marshal(envelope{
		ID:         e.ID,
		Type:       e.Type,
		Repository: e.Repository,
		Resource:   e.Resource,
		Actor:      e.Actor,
		At:         e.At.UTC(),
		Payload:    payload,
	})
}

// Decode parses an event's wire form back into a typed event. It is the inverse
// of MarshalJSON, which is what makes the goldens a round-trip test rather than
// a snapshot: a field that encodes but does not decode is caught here.
func Decode(data []byte) (Event, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	payload, err := DecodePayload(env.Type, env.Payload)
	if err != nil {
		return Event{}, err
	}
	decoded := Event{
		ID:         env.ID,
		Type:       env.Type,
		Repository: env.Repository,
		Resource:   env.Resource,
		Actor:      env.Actor,
		Payload:    payload,
		At:         env.At.UTC(),
	}
	if err := decoded.Validate(); err != nil {
		return Event{}, err
	}
	return decoded, nil
}

// DecodePayload parses a stored payload into the struct its type calls for.
//
// The switch is exhaustive over the taxonomy and there is a test that proves
// it: a type added to the set without a case here fails before it can produce
// an event nobody can read back.
func DecodePayload(t Type, raw json.RawMessage) (Payload, error) {
	switch t {
	case ArtifactPushed:
		return decodePayload[ArtifactPushedPayload](t, raw)
	case ArtifactPulled:
		return decodePayload[ArtifactPulledPayload](t, raw)
	case ArtifactDeleted:
		return decodePayload[ArtifactDeletedPayload](t, raw)
	case CacheFilled:
		return decodePayload[CacheFilledPayload](t, raw)
	case CacheEvicted:
		return decodePayload[CacheEvictedPayload](t, raw)
	case CacheStaleServed:
		return decodePayload[CacheStaleServedPayload](t, raw)
	case GroupMemberSkipped:
		return decodePayload[GroupMemberSkippedPayload](t, raw)
	case ScanCompleted:
		return decodePayload[ScanCompletedPayload](t, raw)
	case ScanRegressed:
		return decodePayload[ScanRegressedPayload](t, raw)
	case PolicyViolated:
		return decodePayload[PolicyViolatedPayload](t, raw)
	case AuthzDenied:
		return decodePayload[AuthzDeniedPayload](t, raw)
	case RoleChanged:
		return decodePayload[RoleChangedPayload](t, raw)
	case QuotaWarned:
		return decodePayload[QuotaWarnedPayload](t, raw)
	case QuotaExceeded:
		return decodePayload[QuotaExceededPayload](t, raw)
	case GCCompleted:
		return decodePayload[GCCompletedPayload](t, raw)
	case BlobCorrupt:
		return decodePayload[BlobCorruptPayload](t, raw)
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidEvent, t)
	}
}

// decodePayload unmarshals into one payload struct. It is generic so each case
// above is one line: sixteen hand-written copies of the same four lines is
// sixteen chances to decode into the wrong struct.
func decodePayload[P Payload](t Type, raw json.RawMessage) (Payload, error) {
	var payload P
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s has no payload", ErrInvalidEvent, t)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("%w: decoding the %s payload: %w", ErrInvalidEvent, t, err)
	}
	return payload, nil
}

// Record renders the event as the row the outbox stores. The payload is
// encoded once, here, and stored byte for byte: delivery re-sends exactly what
// was recorded, so a signature computed over the body cannot drift from it.
func (e Event) Record() (meta.Event, error) {
	if err := e.Validate(); err != nil {
		return meta.Event{}, err
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return meta.Event{}, fmt.Errorf("%w: encoding the %s payload: %w", ErrInvalidEvent, e.Type, err)
	}
	return meta.Event{
		ID:         e.ID,
		Type:       string(e.Type),
		Repository: e.Repository,
		Resource:   e.Resource,
		Actor:      e.Actor,
		Payload:    payload,
		At:         e.At.UTC(),
	}, nil
}

// FromRecord rebuilds an event from a stored row. Delivery (E-003) and the
// activity feed read rows, and this is how they get back to a typed event
// without either of them knowing the payload switch.
func FromRecord(row meta.Event) (Event, error) {
	payload, err := DecodePayload(Type(row.Type), row.Payload)
	if err != nil {
		return Event{}, err
	}
	restored := Event{
		ID:         row.ID,
		Type:       Type(row.Type),
		Repository: row.Repository,
		Resource:   row.Resource,
		Actor:      row.Actor,
		Payload:    payload,
		At:         row.At.UTC(),
	}
	if err := restored.Validate(); err != nil {
		return Event{}, err
	}
	return restored, nil
}
