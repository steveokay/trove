package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// update rewrites the goldens instead of comparing against them. It exists so
// a deliberate change to the wire format is one command; an accidental one is
// still a failing test, because the diff lands in the review.
var update = flag.Bool("update", false, "rewrite the event payload goldens")

var fixtureTime = time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

// fixtures is one fully populated event per type. Every optional field is set:
// a golden that left them out would pin down half the contract and let the
// other half change unnoticed.
//
// The keys are checked against Types(), so a type added to the taxonomy without
// a fixture -- and therefore without a golden -- fails.
func fixtures() map[Type]Event {
	return map[Type]Event{
		ArtifactPushed: {
			ID:         "01K4EXAMPLE0PUSHED000000AA",
			Type:       ArtifactPushed,
			Repository: "team-a/api",
			Resource:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Actor:      "alice",
			At:         fixtureTime,
			Payload: ArtifactPushedPayload{
				Repository:   "team-a/api",
				Digest:       "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Tag:          "v1.4.2",
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				ArtifactType: "application/vnd.example.sbom+json",
				Subject:      "sha256:2222222222222222222222222222222222222222222222222222222222222222",
				Size:         4711,
			},
		},
		ArtifactPulled: {
			ID:         "01K4EXAMPLE0PULLED000000AA",
			Type:       ArtifactPulled,
			Repository: "team-a/api",
			Resource:   "v1.4.2",
			Actor:      "robot-ci",
			At:         fixtureTime,
			Payload: ArtifactPulledPayload{
				Repository: "team-a/api",
				Digest:     "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Reference:  "v1.4.2",
				MediaType:  "application/vnd.oci.image.manifest.v1+json",
			},
		},
		ArtifactDeleted: {
			ID:         "01K4EXAMPLE0DELETED00000AA",
			Type:       ArtifactDeleted,
			Repository: "team-a/api",
			Resource:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			Actor:      "alice",
			At:         fixtureTime,
			Payload: ArtifactDeletedPayload{
				Repository: "team-a/api",
				Digest:     "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Tags:       []string{"v1.4.2", "latest"},
				Cascaded:   true,
			},
		},
		CacheFilled: {
			ID:         "01K4EXAMPLE0CACHEFILL000AA",
			Type:       CacheFilled,
			Repository: "dockerhub/library/nginx",
			Resource:   "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			At:         fixtureTime,
			Payload: CacheFilledPayload{
				Repository: "dockerhub/library/nginx",
				Upstream:   "dockerhub",
				Digest:     "sha256:3333333333333333333333333333333333333333333333333333333333333333",
				Reference:  "1.27",
				Size:       58720256,
			},
		},
		CacheEvicted: {
			ID:         "01K4EXAMPLE0CACHEEVICT00AA",
			Type:       CacheEvicted,
			Repository: "dockerhub/library/nginx",
			Resource:   "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			At:         fixtureTime,
			Payload: CacheEvictedPayload{
				Repository: "dockerhub/library/nginx",
				Digest:     "sha256:3333333333333333333333333333333333333333333333333333333333333333",
				Size:       58720256,
				Reason:     "budget",
			},
		},
		CacheStaleServed: {
			ID:         "01K4EXAMPLE0CACHESTALE00AA",
			Type:       CacheStaleServed,
			Repository: "dockerhub/library/nginx",
			Resource:   "1.27",
			At:         fixtureTime,
			Payload: CacheStaleServedPayload{
				Repository:   "dockerhub/library/nginx",
				Upstream:     "dockerhub",
				Reference:    "1.27",
				Digest:       "sha256:3333333333333333333333333333333333333333333333333333333333333333",
				StaleSeconds: 3600,
				Reason:       "unreachable",
			},
		},
		GroupMemberSkipped: {
			ID:         "01K4EXAMPLE0GROUPSKIP000AA",
			Type:       GroupMemberSkipped,
			Repository: "public",
			Resource:   "library/nginx:1.27",
			At:         fixtureTime,
			Payload: GroupMemberSkippedPayload{
				Group:     "public",
				Member:    "dockerhub",
				Reference: "library/nginx:1.27",
				Reason:    "unreachable",
			},
		},
		ScanCompleted: {
			ID:         "01K4EXAMPLE0SCANDONE0000AA",
			Type:       ScanCompleted,
			Repository: "team-a/api",
			Resource:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			At:         fixtureTime,
			Payload: ScanCompletedPayload{
				Repository:      "team-a/api",
				Digest:          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Scanner:         "trivy",
				DatabaseVersion: "2026-09-03T06:00:00Z",
				Findings: SeverityCounts{
					Critical: 1, High: 4, Medium: 12, Low: 30, Unknown: 2, Fixable: 9,
				},
			},
		},
		ScanRegressed: {
			ID:         "01K4EXAMPLE0SCANREGRESSSAA",
			Type:       ScanRegressed,
			Repository: "team-a/api",
			Resource:   "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			At:         fixtureTime,
			Payload: ScanRegressedPayload{
				Repository:      "team-a/api",
				Digest:          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Scanner:         "trivy",
				DatabaseVersion: "2026-09-04T06:00:00Z",
				Previous:        SeverityCounts{High: 1, Medium: 3, Low: 8, Fixable: 2},
				Current: SeverityCounts{
					Critical: 2, High: 3, Medium: 3, Low: 8, Unknown: 1, Fixable: 5,
				},
				NewCVEs: []string{"CVE-2026-1000", "CVE-2026-1001"},
			},
		},
		PolicyViolated: {
			ID:         "01K4EXAMPLE0POLICYVIOL00AA",
			Type:       PolicyViolated,
			Repository: "team-a/api",
			Resource:   "v1.4.2",
			Actor:      "robot-ci",
			At:         fixtureTime,
			Payload: PolicyViolatedPayload{
				Repository: "team-a/api",
				Digest:     "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Reference:  "v1.4.2",
				Policy:     "production-gate",
				Rule:       "max-severity",
				Reason:     "1 critical finding, threshold high",
				Action:     "blocked",
				Overridden: true,
			},
		},
		AuthzDenied: {
			ID:       "01K4EXAMPLE0AUTHZDENIED0AA",
			Type:     AuthzDenied,
			Resource: "team-b/secret",
			Actor:    "alice",
			At:       fixtureTime,
			Payload: AuthzDeniedPayload{
				Subject:  "alice",
				Verb:     "repo:write",
				Resource: "team-b/secret",
				Reason:   "no-binding",
			},
		},
		RoleChanged: {
			ID:       "01K4EXAMPLE0ROLECHANGED0AA",
			Type:     RoleChanged,
			Resource: "publisher",
			Actor:    "admin",
			At:       fixtureTime,
			Payload: RoleChangedPayload{
				Change:        "updated",
				Role:          "publisher",
				Binding:       "01K4BINDING00000000000000A",
				Principal:     "team-a",
				Scope:         "team-a/*",
				PreviousVerbs: []string{"repo:read"},
				Verbs:         []string{"repo:read", "repo:write"},
			},
		},
		QuotaWarned: {
			ID:         "01K4EXAMPLE0QUOTAWARNED0AA",
			Type:       QuotaWarned,
			Repository: "team-a",
			Resource:   "team-a",
			At:         fixtureTime,
			Payload: QuotaWarnedPayload{
				Scope:     "repo",
				Key:       "team-a",
				UsedBytes: 8589934592,
				SoftBytes: 8589934592,
				HardBytes: 10737418240,
			},
		},
		QuotaExceeded: {
			ID:         "01K4EXAMPLE0QUOTAEXCEED0AA",
			Type:       QuotaExceeded,
			Repository: "team-a",
			Resource:   "team-a",
			Actor:      "robot-ci",
			At:         fixtureTime,
			Payload: QuotaExceededPayload{
				Scope:          "repo",
				Key:            "team-a",
				UsedBytes:      10737418240,
				HardBytes:      10737418240,
				RequestedBytes: 4194304,
			},
		},
		GCCompleted: {
			ID:       "01K4EXAMPLE0GCCOMPLETED0AA",
			Type:     GCCompleted,
			Resource: "01K4GCRUN000000000000000A",
			At:       fixtureTime,
			Payload: GCCompletedPayload{
				RunID:            "01K4GCRUN000000000000000A",
				ManifestsScanned: 1842,
				BlobsDeleted:     37,
				BytesReclaimed:   912457728,
				DurationSeconds:  94,
				Resumed:          true,
			},
		},
		BlobCorrupt: {
			ID:         "01K4EXAMPLE0BLOBCORRUPT0AA",
			Type:       BlobCorrupt,
			Repository: "team-a/api",
			Resource:   "sha256:4444444444444444444444444444444444444444444444444444444444444444",
			At:         fixtureTime,
			Payload: BlobCorruptPayload{
				Repository: "team-a/api",
				Expected:   "sha256:4444444444444444444444444444444444444444444444444444444444444444",
				Actual:     "sha256:5555555555555555555555555555555555555555555555555555555555555555",
				Source:     "hosted",
			},
		},
	}
}

// Every type in the taxonomy needs a fixture, and therefore a golden. Without
// this, adding a type would add an unencoded, untested wire shape.
func TestEveryTypeHasAFixture(t *testing.T) {
	t.Parallel()

	built := fixtures()
	for _, typ := range Types() {
		if _, ok := built[typ]; !ok {
			t.Errorf("type %q has no fixture: add one, and its golden", typ)
		}
	}
	if len(built) != len(Types()) {
		t.Errorf("got %d fixtures for %d types", len(built), len(Types()))
	}
	for typ := range built {
		if !typ.Valid() {
			t.Errorf("fixture for %q, which is not in the taxonomy", typ)
		}
	}
}

// The wire form is contract: an external system parses it, so a renamed field
// is somebody's broken integration. The golden pins the whole envelope, and
// decoding it back proves the shape round-trips rather than merely encodes.
func TestPayloadGoldens(t *testing.T) {
	t.Parallel()

	for typ, fixture := range fixtures() {
		t.Run(string(typ), func(t *testing.T) {
			t.Parallel()

			encoded, err := json.Marshal(fixture)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, encoded, "", "  "); err != nil {
				t.Fatalf("Indent: %v", err)
			}
			pretty.WriteByte('\n')

			path := filepath.Join("testdata", strings.ReplaceAll(string(typ), ".", "-")+".golden")
			if *update {
				if err := os.WriteFile(path, pretty.Bytes(), 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run with -update to create it)", err)
			}
			if got := pretty.String(); got != string(want) {
				t.Errorf("wire form changed.\n got:\n%s\nwant:\n%s", got, want)
			}

			decoded, err := Decode(want)
			if err != nil {
				t.Fatalf("Decode the golden: %v", err)
			}
			if !reflect.DeepEqual(decoded, fixture) {
				t.Errorf("round trip changed the event:\n got: %+v\nwant: %+v", decoded, fixture)
			}
		})
	}
}

// An event stored and read back is the same event. This is the path webhook
// delivery takes: the row is written once and re-sent from storage, so a
// column that lost a field would send a body nobody could act on.
func TestRecordRoundTrip(t *testing.T) {
	t.Parallel()

	for typ, fixture := range fixtures() {
		t.Run(string(typ), func(t *testing.T) {
			t.Parallel()

			row, err := fixture.Record()
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if row.ID != fixture.ID || row.Type != string(fixture.Type) {
				t.Errorf("row = %+v, want the envelope's id and type", row)
			}
			restored, err := FromRecord(row)
			if err != nil {
				t.Fatalf("FromRecord: %v", err)
			}
			if !reflect.DeepEqual(restored, fixture) {
				t.Errorf("storing changed the event:\n got: %+v\nwant: %+v", restored, fixture)
			}
		})
	}
}

// DecodePayload must handle every type. A type with no case would encode fine
// and be unreadable afterwards, which is the worst possible order to find out.
func TestDecodePayloadCoversTheTaxonomy(t *testing.T) {
	t.Parallel()

	for _, typ := range Types() {
		t.Run(string(typ), func(t *testing.T) {
			t.Parallel()

			payload, err := DecodePayload(typ, json.RawMessage(`{}`))
			if err != nil {
				t.Fatalf("DecodePayload(%q): %v", typ, err)
			}
			if payload.EventType() != typ {
				t.Errorf("decoded a %q payload for %q", payload.EventType(), typ)
			}
		})
	}
}

func TestTypeValidity(t *testing.T) {
	t.Parallel()

	for _, typ := range Types() {
		if !typ.Valid() {
			t.Errorf("%q is in Types() but not Valid()", typ)
		}
		if typ.String() != string(typ) {
			t.Errorf("String() = %q, want %q", typ.String(), string(typ))
		}
	}
	for _, typ := range []Type{"", "artifact.push", "ARTIFACT.PUSHED", "webhook.delivered"} {
		if typ.Valid() {
			t.Errorf("%q is not in the taxonomy but reports valid", typ)
		}
	}
}

// Types returns a copy: a caller that sorted or truncated the slice must not
// be able to shrink the taxonomy for everybody else.
func TestTypesIsACopy(t *testing.T) {
	t.Parallel()

	first := Types()
	first[0] = "mutated"
	if second := Types(); second[0] != ArtifactPushed {
		t.Errorf("Types()[0] = %q after a caller wrote to it, want %q", second[0], ArtifactPushed)
	}
}

// A payload that does not match its type is the mistake the interface exists to
// prevent, so it is refused at construction rather than delivered.
func TestValidate(t *testing.T) {
	t.Parallel()

	valid := fixtures()[ArtifactPushed]

	noID := valid
	noID.ID = ""
	badType := valid
	badType.Type = "artifact.push"
	noTime := valid
	noTime.At = time.Time{}
	noPayload := valid
	noPayload.Payload = nil
	mismatched := valid
	mismatched.Payload = ArtifactPulledPayload{}

	for _, tc := range []struct {
		name  string
		event Event
	}{
		{"no id", noID},
		{"a type outside the taxonomy", badType},
		{"no timestamp", noTime},
		{"no payload", noPayload},
		{"a payload from another type", mismatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.event.Validate(); !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("Validate = %v, want ErrInvalidEvent", err)
			}
			if _, err := json.Marshal(tc.event); err == nil {
				t.Error("an invalid event encoded anyway")
			}
			if _, err := tc.event.Record(); !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("Record = %v, want ErrInvalidEvent", err)
			}
		})
	}

	if err := valid.Validate(); err != nil {
		t.Errorf("a complete event did not validate: %v", err)
	}
}

// unencodablePayload has a body json cannot render. It is the case that gets
// past Validate -- a type in the taxonomy carrying a payload that says it
// belongs there -- and it must fail at encoding rather than produce a half
// written body.
type unencodablePayload struct {
	Broken chan int `json:"broken"`
}

func (unencodablePayload) EventType() Type { return ArtifactPushed }

func TestAPayloadThatWillNotEncodeIsAnError(t *testing.T) {
	t.Parallel()

	e := Event{
		ID:      "01K4EXAMPLE0UNENCODABLE0AA",
		Type:    ArtifactPushed,
		At:      fixtureTime,
		Payload: unencodablePayload{},
	}
	if _, err := json.Marshal(e); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("Marshal = %v, want ErrInvalidEvent", err)
	}
	if _, err := e.Record(); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("Record = %v, want ErrInvalidEvent", err)
	}
}

func TestDecodeRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		data string
	}{
		{"not json", `{`},
		{"an unknown type", `{"id":"01A","type":"artifact.exploded","at":"2026-09-04T09:30:15Z","payload":{}}`},
		{"no payload", `{"id":"01A","type":"artifact.pushed","at":"2026-09-04T09:30:15Z"}`},
		{"a payload of the wrong shape", `{"id":"01A","type":"artifact.pushed","at":"2026-09-04T09:30:15Z","payload":{"size":"big"}}`},
		{"no id", `{"type":"artifact.pushed","at":"2026-09-04T09:30:15Z","payload":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Decode([]byte(tc.data)); !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("Decode = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// A row the store cannot have produced -- a type from a newer version, a
// payload that was truncated -- must fail loudly rather than deliver a
// half-built event.
func TestFromRecordRejectsUnreadableRows(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		row  meta.Event
	}{
		{"an unknown type", meta.Event{
			ID: "01A", Type: "artifact.exploded", Payload: []byte(`{}`), At: fixtureTime,
		}},
		{"a truncated payload", meta.Event{
			ID: "01A", Type: "artifact.pushed", Payload: []byte(`{"size":`), At: fixtureTime,
		}},
		{"no id", meta.Event{
			Type: "artifact.pushed", Payload: []byte(`{}`), At: fixtureTime,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := FromRecord(tc.row); !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("FromRecord = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// The encoding must not depend on the process's time zone: the same event has
// to sign to the same HMAC wherever it runs.
func TestTimestampsAreNormalisedToUTC(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("UTC+7", 7*60*60)
	local := fixtures()[ArtifactPushed]
	local.At = local.At.In(zone)

	utc, err := json.Marshal(fixtures()[ArtifactPushed])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	shifted, err := json.Marshal(local)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(utc, shifted) {
		t.Errorf("the zone changed the wire form:\n got: %s\nwant: %s", shifted, utc)
	}

	row, err := local.Record()
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if row.At.Location() != time.UTC {
		t.Errorf("row timestamp is in %s, want UTC", row.At.Location())
	}
}
