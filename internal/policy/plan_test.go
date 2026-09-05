package policy_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/policy"
)

// sizedManifest builds a manifest with a byte size, for the plan's estimate.
func sizedManifest(digest string, pushed time.Time, size int64) policy.Manifest {
	m := mf(digest, pushed)
	m.Size = size
	return m
}

// A plan entry carries its whole referrer subtree, so applying it never
// deletes an artifact the dry run did not show (ADR 0011).
func TestPlanEntryCarriesTheReferrerSubtree(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		sizedManifest("sha256:image", ago(30*24*time.Hour), 100),
		withSubject(sizedManifest("sha256:sbom", ago(30*24*time.Hour), 20), "sha256:image"),
		withSubject(sizedManifest("sha256:sig", ago(30*24*time.Hour), 5), "sha256:sbom"),
		withSubject(sizedManifest("sha256:scan", ago(30*24*time.Hour), 7), "sha256:image"),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "sweep", Kind: policy.SelectMatched},
	))

	if len(plan.Selected) != 1 {
		t.Fatalf("selected %v, want only the image: its attachments are not selectable", selected(plan))
	}
	entry := plan.Selected[0]
	if entry.Digest != "sha256:image" {
		t.Fatalf("selected %s, want sha256:image", entry.Digest)
	}

	// Tag lists are empty rather than absent throughout, so that a rendered
	// plan carries an empty list where there is nothing rather than a null.
	want := []policy.Referrer{
		{Digest: "sha256:sbom", Subject: "sha256:image", Size: 20, ArtifactTags: []string{}},
		{Digest: "sha256:scan", Subject: "sha256:image", Size: 7, ArtifactTags: []string{}},
		{Digest: "sha256:sig", Subject: "sha256:sbom", Size: 5, ArtifactTags: []string{}},
	}
	if got := entry.Referrers; !reflect.DeepEqual(got, want) {
		t.Fatalf("Referrers = %+v, want %+v", got, want)
	}
	if got, want := entry.TotalSize(), int64(132); got != want {
		t.Fatalf("TotalSize = %d, want %d", got, want)
	}

	// The cascade is deleted, so it is not also reported as surviving.
	if len(plan.Kept) != 0 {
		t.Fatalf("kept %+v, want nothing: everything is either the entry or its cascade", plan.Kept)
	}
	wantDigests := []policy.Digest{"sha256:image", "sha256:sbom", "sha256:scan", "sha256:sig"}
	if got := plan.Digests(); !reflect.DeepEqual(got, wantDigests) {
		t.Fatalf("Digests = %v, want %v", got, wantDigests)
	}
}

// A tagged attachment is unusual, and a plan that hides it is a plan that
// deletes a tag the operator was never shown.
func TestCascadeShowsTagsOnAttachments(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		mf("sha256:image", ago(time.Hour)),
		withTags(withSubject(mf("sha256:sbom", ago(time.Hour)), "sha256:image"), "sbom-latest"),
	)
	plan := mustPlan(t, inv, mustRules(t, policy.Rule{Name: "sweep", Kind: policy.SelectMatched}))

	referrer := plan.Selected[0].Referrers[0]
	if got, want := referrer.ArtifactTags, []string{"sbom-latest"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ArtifactTags = %v, want %v", got, want)
	}
}

// Q10 beats the cascade (ADR 0011): the operator must delete the index first.
// Surfacing that in the dry run rather than at apply time is the whole point
// of a dry run.
func TestASelectionWhoseCascadeIsPinnedByALiveIndexIsBlocked(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		withTags(mf("sha256:image", ago(30*24*time.Hour)), "old"),
		withSubject(mf("sha256:attestation", ago(30*24*time.Hour)), "sha256:image"),
		// An index in the same repository lists the attestation as a child, so
		// deleting it would break the index.
		withTags(withChildren(mf("sha256:index", ago(time.Hour)), "sha256:attestation"), "latest"),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "sweep-old", Kind: policy.KeepNewerThan, Age: 24 * time.Hour},
	))

	if !plan.Empty() {
		t.Fatalf("selected %v, want nothing deletable", selected(plan))
	}
	if len(plan.Blocked) != 1 {
		t.Fatalf("blocked %+v, want one entry", plan.Blocked)
	}
	blocked := plan.Blocked[0]
	want := policy.BlockedEntry{
		Digest: "sha256:image", Tags: []string{"old"},
		Rule: "sweep-old", RuleKind: policy.KeepNewerThan, Priority: 0,
		Referrer: "sha256:attestation",
		Blocker: policy.Exclusion{
			Digest: "sha256:attestation", Reason: policy.ExcludedIndexChild, Detail: "sha256:index",
		},
	}
	if !reflect.DeepEqual(blocked, want) {
		t.Fatalf("blocked = %+v, want %+v", blocked, want)
	}
	// A blocked entry is not deleted, and neither is its cascade.
	if got := plan.Digests(); len(got) != 0 {
		t.Fatalf("Digests = %v, want nothing", got)
	}
	// The blocked manifest is not double-reported as kept.
	if _, alsoKept := keptBy(plan)["sha256:image"]; alsoKept {
		t.Fatal("the blocked manifest is also reported as kept")
	}
	if got := blocked.String(); !strings.Contains(got, "sha256:index") {
		t.Fatalf("String = %q, does not name the index", got)
	}
}

// The cascade is the one path by which a plan deletes something no rule
// selected, so it is the one path on which protection has to be re-checked.
//
// Found by FuzzProtectedContentSurvivesEveryRuleSet: an untagged image with a
// tagged, protected attestation attached was swept by an untagged rule, and
// the cascade took the protected manifest with it. Protection beats every
// retention rule (§7) -- including the cascade of one.
func TestACascadeCannotWalkThroughAProtectedAttachment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		attachment policy.Manifest
		reason     policy.ExclusionReason
	}{
		{
			name:       "a protected tag on the attachment",
			attachment: withProtected(withSubject(mf("sha256:sbom", ago(30*24*time.Hour)), "sha256:image"), "keep-me"),
			reason:     policy.ExcludedProtectedTag,
		},
		{
			name:       "an immutable tag on the attachment",
			attachment: withImmutable(withSubject(mf("sha256:sbom", ago(30*24*time.Hour)), "sha256:image"), "sbom-v1"),
			reason:     policy.ExcludedImmutableTag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			inv := mustInventory(t, mf("sha256:image", ago(30*24*time.Hour)), tt.attachment)
			plan := mustPlan(t, inv, mustRules(t,
				policy.Rule{Name: "reap-untagged", Kind: policy.SelectMatched, TagStatus: policy.Untagged},
			))

			if got := plan.Digests(); len(got) != 0 {
				t.Fatalf("plan would delete %v, want nothing", got)
			}
			if len(plan.Blocked) != 1 {
				t.Fatalf("blocked = %+v, want the subject blocked by its attachment", plan.Blocked)
			}
			if got := plan.Blocked[0].Blocker.Reason; got != tt.reason {
				t.Fatalf("blocker reason = %q, want %q", got, tt.reason)
			}
			if plan.Blocked[0].Referrer != "sha256:sbom" {
				t.Fatalf("blocked entry names %q as the blocked referrer", plan.Blocked[0].Referrer)
			}
			// The attachment itself still reads as a survivor, with its own
			// reason -- it is not in the deletion set, so it is in the kept
			// list like anything else that lives.
			if got := keptBy(plan)["sha256:sbom"]; got != policy.KeptNotSelectable {
				t.Fatalf("the attachment is kept for %q, want %q", got, policy.KeptNotSelectable)
			}
		})
	}
}

// The first question about a plan that deletes nothing is why not, and the
// kept list is where it is answered.
func TestPlanExplainsEverySurvivor(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		// Kept by a rule.
		withTags(mf("sha256:recent", ago(time.Hour)), "latest"),
		// No rule has an opinion: the rule below is about tagged manifests.
		mf("sha256:untouched", ago(30*24*time.Hour)),
		// Not selectable at all.
		withProtected(mf("sha256:pinned", ago(30*24*time.Hour)), "release"),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "keep-a-day", Kind: policy.KeepNewerThan, Age: 24 * time.Hour, TagStatus: policy.Tagged},
	))

	if !plan.Empty() {
		t.Fatalf("selected %v, want nothing", selected(plan))
	}
	want := map[string]policy.KeptReason{
		"sha256:recent":    policy.KeptByRule,
		"sha256:untouched": policy.KeptNoRuleApplies,
		"sha256:pinned":    policy.KeptNotSelectable,
	}
	if got := keptBy(plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("kept reasons = %v, want %v", got, want)
	}

	for _, entry := range plan.Kept {
		switch entry.Digest {
		case "sha256:recent":
			if entry.Rule != "keep-a-day" || entry.RuleKind != policy.KeepNewerThan {
				t.Fatalf("kept-by-rule entry does not name the rule: %+v", entry)
			}
		case "sha256:pinned":
			if len(entry.Exclusions) != 1 || entry.Exclusions[0].Reason != policy.ExcludedProtectedTag {
				t.Fatalf("not-selectable entry does not carry its exclusions: %+v", entry)
			}
			if entry.Rule != "" {
				t.Fatalf("not-selectable entry names a rule that was never shown it: %+v", entry)
			}
		case "sha256:untouched":
			if entry.Rule != "" || len(entry.Exclusions) != 0 {
				t.Fatalf("no-rule-applies entry carries an explanation it should not: %+v", entry)
			}
		}
	}
}

func TestPlanSummary(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		sizedManifest("sha256:old", ago(30*24*time.Hour), 100),
		withSubject(sizedManifest("sha256:sbom", ago(30*24*time.Hour), 20), "sha256:old"),
		withTags(sizedManifest("sha256:new", ago(time.Hour), 50), "latest"),
		withProtected(sizedManifest("sha256:pinned", ago(30*24*time.Hour), 70), "release"),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "keep-a-day", Kind: policy.KeepNewerThan, Age: 24 * time.Hour},
	))

	want := policy.Summary{
		Manifests: 4, Selected: 1, Cascaded: 1, Blocked: 0, Kept: 2, Bytes: 120,
		KeptBecause: []policy.KeptReasonCount{
			{Reason: policy.KeptByRule, Count: 1},
			{Reason: policy.KeptNotSelectable, Count: 1},
		},
	}
	if got := plan.Summary(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Summary = %+v, want %+v", got, want)
	}
	if got, want := plan.Summary().String(),
		"4 manifest(s): 1 selected, 1 cascaded, 0 blocked, 2 kept, 120 byte(s)"; got != want {
		t.Fatalf("Summary.String = %q, want %q", got, want)
	}

	// The summary accounts for every manifest the inventory held.
	if plan.Summary().Manifests != inv.Len() {
		t.Fatalf("summary counts %d manifests, inventory held %d", plan.Summary().Manifests, inv.Len())
	}
}

func TestPlanAndEntryStrings(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		withTags(sizedManifest("sha256:old", ago(30*24*time.Hour), 100), "v1"),
		withSubject(sizedManifest("sha256:sbom", ago(30*24*time.Hour), 20), "sha256:old"),
		sizedManifest("sha256:bare", ago(30*24*time.Hour), 3),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "keep-a-day", Kind: policy.KeepNewerThan, Age: 24 * time.Hour, Priority: 2},
	))

	if got, want := plan.String(),
		"retention plan for team-a/api at 2026-09-04T12:00:00Z: "+
			"3 manifest(s): 2 selected, 1 cascaded, 0 blocked, 0 kept, 123 byte(s)"; got != want {
		t.Fatalf("Plan.String = %q, want %q", got, want)
	}

	byDigest := map[policy.Digest]policy.Entry{}
	for _, entry := range plan.Selected {
		byDigest[entry.Digest] = entry
	}
	if got, want := byDigest["sha256:old"].String(),
		`delete sha256:old (v1): rule "keep-a-day" at priority 2, cascading to 1 referrer(s)`; got != want {
		t.Fatalf("Entry.String = %q, want %q", got, want)
	}
	if got, want := byDigest["sha256:bare"].String(),
		`delete sha256:bare (untagged): rule "keep-a-day" at priority 2`; got != want {
		t.Fatalf("Entry.String = %q, want %q", got, want)
	}
}

func TestKeptEntryStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry policy.KeptEntry
		want  string
	}{
		{
			name: "kept by a rule",
			entry: policy.KeptEntry{
				Digest: "sha256:a", Reason: policy.KeptByRule, Rule: "keep-a-day", Priority: 2,
			},
			want: `keep sha256:a: rule "keep-a-day" at priority 2`,
		},
		{
			name:  "no rule applies",
			entry: policy.KeptEntry{Digest: "sha256:a", Reason: policy.KeptNoRuleApplies},
			want:  "keep sha256:a: no rule applies",
		},
		{
			name: "not selectable",
			entry: policy.KeptEntry{
				Digest: "sha256:a", Reason: policy.KeptNotSelectable,
				Exclusions: []policy.Exclusion{
					{Digest: "sha256:a", Reason: policy.ExcludedProtectedTag, Detail: "release"},
					{Digest: "sha256:a", Reason: policy.ExcludedImmutableTag, Detail: "release"},
				},
			},
			want: "keep sha256:a: not selectable (protected tag; immutable tag)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.entry.String(); got != tt.want {
				t.Fatalf("String = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEmptyPlanSummary(t *testing.T) {
	t.Parallel()

	plan := mustPlan(t, mustInventory(t), policy.RuleSet{})
	if !plan.Empty() {
		t.Fatal("an empty inventory produced a non-empty plan")
	}
	summary := plan.Summary()
	if summary.Manifests != 0 || len(summary.KeptBecause) != 0 {
		t.Fatalf("Summary = %+v, want zeroes", summary)
	}
	if got := plan.Digests(); len(got) != 0 {
		t.Fatalf("Digests = %v, want none", got)
	}
	// The plan still says what it is a plan for and when it was evaluated: a
	// plan that deletes nothing is still a record.
	if plan.Repository != "team-a/api" || !plan.EvaluatedAt.Equal(now) {
		t.Fatalf("plan = %+v, want the repository and evaluation time carried", plan)
	}
}
