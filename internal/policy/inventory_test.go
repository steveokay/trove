package policy_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/policy"
)

// now is the evaluation time every test measures from. Nothing in this package
// reads a clock, so the value is arbitrary -- what matters is that it is the
// same one in the fixtures and in the call.
var now = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

// ago builds a time before now, which is how every fixture states an age.
func ago(d time.Duration) time.Time { return now.Add(-d) }

// mf builds a manifest with the fields a case is not about left at their
// ordinary values: pushed an hour ago, one byte, untagged, unattached.
func mf(digest string, pushed time.Time) policy.Manifest {
	return policy.Manifest{Digest: policy.Digest(digest), PushedAt: pushed, Size: 1}
}

// withTags returns the manifest tagged with plain, unprotected tags.
func withTags(m policy.Manifest, names ...string) policy.Manifest {
	for _, name := range names {
		m.Tags = append(m.Tags, policy.Tag{Name: name})
	}
	return m
}

func withProtected(m policy.Manifest, name string) policy.Manifest {
	m.Tags = append(m.Tags, policy.Tag{Name: name, Protected: true})
	return m
}

func withImmutable(m policy.Manifest, name string) policy.Manifest {
	m.Tags = append(m.Tags, policy.Tag{Name: name, Immutable: true})
	return m
}

func withSubject(m policy.Manifest, subject string) policy.Manifest {
	m.Subject = policy.Digest(subject)
	return m
}

func withChildren(m policy.Manifest, children ...string) policy.Manifest {
	for _, child := range children {
		m.Children = append(m.Children, policy.Digest(child))
	}
	return m
}

func withPulls(m policy.Manifest, at time.Time, count int64) policy.Manifest {
	m.LastPulledAt = at
	m.PullCount = count
	return m
}

// mustInventory builds an inventory a test expects to be valid.
func mustInventory(t *testing.T, manifests ...policy.Manifest) *policy.Inventory {
	t.Helper()

	inv, err := policy.NewInventory("team-a/api", manifests)
	if err != nil {
		t.Fatalf("NewInventory: %v", err)
	}
	return inv
}

// digests renders a manifest slice as digest strings, for comparison.
func digests(manifests []policy.Manifest) []string {
	out := make([]string, 0, len(manifests))
	for _, m := range manifests {
		out = append(out, string(m.Digest))
	}
	return out
}

func digestList(list []policy.Digest) []string {
	out := make([]string, 0, len(list))
	for _, d := range list {
		out = append(out, string(d))
	}
	return out
}

// A snapshot the evaluator cannot reason about deterministically is refused,
// not evaluated on a guess. Every row here is something the metadata store
// makes impossible; this is the assertion that it stayed impossible, and the
// cost of being wrong is a blob that cannot be re-fetched.
func TestNewInventoryRefusesUnusableSnapshots(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		manifests []policy.Manifest
		reason    string
	}{
		{
			name:      "a manifest with no digest",
			manifests: []policy.Manifest{{PushedAt: ago(time.Hour)}},
			reason:    "a manifest has no digest",
		},
		{
			name: "the same digest twice",
			manifests: []policy.Manifest{
				mf("sha256:a", ago(time.Hour)),
				mf("sha256:a", ago(2*time.Hour)),
			},
			reason: "listed twice",
		},
		{
			// A zero push time reads as the year one, which makes every age
			// rule select the manifest. Silence here is a sweep.
			name:      "no push time",
			manifests: []policy.Manifest{{Digest: "sha256:a"}},
			reason:    "push time is required",
		},
		{
			name:      "a negative size",
			manifests: []policy.Manifest{{Digest: "sha256:a", PushedAt: ago(time.Hour), Size: -1}},
			reason:    "size is negative",
		},
		{
			name:      "a negative pull count",
			manifests: []policy.Manifest{{Digest: "sha256:a", PushedAt: ago(time.Hour), PullCount: -1}},
			reason:    "pull count is negative",
		},
		{
			name: "a manifest that is its own subject",
			manifests: []policy.Manifest{
				withSubject(mf("sha256:a", ago(time.Hour)), "sha256:a"),
			},
			reason: "is its own subject",
		},
		{
			name: "a manifest that is its own child",
			manifests: []policy.Manifest{
				withChildren(mf("sha256:a", ago(time.Hour)), "sha256:a"),
			},
			reason: "is its own child",
		},
		{
			name: "a child with an empty digest",
			manifests: []policy.Manifest{
				withChildren(mf("sha256:a", ago(time.Hour)), ""),
			},
			reason: "lists a child with an empty digest",
		},
		{
			name: "a tag with an empty name",
			manifests: []policy.Manifest{
				withTags(mf("sha256:a", ago(time.Hour)), ""),
			},
			reason: "has a tag with an empty name",
		},
		{
			name: "one manifest listing a tag twice",
			manifests: []policy.Manifest{
				withTags(mf("sha256:a", ago(time.Hour)), "latest", "latest"),
			},
			reason: `lists tag "latest" twice`,
		},
		{
			// A tag names exactly one digest. Two claims mean one of the two
			// manifests looks protected, or deletable, on false evidence.
			name: "two manifests claiming one tag",
			manifests: []policy.Manifest{
				withTags(mf("sha256:a", ago(time.Hour)), "latest"),
				withTags(mf("sha256:b", ago(time.Hour)), "latest"),
			},
			reason: `tag "latest" also points at sha256:a`,
		},
		{
			name: "a subject cycle",
			manifests: []policy.Manifest{
				withSubject(mf("sha256:a", ago(time.Hour)), "sha256:b"),
				withSubject(mf("sha256:b", ago(time.Hour)), "sha256:a"),
			},
			reason: "is part of a subject cycle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			inv, err := policy.NewInventory("team-a/api", tt.manifests)
			if err == nil {
				t.Fatalf("NewInventory succeeded, want refusal; inventory = %v", inv.Manifests())
			}
			if inv != nil {
				t.Fatalf("NewInventory returned an inventory alongside an error")
			}
			if !errors.Is(err, policy.ErrInvalidInventory) {
				t.Fatalf("error %v is not ErrInvalidInventory", err)
			}
			var typed *policy.InventoryError
			if !errors.As(err, &typed) {
				t.Fatalf("error %v is not an *InventoryError", err)
			}
			if !strings.Contains(typed.Reason, tt.reason) {
				t.Fatalf("reason %q does not mention %q", typed.Reason, tt.reason)
			}
		})
	}
}

func TestNewInventoryRequiresARepositoryName(t *testing.T) {
	t.Parallel()

	inv, err := policy.NewInventory("", []policy.Manifest{mf("sha256:a", ago(time.Hour))})
	if inv != nil || !errors.Is(err, policy.ErrInvalidInventory) {
		t.Fatalf("NewInventory(\"\") = %v, %v; want nil and ErrInvalidInventory", inv, err)
	}
	if !strings.Contains(err.Error(), "repository name is required") {
		t.Fatalf("error %q does not say why", err)
	}
}

// The invariant this whole package rests on: protection is a property of the
// inventory, not a filter applied to a plan. Every row is a manifest no rule
// may ever be shown.
func TestSelectableSetExcludesProtectedContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		manifests  []policy.Manifest
		selectable []string
		exclusions []policy.Exclusion
	}{
		{
			name: "a protected tag",
			manifests: []policy.Manifest{
				withProtected(mf("sha256:a", ago(time.Hour)), "release"),
				mf("sha256:b", ago(time.Hour)),
			},
			selectable: []string{"sha256:b"},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:a", Reason: policy.ExcludedProtectedTag, Detail: "release"},
			},
		},
		{
			name: "an immutable tag",
			manifests: []policy.Manifest{
				withImmutable(mf("sha256:a", ago(time.Hour)), "v1.0.0"),
			},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:a", Reason: policy.ExcludedImmutableTag, Detail: "v1.0.0"},
			},
		},
		{
			// Every reason that applies is recorded: an operator who
			// unprotects the tag and comes back to find it still kept has been
			// told half an answer.
			name: "protected and immutable together",
			manifests: []policy.Manifest{
				func() policy.Manifest {
					m := mf("sha256:a", ago(time.Hour))
					m.Tags = []policy.Tag{{Name: "release", Protected: true, Immutable: true}}
					return m
				}(),
			},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:a", Reason: policy.ExcludedProtectedTag, Detail: "release"},
				{Digest: "sha256:a", Reason: policy.ExcludedImmutableTag, Detail: "release"},
			},
		},
		{
			name: "a child of a live index",
			manifests: []policy.Manifest{
				withChildren(withTags(mf("sha256:index", ago(time.Hour)), "latest"), "sha256:amd64", "sha256:arm64"),
				mf("sha256:amd64", ago(time.Hour)),
				mf("sha256:arm64", ago(time.Hour)),
			},
			selectable: []string{"sha256:index"},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:amd64", Reason: policy.ExcludedIndexChild, Detail: "sha256:index"},
				{Digest: "sha256:arm64", Reason: policy.ExcludedIndexChild, Detail: "sha256:index"},
			},
		},
		{
			name: "a child of two live indexes names both",
			manifests: []policy.Manifest{
				withChildren(mf("sha256:index-b", ago(time.Hour)), "sha256:child"),
				withChildren(mf("sha256:index-a", ago(time.Hour)), "sha256:child"),
				mf("sha256:child", ago(time.Hour)),
			},
			selectable: []string{"sha256:index-a", "sha256:index-b"},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:child", Reason: policy.ExcludedIndexChild, Detail: "sha256:index-a, sha256:index-b"},
			},
		},
		{
			// ADR 0011: attached, not orphaned. This is what stops an untagged
			// rule reaping the SBOM of a live image.
			name: "a referrer of a live subject",
			manifests: []policy.Manifest{
				withTags(mf("sha256:image", ago(time.Hour)), "latest"),
				withSubject(mf("sha256:sbom", ago(time.Hour)), "sha256:image"),
			},
			selectable: []string{"sha256:image"},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:sbom", Reason: policy.ExcludedLiveSubject, Detail: "sha256:image"},
			},
		},
		{
			// A signature on an SBOM is excluded by its own subject being
			// live, one link further down the same chain.
			name: "a referrer of a referrer of a live subject",
			manifests: []policy.Manifest{
				withTags(mf("sha256:image", ago(time.Hour)), "latest"),
				withSubject(mf("sha256:sbom", ago(time.Hour)), "sha256:image"),
				withSubject(mf("sha256:sig", ago(time.Hour)), "sha256:sbom"),
			},
			selectable: []string{"sha256:image"},
			exclusions: []policy.Exclusion{
				{Digest: "sha256:sbom", Reason: policy.ExcludedLiveSubject, Detail: "sha256:image"},
				{Digest: "sha256:sig", Reason: policy.ExcludedLiveSubject, Detail: "sha256:sbom"},
			},
		},
		{
			// An orphan -- its subject is already gone -- is ordinary content
			// again and may be reaped. That is ADR 0011's crash-recovery net,
			// and the reason the exclusion is "live subject" and not
			// "has a subject".
			name: "a referrer whose subject is gone is selectable",
			manifests: []policy.Manifest{
				withSubject(mf("sha256:orphan", ago(time.Hour)), "sha256:deleted"),
			},
			selectable: []string{"sha256:orphan"},
		},
		{
			// The mirror case for children: an index edge pointing outside the
			// snapshot pins nothing, because there is nothing there to pin it.
			name: "a child edge pointing outside the snapshot pins nothing",
			manifests: []policy.Manifest{
				withChildren(mf("sha256:index", ago(time.Hour)), "sha256:gone"),
			},
			selectable: []string{"sha256:index"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			inv := mustInventory(t, tt.manifests...)

			if got := digests(inv.Selectable()); !reflect.DeepEqual(got, tt.selectable) && !(len(got) == 0 && len(tt.selectable) == 0) {
				t.Fatalf("selectable = %v, want %v", got, tt.selectable)
			}
			got := inv.Exclusions()
			if len(got) != len(tt.exclusions) {
				t.Fatalf("exclusions = %v, want %v", got, tt.exclusions)
			}
			for i, want := range tt.exclusions {
				if got[i] != want {
					t.Fatalf("exclusion %d = %v, want %v", i, got[i], want)
				}
				for _, forDigest := range inv.ExclusionsFor(want.Digest) {
					if forDigest.Digest != want.Digest {
						t.Fatalf("ExclusionsFor(%s) returned %v", want.Digest, forDigest)
					}
				}
			}
		})
	}
}

func TestInventoryAccessors(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		withChildren(withTags(mf("sha256:index", ago(time.Hour)), "latest"), "sha256:child", "sha256:child"),
		mf("sha256:child", ago(2*time.Hour)),
		withSubject(mf("sha256:sbom", ago(time.Hour)), "sha256:index"),
		withSubject(mf("sha256:sig", ago(time.Hour)), "sha256:sbom"),
	)

	if inv.Repository() != "team-a/api" {
		t.Fatalf("Repository = %q", inv.Repository())
	}
	if inv.Len() != 4 {
		t.Fatalf("Len = %d, want 4", inv.Len())
	}
	if got, want := digests(inv.Manifests()), []string{"sha256:child", "sha256:index", "sha256:sbom", "sha256:sig"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Manifests = %v, want %v (digest order)", got, want)
	}
	if got, want := digests(inv.Selectable()), []string{"sha256:index"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Selectable = %v, want %v", got, want)
	}

	m, ok := inv.Lookup("sha256:index")
	if !ok {
		t.Fatal("Lookup(sha256:index) missing")
	}
	// The duplicate child edge is compacted: an index listing one child twice
	// pins it once.
	if got, want := digestList(m.Children), []string{"sha256:child"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Children = %v, want %v", got, want)
	}
	if _, ok := inv.Lookup("sha256:missing"); ok {
		t.Fatal("Lookup of an absent digest reported found")
	}

	if got, want := digestList(inv.IndexParents("sha256:child")), []string{"sha256:index"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IndexParents = %v, want %v", got, want)
	}
	if got := inv.IndexParents("sha256:index"); len(got) != 0 {
		t.Fatalf("IndexParents of a root = %v, want none", got)
	}
	if got, want := digestList(inv.Referrers("sha256:index")), []string{"sha256:sbom"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Referrers = %v, want %v", got, want)
	}
	// The subtree is transitive: the signature on the SBOM dies with the image.
	if got, want := digestList(inv.ReferrerSubtree("sha256:index")), []string{"sha256:sbom", "sha256:sig"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ReferrerSubtree = %v, want %v", got, want)
	}
	if got := inv.ReferrerSubtree("sha256:child"); len(got) != 0 {
		t.Fatalf("ReferrerSubtree of an unattached manifest = %v, want none", got)
	}
	if got := inv.ExclusionsFor("sha256:index"); len(got) != 0 {
		t.Fatalf("ExclusionsFor a selectable manifest = %v, want none", got)
	}
}

// The inventory owns its copy of the snapshot. A caller that keeps mutating
// the slice it handed in must not be able to change a plan that has already
// been shown to an operator.
func TestNewInventoryCopiesTheSnapshot(t *testing.T) {
	t.Parallel()

	manifests := []policy.Manifest{
		withTags(mf("sha256:a", ago(time.Hour)), "latest"),
	}
	inv := mustInventory(t, manifests...)

	manifests[0].Tags[0].Protected = true
	manifests[0].Tags = append(manifests[0].Tags, policy.Tag{Name: "extra"})

	if got := len(inv.Selectable()); got != 1 {
		t.Fatalf("selectable = %d after the caller mutated its slice, want 1", got)
	}
	m, _ := inv.Lookup("sha256:a")
	if len(m.Tags) != 1 || m.Tags[0].Protected {
		t.Fatalf("inventory saw the caller's mutation: %+v", m.Tags)
	}

	// And the accessors hand back copies too.
	selectable := inv.Selectable()
	selectable[0].Digest = "sha256:tampered"
	if got := digests(inv.Selectable()); got[0] != "sha256:a" {
		t.Fatalf("Selectable is not a copy: %v", got)
	}
}

func TestManifestHelpers(t *testing.T) {
	t.Parallel()

	m := withTags(mf("sha256:a", ago(time.Hour)), "v2", "latest")
	if got, want := m.TagNames(), []string{"latest", "v2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("TagNames = %v, want %v (sorted)", got, want)
	}
	if m.Status() != policy.Tagged {
		t.Fatalf("Status = %q, want tagged", m.Status())
	}
	if mf("sha256:b", ago(time.Hour)).Status() != policy.Untagged {
		t.Fatal("an untagged manifest does not report untagged")
	}
	if got := len(mf("sha256:b", ago(time.Hour)).TagNames()); got != 0 {
		t.Fatalf("TagNames of an untagged manifest = %d entries", got)
	}
}

func TestExclusionString(t *testing.T) {
	t.Parallel()

	withDetail := policy.Exclusion{Digest: "sha256:a", Reason: policy.ExcludedProtectedTag, Detail: "release"}
	if got, want := withDetail.String(), "sha256:a: protected tag (release)"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	bare := policy.Exclusion{Digest: "sha256:a", Reason: policy.ExcludedIndexChild}
	if got, want := bare.String(), "sha256:a: child of a live index"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestInventoryErrorMessages(t *testing.T) {
	t.Parallel()

	whole := &policy.InventoryError{Reason: "repository name is required"}
	if got, want := whole.Error(), "invalid retention inventory: repository name is required"; got != want {
		t.Fatalf("Error = %q, want %q", got, want)
	}
	one := &policy.InventoryError{Digest: "sha256:a", Reason: "listed twice"}
	if got, want := one.Error(), `invalid retention inventory: manifest "sha256:a": listed twice`; got != want {
		t.Fatalf("Error = %q, want %q", got, want)
	}
	if errors.Is(whole, policy.ErrInvalidRule) {
		t.Fatal("an InventoryError matched ErrInvalidRule")
	}
}
