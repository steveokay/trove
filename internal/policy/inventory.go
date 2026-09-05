package policy

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Digest is a content-addressed manifest identifier in "algorithm:hex" form.
//
// The evaluator treats it as an opaque key. It is deliberately this package's
// own type rather than the metadata store's: retention is a pure function over
// a snapshot, and a type shared with the storage layer is the first edge along
// which a query gets added to something that must never run one (ADR 0010).
// The caller converts when it builds the inventory, which is also where the
// exclusions that make deletion safe are computed.
type Digest string

// ErrInvalidInventory reports a snapshot NewInventory refuses to build an
// inventory from. Callers assert with errors.Is.
var ErrInvalidInventory = errors.New("invalid retention inventory")

// ErrNoInventory reports that Evaluate was called without an inventory.
var ErrNoInventory = errors.New("retention: inventory is required")

// ErrNoEvaluationTime reports that Evaluate was called with a zero evaluation
// time.
//
// It is refused rather than defaulted because the clock is injected (§7) and a
// zero reading is not a neutral one: every age comparison would measure from
// the year one, keep-newer-than would keep nothing, and a rule the operator
// wrote to protect this week's builds would sweep them. A missing clock must
// fail, not decide.
var ErrNoEvaluationTime = errors.New("retention: evaluation time is required")

// InventoryError names the manifest that made a snapshot unusable and why.
type InventoryError struct {
	// Digest is the manifest the problem is about. It is empty when the
	// problem is with the snapshot as a whole.
	Digest Digest
	// Reason says what was wrong.
	Reason string
}

func (e *InventoryError) Error() string {
	if e.Digest == "" {
		return fmt.Sprintf("invalid retention inventory: %s", e.Reason)
	}
	return fmt.Sprintf("invalid retention inventory: manifest %q: %s", e.Digest, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidInventory) true for this typed error.
func (e *InventoryError) Is(target error) bool { return target == ErrInvalidInventory }

func inventoryErr(digest Digest, format string, args ...any) error {
	return &InventoryError{Digest: digest, Reason: fmt.Sprintf(format, args...)}
}

// Tag is one name pointing at a manifest, carrying the protection the tag
// policy (P-001) computed for it.
//
// Protection is resolved by the caller and handed in already decided, because
// immutability supports prefix exceptions (§7) and the pattern grammar belongs
// with the tag policy rather than with retention. What retention needs to know
// is only the answer: this tag is protected, this one is immutable.
type Tag struct {
	// Name is the tag.
	Name string
	// Protected marks a tag on an operator's protected list. Protected beats
	// every retention rule, always (§7).
	Protected bool
	// Immutable marks a tag the tag policy makes immutable, after prefix
	// exceptions have been applied. An immutable tag cannot be re-pointed and
	// must not be deleted out from under the digest it names.
	Immutable bool
}

// Manifest is one manifest of a repository as the caller read it out of the
// metadata store, with the edges that decide whether it may be deleted.
//
// The field set mirrors the stored shapes (ADR 0006) without depending on
// them: Digest, PushedAt and Size come from the manifest row, Tags from the
// tag rows plus the tag policy, LastPulledAt and PullCount from pull
// statistics, and Children and Subject from the child-manifest and subject
// edges of manifest_refs.
type Manifest struct {
	// Digest identifies the manifest.
	Digest Digest
	// Tags are the tags pointing at it, in any order. A manifest with none is
	// untagged, which is what the untagged tag-status filter selects on.
	Tags []Tag
	// PushedAt is when the manifest was stored -- the manifest row's
	// created_at. It is what keep-last-N ranks on and what keep-newer-than
	// measures. It is required: a zero value would read as "pushed in the year
	// one" and make every age rule select the manifest.
	PushedAt time.Time
	// LastPulledAt is the most recent pull of this manifest, by tag or by
	// digest. The zero value means never pulled, which keep-if-pulled-since
	// treats explicitly rather than as "pulled in the year one".
	//
	// Pull statistics are written by a batched writer that flushes at most 60s
	// behind (ADR 0010), so this value is that much stale in the worst case.
	// That is the precision bound of every rule reading it, and it is why the
	// rules that do are age comparisons rather than equality tests.
	LastPulledAt time.Time
	// PullCount is how many pulls have been recorded. Retention does not rule
	// on it today; it is carried because a plan an operator reads is more
	// useful with it than without, and because omitting it would mean a
	// schema change to add a rule that uses it.
	PullCount int64
	// Size is the manifest's own byte size, used for the plan's byte estimate.
	Size int64
	// Children are the manifests this one references as a child -- the
	// child-manifest edges of a multi-arch index. Deleting a child that a live
	// index still lists is an error (Q10), so these edges are what put the
	// child out of reach.
	//
	// The edge is recorded on the index rather than as a flag on the child so
	// that the two cannot disagree: there is no way to describe a child whose
	// parent does not claim it.
	Children []Digest
	// Subject is the manifest this one attaches to through the OCI referrers
	// relationship -- an SBOM's image, a signature's SBOM. Empty when the
	// manifest is not a referrer.
	Subject Digest
}

// TagNames returns the manifest's tag names, sorted. It is what a plan entry
// shows an operator, and sorting it here is what keeps two evaluations of the
// same state from producing two different plans.
func (m Manifest) TagNames() []string {
	names := make([]string, 0, len(m.Tags))
	for _, tag := range m.Tags {
		names = append(names, tag.Name)
	}
	slices.Sort(names)
	return names
}

// Status reports whether the manifest is tagged or untagged.
//
// It is derived from the tags rather than stored beside them, because a stored
// status is a second source of truth that can disagree with the first -- and
// the disagreement that matters is a manifest recorded as untagged while a tag
// still points at it, which is a rule sweeping a live image.
func (m Manifest) Status() TagStatus {
	if len(m.Tags) == 0 {
		return Untagged
	}
	return Tagged
}

// ExclusionReason says why a manifest is outside the selectable set.
type ExclusionReason string

// The four reasons a manifest is not selectable. Each one is a rule from §7,
// ADR 0010 or ADR 0011 that no retention rule may override, which is why they
// are applied when the inventory is built rather than filtered afterwards.
const (
	// ExcludedProtectedTag: a tag on the manifest is protected. Protected
	// beats every retention rule (§7), with no exception and no priority that
	// outranks it.
	ExcludedProtectedTag ExclusionReason = "protected tag"
	// ExcludedImmutableTag: a tag on the manifest is immutable. An immutable
	// tag is a promise that the name keeps meaning this digest; deleting the
	// digest breaks the promise as thoroughly as re-pointing the tag would.
	ExcludedImmutableTag ExclusionReason = "immutable tag"
	// ExcludedIndexChild: a manifest in this repository lists the manifest as
	// a child. Deleting it is an error while the index lives (Q10) -- the
	// index would reference a manifest that is gone.
	ExcludedIndexChild ExclusionReason = "child of a live index"
	// ExcludedLiveSubject: the manifest attaches to a subject that is still
	// here. Such a manifest is attached, not orphaned (ADR 0011): it dies with
	// its subject, by cascade, and never on its own -- which is what stops an
	// untagged rule from reaping the SBOM of a live image.
	ExcludedLiveSubject ExclusionReason = "attached to a live subject"
)

// Exclusion is one manifest's reason for being outside the selectable set,
// with the detail an operator needs to act on it.
type Exclusion struct {
	// Digest is the manifest that is not selectable.
	Digest Digest
	// Reason is why.
	Reason ExclusionReason
	// Detail names the thing that caused it: the tag, the index, the subject.
	Detail string
}

// String renders an exclusion the way a plan and a log line report it.
func (e Exclusion) String() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: %s", e.Digest, e.Reason)
	}
	return fmt.Sprintf("%s: %s (%s)", e.Digest, e.Reason, e.Detail)
}

// Inventory is one repository's manifests as of a single read, together with
// the set of them a retention rule is allowed to select.
//
// # The selectable set is the invariant
//
// The safety property this whole package rests on is that protection is not a
// filter applied to a plan -- it is a property of the inventory. A protected
// tag, an immutable tag, a child of a live index, and a referrer of a live
// subject are removed here, before any rule runs, and the evaluator only ever
// ranges over what remains. A rule therefore cannot select one of them, not
// because every rule remembers to check, but because no rule is ever shown
// them. There is no keep-last-0, no priority, and no regex that reaches back
// into the excluded set.
//
// This is ADR 0010's first layer. The second is the apply path (P-005), which
// re-checks every entry against live state inside the deletion transaction.
// Both exist because a snapshot is stale the moment it is taken.
//
// # Completeness
//
// The snapshot must contain every manifest in the repository. The index-child
// and live-subject exclusions are computed from edges between manifests in the
// snapshot, so a partial page of a repository can make a child of an index
// that was not read look selectable. The apply path's re-check is what catches
// that; the contract here is that callers do not rely on it to.
type Inventory struct {
	repository string
	// manifests is every manifest in the snapshot, sorted by digest.
	manifests []Manifest
	// selectable is the subset a rule may select, sorted by digest. It is the
	// invariant described above.
	selectable []Manifest
	// exclusions is why each non-selectable manifest is out, sorted by digest
	// then by the order the reasons are checked in.
	exclusions []Exclusion
	byDigest   map[Digest]Manifest
	excludedBy map[Digest][]Exclusion
	// referrers maps a subject to the manifests attached directly to it,
	// sorted by digest.
	referrers map[Digest][]Digest
	// indexParents maps a manifest to the manifests in the snapshot that list
	// it as a child, sorted by digest.
	indexParents map[Digest][]Digest
}

// NewInventory builds a retention inventory from a repository snapshot,
// computing the selectable set as it goes.
//
// It refuses a snapshot it cannot reason about deterministically rather than
// evaluating a best guess: a duplicate digest, a tag name claimed by two
// manifests, a manifest that is its own subject or its own child, a subject
// cycle, a missing push time. Those are metadata-store impossibilities, and
// this is the assertion that they stayed impossible -- the cost of being wrong
// here is a deleted blob that cannot be re-fetched.
func NewInventory(repository string, manifests []Manifest) (*Inventory, error) {
	if repository == "" {
		return nil, inventoryErr("", "repository name is required")
	}

	inv := &Inventory{
		repository:   repository,
		manifests:    make([]Manifest, 0, len(manifests)),
		byDigest:     make(map[Digest]Manifest, len(manifests)),
		excludedBy:   make(map[Digest][]Exclusion),
		referrers:    make(map[Digest][]Digest),
		indexParents: make(map[Digest][]Digest),
	}

	tagOwner := make(map[string]Digest, len(manifests))
	for _, m := range manifests {
		clone, err := validateManifest(m, inv.byDigest, tagOwner)
		if err != nil {
			return nil, err
		}
		inv.byDigest[clone.Digest] = clone
		inv.manifests = append(inv.manifests, clone)
	}

	slices.SortFunc(inv.manifests, func(a, b Manifest) int { return cmp.Compare(a.Digest, b.Digest) })

	if err := inv.buildEdges(); err != nil {
		return nil, err
	}
	inv.buildSelectable()
	return inv, nil
}

// validateManifest checks one snapshot row and returns the defensive copy the
// inventory keeps.
//
// The copy is not politeness: the inventory is the input to a function whose
// whole value is that it is reproducible, and a caller that appends to the tag
// slice it handed in would change a plan that has already been shown to an
// operator.
func validateManifest(m Manifest, seen map[Digest]Manifest, tagOwner map[string]Digest) (Manifest, error) {
	if m.Digest == "" {
		return Manifest{}, inventoryErr("", "a manifest has no digest")
	}
	if _, duplicate := seen[m.Digest]; duplicate {
		return Manifest{}, inventoryErr(m.Digest, "listed twice")
	}
	if m.PushedAt.IsZero() {
		return Manifest{}, inventoryErr(m.Digest, "push time is required: a zero time makes every age rule select the manifest")
	}
	if m.Size < 0 {
		return Manifest{}, inventoryErr(m.Digest, "size is negative")
	}
	if m.PullCount < 0 {
		return Manifest{}, inventoryErr(m.Digest, "pull count is negative")
	}
	if m.Subject == m.Digest {
		return Manifest{}, inventoryErr(m.Digest, "is its own subject")
	}

	clone := m
	clone.Tags = slices.Clone(m.Tags)
	slices.SortFunc(clone.Tags, func(a, b Tag) int { return cmp.Compare(a.Name, b.Name) })

	tagsHere := make(map[string]struct{}, len(clone.Tags))
	for _, tag := range clone.Tags {
		if tag.Name == "" {
			return Manifest{}, inventoryErr(m.Digest, "has a tag with an empty name")
		}
		if _, duplicate := tagsHere[tag.Name]; duplicate {
			return Manifest{}, inventoryErr(m.Digest, "lists tag %q twice", tag.Name)
		}
		tagsHere[tag.Name] = struct{}{}
		if owner, taken := tagOwner[tag.Name]; taken {
			// A tag names exactly one digest. Two claims mean the snapshot is
			// inconsistent, and the manifest the tag does not really point at
			// would look protected -- or, worse, deletable.
			return Manifest{}, inventoryErr(m.Digest, "tag %q also points at %s", tag.Name, owner)
		}
		tagOwner[tag.Name] = m.Digest
	}

	children := slices.Clone(m.Children)
	slices.Sort(children)
	children = slices.Compact(children)
	for _, child := range children {
		if child == "" {
			return Manifest{}, inventoryErr(m.Digest, "lists a child with an empty digest")
		}
		if child == m.Digest {
			return Manifest{}, inventoryErr(m.Digest, "is its own child")
		}
	}
	clone.Children = children

	return clone, nil
}

// buildEdges indexes the subject and child edges and refuses a subject cycle.
//
// A cycle cannot arise from a legal push -- a subject must exist before
// something attaches to it -- and every manifest in one would be excluded as
// attached to a live subject anyway. It is refused rather than tolerated
// because a cycle in the snapshot means the edges are wrong, and edges that
// are wrong in one direction are the ones that make a live attachment look
// orphaned.
func (i *Inventory) buildEdges() error {
	for _, m := range i.manifests {
		if m.Subject != "" {
			if _, live := i.byDigest[m.Subject]; live {
				i.referrers[m.Subject] = append(i.referrers[m.Subject], m.Digest)
			}
		}
		for _, child := range m.Children {
			if _, live := i.byDigest[child]; live {
				i.indexParents[child] = append(i.indexParents[child], m.Digest)
			}
		}
	}
	for subject := range i.referrers {
		slices.Sort(i.referrers[subject])
	}
	for child := range i.indexParents {
		slices.Sort(i.indexParents[child])
	}

	// Iterative three-colour walk over the subject edges. Each manifest has at
	// most one subject, so the graph is functional and one pass per unvisited
	// node visits every edge once.
	const (
		unvisited = 0
		onPath    = 1
		settled   = 2
	)
	state := make(map[Digest]int, len(i.manifests))
	for _, start := range i.manifests {
		if state[start.Digest] != unvisited {
			continue
		}
		var path []Digest
		current := start.Digest
		for {
			if state[current] == onPath {
				return inventoryErr(current, "is part of a subject cycle: %s", strings.Join(digestStrings(path), " -> "))
			}
			if state[current] == settled {
				break
			}
			state[current] = onPath
			path = append(path, current)
			next, live := i.byDigest[current]
			if !live || next.Subject == "" {
				break
			}
			current = next.Subject
		}
		for _, node := range path {
			state[node] = settled
		}
	}
	return nil
}

// buildSelectable computes the exclusions and the selectable set.
//
// The reasons are checked in a fixed order and every one that applies is
// recorded, because "why is this not on the list" is answered badly by naming
// only the first of three reasons: an operator who unprotects the tag would
// come back to find the manifest still kept.
func (i *Inventory) buildSelectable() {
	for _, m := range i.manifests {
		var reasons []Exclusion
		for _, tag := range m.Tags {
			if tag.Protected {
				reasons = append(reasons, Exclusion{Digest: m.Digest, Reason: ExcludedProtectedTag, Detail: tag.Name})
			}
			if tag.Immutable {
				reasons = append(reasons, Exclusion{Digest: m.Digest, Reason: ExcludedImmutableTag, Detail: tag.Name})
			}
		}
		if parents := i.indexParents[m.Digest]; len(parents) > 0 {
			reasons = append(reasons, Exclusion{
				Digest: m.Digest,
				Reason: ExcludedIndexChild,
				Detail: strings.Join(digestStrings(parents), ", "),
			})
		}
		if m.Subject != "" {
			if _, live := i.byDigest[m.Subject]; live {
				reasons = append(reasons, Exclusion{
					Digest: m.Digest,
					Reason: ExcludedLiveSubject,
					Detail: string(m.Subject),
				})
			}
		}

		if len(reasons) == 0 {
			i.selectable = append(i.selectable, m)
			continue
		}
		i.excludedBy[m.Digest] = reasons
		i.exclusions = append(i.exclusions, reasons...)
	}
}

// Repository is the repository the inventory is a snapshot of.
func (i *Inventory) Repository() string { return i.repository }

// Len is how many manifests the snapshot holds.
func (i *Inventory) Len() int { return len(i.manifests) }

// Manifests returns every manifest in the snapshot, sorted by digest.
func (i *Inventory) Manifests() []Manifest { return slices.Clone(i.manifests) }

// Selectable returns the manifests a retention rule may select, sorted by
// digest.
//
// It is the invariant this package is built around: nothing outside this set
// can appear in a plan's deletions, because nothing outside it is ever shown
// to a rule.
func (i *Inventory) Selectable() []Manifest { return slices.Clone(i.selectable) }

// Exclusions returns why every non-selectable manifest is out, in digest
// order. It is what a plan reports so that a plan which deletes nothing still
// says why.
func (i *Inventory) Exclusions() []Exclusion { return slices.Clone(i.exclusions) }

// ExclusionsFor returns the reasons one manifest is not selectable, or nil if
// it is.
func (i *Inventory) ExclusionsFor(digest Digest) []Exclusion {
	return slices.Clone(i.excludedBy[digest])
}

// Lookup returns a manifest from the snapshot.
func (i *Inventory) Lookup(digest Digest) (Manifest, bool) {
	m, ok := i.byDigest[digest]
	return m, ok
}

// IndexParents returns the manifests in the snapshot that list the given
// digest as a child, sorted. A non-empty result is what makes the manifest
// undeletable under Q10.
func (i *Inventory) IndexParents(digest Digest) []Digest {
	return slices.Clone(i.indexParents[digest])
}

// Referrers returns the manifests attached directly to a subject, sorted.
func (i *Inventory) Referrers(digest Digest) []Digest {
	return slices.Clone(i.referrers[digest])
}

// ReferrerSubtree returns every manifest that attaches to the given digest,
// transitively and sorted -- a signature on an SBOM is in the SBOM's subject's
// subtree, because deleting the image deletes the SBOM and the signature dies
// with it (ADR 0011).
//
// This is what a plan entry carries, so that applying a plan never deletes an
// artifact the dry run did not show.
func (i *Inventory) ReferrerSubtree(digest Digest) []Digest {
	seen := map[Digest]struct{}{digest: {}}
	queue := []Digest{digest}
	var out []Digest
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, referrer := range i.referrers[current] {
			if _, visited := seen[referrer]; visited {
				continue
			}
			seen[referrer] = struct{}{}
			out = append(out, referrer)
			queue = append(queue, referrer)
		}
	}
	slices.Sort(out)
	return out
}

// digestStrings renders digests for a message.
func digestStrings(digests []Digest) []string {
	out := make([]string, 0, len(digests))
	for _, d := range digests {
		out = append(out, string(d))
	}
	return out
}
