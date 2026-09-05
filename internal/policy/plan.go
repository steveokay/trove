package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Referrer is one member of a plan entry's cascade: a manifest that dies with
// the entry because it is attached to it (Q22, ADR 0011).
//
// It is listed in the plan rather than discovered at apply time so that
// applying never deletes an artifact the dry run did not show. An operator who
// approves the deletion of an image has approved the deletion of its SBOM, its
// signature and its scan attestation -- but only if they were told.
type Referrer struct {
	// Digest is the attached manifest.
	Digest Digest
	// Subject is what it attaches to: the entry itself, or another referrer
	// further up the chain. Carried so a nested cascade reads as a chain
	// rather than as a flat list.
	Subject Digest
	// Size is its byte size, counted in the entry's total.
	Size int64
	// ArtifactTags are the tags pointing at the referrer, sorted. Normally
	// empty -- attachments are untagged -- and shown when they are not,
	// because a tagged attachment disappearing is the surprise worth printing.
	ArtifactTags []string
}

// Entry is one manifest a plan would delete, and the reason it is on the list.
type Entry struct {
	// Digest is the manifest to be deleted.
	Digest Digest
	// Tags are the tags pointing at it, sorted.
	Tags []string
	// Size is the manifest's own byte size.
	Size int64
	// Rule is the name of the rule that selected it -- the answer to "why is
	// this on the list", which is the question a dry run exists to answer.
	Rule string
	// RuleKind is that rule's kind.
	RuleKind RuleKind
	// Priority is the precedence the decision was made at.
	Priority int
	// AlsoSelectedBy names the other rules at that precedence that agreed,
	// sorted. Empty when one rule decided alone.
	AlsoSelectedBy []string
	// Referrers is the cascade: every manifest attached to this one,
	// transitively, in digest order.
	Referrers []Referrer
}

// TotalSize is the bytes the entry accounts for: the manifest and its whole
// cascade. It is derived rather than stored so that it cannot disagree with
// the list above it.
func (e Entry) TotalSize() int64 {
	total := e.Size
	for _, referrer := range e.Referrers {
		total += referrer.Size
	}
	return total
}

// String renders an entry the way a plan listing and a log line report it.
func (e Entry) String() string {
	tags := "untagged"
	if len(e.Tags) > 0 {
		tags = strings.Join(e.Tags, ", ")
	}
	if len(e.Referrers) == 0 {
		return fmt.Sprintf("delete %s (%s): rule %q at priority %d", e.Digest, tags, e.Rule, e.Priority)
	}
	return fmt.Sprintf("delete %s (%s): rule %q at priority %d, cascading to %d referrer(s)",
		e.Digest, tags, e.Rule, e.Priority, len(e.Referrers))
}

// BlockedEntry is a manifest a rule selected that the plan will not delete,
// because the cascade would reach a manifest that is protected in its own
// right.
//
// The cascade is the one path by which a plan deletes something no rule
// selected, so it is the one path on which protection has to be re-checked. A
// tagged attestation whose tag an operator protected, or an attestation a live
// index lists as a child (Q10, ADR 0011), is not deletable -- and because the
// subject cannot be deleted without it, neither is the subject. The cascade
// fails closed and the operator unprotects the attachment, or deletes the
// index, first.
//
// Surfacing that in the dry run rather than at apply time is the whole point
// of a dry run: the plan says what it will do, and this is something it will
// not do.
type BlockedEntry struct {
	// Digest is the manifest the rule selected.
	Digest Digest
	// Tags are the tags pointing at it, sorted.
	Tags []string
	// Rule, RuleKind and Priority describe the selection that was refused.
	Rule     string
	RuleKind RuleKind
	Priority int
	// Referrer is the cascade member that cannot be deleted. It is never the
	// entry itself: the selectable-set invariant already keeps a protected
	// manifest from being selected.
	Referrer Digest
	// Blocker is that member's own exclusion -- the protected tag, the
	// immutable tag, or the live index -- so the entry says what to change.
	Blocker Exclusion
}

// String renders a blocked entry for a plan listing.
func (e BlockedEntry) String() string {
	return fmt.Sprintf("blocked %s: rule %q selected it, but its referrer %s cannot be deleted: %s",
		e.Digest, e.Rule, e.Referrer, e.Blocker)
}

// KeptReason says why a manifest survived a plan.
type KeptReason string

// The three ways a manifest survives. They are distinguished because they are
// three different follow-up actions: change a rule, add a rule, or unprotect
// something.
const (
	// KeptByRule: a rule at the deciding precedence saved it.
	KeptByRule KeptReason = "kept by rule"
	// KeptNoRuleApplies: no rule had an opinion about it. Absence of a rule
	// keeps; it never deletes.
	KeptNoRuleApplies KeptReason = "no rule applies"
	// KeptNotSelectable: the manifest is outside the selectable set, so no
	// rule was ever shown it. Exclusions says which of the four reasons apply.
	KeptNotSelectable KeptReason = "not selectable"
)

// KeptEntry is one manifest a plan leaves alone, and why.
//
// The kept list is not decoration. The first question about a plan that
// deletes nothing is why not, and a plan that answers it with silence sends an
// operator to read their rules again -- or, worse, to widen them.
type KeptEntry struct {
	// Digest is the manifest that survives.
	Digest Digest
	// Tags are the tags pointing at it, sorted.
	Tags []string
	// Reason is which of the three ways it survived.
	Reason KeptReason
	// Rule, RuleKind and Priority name the rule that saved it, for
	// KeptByRule. Empty and zero otherwise.
	Rule     string
	RuleKind RuleKind
	Priority int
	// AlsoKeptBy names the other rules at that precedence that agreed, sorted.
	AlsoKeptBy []string
	// Exclusions are why it is not selectable, for KeptNotSelectable. Empty
	// otherwise.
	Exclusions []Exclusion
}

// String renders a kept entry for a plan listing.
func (e KeptEntry) String() string {
	switch e.Reason {
	case KeptByRule:
		return fmt.Sprintf("keep %s: rule %q at priority %d", e.Digest, e.Rule, e.Priority)
	case KeptNotSelectable:
		reasons := make([]string, 0, len(e.Exclusions))
		for _, exclusion := range e.Exclusions {
			reasons = append(reasons, string(exclusion.Reason))
		}
		return fmt.Sprintf("keep %s: %s (%s)", e.Digest, e.Reason, strings.Join(reasons, "; "))
	default:
		return fmt.Sprintf("keep %s: %s", e.Digest, e.Reason)
	}
}

// KeptReasonCount is how many manifests one reason accounts for. It is a
// sorted slice rather than a map so that a rendered plan is byte-identical
// between two evaluations of the same state.
type KeptReasonCount struct {
	Reason KeptReason
	Count  int
}

// Summary is a plan at a glance: the numbers an operator reads before deciding
// whether to read the entries.
type Summary struct {
	// Manifests is how many the inventory held.
	Manifests int
	// Selected is how many entries the plan would delete outright.
	Selected int
	// Cascaded is how many attached manifests die with them.
	Cascaded int
	// Blocked is how many selections were refused under Q10.
	Blocked int
	// Kept is how many manifests survive.
	Kept int
	// Bytes is the byte estimate for everything deleted, entries and cascades
	// together. It counts manifest sizes, not the blobs they reference: what a
	// deletion actually reclaims is decided by garbage collection, because a
	// layer shared with a manifest that stays is not freed by deleting this
	// one.
	Bytes int64
	// KeptBecause breaks the survivors down by reason, sorted by reason.
	KeptBecause []KeptReasonCount
}

// String renders the summary as one line.
func (s Summary) String() string {
	return fmt.Sprintf("%d manifest(s): %d selected, %d cascaded, %d blocked, %d kept, %d byte(s)",
		s.Manifests, s.Selected, s.Cascaded, s.Blocked, s.Kept, s.Bytes)
}

// Plan is the product of evaluating retention rules against an inventory: what
// would be deleted, what would not, and why in both directions.
//
// It is a dry run and nothing else. Producing it deletes nothing and touches
// nothing; applying it is a separate operation behind a separate permission
// (§5, `policy:apply`). Dry run is not a mode of this package -- it is the
// only thing this package does.
type Plan struct {
	// Repository is the repository the plan is for.
	Repository string
	// EvaluatedAt is the evaluation time that was passed in. Every age
	// comparison in the plan was measured from it, so a plan read tomorrow is
	// still interpretable.
	EvaluatedAt time.Time
	// Selected are the manifests to delete, in digest order, each with its
	// cascade.
	Selected []Entry
	// Blocked are selections the plan refuses to carry out, in digest order.
	Blocked []BlockedEntry
	// Kept is every manifest that survives, in digest order.
	Kept []KeptEntry
}

// Digests returns every manifest the plan would delete -- entries and their
// cascades together -- sorted.
//
// This is the set the apply path acts on and the set an audit trail must
// account for. Blocked entries are not in it: the plan does not delete them.
func (p Plan) Digests() []Digest {
	var out []Digest
	for _, entry := range p.Selected {
		out = append(out, entry.Digest)
		for _, referrer := range entry.Referrers {
			out = append(out, referrer.Digest)
		}
	}
	slices.Sort(out)
	return out
}

// Empty reports whether the plan would delete nothing.
func (p Plan) Empty() bool { return len(p.Selected) == 0 }

// Summary computes the plan's headline numbers. It is derived on demand rather
// than stored, so it cannot drift from the lists it describes.
func (p Plan) Summary() Summary {
	summary := Summary{
		Selected: len(p.Selected),
		Blocked:  len(p.Blocked),
		Kept:     len(p.Kept),
	}
	for _, entry := range p.Selected {
		summary.Cascaded += len(entry.Referrers)
		summary.Bytes += entry.TotalSize()
	}
	summary.Manifests = summary.Selected + summary.Cascaded + summary.Blocked + summary.Kept

	counts := make(map[KeptReason]int, 3)
	for _, kept := range p.Kept {
		counts[kept.Reason]++
	}
	for _, reason := range []KeptReason{KeptByRule, KeptNoRuleApplies, KeptNotSelectable} {
		if count := counts[reason]; count > 0 {
			summary.KeptBecause = append(summary.KeptBecause, KeptReasonCount{Reason: reason, Count: count})
		}
	}
	return summary
}

// String renders the plan's headline for a log line.
func (p Plan) String() string {
	return fmt.Sprintf("retention plan for %s at %s: %s",
		p.Repository, p.EvaluatedAt.UTC().Format(time.RFC3339), p.Summary())
}

// buildPlan turns resolved verdicts into the plan, computing each selection's
// cascade and refusing the ones Q10 blocks.
func buildPlan(inv *Inventory, verdicts map[Digest]verdict, now time.Time) Plan {
	plan := Plan{Repository: inv.repository, EvaluatedAt: now}

	// cascading holds every digest that dies as an attachment, so the kept
	// pass below does not report a manifest as surviving that an entry above
	// it already accounts for.
	cascading := make(map[Digest]struct{})
	selected := make(map[Digest]struct{})
	blocked := make(map[Digest]struct{})

	for _, m := range inv.selectable {
		decided := verdicts[m.Digest]
		if !decided.applicable || decided.keep {
			continue
		}

		subtree := inv.ReferrerSubtree(m.Digest)
		if pinned, blocker, refused := firstProtectedReferrer(inv, subtree); refused {
			plan.Blocked = append(plan.Blocked, BlockedEntry{
				Digest:   m.Digest,
				Tags:     m.TagNames(),
				Rule:     decided.rule,
				RuleKind: decided.kind,
				Priority: decided.priority,
				Referrer: pinned,
				Blocker:  blocker,
			})
			blocked[m.Digest] = struct{}{}
			continue
		}

		entry := Entry{
			Digest:         m.Digest,
			Tags:           m.TagNames(),
			Size:           m.Size,
			Rule:           decided.rule,
			RuleKind:       decided.kind,
			Priority:       decided.priority,
			AlsoSelectedBy: decided.agreeing,
		}
		for _, digest := range subtree {
			attached, _ := inv.Lookup(digest)
			entry.Referrers = append(entry.Referrers, Referrer{
				Digest:       digest,
				Subject:      attached.Subject,
				Size:         attached.Size,
				ArtifactTags: attached.TagNames(),
			})
			cascading[digest] = struct{}{}
		}
		selected[m.Digest] = struct{}{}
		plan.Selected = append(plan.Selected, entry)
	}

	for _, m := range inv.manifests {
		if _, gone := selected[m.Digest]; gone {
			continue
		}
		if _, gone := cascading[m.Digest]; gone {
			continue
		}
		if _, refused := blocked[m.Digest]; refused {
			continue
		}
		plan.Kept = append(plan.Kept, keptEntry(inv, m, verdicts[m.Digest]))
	}

	return plan
}

// firstProtectedReferrer reports the first cascade member that cannot be
// deleted, in digest order, with the exclusion that stops it.
//
// Every cascade member is excluded from the selectable set -- being attached
// to a live subject is what put it there -- so that one reason is expected and
// is what the cascade exists to override. Any *other* reason is protection the
// cascade may not walk through: a protected or immutable tag on the
// attachment, or an index that lists it as a child.
//
// A member is pinned by any index in the snapshot, including one this same
// plan would delete. That is deliberate and matches how the selectable set is
// built: the exclusions are computed from the state as read, before rules run,
// not from the state the plan would produce. A manifest freed by another
// deletion in this plan becomes deletable on the next evaluation, one round
// later -- which is the conservative direction, and the only one that keeps
// the plan independent of the order its entries are applied in.
func firstProtectedReferrer(inv *Inventory, subtree []Digest) (Digest, Exclusion, bool) {
	for _, digest := range subtree {
		for _, exclusion := range inv.excludedBy[digest] {
			if exclusion.Reason == ExcludedLiveSubject {
				continue
			}
			return digest, exclusion, true
		}
	}
	return "", Exclusion{}, false
}

// keptEntry explains one survivor.
func keptEntry(inv *Inventory, m Manifest, decided verdict) KeptEntry {
	entry := KeptEntry{Digest: m.Digest, Tags: m.TagNames()}
	if exclusions := inv.excludedBy[m.Digest]; len(exclusions) > 0 {
		entry.Reason = KeptNotSelectable
		entry.Exclusions = slices.Clone(exclusions)
		return entry
	}
	if !decided.applicable {
		entry.Reason = KeptNoRuleApplies
		return entry
	}
	entry.Reason = KeptByRule
	entry.Rule = decided.rule
	entry.RuleKind = decided.kind
	entry.Priority = decided.priority
	entry.AlsoKeptBy = decided.agreeing
	return entry
}
