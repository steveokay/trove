package policy_test

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/policy"
)

// The properties below are the reason this evaluator is worth trusting with a
// delete button. Each one is something an operator relies on without being
// told: that a protected tag survives whatever the rules say, that a plan is
// the same plan when the same state is evaluated twice, and that every
// manifest is accounted for exactly once.
//
// They are checked over generated inventories and rule sets rather than
// examples, because an example only ever proves the case somebody thought of.

// propertyKinds, propertyStatuses and propertyPatterns are the alphabet
// generated rules are built from -- small on purpose, so overlaps, near-misses
// and disjoint filters all occur frequently rather than by luck.
var (
	propertyKinds = []policy.RuleKind{
		policy.SelectMatched, policy.KeepLastN, policy.KeepNewerThan, policy.KeepIfPulledSince,
	}
	propertyStatuses = []policy.TagStatus{policy.AnyTags, policy.Tagged, policy.Untagged}
	propertyPatterns = []string{"", `t[0-9]`, `t1`, `.*`}
)

// inventoryFrom turns a byte string into a valid inventory, so a fuzzer can
// explore shapes without knowing anything about the types.
//
// Subject and child edges only ever point at a lower index, which is what
// keeps every generated snapshot acyclic and therefore constructible; the
// refusals for the cyclic ones are covered by the table tests.
func inventoryFrom(t *testing.T, seed []byte) *policy.Inventory {
	t.Helper()

	var manifests []policy.Manifest
	for i := 0; i+2 < len(seed) && i/3 < 10; i += 3 {
		index := i / 3
		age, shape, detail := seed[i], seed[i+1], seed[i+2]

		m := policy.Manifest{
			Digest:   policy.Digest(fmt.Sprintf("sha256:%02x", index)),
			PushedAt: now.Add(-time.Duration(age) * time.Hour),
			Size:     int64(detail),
		}
		if shape&1 != 0 {
			m.Tags = []policy.Tag{{
				Name:      fmt.Sprintf("t%d", index),
				Protected: shape&2 != 0,
				Immutable: shape&4 != 0,
			}}
		}
		if shape&8 != 0 && index > 0 {
			m.Subject = policy.Digest(fmt.Sprintf("sha256:%02x", int(detail)%index))
		}
		if shape&16 != 0 && index > 0 {
			m.Children = []policy.Digest{policy.Digest(fmt.Sprintf("sha256:%02x", int(age)%index))}
		}
		if shape&32 != 0 {
			m.LastPulledAt = now.Add(-time.Duration(detail) * time.Hour)
			m.PullCount = int64(detail)
		}
		manifests = append(manifests, m)
	}

	inv, err := policy.NewInventory("team-a/api", manifests)
	if err != nil {
		t.Fatalf("generated an inventory that will not build: %v", err)
	}
	return inv
}

// rulesFrom turns a byte string into a compiled rule set.
func rulesFrom(t *testing.T, seed []byte) []policy.Rule {
	t.Helper()

	var rules []policy.Rule
	for i := 0; i+2 < len(seed) && i/3 < 6; i += 3 {
		shape, filter, amount := seed[i], seed[i+1], seed[i+2]

		rule := policy.Rule{
			Name:      fmt.Sprintf("r%d", i/3),
			Priority:  int(shape % 4),
			Kind:      propertyKinds[int(shape/4)%len(propertyKinds)],
			TagStatus: propertyStatuses[int(filter)%len(propertyStatuses)],
		}
		if pattern := propertyPatterns[int(filter/4)%len(propertyPatterns)]; pattern != "" {
			rule.IncludeTags = []string{pattern}
		}
		if pattern := propertyPatterns[int(filter/16)%len(propertyPatterns)]; pattern != "" {
			rule.ExcludeTags = []string{pattern}
		}
		switch rule.Kind {
		case policy.KeepLastN:
			rule.N = int(amount % 5)
		case policy.KeepNewerThan, policy.KeepIfPulledSince:
			rule.Age = time.Duration(amount%64+1) * time.Hour
		case policy.SelectMatched:
		}
		rules = append(rules, rule)
	}
	return rules
}

// evaluateGenerated compiles and evaluates a generated policy, tolerating the
// one failure a generated rule set is allowed to produce: an equal-priority
// tie, which is an answer and not a bug.
func evaluateGenerated(t *testing.T, inv *policy.Inventory, rules []policy.Rule) (policy.Plan, bool) {
	t.Helper()

	set, err := policy.CompileRules(rules...)
	if err != nil {
		t.Fatalf("generated a rule set that will not compile: %v", err)
	}
	plan, err := policy.Evaluate(inv, set, now)
	if err != nil {
		if !errors.Is(err, policy.ErrRuleConflict) {
			t.Fatalf("Evaluate failed with something other than a conflict: %v", err)
		}
		return policy.Plan{}, false
	}
	return plan, true
}

// FuzzPlanStaysInsideTheSelectableSet is the property the package exists for:
// no rule set, at any priority, with any count, reaches a manifest the
// inventory excluded.
//
// It is checked here as well as by construction because the two arguments are
// independent. The constructor's is that a rule is never shown an excluded
// manifest; this one is that the plan built afterwards does not put one back.
func FuzzPlanStaysInsideTheSelectableSet(f *testing.F) {
	f.Add([]byte{1, 3, 5}, []byte{0, 0, 0})
	f.Add([]byte{1, 7, 2, 9, 24, 4, 3, 8, 1}, []byte{4, 1, 2, 9, 5, 3})
	f.Add([]byte{200, 63, 7, 10, 31, 3}, []byte{2, 0, 0, 7, 6, 4})

	f.Fuzz(func(t *testing.T, inventorySeed, ruleSeed []byte) {
		inv := inventoryFrom(t, inventorySeed)
		plan, ok := evaluateGenerated(t, inv, rulesFrom(t, ruleSeed))
		if !ok {
			return
		}

		selectable := make(map[policy.Digest]struct{}, len(inv.Selectable()))
		for _, m := range inv.Selectable() {
			selectable[m.Digest] = struct{}{}
		}

		for _, entry := range plan.Selected {
			if _, allowed := selectable[entry.Digest]; !allowed {
				t.Fatalf("plan selected %s, which is not in the selectable set (%v)",
					entry.Digest, inv.ExclusionsFor(entry.Digest))
			}
		}
		for _, entry := range plan.Blocked {
			if _, allowed := selectable[entry.Digest]; !allowed {
				t.Fatalf("plan blocked %s, which was never selectable", entry.Digest)
			}
		}
		// A cascade member is deleted too, so it must at least be a manifest
		// the snapshot knows about -- a plan cannot delete something it never
		// saw.
		for _, digest := range plan.Digests() {
			if _, known := inv.Lookup(digest); !known {
				t.Fatalf("plan would delete %s, which is not in the inventory", digest)
			}
		}
	})
}

// FuzzProtectedContentSurvivesEveryRuleSet states the §7 rule directly:
// protected and immutable tags beat every retention rule, always. So does a
// live index's child, and so does a live subject's attachment.
func FuzzProtectedContentSurvivesEveryRuleSet(f *testing.F) {
	f.Add([]byte{1, 3, 5}, []byte{0, 0, 0})
	f.Add([]byte{1, 7, 2, 9, 27, 4, 3, 15, 1}, []byte{4, 1, 2, 9, 5, 3})
	f.Add([]byte{5, 31, 9, 12, 63, 2, 40, 11, 6}, []byte{1, 1, 0, 8, 2, 4})

	f.Fuzz(func(t *testing.T, inventorySeed, ruleSeed []byte) {
		inv := inventoryFrom(t, inventorySeed)
		plan, ok := evaluateGenerated(t, inv, rulesFrom(t, ruleSeed))
		if !ok {
			return
		}

		deleting := make(map[policy.Digest]struct{})
		for _, digest := range plan.Digests() {
			deleting[digest] = struct{}{}
		}

		for _, exclusion := range inv.Exclusions() {
			if _, gone := deleting[exclusion.Digest]; !gone {
				continue
			}
			// A referrer of a live subject is the one exclusion a plan may
			// delete -- but only by cascade, with its subject, and only
			// because the plan showed it. Any other excluded manifest in the
			// deletion set is the bug this property exists to catch.
			if exclusion.Reason == policy.ExcludedLiveSubject && cascadeContains(plan, exclusion.Digest) {
				continue
			}
			t.Fatalf("plan would delete %s, excluded because of a %s", exclusion.Digest, exclusion.Reason)
		}
	})
}

// cascadeContains reports whether a digest is in some entry's referrer
// subtree.
func cascadeContains(plan policy.Plan, digest policy.Digest) bool {
	for _, entry := range plan.Selected {
		for _, referrer := range entry.Referrers {
			if referrer.Digest == digest {
				return true
			}
		}
	}
	return false
}

// FuzzPlanPartitionsTheInventory: every manifest is deleted, cascaded,
// blocked, or kept -- exactly one of the four.
//
// This is what makes a plan readable as an account rather than a suggestion.
// A manifest in two lists is a double delete or a contradiction; a manifest in
// none is an artifact whose fate the dry run did not mention.
func FuzzPlanPartitionsTheInventory(f *testing.F) {
	f.Add([]byte{1, 3, 5}, []byte{0, 0, 0})
	f.Add([]byte{1, 9, 2, 30, 25, 4, 3, 8, 1}, []byte{4, 1, 2, 9, 5, 3})
	f.Add([]byte{7, 11, 1, 6, 19, 2, 3, 41, 5, 8, 1, 0}, []byte{9, 2, 3})

	f.Fuzz(func(t *testing.T, inventorySeed, ruleSeed []byte) {
		inv := inventoryFrom(t, inventorySeed)
		plan, ok := evaluateGenerated(t, inv, rulesFrom(t, ruleSeed))
		if !ok {
			return
		}

		seen := make(map[policy.Digest]string, inv.Len())
		claim := func(digest policy.Digest, list string) {
			if previous, taken := seen[digest]; taken {
				t.Fatalf("%s appears in both %s and %s", digest, previous, list)
			}
			seen[digest] = list
		}
		for _, entry := range plan.Selected {
			claim(entry.Digest, "selected")
			for _, referrer := range entry.Referrers {
				claim(referrer.Digest, "cascaded")
			}
		}
		for _, entry := range plan.Blocked {
			claim(entry.Digest, "blocked")
		}
		for _, entry := range plan.Kept {
			claim(entry.Digest, "kept")
		}

		for _, m := range inv.Manifests() {
			if _, accounted := seen[m.Digest]; !accounted {
				t.Fatalf("%s is in no list: the plan does not account for it", m.Digest)
			}
		}
		if got, want := len(seen), inv.Len(); got != want {
			t.Fatalf("the plan accounts for %d manifests, the inventory held %d", got, want)
		}
		if got, want := plan.Summary().Manifests, inv.Len(); got != want {
			t.Fatalf("summary counts %d manifests, the inventory held %d", got, want)
		}
	})
}

// FuzzPlanIsIndependentOfInputOrder: the plan is a function of the state and
// the rules, not of the order the store returned rows in or the order the
// policy document lists rules in.
//
// It is the property an operator relies on when they reproduce a plan from
// stored configuration, and the one that makes the plan hash P-005 pins an
// apply to worth computing at all.
func FuzzPlanIsIndependentOfInputOrder(f *testing.F) {
	f.Add([]byte{1, 3, 5}, []byte{0, 0, 0})
	f.Add([]byte{1, 7, 2, 9, 24, 4, 3, 8, 1}, []byte{4, 1, 2, 9, 5, 3})
	f.Add([]byte{2, 5, 9, 30, 13, 4, 60, 3, 1, 6, 33, 2}, []byte{7, 6, 5, 1, 0, 2})

	f.Fuzz(func(t *testing.T, inventorySeed, ruleSeed []byte) {
		inv := inventoryFrom(t, inventorySeed)
		rules := rulesFrom(t, ruleSeed)

		baseline, ok := evaluateGenerated(t, inv, rules)
		if !ok {
			return
		}

		reversedManifests := inv.Manifests()
		slices.Reverse(reversedManifests)
		shuffled, err := policy.NewInventory(inv.Repository(), reversedManifests)
		if err != nil {
			t.Fatalf("rebuilding the inventory in reverse order: %v", err)
		}
		reversedRules := slices.Clone(rules)
		slices.Reverse(reversedRules)

		again, ok := evaluateGenerated(t, shuffled, reversedRules)
		if !ok {
			t.Fatal("reversing the inputs turned a plan into a conflict")
		}
		if !reflect.DeepEqual(baseline, again) {
			t.Fatalf("plan depends on input order:\n%+v\n%+v", baseline, again)
		}
	})
}

// FuzzWeakerRulesDoNotOverrideStrongerOnes: a rule added at a weaker
// precedence than every existing one can decide manifests nobody had an
// opinion about, and can decide nothing else.
//
// This is what makes a policy extensible. An operator adding a catch-all sweep
// at priority 100 must not have to re-audit the rules already protecting
// things, and here that is checked rather than asserted in a comment.
func FuzzWeakerRulesDoNotOverrideStrongerOnes(f *testing.F) {
	f.Add([]byte{1, 3, 5}, []byte{0, 0, 0}, byte(0))
	f.Add([]byte{1, 7, 2, 9, 24, 4, 3, 8, 1}, []byte{4, 1, 2, 9, 5, 3}, byte(2))
	f.Add([]byte{9, 15, 3, 22, 7, 8}, []byte{6, 3, 1}, byte(5))

	f.Fuzz(func(t *testing.T, inventorySeed, ruleSeed []byte, extra byte) {
		inv := inventoryFrom(t, inventorySeed)
		rules := rulesFrom(t, ruleSeed)

		before, ok := evaluateGenerated(t, inv, rules)
		if !ok {
			return
		}

		weakest := policy.Rule{
			Name:      "catch-all",
			Priority:  100,
			Kind:      propertyKinds[int(extra)%len(propertyKinds)],
			TagStatus: propertyStatuses[int(extra/4)%len(propertyStatuses)],
		}
		switch weakest.Kind {
		case policy.KeepLastN:
			weakest.N = int(extra % 3)
		case policy.KeepNewerThan, policy.KeepIfPulledSince:
			weakest.Age = time.Duration(extra%32+1) * time.Hour
		case policy.SelectMatched:
		}

		after, ok := evaluateGenerated(t, inv, append(slices.Clone(rules), weakest))
		if !ok {
			t.Fatal("a rule at a weaker precedence created a conflict")
		}

		for _, entry := range before.Selected {
			found := false
			for _, candidate := range after.Selected {
				if candidate.Digest != entry.Digest {
					continue
				}
				found = true
				if candidate.Rule != entry.Rule || candidate.Priority != entry.Priority {
					t.Fatalf("%s was decided by %q at priority %d, now by %q at %d",
						entry.Digest, entry.Rule, entry.Priority, candidate.Rule, candidate.Priority)
				}
			}
			if !found {
				t.Fatalf("%s was selected before the weaker rule was added and is not now", entry.Digest)
			}
		}
		for _, entry := range before.Kept {
			if entry.Reason != policy.KeptByRule {
				continue
			}
			for _, candidate := range after.Kept {
				if candidate.Digest == entry.Digest && candidate.Rule != entry.Rule {
					t.Fatalf("%s was kept by %q, now by %q", entry.Digest, entry.Rule, candidate.Rule)
				}
			}
			for _, candidate := range after.Selected {
				if candidate.Digest == entry.Digest {
					t.Fatalf("%s was kept by rule %q and a weaker rule now selects it", entry.Digest, entry.Rule)
				}
			}
		}
	})
}
