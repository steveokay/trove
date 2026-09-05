package policy_test

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/policy"
)

// mustRules compiles rules a test expects to be valid.
func mustRules(t *testing.T, rules ...policy.Rule) policy.RuleSet {
	t.Helper()

	set, err := policy.CompileRules(rules...)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	return set
}

// mustPlan evaluates a plan a test expects to succeed.
func mustPlan(t *testing.T, inv *policy.Inventory, rules policy.RuleSet) policy.Plan {
	t.Helper()

	plan, err := policy.Evaluate(inv, rules, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return plan
}

// selected renders the digests a plan would delete outright, sorted.
func selected(plan policy.Plan) []string {
	out := make([]string, 0, len(plan.Selected))
	for _, entry := range plan.Selected {
		out = append(out, string(entry.Digest))
	}
	return out
}

// decidedBy maps each selected digest to the rule that put it on the list.
func decidedBy(plan policy.Plan) map[string]string {
	out := make(map[string]string, len(plan.Selected))
	for _, entry := range plan.Selected {
		out[string(entry.Digest)] = entry.Rule
	}
	return out
}

// keptBy maps each surviving digest to the reason it survived.
func keptBy(plan policy.Plan) map[string]policy.KeptReason {
	out := make(map[string]policy.KeptReason, len(plan.Kept))
	for _, entry := range plan.Kept {
		out[string(entry.Digest)] = entry.Reason
	}
	return out
}

// matrixInventory is the fixture the rule matrix runs against: four manifests
// an hour apart, three of them tagged.
func matrixInventory(t *testing.T) *policy.Inventory {
	t.Helper()

	return mustInventory(t,
		withTags(mf("sha256:a", ago(1*time.Hour)), "latest"),
		withTags(mf("sha256:b", ago(2*time.Hour)), "v2"),
		withTags(mf("sha256:c", ago(3*time.Hour)), "v1"),
		mf("sha256:d", ago(4*time.Hour)),
	)
}

// A rule set is the input to the one destructive operation trove performs.
// Every row here is a rule that could not mean what it says, and refusing it
// at compile time is how an operator finds out before a plan does.
func TestCompileRulesRefusesRulesThatCannotMeanWhatTheySay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules []policy.Rule
		rule  string
		field string
		want  string
	}{
		{
			name:  "an unnamed rule",
			rules: []policy.Rule{{Kind: policy.SelectMatched}},
			rule:  "#0", field: "name", want: "a rule must be named",
		},
		{
			name: "two rules with one name",
			rules: []policy.Rule{
				{Name: "sweep", Kind: policy.SelectMatched},
				{Name: "sweep", Kind: policy.SelectMatched},
			},
			rule: "sweep", field: "name", want: "already used",
		},
		{
			// The zero value of RuleKind is not a kind. A half-built rule must
			// fail, never read as "select everything the filter matched".
			name:  "a rule with no kind",
			rules: []policy.Rule{{Name: "half-built"}},
			rule:  "half-built", field: "kind", want: `unknown rule kind ""`,
		},
		{
			name:  "an unknown kind",
			rules: []policy.Rule{{Name: "typo", Kind: "keep-lots"}},
			rule:  "typo", field: "kind", want: "unknown rule kind",
		},
		{
			name:  "an unknown tag status",
			rules: []policy.Rule{{Name: "typo", Kind: policy.SelectMatched, TagStatus: "tagless"}},
			rule:  "typo", field: "tag_status", want: "unknown tag status",
		},
		{
			name:  "a negative keep count",
			rules: []policy.Rule{{Name: "keep", Kind: policy.KeepLastN, N: -1}},
			rule:  "keep", field: "n", want: "must not be negative",
		},
		{
			// A field the kind never reads is an operator who believes there
			// is a condition on the rule that is not there.
			name:  "keep-last-n carrying an age",
			rules: []policy.Rule{{Name: "keep", Kind: policy.KeepLastN, N: 3, Age: time.Hour}},
			rule:  "keep", field: "age", want: "does not read an age",
		},
		{
			name:  "keep-newer-than with a zero age",
			rules: []policy.Rule{{Name: "recent", Kind: policy.KeepNewerThan}},
			rule:  "recent", field: "age", want: "must be positive",
		},
		{
			name:  "keep-newer-than with a negative age",
			rules: []policy.Rule{{Name: "recent", Kind: policy.KeepNewerThan, Age: -time.Hour}},
			rule:  "recent", field: "age", want: "must be positive",
		},
		{
			name:  "keep-newer-than carrying a count",
			rules: []policy.Rule{{Name: "recent", Kind: policy.KeepNewerThan, Age: time.Hour, N: 2}},
			rule:  "recent", field: "n", want: "does not read a count",
		},
		{
			name:  "keep-if-pulled-since with a zero age",
			rules: []policy.Rule{{Name: "used", Kind: policy.KeepIfPulledSince}},
			rule:  "used", field: "age", want: "must be positive",
		},
		{
			name:  "keep-if-pulled-since carrying a count",
			rules: []policy.Rule{{Name: "used", Kind: policy.KeepIfPulledSince, Age: time.Hour, N: 1}},
			rule:  "used", field: "n", want: "does not read a count",
		},
		{
			name:  "select-matched carrying a count",
			rules: []policy.Rule{{Name: "sweep", Kind: policy.SelectMatched, N: 1}},
			rule:  "sweep", field: "n", want: "does not read a count",
		},
		{
			name:  "select-matched carrying an age",
			rules: []policy.Rule{{Name: "sweep", Kind: policy.SelectMatched, Age: time.Hour}},
			rule:  "sweep", field: "age", want: "does not read an age",
		},
		{
			name:  "an unparseable include pattern",
			rules: []policy.Rule{{Name: "sweep", Kind: policy.SelectMatched, IncludeTags: []string{"v(1"}}},
			rule:  "sweep", field: "include_tags", want: "does not compile",
		},
		{
			name:  "an unparseable exclude pattern",
			rules: []policy.Rule{{Name: "sweep", Kind: policy.SelectMatched, ExcludeTags: []string{"*"}}},
			rule:  "sweep", field: "exclude_tags", want: "does not compile",
		},
		{
			// A pattern that can never fire is a pattern an operator believes
			// is protecting something.
			name:  "an empty include pattern",
			rules: []policy.Rule{{Name: "sweep", Kind: policy.SelectMatched, IncludeTags: []string{""}}},
			rule:  "sweep", field: "include_tags", want: "would never fire",
		},
		{
			name:  "an empty exclude pattern",
			rules: []policy.Rule{{Name: "sweep", Kind: policy.SelectMatched, ExcludeTags: []string{""}}},
			rule:  "sweep", field: "exclude_tags", want: "would never fire",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			set, err := policy.CompileRules(tt.rules...)
			if err == nil {
				t.Fatalf("CompileRules succeeded, want refusal; set has %d rule(s)", set.Len())
			}
			if set.Len() != 0 {
				t.Fatalf("CompileRules returned %d rule(s) alongside an error", set.Len())
			}
			if !errors.Is(err, policy.ErrInvalidRule) {
				t.Fatalf("error %v is not ErrInvalidRule", err)
			}
			var typed *policy.RuleError
			if !errors.As(err, &typed) {
				t.Fatalf("error %v is not a *RuleError", err)
			}
			if typed.Rule != tt.rule {
				t.Fatalf("Rule = %q, want %q", typed.Rule, tt.rule)
			}
			if typed.Field != tt.field {
				t.Fatalf("Field = %q, want %q", typed.Field, tt.field)
			}
			if !strings.Contains(typed.Reason, tt.want) {
				t.Fatalf("Reason %q does not mention %q", typed.Reason, tt.want)
			}
		})
	}
}

// The rule matrix. Each row is one shape of policy an operator writes, and the
// manifests it must and must not put on the list.
func TestEvaluateRuleMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rules    []policy.Rule
		selected []string
		by       map[string]string
	}{
		{
			// Absence of a rule keeps. It never deletes.
			name:     "no rules select nothing",
			selected: []string{},
		},
		{
			name:     "keep-last-2 selects the two oldest",
			rules:    []policy.Rule{{Name: "keep-2", Kind: policy.KeepLastN, N: 2}},
			selected: []string{"sha256:c", "sha256:d"},
			by:       map[string]string{"sha256:c": "keep-2", "sha256:d": "keep-2"},
		},
		{
			// The sweep an operator writes deliberately. It reaches everything
			// selectable and nothing else -- which is the point of the
			// protection tests below.
			name:     "keep-last-0 selects everything selectable",
			rules:    []policy.Rule{{Name: "sweep", Kind: policy.KeepLastN, N: 0}},
			selected: []string{"sha256:a", "sha256:b", "sha256:c", "sha256:d"},
		},
		{
			name:     "keep-last-N larger than the set selects nothing",
			rules:    []policy.Rule{{Name: "keep-99", Kind: policy.KeepLastN, N: 99}},
			selected: []string{},
		},
		{
			name: "keep-last-2 among tagged manifests ignores untagged ones",
			rules: []policy.Rule{
				{Name: "keep-2-tagged", Kind: policy.KeepLastN, N: 2, TagStatus: policy.Tagged},
			},
			selected: []string{"sha256:c"},
		},
		{
			name:     "keep-newer-than keeps what is inside the window",
			rules:    []policy.Rule{{Name: "recent", Kind: policy.KeepNewerThan, Age: 150 * time.Minute}},
			selected: []string{"sha256:c", "sha256:d"},
		},
		{
			// Exactly at the cutoff is outside the window: the comparison is
			// strictly after, and a boundary that keeps would make the rule's
			// meaning depend on clock resolution.
			name:     "keep-newer-than is exclusive at the boundary",
			rules:    []policy.Rule{{Name: "recent", Kind: policy.KeepNewerThan, Age: 2 * time.Hour}},
			selected: []string{"sha256:b", "sha256:c", "sha256:d"},
		},
		{
			name: "untagged reaping selects only untagged manifests",
			rules: []policy.Rule{
				{Name: "reap-untagged", Kind: policy.SelectMatched, TagStatus: policy.Untagged},
			},
			selected: []string{"sha256:d"},
		},
		{
			name: "a tagged filter never selects an untagged manifest",
			rules: []policy.Rule{
				{Name: "sweep-tagged", Kind: policy.SelectMatched, TagStatus: policy.Tagged},
			},
			selected: []string{"sha256:a", "sha256:b", "sha256:c"},
		},
		{
			name: "an include pattern narrows the rule to matching tags",
			rules: []policy.Rule{
				{Name: "versions", Kind: policy.SelectMatched, IncludeTags: []string{`v[0-9]`}},
			},
			selected: []string{"sha256:b", "sha256:c"},
		},
		{
			// Exclusion is checked first: an operator who writes both means
			// the narrower, refusing one.
			name: "an exclude pattern beats an include pattern",
			rules: []policy.Rule{
				{Name: "versions", Kind: policy.SelectMatched, IncludeTags: []string{`v[0-9]`}, ExcludeTags: []string{`v1`}},
			},
			selected: []string{"sha256:b"},
		},
		{
			// Tag patterns cannot reap untagged content. Reaping it needs the
			// untagged status filter said out loud.
			name: "a tag pattern never matches an untagged manifest",
			rules: []policy.Rule{
				{Name: "everything", Kind: policy.SelectMatched, IncludeTags: []string{`.*`}},
			},
			selected: []string{"sha256:a", "sha256:b", "sha256:c"},
		},
		{
			// Lower priority wins, following ECR. The keep rule at 1 decides
			// every manifest it matched; the sweep at 10 is never consulted.
			name: "the numerically lower priority decides",
			rules: []policy.Rule{
				{Name: "sweep", Kind: policy.SelectMatched, Priority: 10},
				{Name: "keep-recent", Kind: policy.KeepNewerThan, Age: 150 * time.Minute, Priority: 1},
			},
			selected: []string{"sha256:c", "sha256:d"},
			by:       map[string]string{"sha256:c": "keep-recent", "sha256:d": "keep-recent"},
		},
		{
			name: "and the same rules with the priorities swapped decide the other way",
			rules: []policy.Rule{
				{Name: "sweep", Kind: policy.SelectMatched, Priority: 1},
				{Name: "keep-recent", Kind: policy.KeepNewerThan, Age: 150 * time.Minute, Priority: 10},
			},
			selected: []string{"sha256:a", "sha256:b", "sha256:c", "sha256:d"},
			by: map[string]string{
				"sha256:a": "sweep", "sha256:b": "sweep", "sha256:c": "sweep", "sha256:d": "sweep",
			},
		},
		{
			// A rule at a weaker precedence still decides the manifests the
			// stronger one had no opinion about.
			name: "a weaker rule decides what the stronger one does not match",
			rules: []policy.Rule{
				{Name: "keep-tagged", Kind: policy.KeepLastN, N: 99, TagStatus: policy.Tagged, Priority: 1},
				{Name: "sweep", Kind: policy.SelectMatched, Priority: 5},
			},
			selected: []string{"sha256:d"},
			by:       map[string]string{"sha256:d": "sweep"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := mustPlan(t, matrixInventory(t), mustRules(t, tt.rules...))

			if got := selected(plan); !reflect.DeepEqual(got, tt.selected) {
				t.Fatalf("selected = %v, want %v", got, tt.selected)
			}
			for digest, rule := range tt.by {
				if got := decidedBy(plan)[digest]; got != rule {
					t.Fatalf("%s was selected by %q, want %q", digest, got, rule)
				}
			}
			if got, want := len(plan.Selected)+len(plan.Kept), 4; got != want {
				t.Fatalf("the plan accounts for %d manifests, want %d", got, want)
			}
		})
	}
}

// Anchoring is what keeps a pattern from quietly meaning more than the
// operator wrote, in the one rule set that decides what gets deleted.
func TestTagPatternsAreAnchored(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		withTags(mf("sha256:a", ago(time.Hour)), "v1"),
		withTags(mf("sha256:b", ago(time.Hour)), "v10"),
		withTags(mf("sha256:c", ago(time.Hour)), "dev-v1"),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "exact", Kind: policy.SelectMatched, IncludeTags: []string{"v1"}},
	))

	if got, want := selected(plan), []string{"sha256:a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected = %v, want %v: the pattern must match a whole tag name", got, want)
	}
}

// keep-if-pulled-since is the rule that needs pull statistics, and the one
// whose fallback has to be stated rather than inferred: never pulled means the
// push is the newest thing known about the manifest.
func TestKeepIfPulledSince(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		// Old, but pulled this morning: in use, keep it.
		withPulls(mf("sha256:used", ago(30*24*time.Hour)), ago(time.Hour), 12),
		// Old and last pulled long ago: nobody wants it.
		withPulls(mf("sha256:cold", ago(30*24*time.Hour)), ago(20*24*time.Hour), 3),
		// Pulled exactly at the cutoff. The comparison is strictly after, the
		// same boundary keep-newer-than uses.
		withPulls(mf("sha256:boundary", ago(30*24*time.Hour)), ago(7*24*time.Hour), 1),
		// Never pulled but pushed an hour ago: it has not had time to be
		// pulled, and it is the push that is recent.
		mf("sha256:fresh", ago(time.Hour)),
		// Never pulled and pushed a month ago.
		mf("sha256:stale", ago(30*24*time.Hour)),
	)
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "in-use", Kind: policy.KeepIfPulledSince, Age: 7 * 24 * time.Hour},
	))

	want := []string{"sha256:boundary", "sha256:cold", "sha256:stale"}
	if got := selected(plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("selected = %v, want %v", got, want)
	}
}

// Ranking must not depend on the order the store returned rows in.
func TestKeepLastNBreaksPushTimeTiesByDigest(t *testing.T) {
	t.Parallel()

	pushed := ago(time.Hour)
	forward := mustInventory(t,
		mf("sha256:a", pushed), mf("sha256:b", pushed), mf("sha256:c", pushed),
	)
	reversed := mustInventory(t,
		mf("sha256:c", pushed), mf("sha256:b", pushed), mf("sha256:a", pushed),
	)
	rules := mustRules(t, policy.Rule{Name: "keep-1", Kind: policy.KeepLastN, N: 1})

	first := selected(mustPlan(t, forward, rules))
	second := selected(mustPlan(t, reversed, rules))
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("ranking depends on input order: %v then %v", first, second)
	}
	if want := []string{"sha256:b", "sha256:c"}; !reflect.DeepEqual(first, want) {
		t.Fatalf("selected = %v, want %v (the lowest digest ranks first)", first, want)
	}
}

// Protection is not a slot in a keep-last-N budget. Ranking runs over the
// selectable set alone, so protected manifests do not consume the count -- the
// direction that keeps more, which is the only direction to be wrong in.
func TestKeepLastNRanksOverTheSelectableSetOnly(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		withProtected(mf("sha256:a", ago(1*time.Hour)), "release"),
		withProtected(mf("sha256:b", ago(2*time.Hour)), "pinned"),
		withTags(mf("sha256:c", ago(3*time.Hour)), "v3"),
		withTags(mf("sha256:d", ago(4*time.Hour)), "v2"),
		withTags(mf("sha256:e", ago(5*time.Hour)), "v1"),
	)
	plan := mustPlan(t, inv, mustRules(t, policy.Rule{Name: "keep-2", Kind: policy.KeepLastN, N: 2}))

	if got, want := selected(plan), []string{"sha256:e"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected = %v, want %v: the two protected manifests must not consume the budget", got, want)
	}
}

// Two rules of equal precedence that agree are not a conflict; the plan names
// them all, because "rule X selected this" is only half an answer when two
// rules did.
func TestEqualPrioritiesThatAgreeNameEveryRule(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t, mf("sha256:d", ago(4*time.Hour)))
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "zeta-sweep", Kind: policy.SelectMatched, Priority: 5},
		policy.Rule{Name: "alpha-reap", Kind: policy.SelectMatched, TagStatus: policy.Untagged, Priority: 5},
	))

	if len(plan.Selected) != 1 {
		t.Fatalf("selected %d manifests, want 1", len(plan.Selected))
	}
	entry := plan.Selected[0]
	if entry.Rule != "alpha-reap" {
		t.Fatalf("deciding rule = %q, want the first by name", entry.Rule)
	}
	if got, want := entry.AlsoSelectedBy, []string{"zeta-sweep"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AlsoSelectedBy = %v, want %v", got, want)
	}
	if entry.RuleKind != policy.SelectMatched || entry.Priority != 5 {
		t.Fatalf("entry does not carry the deciding rule's kind and priority: %+v", entry)
	}
}

func TestEqualPrioritiesThatAgreeToKeepNameEveryRule(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t, withTags(mf("sha256:a", ago(time.Hour)), "latest"))
	plan := mustPlan(t, inv, mustRules(t,
		policy.Rule{Name: "zeta-keep", Kind: policy.KeepLastN, N: 5, Priority: 2},
		policy.Rule{Name: "alpha-keep", Kind: policy.KeepNewerThan, Age: 24 * time.Hour, Priority: 2},
	))

	if len(plan.Kept) != 1 {
		t.Fatalf("kept %d manifests, want 1", len(plan.Kept))
	}
	kept := plan.Kept[0]
	if kept.Reason != policy.KeptByRule || kept.Rule != "alpha-keep" {
		t.Fatalf("kept entry = %+v, want kept by alpha-keep", kept)
	}
	if got, want := kept.AlsoKeptBy, []string{"zeta-keep"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AlsoKeptBy = %v, want %v", got, want)
	}
	if kept.RuleKind != policy.KeepNewerThan || kept.Priority != 2 {
		t.Fatalf("kept entry does not carry the deciding rule's kind and priority: %+v", kept)
	}
}

// The tie §7 refuses to break. Both sides are named, because the fix is to
// move one rule's priority and an operator cannot do that without knowing
// which two rules to move.
func TestEqualPrioritiesThatDisagreeAreAnError(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t,
		withTags(mf("sha256:a", ago(1*time.Hour)), "latest"),
		withTags(mf("sha256:b", ago(2*time.Hour)), "v2"),
	)
	_, err := policy.Evaluate(inv, mustRules(t,
		policy.Rule{Name: "sweep-everything", Kind: policy.SelectMatched, Priority: 3},
		policy.Rule{Name: "keep-a-week", Kind: policy.KeepNewerThan, Age: 7 * 24 * time.Hour, Priority: 3},
	), now)

	if !errors.Is(err, policy.ErrRuleConflict) {
		t.Fatalf("error %v is not ErrRuleConflict", err)
	}
	var typed *policy.ConflictError
	if !errors.As(err, &typed) {
		t.Fatalf("error %v is not a *ConflictError", err)
	}
	if len(typed.Conflicts) != 2 {
		t.Fatalf("reported %d conflicts, want 2 (one per disputed manifest)", len(typed.Conflicts))
	}
	first := typed.Conflicts[0]
	if first.Digest != "sha256:a" || first.Priority != 3 {
		t.Fatalf("conflict = %+v, want sha256:a at priority 3", first)
	}
	if got, want := first.Selecting, []string{"sweep-everything"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Selecting = %v, want %v", got, want)
	}
	if got, want := first.Keeping, []string{"keep-a-week"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Keeping = %v, want %v", got, want)
	}
	if !strings.Contains(err.Error(), "and 1 more") {
		t.Fatalf("error %q does not account for the second conflict", err)
	}
	if !strings.Contains(err.Error(), "sweep-everything") || !strings.Contains(err.Error(), "keep-a-week") {
		t.Fatalf("error %q does not name both rules", err)
	}
}

// A conflict fails the whole evaluation. A partial plan would be a plan an
// operator could apply without ever seeing the rules that disagree.
func TestAConflictProducesNoPlan(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t, withTags(mf("sha256:a", ago(time.Hour)), "latest"))
	plan, err := policy.Evaluate(inv, mustRules(t,
		policy.Rule{Name: "sweep", Kind: policy.SelectMatched},
		policy.Rule{Name: "keep", Kind: policy.KeepNewerThan, Age: time.Hour * 24},
	), now)

	if err == nil {
		t.Fatal("Evaluate succeeded on a tie")
	}
	if !reflect.DeepEqual(plan, policy.Plan{}) {
		t.Fatalf("Evaluate returned a plan alongside a conflict: %+v", plan)
	}
	if got, want := err.Error(), "retention rules conflict: sha256:a: priority 0: sweep would select it, keep would keep it"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

// A protected manifest cannot even be the subject of a conflict: no rule is
// ever shown it, so no two rules can disagree about it.
func TestProtectedManifestsCannotConflict(t *testing.T) {
	t.Parallel()

	inv := mustInventory(t, withProtected(mf("sha256:a", ago(time.Hour)), "release"))
	plan, err := policy.Evaluate(inv, mustRules(t,
		policy.Rule{Name: "sweep", Kind: policy.SelectMatched},
		policy.Rule{Name: "keep", Kind: policy.KeepNewerThan, Age: 24 * time.Hour},
	), now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !plan.Empty() || len(plan.Kept) != 1 {
		t.Fatalf("plan = %+v, want one kept manifest and nothing selected", plan)
	}
	if plan.Kept[0].Reason != policy.KeptNotSelectable {
		t.Fatalf("kept reason = %q, want %q", plan.Kept[0].Reason, policy.KeptNotSelectable)
	}
}

func TestEvaluateRefusesMissingArguments(t *testing.T) {
	t.Parallel()

	if _, err := policy.Evaluate(nil, policy.RuleSet{}, now); !errors.Is(err, policy.ErrNoInventory) {
		t.Fatalf("Evaluate(nil, ...) = %v, want ErrNoInventory", err)
	}

	inv := mustInventory(t, mf("sha256:a", ago(time.Hour)))
	// A zero clock reading is not a neutral one: every age would be measured
	// from the year one and keep-newer-than would keep nothing.
	if _, err := policy.Evaluate(inv, policy.RuleSet{}, time.Time{}); !errors.Is(err, policy.ErrNoEvaluationTime) {
		t.Fatalf("Evaluate with a zero time = %v, want ErrNoEvaluationTime", err)
	}
}

// The zero rule set is the rule set of a policy that configures no rules, and
// it answers the same way an empty CompileRules does.
func TestZeroRuleSetKeepsEverything(t *testing.T) {
	t.Parallel()

	inv := matrixInventory(t)
	zero := mustPlan(t, inv, policy.RuleSet{})
	empty := mustPlan(t, inv, mustRules(t))

	if !reflect.DeepEqual(zero, empty) {
		t.Fatalf("the zero rule set and an empty one disagree:\n%+v\n%+v", zero, empty)
	}
	if !zero.Empty() {
		t.Fatalf("a policy with no rules selected %v", selected(zero))
	}
	for digest, reason := range keptBy(zero) {
		if reason != policy.KeptNoRuleApplies {
			t.Fatalf("%s kept for %q, want %q", digest, reason, policy.KeptNoRuleApplies)
		}
	}
}

func TestRuleSetAccessors(t *testing.T) {
	t.Parallel()

	set := mustRules(t,
		policy.Rule{Name: "zeta", Kind: policy.SelectMatched},
		policy.Rule{Name: "alpha", Kind: policy.KeepLastN, N: 1},
	)
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	if got, want := set.Names(), []string{"alpha", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Names = %v, want %v (sorted)", got, want)
	}
	if got := (policy.RuleSet{}).Names(); len(got) != 0 {
		t.Fatalf("the zero rule set names %v", got)
	}
}

// CompileRules keeps its own copy of the pattern lists: a caller that keeps
// writing to the slice it handed in must not be able to change what a
// compiled policy means.
func TestCompileRulesCopiesPatternLists(t *testing.T) {
	t.Parallel()

	patterns := []string{"v1"}
	set := mustRules(t, policy.Rule{Name: "exact", Kind: policy.SelectMatched, IncludeTags: patterns})
	patterns[0] = "v2"

	inv := mustInventory(t,
		withTags(mf("sha256:a", ago(time.Hour)), "v1"),
		withTags(mf("sha256:b", ago(time.Hour)), "v2"),
	)
	if got, want := selected(mustPlan(t, inv, set)), []string{"sha256:a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected = %v, want %v", got, want)
	}
}

func TestKindAndStatusValidity(t *testing.T) {
	t.Parallel()

	for _, kind := range []policy.RuleKind{
		policy.SelectMatched, policy.KeepLastN, policy.KeepNewerThan, policy.KeepIfPulledSince,
	} {
		if !kind.Valid() {
			t.Fatalf("%q is not valid", kind)
		}
	}
	for _, kind := range []policy.RuleKind{"", "keep-lots"} {
		if kind.Valid() {
			t.Fatalf("%q is valid", kind)
		}
	}

	for _, status := range []policy.TagStatus{policy.AnyTags, policy.Tagged, policy.Untagged} {
		if !status.Valid() {
			t.Fatalf("%q is not valid", status)
		}
	}
	if policy.TagStatus("tagless").Valid() {
		t.Fatal("an unknown tag status is valid")
	}
}

func TestRuleAndConflictErrorMessages(t *testing.T) {
	t.Parallel()

	ruleErr := &policy.RuleError{Rule: "sweep", Field: "age", Reason: "must be positive"}
	if got, want := ruleErr.Error(), `invalid retention rule "sweep": age: must be positive`; got != want {
		t.Fatalf("Error = %q, want %q", got, want)
	}
	if errors.Is(ruleErr, policy.ErrRuleConflict) {
		t.Fatal("a RuleError matched ErrRuleConflict")
	}

	conflict := policy.Conflict{
		Digest: "sha256:a", Priority: 2,
		Selecting: []string{"sweep"}, Keeping: []string{"keep-a", "keep-b"},
	}
	if got, want := conflict.String(), "sha256:a: priority 2: sweep would select it, keep-a, keep-b would keep it"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	conflictErr := &policy.ConflictError{Conflicts: []policy.Conflict{conflict}}
	if !strings.HasPrefix(conflictErr.Error(), "retention rules conflict: sha256:a") {
		t.Fatalf("Error = %q", conflictErr.Error())
	}
	if errors.Is(conflictErr, policy.ErrInvalidRule) {
		t.Fatal("a ConflictError matched ErrInvalidRule")
	}
}

// Rules are ranked by priority and name, never by the order they were written
// in, so reordering a policy document cannot change a plan.
func TestPlanDoesNotDependOnRuleOrder(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{
		{Name: "keep-recent", Kind: policy.KeepNewerThan, Age: 150 * time.Minute, Priority: 1},
		{Name: "keep-tagged", Kind: policy.KeepLastN, N: 1, TagStatus: policy.Tagged, Priority: 4},
		{Name: "sweep", Kind: policy.SelectMatched, Priority: 9},
	}
	inv := matrixInventory(t)
	baseline := mustPlan(t, inv, mustRules(t, rules...))

	for _, permutation := range permutations(rules) {
		got := mustPlan(t, inv, mustRules(t, permutation...))
		if !reflect.DeepEqual(got, baseline) {
			t.Fatalf("permuting the rules changed the plan:\n%+v\n%+v", baseline, got)
		}
	}
}

// permutations returns every ordering of a small slice.
func permutations[T any](in []T) [][]T {
	if len(in) <= 1 {
		return [][]T{slices.Clone(in)}
	}
	var out [][]T
	for i := range in {
		rest := make([]T, 0, len(in)-1)
		rest = append(rest, in[:i]...)
		rest = append(rest, in[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]T{in[i]}, tail...))
		}
	}
	return out
}
