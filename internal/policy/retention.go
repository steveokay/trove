package policy

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// TagStatus is the tag-status filter of a retention rule: whether it is about
// tagged manifests, untagged ones, or makes no distinction.
type TagStatus string

// The three tag-status filters. The zero value is AnyTags, which is the
// widening default and therefore safe: a rule that forgot to say is about
// every manifest its other filters match, not about a set nobody intended.
const (
	// AnyTags places no constraint on tags. It is the zero value.
	AnyTags TagStatus = ""
	// Tagged selects manifests at least one tag points at.
	Tagged TagStatus = "tagged"
	// Untagged selects manifests no tag points at -- untagged reaping.
	//
	// It cannot reach an attachment: a manifest whose subject is still here is
	// attached rather than orphaned and is not in the selectable set at all
	// (ADR 0011), so an untagged rule structurally cannot select the SBOM,
	// signature, or scan result of a live image.
	Untagged TagStatus = "untagged"
)

// Valid reports whether s is a known tag-status filter.
func (s TagStatus) Valid() bool {
	switch s {
	case AnyTags, Tagged, Untagged:
		return true
	default:
		return false
	}
}

// RuleKind is what a rule keeps out of the manifests its filters match.
//
// Every kind is a *keep* condition; what a rule selects for deletion is the
// remainder of its filtered set. That is the direction retention has to be
// written in: an operator states what must survive, and deletion is what is
// left over, so a filter that matches more than intended keeps more than
// intended rather than deleting more.
type RuleKind string

// The four rule kinds. There is deliberately no zero value among them: an
// unset kind is a rule that was half-built, and the safe reading of half-built
// is refusal, not "select everything the filter matched".
const (
	// SelectMatched keeps nothing: every manifest the rule's filters match is
	// selected. It is what "delete every untagged manifest" is written with,
	// and it is the one kind whose blast radius is entirely in its filters.
	SelectMatched RuleKind = "select-matched"
	// KeepLastN keeps the N most recently pushed of the matched manifests and
	// selects the rest.
	KeepLastN RuleKind = "keep-last-n"
	// KeepNewerThan keeps manifests pushed within Age of the evaluation time.
	KeepNewerThan RuleKind = "keep-newer-than"
	// KeepIfPulledSince keeps manifests pulled within Age of the evaluation
	// time.
	KeepIfPulledSince RuleKind = "keep-if-pulled-since"
)

// Valid reports whether k is a known rule kind.
func (k RuleKind) Valid() bool {
	switch k {
	case SelectMatched, KeepLastN, KeepNewerThan, KeepIfPulledSince:
		return true
	default:
		return false
	}
}

// ErrInvalidRule reports a rule CompileRules refuses. Callers assert with
// errors.Is.
var ErrInvalidRule = errors.New("invalid retention rule")

// ErrRuleConflict reports two rules of equal priority that disagree about the
// same manifest. Callers assert with errors.Is.
var ErrRuleConflict = errors.New("retention rules conflict")

// RuleError names the rule that would not compile, the field at fault, and
// why.
type RuleError struct {
	// Rule is the rule's name, or its position when the name is what is wrong.
	Rule string
	// Field is the field at fault.
	Field string
	// Reason says what was wrong with it.
	Reason string
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("invalid retention rule %q: %s: %s", e.Rule, e.Field, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidRule) true for this typed error.
func (e *RuleError) Is(target error) bool { return target == ErrInvalidRule }

func ruleErr(rule, field, format string, args ...any) error {
	return &RuleError{Rule: rule, Field: field, Reason: fmt.Sprintf(format, args...)}
}

// Rule is one retention rule: which manifests it is about, what it keeps of
// them, and how it ranks against the rules that disagree.
//
// A rule is a filter plus a keep condition. The filter -- tag status, tag
// include and exclude patterns -- decides which manifests the rule has an
// opinion about at all; the kind decides which of those it saves. Everything
// the filter matched and the kind did not save is selected for deletion by
// this rule.
type Rule struct {
	// Name identifies the rule. It is required and must be unique in a rule
	// set, because it is what a plan entry names when an operator asks why a
	// manifest is on the list, and what a conflict error names when two rules
	// disagree.
	Name string
	// Priority orders rules against each other. **Lower wins**, following ECR
	// lifecycle policies, the prior art this feature is measured against
	// (§12). The highest-precedence rules that have an opinion about a
	// manifest decide it; rules at any lower precedence are not consulted.
	//
	// Rules may share a priority as long as they agree. Two that share one and
	// disagree are an error, not a coin flip (§7).
	Priority int
	// Kind is the keep condition. Required.
	Kind RuleKind
	// N is how many to keep, for KeepLastN. Zero is legal and means keep none
	// of the matched manifests -- the sweep an operator writes deliberately.
	N int
	// Age is the window to keep within, for KeepNewerThan and
	// KeepIfPulledSince. It must be positive: a zero window keeps nothing,
	// which is SelectMatched wearing a disguise, and a negative one keeps
	// nothing while reading as though it keeps something.
	Age time.Duration
	// TagStatus filters on whether the manifest is tagged. The zero value
	// places no constraint.
	TagStatus TagStatus
	// IncludeTags are regular expressions; the rule is about a manifest when
	// any of its tags matches any of them. An empty list places no constraint.
	//
	// Patterns are anchored: they must match a whole tag name, so `v1` is
	// about `v1` and not about `v1.2` or `dev-v1`. An unanchored reading is
	// the one that quietly matches more than the operator wrote, and this rule
	// set decides what gets deleted.
	//
	// An untagged manifest matches no pattern and so is never about a rule
	// that lists any: tag patterns cannot reap untagged content, which needs
	// the untagged tag-status filter said out loud.
	IncludeTags []string
	// ExcludeTags are regular expressions, anchored the same way; the rule is
	// not about a manifest when any of its tags matches any of them. Exclusion
	// is checked before inclusion, so a tag named by both is excluded -- an
	// operator who writes both means the narrower, refusing one.
	ExcludeTags []string
}

// compiledRule is a rule with its patterns parsed once.
type compiledRule struct {
	Rule
	include []*regexp.Regexp
	exclude []*regexp.Regexp
}

// RuleSet is a compiled, validated set of retention rules.
//
// The zero value is the rule set of a policy that configures no rules: it has
// an opinion about nothing, so evaluating it produces a plan that deletes
// nothing and says of every manifest that no rule applies. That is the correct
// reading of an empty policy and the same answer CompileRules with no
// arguments gives.
type RuleSet struct {
	rules []compiledRule
}

// CompileRules validates a rule set and parses its patterns once, so that
// evaluating it is matching rather than parsing.
//
// It refuses a rule that cannot mean what it says: no name, a duplicate name,
// an unknown kind, a field the kind ignores, a non-positive age, a negative
// count, an unparseable or empty pattern. A rule set is the input to the one
// destructive operation trove performs, and a rule that silently never fires
// is a rule an operator believes is protecting something.
func CompileRules(rules ...Rule) (RuleSet, error) {
	set := RuleSet{rules: make([]compiledRule, 0, len(rules))}
	names := make(map[string]struct{}, len(rules))

	for position, rule := range rules {
		label := rule.Name
		if label == "" {
			return RuleSet{}, ruleErr(fmt.Sprintf("#%d", position), "name", "a rule must be named: the name is what a plan entry cites")
		}
		if _, duplicate := names[rule.Name]; duplicate {
			return RuleSet{}, ruleErr(label, "name", "already used: rule names must be unique")
		}
		names[rule.Name] = struct{}{}

		if !rule.Kind.Valid() {
			return RuleSet{}, ruleErr(label, "kind", "unknown rule kind %q", rule.Kind)
		}
		if !rule.TagStatus.Valid() {
			return RuleSet{}, ruleErr(label, "tag_status", "unknown tag status %q", rule.TagStatus)
		}

		if err := validateKindFields(rule); err != nil {
			return RuleSet{}, err
		}

		compiled := compiledRule{Rule: rule}
		var err error
		if compiled.include, err = compilePatterns(label, "include_tags", rule.IncludeTags); err != nil {
			return RuleSet{}, err
		}
		if compiled.exclude, err = compilePatterns(label, "exclude_tags", rule.ExcludeTags); err != nil {
			return RuleSet{}, err
		}
		compiled.Rule.IncludeTags = slices.Clone(rule.IncludeTags)
		compiled.Rule.ExcludeTags = slices.Clone(rule.ExcludeTags)

		set.rules = append(set.rules, compiled)
	}
	return set, nil
}

// validateKindFields refuses a rule carrying a value its kind does not read.
//
// A keep-last-N rule with an Age is not a rule with a harmless extra field: it
// is an operator who believes there is an age condition on it. Refusing is how
// they find out at write time rather than from a plan that deleted more than
// they expected.
func validateKindFields(rule Rule) error {
	switch rule.Kind {
	case KeepLastN:
		if rule.N < 0 {
			return ruleErr(rule.Name, "n", "must not be negative")
		}
		if rule.Age != 0 {
			return ruleErr(rule.Name, "age", "%s does not read an age", rule.Kind)
		}
	case KeepNewerThan, KeepIfPulledSince:
		if rule.Age <= 0 {
			return ruleErr(rule.Name, "age", "must be positive: a zero or negative window keeps nothing")
		}
		if rule.N != 0 {
			return ruleErr(rule.Name, "n", "%s does not read a count", rule.Kind)
		}
	default: // SelectMatched -- the kind was validated by the caller.
		if rule.N != 0 {
			return ruleErr(rule.Name, "n", "%s does not read a count", rule.Kind)
		}
		if rule.Age != 0 {
			return ruleErr(rule.Name, "age", "%s does not read an age", rule.Kind)
		}
	}
	return nil
}

// compilePatterns anchors and compiles a tag pattern list.
//
// Go's regexp is RE2: a pattern cannot backtrack catastrophically, so an
// operator-supplied expression is a correctness question rather than a
// denial-of-service one. What is left to guard is meaning, which is what the
// anchoring and the empty-pattern refusal do.
func compilePatterns(rule, field string, patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern == "" {
			return nil, ruleErr(rule, field, "an empty pattern matches no tag name and would never fire")
		}
		re, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
		if err != nil {
			return nil, ruleErr(rule, field, "pattern %q does not compile: %v", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// Len is how many rules the set holds.
func (s RuleSet) Len() int { return len(s.rules) }

// Names returns the rule names, sorted. It exists so an API or a UI can report
// what a policy contains without holding the rules themselves.
func (s RuleSet) Names() []string {
	names := make([]string, 0, len(s.rules))
	for _, rule := range s.rules {
		names = append(names, rule.Name)
	}
	slices.Sort(names)
	return names
}

// matches reports whether the rule has an opinion about a manifest at all.
func (r compiledRule) matches(m Manifest) bool {
	switch r.TagStatus {
	case Tagged:
		if m.Status() != Tagged {
			return false
		}
	case Untagged:
		if m.Status() != Untagged {
			return false
		}
	case AnyTags:
	}

	for _, tag := range m.Tags {
		for _, re := range r.exclude {
			if re.MatchString(tag.Name) {
				return false
			}
		}
	}
	if len(r.include) == 0 {
		return true
	}
	for _, tag := range m.Tags {
		for _, re := range r.include {
			if re.MatchString(tag.Name) {
				return true
			}
		}
	}
	return false
}

// keeps returns the digests the rule saves out of the manifests it matched.
//
// matched arrives in digest order and is not reordered: ranking sorts a copy,
// because a rule that reorders the set the next rule sees is a rule set whose
// answer depends on the order it was written in.
func (r compiledRule) keeps(matched []Manifest, now time.Time) map[Digest]struct{} {
	kept := make(map[Digest]struct{})
	switch r.Kind {
	case KeepLastN:
		// Newest first, ties broken by digest so that two manifests pushed in
		// the same clock tick rank in a fixed order rather than in whatever
		// order the store returned them.
		ranked := slices.Clone(matched)
		slices.SortFunc(ranked, func(a, b Manifest) int {
			if c := b.PushedAt.Compare(a.PushedAt); c != 0 {
				return c
			}
			return cmp.Compare(a.Digest, b.Digest)
		})
		for index, m := range ranked {
			if index >= r.N {
				break
			}
			kept[m.Digest] = struct{}{}
		}
	case KeepNewerThan:
		cutoff := now.Add(-r.Age)
		for _, m := range matched {
			if m.PushedAt.After(cutoff) {
				kept[m.Digest] = struct{}{}
			}
		}
	case KeepIfPulledSince:
		cutoff := now.Add(-r.Age)
		for _, m := range matched {
			// Never pulled falls back to the push time, so a manifest pushed
			// this morning is not swept for want of a pull that has not had
			// time to happen. It is the push, not the absence of a pull, that
			// is the newest thing known about it.
			reference := m.LastPulledAt
			if reference.IsZero() {
				reference = m.PushedAt
			}
			if reference.After(cutoff) {
				kept[m.Digest] = struct{}{}
			}
		}
	case SelectMatched:
		// Keeps nothing by construction.
	}
	return kept
}

// Conflict is one manifest two rules of equal priority disagree about.
type Conflict struct {
	// Digest is the manifest in dispute.
	Digest Digest
	// Priority is the precedence the disagreeing rules share.
	Priority int
	// Selecting names the rules that would delete it, sorted.
	Selecting []string
	// Keeping names the rules that would save it, sorted.
	Keeping []string
}

// String renders a conflict the way the error and the API report it.
func (c Conflict) String() string {
	return fmt.Sprintf("%s: priority %d: %s would select it, %s would keep it",
		c.Digest, c.Priority, strings.Join(c.Selecting, ", "), strings.Join(c.Keeping, ", "))
}

// ConflictError reports every manifest whose fate two equal-priority rules
// disagree about.
//
// Evaluation fails whole rather than deciding: §7 says a tie is an error and
// not a coin flip, and the reason is that the alternative -- picking one --
// makes a plan that deletes an image depend on which rule happened to be
// written first. An operator resolves it by moving one rule's priority, which
// is why both sides are named.
type ConflictError struct {
	// Conflicts are the disputed manifests, in digest order.
	Conflicts []Conflict
}

func (e *ConflictError) Error() string {
	if len(e.Conflicts) == 1 {
		return fmt.Sprintf("retention rules conflict: %s", e.Conflicts[0])
	}
	return fmt.Sprintf("retention rules conflict on %d manifests: %s (and %d more)",
		len(e.Conflicts), e.Conflicts[0], len(e.Conflicts)-1)
}

// Is makes errors.Is(err, ErrRuleConflict) true for this typed error.
func (e *ConflictError) Is(target error) bool { return target == ErrRuleConflict }

// opinion is one rule's verdict on one manifest.
type opinion struct {
	rule     string
	priority int
	kind     RuleKind
	keep     bool
}

// Evaluate produces the retention plan for a repository: the manifests the
// rules select for deletion, what each selection cascades to, and what
// survives and why.
//
// It is a pure function of its three arguments -- ADR 0010's
// `Evaluate(inventory, rules, now) → Plan`. It reads no store, opens no file,
// takes no clock and holds no lock. That is not an aesthetic preference: this
// is the function whose output an operator approves before blobs that cannot
// be re-fetched are deleted, and a function that can read state can disagree
// with the snapshot it was handed, which means approving its output stops
// meaning anything.
//
// # How rules combine
//
// Every rule whose filters match a manifest has an opinion about it: keep, or
// select. The opinions at the strongest precedence -- the numerically lowest
// Priority -- decide, and lower-precedence rules are not consulted at all.
// Opinions at that precedence that disagree are a ConflictError and no plan;
// opinions that agree name the deciding rule by sorted name, so that
// reordering a policy's rules can never change a plan.
//
// A manifest no rule has an opinion about is kept. Absence of a rule never
// deletes.
//
// # What it cannot do
//
// It can only ever select from the inventory's selectable set, which excludes
// protected tags, immutable tags, children of live indexes, and referrers of
// live subjects before any rule runs. There is no rule, priority, or count
// that reaches past that (ADR 0010 layer 1).
//
// The cascade is the one path by which a plan deletes a manifest no rule
// selected, so protection is re-checked along it: a selection whose referrer
// subtree contains a manifest that is protected in its own right is reported
// as blocked rather than deleted, and the selection fails closed with it.
func Evaluate(inv *Inventory, rules RuleSet, now time.Time) (Plan, error) {
	if inv == nil {
		return Plan{}, ErrNoInventory
	}
	if now.IsZero() {
		return Plan{}, ErrNoEvaluationTime
	}

	opinions := make(map[Digest][]opinion, len(inv.selectable))
	for _, rule := range rules.rules {
		matched := make([]Manifest, 0, len(inv.selectable))
		for _, m := range inv.selectable {
			if rule.matches(m) {
				matched = append(matched, m)
			}
		}
		kept := rule.keeps(matched, now)
		for _, m := range matched {
			_, keep := kept[m.Digest]
			opinions[m.Digest] = append(opinions[m.Digest], opinion{
				rule:     rule.Name,
				priority: rule.Priority,
				kind:     rule.Kind,
				keep:     keep,
			})
		}
	}

	verdicts := make(map[Digest]verdict, len(inv.selectable))
	var conflicts []Conflict
	for _, m := range inv.selectable {
		decided, conflict := resolve(m.Digest, opinions[m.Digest])
		if conflict != nil {
			conflicts = append(conflicts, *conflict)
			continue
		}
		verdicts[m.Digest] = decided
	}
	if len(conflicts) > 0 {
		return Plan{}, &ConflictError{Conflicts: conflicts}
	}

	return buildPlan(inv, verdicts, now), nil
}

// verdict is what the winning precedence tier decided about one manifest.
type verdict struct {
	// applicable is false when no rule had an opinion at all.
	applicable bool
	keep       bool
	rule       string
	kind       RuleKind
	priority   int
	// agreeing names the other rules at the deciding precedence that said the
	// same thing, sorted. It is what turns "rule X selected this" into the
	// whole answer when several rules agree.
	agreeing []string
}

// resolve reduces one manifest's opinions to a verdict, or to the conflict
// that stops the evaluation.
func resolve(digest Digest, opinions []opinion) (verdict, *Conflict) {
	if len(opinions) == 0 {
		return verdict{}, nil
	}

	best := opinions[0].priority
	for _, o := range opinions[1:] {
		if o.priority < best {
			best = o.priority
		}
	}

	var selecting, keeping []string
	kinds := make(map[string]RuleKind, len(opinions))
	for _, o := range opinions {
		if o.priority != best {
			continue
		}
		kinds[o.rule] = o.kind
		if o.keep {
			keeping = append(keeping, o.rule)
			continue
		}
		selecting = append(selecting, o.rule)
	}
	slices.Sort(selecting)
	slices.Sort(keeping)

	if len(selecting) > 0 && len(keeping) > 0 {
		return verdict{}, &Conflict{
			Digest:    digest,
			Priority:  best,
			Selecting: selecting,
			Keeping:   keeping,
		}
	}

	deciders := selecting
	keep := false
	if len(keeping) > 0 {
		deciders = keeping
		keep = true
	}
	// The deciding rule is the first by name, not the first in the configured
	// order: names are unique and stable, so a plan does not change because
	// somebody reordered the policy document. Positions decide nothing here,
	// exactly as they decide nothing in a group's member list.
	var agreeing []string
	if len(deciders) > 1 {
		agreeing = slices.Clone(deciders[1:])
	}
	return verdict{
		applicable: true,
		keep:       keep,
		rule:       deciders[0],
		kind:       kinds[deciders[0]],
		priority:   best,
		agreeing:   agreeing,
	}, nil
}
