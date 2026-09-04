package repo

import (
	"fmt"

	"github.com/steveokay/trove/internal/authz"
)

// RoutingReason names what decided a routing question. It is carried on every
// decision because an operator staring at a blocked pull needs to know which
// rule blocked it, and "denied" on its own sends them reading configuration
// they have already read.
type RoutingReason string

// The four things that can decide a routing question, in precedence order.
const (
	// RoutedByBlock: an explicit block pattern matched. Block beats an allow
	// that also matched -- an operator who writes both means the narrower,
	// refusing one.
	RoutedByBlock RoutingReason = "blocked by rule"
	// RoutedByAllow: an explicit allow pattern matched and no block did.
	RoutedByAllow RoutingReason = "allowed by rule"
	// RoutedByDefaultAllow: no rule matched and the proxy is not default-deny.
	RoutedByDefaultAllow RoutingReason = "allowed by default"
	// RoutedByDefaultDeny: no allow rule matched and the proxy is
	// default-deny, which is what turns it from an open relay over one
	// upstream into an allowlist (C-010).
	RoutedByDefaultDeny RoutingReason = "denied by default"
)

// RoutingDecision is the outcome of evaluating a proxy's routing rules against
// one remainder, together with the reason for it.
//
// The reason is not a diagnostic bolted on afterwards: it is the same value the
// UI renders on the repository screen and the audit record carries, so what an
// operator is told and what actually decided cannot drift apart.
type RoutingDecision struct {
	// Allowed is the answer. It is true exactly when Reason is
	// RoutedByAllow or RoutedByDefaultAllow.
	Allowed bool
	// Reason is which of the four rules in the precedence order decided.
	Reason RoutingReason
	// Pattern is the rule that matched, for RoutedByBlock and RoutedByAllow.
	// It is empty for the two defaults, where nothing matched.
	Pattern authz.Scope
	// Remainder is what was evaluated, carried so a log line or an event can
	// be built from the decision alone.
	Remainder string
}

// String renders a decision the way a log line and the UI report it.
func (d RoutingDecision) String() string {
	verdict := "denied"
	if d.Allowed {
		verdict = "allowed"
	}
	if d.Pattern == "" {
		return fmt.Sprintf("%s %q: %s", verdict, d.Remainder, d.Reason)
	}
	return fmt.Sprintf("%s %q: %s %s", verdict, d.Remainder, d.Reason, d.Pattern)
}

// RoutingRules is a proxy's compiled allow/block rule set (C-010, ADR 0005).
//
// Patterns are binding scopes -- the ADR 0001 grammar, parsed once here and
// matched many times. A proxy restricted to `library/*` and a role scoped to
// `library/*` mean the same thing because the same code answers both: one
// grammar, one fuzzer. Regex routing rules were rejected in ADR 0005 for
// exactly this reason.
//
// The zero value is the rule set of a proxy that configures no rules: nothing
// blocked, nothing explicitly allowed, default allow. That is deliberately the
// same behaviour as CompileRoutingRules on a configuration with no rules --
// inventing a fifth "never compiled" state would make an honest configuration
// and a dropped one behave differently, and the dropped one is the state a test
// would have to construct on purpose to ever reach.
type RoutingRules struct {
	allow       []authz.Scope
	block       []authz.Scope
	defaultDeny bool
}

// CompileRoutingRules parses a proxy configuration's routing patterns once, so
// that evaluating them on the pull path is matching rather than parsing.
//
// It validates rather than trusting: ProxyConfig.Validate has already refused
// an unparseable pattern at write time, but a rule set is a security control
// and the component that enforces it should not be the one component that
// assumes somebody else checked. A pattern outside the grammar is refused with
// an ErrInvalidConfig-shaped error naming the field.
func CompileRoutingRules(cfg ProxyConfig) (RoutingRules, error) {
	rules := RoutingRules{defaultDeny: cfg.DefaultDeny}

	for _, field := range []struct {
		name     string
		patterns []string
		into     *[]authz.Scope
	}{
		{"allow", cfg.Allow, &rules.allow},
		{"block", cfg.Block, &rules.block},
	} {
		for _, pattern := range field.patterns {
			scope, err := authz.ParseScope(pattern)
			if err != nil {
				return RoutingRules{}, configErr(field.name, err.Error())
			}
			// The system scope is the global, non-repository scope: it matches
			// no repository and so would be a rule that silently never fires.
			// A routing rule that can never decide anything is a mistake, not
			// a no-op.
			if scope == authz.SystemScope {
				return RoutingRules{}, configErr(field.name, "system is a binding scope, not a routing pattern")
			}
			*field.into = append(*field.into, scope)
		}
	}
	return rules, nil
}

// DefaultDeny reports whether the rule set refuses what no allow pattern
// matched. It exists so the admin API and the UI can show the posture of a
// proxy without holding on to the configuration the rules were compiled from.
func (r RoutingRules) DefaultDeny() bool { return r.defaultDeny }

// Evaluate decides whether this proxy may serve a remainder.
//
// The remainder is the part of an OCI repository name after the entity prefix
// -- what Split returns -- as the client asked for it. `mirror/library/nginx`
// on a proxy mounted at `mirror` evaluates `library/nginx`, which is why a
// Docker Hub proxy restricted to the official images is the single rule
// `library/*`.
//
// Precedence is exactly: an explicit block, then an explicit allow, then the
// default -- allow, or deny when the configuration sets default_deny. Within a
// list the first pattern in configured order is the one named, so the decision
// is a function of the rule set and the remainder and of nothing else.
//
// It refuses a remainder that is not a legal repository name rather than
// evaluating it. The router validated the name before it got here, and a
// routing evaluator is the wrong place to be the component that assumed so: a
// traversal sequence must not be able to reach the upstream URL builder by
// matching no rule and falling through to the default allow. An empty
// remainder -- a request naming the proxy entity itself and nothing inside it
// -- is refused by the same check, because there is no upstream repository for
// it to mean.
//
// Callers pass the **rewritten upstream path**, not the remainder as the
// client wrote it. Both readings are expressible -- this evaluates whatever
// string it is given -- and the choice was settled by what the rules are for.
// They exist so a proxy cannot become an open relay (§4), which is a statement
// about what we fetch from the upstream, and they must satisfy C-010's own
// acceptance criterion: a Docker Hub proxy restricted to official images in
// one rule. With a DefaultNamespace rewriting `nginx` to `library/nginx`, only
// the rewritten path makes `library/*` admit `nginx` -- ruling on the raw
// remainder would deny the single most common pull on the preset the criterion
// names, which is the reading being wrong out loud.
//
// C-004 and C-014 pass the rewritten path accordingly; the rewrite happens
// before this call, and both strings are legal repository names, so nothing
// about the validation below changes.
func (r RoutingRules) Evaluate(remainder string) (RoutingDecision, error) {
	// Repository both validates the name and produces the value the scope
	// grammar matches against, so the check that closes traversal and the
	// check that decides are the same check.
	resource, err := authz.Repository(remainder)
	if err != nil {
		return RoutingDecision{}, err
	}

	// A remainder under `system/` cannot be named by a rule: the shared
	// grammar reserves that prefix so a binding written `admin@system/*` can
	// never almost-match. Such a remainder is still covered by `*` and by the
	// default, so it is decidable -- just not nameable.
	for _, pattern := range r.block {
		if pattern.Matches(resource) {
			return RoutingDecision{Reason: RoutedByBlock, Pattern: pattern, Remainder: remainder}, nil
		}
	}
	for _, pattern := range r.allow {
		if pattern.Matches(resource) {
			return RoutingDecision{Allowed: true, Reason: RoutedByAllow, Pattern: pattern, Remainder: remainder}, nil
		}
	}
	if r.defaultDeny {
		return RoutingDecision{Reason: RoutedByDefaultDeny, Remainder: remainder}, nil
	}
	return RoutingDecision{Allowed: true, Reason: RoutedByDefaultAllow, Remainder: remainder}, nil
}
