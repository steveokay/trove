package repo_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/repo"
	"github.com/steveokay/trove/internal/reponame"
)

// upstream is the one field every ProxyConfig in this file needs and none of
// them is about.
const upstream = "https://registry-1.docker.io"

func proxyRules(t *testing.T, cfg repo.ProxyConfig) repo.RoutingRules {
	t.Helper()
	cfg.Upstream = upstream
	rules, err := repo.CompileRoutingRules(cfg)
	if err != nil {
		t.Fatalf("CompileRoutingRules(%+v): %v", cfg, err)
	}
	return rules
}

// Compilation is where a rule set is refused, so this is the test that proves
// no unparseable pattern reaches the pull path -- including the ones that look
// like they would work.
func TestCompileRoutingRules(t *testing.T) {
	t.Parallel()

	t.Run("accepts the grammar", func(t *testing.T) {
		t.Parallel()
		cfg := repo.ProxyConfig{
			Upstream: upstream,
			Allow:    []string{"library/*", "library/nginx", "*"},
			Block:    []string{"library/secret", "internal/*"},
		}
		if _, err := repo.CompileRoutingRules(cfg); err != nil {
			t.Fatalf("CompileRoutingRules: %v", err)
		}
	})

	tests := []struct {
		name string
		cfg  repo.ProxyConfig
	}{
		{"mid-pattern wildcard in allow", repo.ProxyConfig{Allow: []string{"team-*/api"}}},
		{"multi wildcard in block", repo.ProxyConfig{Block: []string{"*/*"}}},
		{"traversal in allow", repo.ProxyConfig{Allow: []string{"../etc/passwd"}}},
		{"traversal past a prefix", repo.ProxyConfig{Block: []string{"library/../secret"}}},
		{"empty pattern", repo.ProxyConfig{Allow: []string{""}}},
		{"uppercase", repo.ProxyConfig{Allow: []string{"Library/*"}}},
		{"tag in a pattern", repo.ProxyConfig{Block: []string{"library/nginx:latest"}}},
		// The global scope matches no repository, so as a routing rule it
		// would be a line of configuration that can never fire. Refused
		// rather than accepted as a no-op.
		{"system scope as an allow rule", repo.ProxyConfig{Allow: []string{"system"}}},
		{"system scope as a block rule", repo.ProxyConfig{Block: []string{"system"}}},
		{"system prefix", repo.ProxyConfig{Allow: []string{"system/*"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.cfg.Upstream = upstream
			rules, err := repo.CompileRoutingRules(tt.cfg)
			if err == nil {
				t.Fatalf("CompileRoutingRules(%+v) = %+v, want a refusal", tt.cfg, rules)
			}
			if !errors.Is(err, repo.ErrInvalidConfig) {
				t.Errorf("error %v is not repo.ErrInvalidConfig", err)
			}
		})
	}
}

// The precedence table: explicit block beats explicit allow beats the default,
// and the default is allow unless the proxy is default-deny.
func TestRoutingRulesEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       repo.ProxyConfig
		remainder string
		allowed   bool
		reason    repo.RoutingReason
		pattern   authz.Scope
	}{
		// No rules at all: the proxy relays everything under its one upstream,
		// which is the documented default.
		{
			name: "no rules, default allow", remainder: "library/nginx",
			allowed: true, reason: repo.RoutedByDefaultAllow,
		},
		{
			name: "no rules, default deny admits nothing",
			cfg:  repo.ProxyConfig{DefaultDeny: true}, remainder: "library/nginx",
			allowed: false, reason: repo.RoutedByDefaultDeny,
		},

		// C-010's stated acceptance criterion: a Docker Hub proxy restricted
		// to the official images is one rule.
		{
			name:      "library/* only, official image",
			cfg:       repo.ProxyConfig{Allow: []string{"library/*"}, DefaultDeny: true},
			remainder: "library/nginx",
			allowed:   true, reason: repo.RoutedByAllow, pattern: "library/*",
		},
		{
			name:      "library/* only, someone else's image",
			cfg:       repo.ProxyConfig{Allow: []string{"library/*"}, DefaultDeny: true},
			remainder: "bitnami/nginx",
			allowed:   false, reason: repo.RoutedByDefaultDeny,
		},
		{
			// "library/*" covers what is under library, not the repository
			// named library itself -- the same reading the binding grammar
			// gives, which is the point of sharing it.
			name:      "library/* does not cover library itself",
			cfg:       repo.ProxyConfig{Allow: []string{"library/*"}, DefaultDeny: true},
			remainder: "library",
			allowed:   false, reason: repo.RoutedByDefaultDeny,
		},
		{
			name:      "library/* covers any depth beneath it",
			cfg:       repo.ProxyConfig{Allow: []string{"library/*"}, DefaultDeny: true},
			remainder: "library/team/nginx",
			allowed:   true, reason: repo.RoutedByAllow, pattern: "library/*",
		},

		// Overlaps. The narrower, refusing rule is what an operator who wrote
		// both meant.
		{
			name: "block beats an overlapping allow",
			cfg: repo.ProxyConfig{
				Allow: []string{"library/*"},
				Block: []string{"library/secret"},
			},
			remainder: "library/secret",
			allowed:   false, reason: repo.RoutedByBlock, pattern: "library/secret",
		},
		{
			name: "block beats a wildcard allow",
			cfg: repo.ProxyConfig{
				Allow: []string{"*"},
				Block: []string{"internal/*"},
			},
			remainder: "internal/api",
			allowed:   false, reason: repo.RoutedByBlock, pattern: "internal/*",
		},
		{
			name: "a wildcard block still leaves the exact allow unreachable",
			cfg: repo.ProxyConfig{
				Allow: []string{"library/nginx"},
				Block: []string{"library/*"},
			},
			remainder: "library/nginx",
			allowed:   false, reason: repo.RoutedByBlock, pattern: "library/*",
		},
		{
			name: "a non-overlapping block leaves the allow standing",
			cfg: repo.ProxyConfig{
				Allow: []string{"library/*"},
				Block: []string{"internal/*"},
			},
			remainder: "library/nginx",
			allowed:   true, reason: repo.RoutedByAllow, pattern: "library/*",
		},
		{
			// The first pattern in configured order is the one named, so the
			// explanation an operator gets is stable.
			name: "the first matching allow is the one named",
			cfg: repo.ProxyConfig{
				Allow: []string{"*", "library/*"}, DefaultDeny: true,
			},
			remainder: "library/nginx",
			allowed:   true, reason: repo.RoutedByAllow, pattern: "*",
		},
		{
			name: "the first matching block is the one named",
			cfg: repo.ProxyConfig{
				Block: []string{"library/*", "library/nginx"},
			},
			remainder: "library/nginx",
			allowed:   false, reason: repo.RoutedByBlock, pattern: "library/*",
		},

		// Block with the default left at allow: an allowlist proxy with a
		// hole punched in it.
		{
			name:      "block only, everything else is allowed by default",
			cfg:       repo.ProxyConfig{Block: []string{"internal/*"}},
			remainder: "library/nginx",
			allowed:   true, reason: repo.RoutedByDefaultAllow,
		},
		{
			// A rule set with allow patterns but no default_deny is not an
			// allowlist: what no rule matched still gets through. This is the
			// misconfiguration operators make, and the decision says so.
			name:      "allow rules without default_deny are not an allowlist",
			cfg:       repo.ProxyConfig{Allow: []string{"library/*"}},
			remainder: "bitnami/nginx",
			allowed:   true, reason: repo.RoutedByDefaultAllow,
		},

		// A remainder under system/ cannot be named by a rule -- the shared
		// grammar reserves the prefix -- but it is still decidable.
		{
			name:      "reserved-prefix remainder falls to the default",
			cfg:       repo.ProxyConfig{Allow: []string{"library/*"}, DefaultDeny: true},
			remainder: "system/api",
			allowed:   false, reason: repo.RoutedByDefaultDeny,
		},
		{
			name:      "reserved-prefix remainder is covered by a wildcard",
			cfg:       repo.ProxyConfig{Allow: []string{"*"}, DefaultDeny: true},
			remainder: "system/api",
			allowed:   true, reason: repo.RoutedByAllow, pattern: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules := proxyRules(t, tt.cfg)
			got, err := rules.Evaluate(tt.remainder)
			if err != nil {
				t.Fatalf("Evaluate(%q): %v", tt.remainder, err)
			}
			if got.Allowed != tt.allowed || got.Reason != tt.reason || got.Pattern != tt.pattern {
				t.Errorf("Evaluate(%q) = %+v, want allowed=%v reason=%q pattern=%q",
					tt.remainder, got, tt.allowed, tt.reason, tt.pattern)
			}
			if got.Remainder != tt.remainder {
				t.Errorf("decision carries remainder %q, want %q", got.Remainder, tt.remainder)
			}
			// The rendering is what the UI and the audit record show, so it
			// has to name the rule when there was one.
			if rendered := got.String(); !strings.Contains(rendered, string(tt.reason)) {
				t.Errorf("String() = %q, does not name the reason %q", rendered, tt.reason)
			}
			if tt.pattern != "" && !strings.Contains(got.String(), tt.pattern.String()) {
				t.Errorf("String() = %q, does not name the pattern %q", got.String(), tt.pattern)
			}
		})
	}
}

// A routing evaluator must not be the component that assumes the router already
// validated the name. Falling through to the default allow with a traversal
// sequence in hand is how a rule set that looks like an allowlist becomes a
// path into the upstream URL builder.
func TestRoutingRulesEvaluateRefusesIllegalRemainders(t *testing.T) {
	t.Parallel()

	// Both defaults, because a remainder that no rule matches under
	// default-allow is exactly the one that would slip through.
	for _, defaultDeny := range []bool{false, true} {
		rules := proxyRules(t, repo.ProxyConfig{Allow: []string{"library/*"}, DefaultDeny: defaultDeny})
		for _, remainder := range []string{
			"",
			"..",
			"library/../secret",
			"../etc/passwd",
			"/library/nginx",
			"library/nginx/",
			"library//nginx",
			"Library/nginx",
			"library/nginx:latest",
			"library/nginx@sha256:0000",
			"library\x00nginx",
			"library/*",
			strings.Repeat("a", reponame.MaxLength+1),
		} {
			got, err := rules.Evaluate(remainder)
			if err == nil {
				t.Errorf("Evaluate(%q) = %+v with default_deny=%v, want a refusal", remainder, got, defaultDeny)
				continue
			}
			if !errors.Is(err, reponame.ErrInvalid) {
				t.Errorf("Evaluate(%q) failed with %v, want reponame.ErrInvalid", remainder, err)
			}
			if got.Allowed {
				t.Errorf("Evaluate(%q) refused and still returned an allowing decision", remainder)
			}
		}
	}
}

// The zero value is a real configuration -- a proxy with no rules -- and it has
// to behave exactly like compiling one.
func TestRoutingRulesZeroValue(t *testing.T) {
	t.Parallel()

	var zero repo.RoutingRules
	compiled := proxyRules(t, repo.ProxyConfig{})

	if zero.DefaultDeny() {
		t.Error("the zero rule set reports default-deny")
	}
	for _, remainder := range []string{"library/nginx", "internal/api", "nginx"} {
		zeroDecision, err := zero.Evaluate(remainder)
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", remainder, err)
		}
		compiledDecision, err := compiled.Evaluate(remainder)
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", remainder, err)
		}
		if zeroDecision != compiledDecision {
			t.Errorf("zero rule set decided %+v, compiled-with-no-rules decided %+v", zeroDecision, compiledDecision)
		}
		if !zeroDecision.Allowed || zeroDecision.Reason != repo.RoutedByDefaultAllow {
			t.Errorf("Evaluate(%q) = %+v, want allowed by default", remainder, zeroDecision)
		}
	}
}

// DefaultDeny is what the admin API and the UI show, so it has to survive
// compilation.
func TestRoutingRulesDefaultDenyReported(t *testing.T) {
	t.Parallel()

	if !proxyRules(t, repo.ProxyConfig{DefaultDeny: true}).DefaultDeny() {
		t.Error("a default-deny configuration compiled to a rule set that does not report it")
	}
	if proxyRules(t, repo.ProxyConfig{Allow: []string{"library/*"}}).DefaultDeny() {
		t.Error("a rule set reports default-deny it was not configured with")
	}
}

// routingCorpus mirrors Z-007's scope corpus: the shapes §9 calls out for
// binding patterns, which are the same shapes here because they are the same
// grammar. Adding a way to widen a routing rule and a way to widen a binding
// scope is one change, and this is the seed set that catches it either way.
var routingCorpus = []string{
	"*",
	"library/*",
	"library/nginx",
	"all/library/*",
	"system",
	"",
	"/",
	"/*",
	"**",
	"*/*",
	"*/prod",
	"team-*/api",
	"team-a/*/api",
	"library/",
	"library*",
	"../etc/passwd",
	"../*",
	"library/../secret",
	"library/../*",
	"library//nginx",
	"system/*",
	"system/api",
	"Library/*",
	"library nginx",
	"library\x00nginx",
	`library\*`,
	"library/nginx:latest",
	strings.Repeat("a/", 200) + "*",
}

// FuzzRoutingRules holds the evaluator to the invariants that make a rule set a
// security control rather than a suggestion: nothing is ever both allowed and
// blocked, a named pattern really matched, an illegal remainder is refused
// rather than defaulted, and default-deny with no allow rules admits nothing at
// all.
func FuzzRoutingRules(f *testing.F) {
	for _, allow := range routingCorpus {
		for _, block := range routingCorpus {
			f.Add(allow, block, "library/nginx")
		}
	}
	for _, remainder := range routingCorpus {
		f.Add("library/*", "library/secret", remainder)
	}

	f.Fuzz(func(t *testing.T, allow, block, remainder string) {
		cfg := repo.ProxyConfig{Upstream: upstream, Allow: []string{allow}, Block: []string{block}}
		rules, err := repo.CompileRoutingRules(cfg)
		if err != nil {
			if !errors.Is(err, repo.ErrInvalidConfig) {
				t.Fatalf("CompileRoutingRules refused %q/%q with %v, want ErrInvalidConfig", allow, block, err)
			}
			return
		}

		decision, err := rules.Evaluate(remainder)
		if err != nil {
			if !errors.Is(err, reponame.ErrInvalid) {
				t.Fatalf("Evaluate(%q) failed with %v, want reponame.ErrInvalid", remainder, err)
			}
			if reponame.Valid(remainder) {
				t.Fatalf("Evaluate refused the legal remainder %q", remainder)
			}
			if decision.Allowed {
				t.Fatalf("Evaluate(%q) refused and allowed at once", remainder)
			}
			return
		}
		if !reponame.Valid(remainder) {
			t.Fatalf("Evaluate accepted the illegal remainder %q", remainder)
		}

		// Allowed and the reason are two readings of one answer; a decision
		// whose reason contradicts its verdict would let a caller that logs
		// one and enforces the other disagree with itself.
		switch decision.Reason {
		case repo.RoutedByAllow, repo.RoutedByDefaultAllow:
			if !decision.Allowed {
				t.Fatalf("%+v: reason allows, verdict denies", decision)
			}
		case repo.RoutedByBlock, repo.RoutedByDefaultDeny:
			if decision.Allowed {
				t.Fatalf("%+v: reason denies, verdict allows", decision)
			}
		default:
			t.Fatalf("%+v: reason is outside the vocabulary", decision)
		}

		resource, err := authz.Repository(remainder)
		if err != nil {
			t.Fatalf("a remainder Evaluate accepted is not a resource: %v", err)
		}

		// The pattern a decision names has to be one that was configured and
		// one that actually matches. An explanation that names the wrong rule
		// sends an operator to edit a line that was never involved.
		switch decision.Reason {
		case repo.RoutedByBlock:
			if decision.Pattern.String() != block {
				t.Fatalf("%+v names a pattern that is not the block rule %q", decision, block)
			}
			if !decision.Pattern.Matches(resource) {
				t.Fatalf("%+v names a pattern that does not match %q", decision, remainder)
			}
		case repo.RoutedByAllow:
			if decision.Pattern.String() != allow {
				t.Fatalf("%+v names a pattern that is not the allow rule %q", decision, allow)
			}
			if !decision.Pattern.Matches(resource) {
				t.Fatalf("%+v names a pattern that does not match %q", decision, remainder)
			}
		default:
			if decision.Pattern != "" {
				t.Fatalf("%+v fell to a default and still names a pattern", decision)
			}
		}

		// No input is ever both allowed and blocked: if the block pattern
		// covers the remainder, the answer is a denial whatever the allow
		// pattern says.
		blockScope, err := authz.ParseScope(block)
		if err == nil && blockScope.Matches(resource) && decision.Allowed {
			t.Fatalf("%q allowed %q while block rule %q covers it", allow, remainder, block)
		}

		// Default-deny with no allow rules is the posture an operator reaches
		// for to stop an open relay. It has to admit nothing, whatever the
		// block list happens to say.
		shut, err := repo.CompileRoutingRules(repo.ProxyConfig{
			Upstream: upstream, Block: []string{block}, DefaultDeny: true,
		})
		if err != nil {
			t.Fatalf("CompileRoutingRules with the already-accepted block rule %q: %v", block, err)
		}
		shutDecision, err := shut.Evaluate(remainder)
		if err != nil {
			t.Fatalf("Evaluate(%q) on the already-accepted remainder: %v", remainder, err)
		}
		if shutDecision.Allowed {
			t.Fatalf("default-deny with no allow rules admitted %q: %+v", remainder, shutDecision)
		}
	})
}
