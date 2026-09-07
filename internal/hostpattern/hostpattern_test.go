package hostpattern_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/hostpattern"
)

func TestValidateAcceptsWhatARegistryNeeds(t *testing.T) {
	t.Parallel()

	// Every entry here is one a real preset carries (C-014), plus the shapes
	// an operator writing their own would reach for.
	for _, pattern := range []string{
		"auth.docker.io",
		"*.docker.com",
		"pkg-containers.githubusercontent.com",
		"storage.googleapis.com",
		"*.pkg.dev",
		"registry.internal",
		"AUTH.DOCKER.IO",
		"203.0.113.5",
		"a-b.example.com",
		"x" + strings.Repeat("y", 62) + ".example.com",
	} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			if err := hostpattern.Validate(pattern); err != nil {
				t.Errorf("Validate(%q) = %v, want nil", pattern, err)
			}
		})
	}
}

func TestValidateRefusesWhatDoesNotMeanWhatItSays(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		pattern string
	}{
		{name: "empty", pattern: ""},
		{name: "whitespace", pattern: "   "},
		{name: "padded", pattern: " auth.docker.io "},
		{name: "url", pattern: "https://auth.docker.io"},
		{name: "path", pattern: "auth.docker.io/v2"},
		{name: "query", pattern: "auth.docker.io?a=b"},
		{name: "fragment", pattern: "auth.docker.io#frag"},
		{name: "credentials", pattern: "user@auth.docker.io"},
		{name: "port", pattern: "cdn.example.com:443"},
		{name: "ipv6", pattern: "[2001:db8::1]"},
		{name: "bare wildcard", pattern: "*"},
		{name: "wildcard with no domain", pattern: "*."},
		{name: "interior wildcard", pattern: "a.*.com"},
		{name: "trailing wildcard", pattern: "example.*"},
		{name: "wildcard over an address", pattern: "*.203.0.113.5"},
		{name: "empty label", pattern: "a..example.com"},
		{name: "trailing dot", pattern: "example.com."},
		{name: "leading hyphen", pattern: "-bad.example.com"},
		{name: "trailing hyphen", pattern: "bad-.example.com"},
		{name: "underscore", pattern: "bad_host.example.com"},
		{name: "space inside", pattern: "bad host.example.com"},
		{name: "label too long", pattern: strings.Repeat("y", 64) + ".example.com"},
		{name: "name too long", pattern: strings.Repeat("abcdefgh.", 30) + "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := hostpattern.Validate(tc.pattern)
			if !errors.Is(err, hostpattern.ErrInvalidPattern) {
				t.Fatalf("Validate(%q) = %v, want ErrInvalidPattern", tc.pattern, err)
			}
			// The message names the pattern, because a refused configuration
			// is read by whoever wrote it and a list of patterns needs to say
			// which one.
			if !strings.Contains(err.Error(), tc.pattern) && tc.pattern != "" {
				t.Errorf("error %q does not name the pattern %q", err, tc.pattern)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		host    string
		pattern string
		want    bool
	}{
		{name: "exact", host: "auth.docker.io", pattern: "auth.docker.io", want: true},
		{name: "exact is case-insensitive", host: "AUTH.Docker.IO", pattern: "auth.docker.io", want: true},
		{name: "exact does not match a subdomain", host: "a.auth.docker.io", pattern: "auth.docker.io"},
		{name: "exact does not match a suffix", host: "evilauth.docker.io", pattern: "auth.docker.io"},
		{name: "wildcard matches one label", host: "cdn.docker.com", pattern: "*.docker.com", want: true},
		{name: "wildcard matches several", host: "production.cloudflare.docker.com", pattern: "*.docker.com", want: true},
		{
			// The rule that keeps a grant from widening by accident.
			name: "wildcard does not match the bare domain",
			host: "docker.com", pattern: "*.docker.com",
		},
		{name: "wildcard does not match a sibling", host: "notdocker.com", pattern: "*.docker.com"},
		{
			// A pattern nobody validated still must not become a grant.
			name: "wildcard with no domain matches nothing",
			host: "anything.example.com", pattern: "*.",
		},
		{name: "empty pattern matches nothing", host: "example.com", pattern: ""},
		{name: "empty host matches nothing", host: "", pattern: "example.com"},
		{name: "a port on the pattern is ignored", host: "cdn.example.com", pattern: "cdn.example.com:443", want: true},
		{name: "padding is ignored", host: "example.com", pattern: "  example.com  ", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := hostpattern.Match(tc.host, tc.pattern); got != tc.want {
				t.Errorf("Match(%q, %q) = %t, want %t", tc.host, tc.pattern, got, tc.want)
			}
		})
	}
}

// FuzzMatchNeverWidensAGrant is the property that matters at an SSRF boundary:
// whatever the input, a match is either the exact host or a strict subdomain of
// a wildcard's domain. Nothing else may ever come back true.
func FuzzMatchNeverWidensAGrant(f *testing.F) {
	for _, seed := range [][2]string{
		{"auth.docker.io", "auth.docker.io"},
		{"production.cloudflare.docker.com", "*.docker.com"},
		{"docker.com", "*.docker.com"},
		{"evil.com", "*.docker.com"},
		{"example.com:443", "example.com"},
		{"", ""},
		{"..", "*.."},
		{"a.b", "*.b"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, host, pattern string) {
		if !hostpattern.Match(host, pattern) {
			return
		}

		normalisedHost := strings.ToLower(strings.TrimSpace(host))
		normalised := strings.ToLower(strings.TrimSpace(pattern))
		if h, _, err := net.SplitHostPort(normalised); err == nil {
			normalised = h
		}

		if suffix, ok := strings.CutPrefix(normalised, "*."); ok {
			switch {
			case suffix == "":
				t.Fatalf("Match(%q, %q) matched a wildcard with no domain", host, pattern)
			case normalisedHost == suffix:
				t.Fatalf("Match(%q, %q) matched the bare domain of a wildcard", host, pattern)
			case !strings.HasSuffix(normalisedHost, "."+suffix):
				t.Fatalf("Match(%q, %q) matched a host outside the wildcard's domain", host, pattern)
			}
			return
		}
		if normalisedHost != normalised {
			t.Fatalf("Match(%q, %q) matched a host that is not the pattern", host, pattern)
		}
	})
}

// FuzzValidatedPatternsAreWellFormed pins the other direction: anything
// Validate accepts is a shape Match can act on, and it is exactly one of the
// two forms the grammar has.
func FuzzValidatedPatternsAreWellFormed(f *testing.F) {
	for _, seed := range []string{"auth.docker.io", "*.docker.com", "*", "", "a..b", "203.0.113.5", "x:1"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		if err := hostpattern.Validate(pattern); err != nil {
			return
		}

		if strings.ContainsAny(pattern, " \t\r\n:/?#@") {
			t.Fatalf("Validate accepted %q, which carries a character no host may have", pattern)
		}
		if stars := strings.Count(pattern, "*"); stars > 1 {
			t.Fatalf("Validate accepted %q, which has %d wildcards", pattern, stars)
		}

		// A validated pattern always matches something: itself for an exact
		// entry, and a subdomain for a wildcard. A grammar that could accept a
		// pattern matching nothing would be a grammar an operator can write a
		// silently dead rule in.
		probe := pattern
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			probe = "probe." + suffix
		}
		if !hostpattern.Match(probe, pattern) {
			t.Fatalf("Validate accepted %q but Match(%q, %q) is false", pattern, probe, pattern)
		}
	})
}
