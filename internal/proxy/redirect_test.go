package proxy_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/proxy"
)

// The redirect policy is the SSRF boundary, and it is a pure function so that
// it can be enumerated rather than sampled. Every row below is a decision an
// upstream can force by sending one header.

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed
}

func TestRedirectPolicyAllow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		upstream string
		target   string
		policy   proxy.RedirectPolicy
		allowed  bool
	}{
		{name: "the upstream itself", upstream: "https://registry.example.com", target: "https://registry.example.com/v2/x", allowed: true},
		{name: "a different port on the upstream", upstream: "https://registry.example.com", target: "https://registry.example.com:8443/v2/x", allowed: true},
		{name: "case-insensitive host", upstream: "https://Registry.Example.com", target: "https://registry.example.COM/v2/x", allowed: true},
		{name: "a subdomain of the upstream", upstream: "https://example.com", target: "https://blobs.example.com/x", allowed: true},
		{name: "a sibling domain", upstream: "https://registry.example.com", target: "https://evil.example.net/x", allowed: false},
		{name: "a suffix that is not a subdomain", upstream: "https://example.com", target: "https://notexample.com/x", allowed: false},
		{
			name: "a trusted host", upstream: "https://registry-1.docker.io",
			target: "https://auth.docker.io/token", allowed: true,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"auth.docker.io"}},
		},
		{
			name: "a trusted wildcard", upstream: "https://registry-1.docker.io",
			target: "https://production.cloudflare.docker.com/registry-v2/x", allowed: true,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"*.docker.com"}},
		},
		{
			name: "a wildcard does not match the bare domain", upstream: "https://registry-1.docker.io",
			target: "https://docker.com/x", allowed: false,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"*.docker.com"}},
		},
		{
			name: "a trusted entry with a port", upstream: "https://registry.example.com",
			target: "https://mirror.example.net:8443/x", allowed: true,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"mirror.example.net:443"}},
		},
		{
			name: "an empty trusted entry grants nothing", upstream: "https://registry.example.com",
			target: "https://elsewhere.example.net/x", allowed: false,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"", "  "}},
		},
		{
			name: "a bare wildcard grants nothing", upstream: "https://registry.example.com",
			target: "https://elsewhere.example.net/x", allowed: false,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"*."}},
		},
		{name: "a non-http scheme", upstream: "https://registry.example.com", target: "file:///etc/passwd", allowed: false},
		{name: "a scheme-relative nonsense", upstream: "https://registry.example.com", target: "gopher://registry.example.com/x", allowed: false},
		{name: "no host", upstream: "https://registry.example.com", target: "https:///v2/x", allowed: false},
		{name: "credentials in the url", upstream: "https://registry.example.com", target: "https://user:pass@registry.example.com/x", allowed: false},

		// The SSRF rows. A private address is refused however the trusted-host
		// list is written, unless it is the upstream the operator configured.
		{
			name: "the metadata service", upstream: "https://registry.example.com",
			target: "http://169.254.169.254/latest/meta-data/", allowed: false,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"169.254.169.254"}, AllowDowngrade: true},
		},
		{
			name: "loopback", upstream: "https://registry.example.com",
			target: "http://127.0.0.1:5000/v2/x", allowed: false,
			policy: proxy.RedirectPolicy{AllowDowngrade: true},
		},
		{
			name: "an rfc1918 address", upstream: "https://registry.example.com",
			target: "http://10.1.2.3/v2/x", allowed: false,
			policy: proxy.RedirectPolicy{AllowDowngrade: true},
		},
		{
			name: "ipv6 loopback", upstream: "https://registry.example.com",
			target: "http://[::1]:5000/v2/x", allowed: false,
			policy: proxy.RedirectPolicy{AllowDowngrade: true},
		},
		{
			name: "an ipv4-mapped private address", upstream: "https://registry.example.com",
			target: "http://[::ffff:10.1.2.3]/v2/x", allowed: false,
			policy: proxy.RedirectPolicy{AllowDowngrade: true},
		},
		{
			name: "the unspecified address", upstream: "https://registry.example.com",
			target: "http://0.0.0.0/v2/x", allowed: false,
			policy: proxy.RedirectPolicy{AllowDowngrade: true},
		},
		{
			name: "a public address", upstream: "https://registry.example.com",
			target: "https://93.184.216.34/v2/x", allowed: false,
		},
		{
			name: "a public address on the trusted list", upstream: "https://registry.example.com",
			target: "https://93.184.216.34/v2/x", allowed: true,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"93.184.216.34"}},
		},
		// A private upstream is a normal deployment -- a mirror on the LAN --
		// and must keep working.
		{name: "a loopback upstream reaching itself", upstream: "http://127.0.0.1:5000", target: "http://127.0.0.1:5000/v2/x", allowed: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.policy.Allow(mustURL(t, tc.upstream), mustURL(t, tc.target))
			switch {
			case tc.allowed && err != nil:
				t.Errorf("Allow(%s -> %s) = %v, want allowed", tc.upstream, tc.target, err)
			case !tc.allowed && err == nil:
				t.Errorf("Allow(%s -> %s) = nil, want refused", tc.upstream, tc.target)
			case !tc.allowed && !errors.Is(err, proxy.ErrRedirectRefused):
				t.Errorf("Allow(%s -> %s) = %v, want ErrRedirectRefused", tc.upstream, tc.target, err)
			}
		})
	}
}

func TestRedirectPolicyFollow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		upstream string
		from     string
		to       string
		hop      int
		policy   proxy.RedirectPolicy
		allowed  bool
	}{
		{name: "first hop on the same host", upstream: "https://r.example.com", from: "https://r.example.com/v2/a", to: "https://r.example.com/v2/b", hop: 1, allowed: true},
		{name: "the last hop within the cap", upstream: "https://r.example.com", from: "https://r.example.com/a", to: "https://r.example.com/b", hop: 5, allowed: true},
		{name: "one hop past the cap", upstream: "https://r.example.com", from: "https://r.example.com/a", to: "https://r.example.com/b", hop: 6, allowed: false},
		{
			name: "a lower cap", upstream: "https://r.example.com", from: "https://r.example.com/a", to: "https://r.example.com/b", hop: 2,
			policy: proxy.RedirectPolicy{MaxRedirects: 1}, allowed: false,
		},
		{
			name: "a policy that refuses every redirect", upstream: "https://r.example.com", from: "https://r.example.com/a", to: "https://r.example.com/b", hop: 1,
			policy: proxy.RedirectPolicy{MaxRedirects: -1}, allowed: false,
		},
		{name: "https to http", upstream: "https://r.example.com", from: "https://r.example.com/a", to: "http://r.example.com/b", hop: 1, allowed: false},
		{
			name: "https to http when the operator allowed it", upstream: "https://r.example.com",
			from: "https://r.example.com/a", to: "http://r.example.com/b", hop: 1,
			policy: proxy.RedirectPolicy{AllowDowngrade: true}, allowed: true,
		},
		{name: "http upstream staying on http", upstream: "http://r.example.com", from: "http://r.example.com/a", to: "http://r.example.com/b", hop: 1, allowed: true},
		{
			name:     "a chain that launders a downgrade through a trusted http host",
			upstream: "https://r.example.com", from: "http://mirror.example.net/a", to: "http://mirror.example.net/b", hop: 2,
			policy: proxy.RedirectPolicy{TrustedHosts: []string{"mirror.example.net"}}, allowed: false,
		},
		{name: "off the family", upstream: "https://r.example.com", from: "https://r.example.com/a", to: "https://evil.example.net/b", hop: 1, allowed: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.policy.Follow(mustURL(t, tc.upstream), mustURL(t, tc.from), mustURL(t, tc.to), tc.hop)
			switch {
			case tc.allowed && err != nil:
				t.Errorf("Follow(hop %d, %s -> %s) = %v, want allowed", tc.hop, tc.from, tc.to, err)
			case !tc.allowed && !errors.Is(err, proxy.ErrRedirectRefused):
				t.Errorf("Follow(hop %d, %s -> %s) = %v, want ErrRedirectRefused", tc.hop, tc.from, tc.to, err)
			}
		})
	}
}

// TestRedirectErrorNamesBothEnds keeps the operator-facing half honest: a
// refusal that does not say where it was being sent is a refusal nobody can
// act on. The query string is dropped because on a redirect to object storage
// it carries a signature.
func TestRedirectErrorNamesBothEnds(t *testing.T) {
	t.Parallel()

	policy := proxy.RedirectPolicy{}
	err := policy.Follow(
		mustURL(t, "https://r.example.com"),
		mustURL(t, "https://r.example.com/v2/a/blobs/sha256:x"),
		mustURL(t, "https://cdn.example.net/object?signature=secret"),
		1)

	var refusal *proxy.RedirectError
	if !errors.As(err, &refusal) {
		t.Fatalf("Follow = %v, want a *proxy.RedirectError", err)
	}
	if refusal.From == "" || refusal.To == "" || refusal.Reason == "" {
		t.Errorf("RedirectError = %+v, want both ends and a reason", refusal)
	}
	if got := refusal.Error(); strings.Contains(got, "signature=secret") {
		t.Errorf("the refusal leaked the signed query string: %s", got)
	}
}
