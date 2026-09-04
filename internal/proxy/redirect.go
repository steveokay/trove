package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DefaultMaxRedirects caps a redirect chain. Real registries use one hop to a
// CDN or a signed object URL; five leaves room for an unusual upstream while
// still terminating a loop quickly (ADR 0008).
const DefaultMaxRedirects = 5

// RedirectPolicy decides which URLs the client may be sent to.
//
// It exists as a value with no I/O for one reason: this is the SSRF boundary,
// and a decision that can be exhaustively table-tested is the only kind worth
// trusting at a boundary. A Location header and a WWW-Authenticate realm are
// both strings an upstream chooses, so both go through here before the client
// opens a connection or attaches a credential.
//
// The zero value is usable and is the strict one: five hops, no downgrade, and
// nothing outside the upstream's own host family.
type RedirectPolicy struct {
	// MaxRedirects caps the chain. Zero means DefaultMaxRedirects; a negative
	// value refuses every redirect.
	MaxRedirects int

	// TrustedHosts are additional hosts the client may be sent to, beyond the
	// upstream's own host and its subdomains. An entry is either an exact host
	// ("auth.docker.io") or a wildcard over one domain's subdomains
	// ("*.docker.com"); matching is case-insensitive and ignores the port.
	//
	// This is the "unless config explicitly allows it" seam (§4). It exists
	// because the largest upstream in the world needs it -- Docker Hub
	// authenticates at auth.docker.io and serves blobs from a CDN under a
	// different registrable domain entirely -- and because the alternative,
	// inferring a "family" from a public-suffix guess, silently trusts every
	// other tenant of whatever domain the guess lands on.
	//
	// It never grants a private address: see Allow.
	TrustedHosts []string

	// AllowDowngrade permits a redirect from https to http. It is false in
	// every configuration an operator should run, and exists so that a
	// plaintext test upstream can be pointed at a plaintext CDN without the
	// policy having to make an exception for itself.
	AllowDowngrade bool
}

// maxHops is the effective cap.
func (p RedirectPolicy) maxHops() int {
	if p.MaxRedirects == 0 {
		return DefaultMaxRedirects
	}
	return p.MaxRedirects
}

// Follow reports whether a redirect may be followed.
//
// upstream is the configured registry root, from is the URL that answered with
// the redirect, to is where it points, and hop counts from 1 for the first
// redirect in the chain. A nil error means follow it.
func (p RedirectPolicy) Follow(upstream, from, to *url.URL, hop int) error {
	if hop > p.maxHops() {
		return &RedirectError{
			From:   redacted(from),
			To:     redacted(to),
			Reason: fmt.Sprintf("more than %d redirects", p.maxHops()),
		}
	}
	// A downgrade is judged against both ends of the chain: against the
	// upstream because that is what the operator configured and what the
	// credentials were meant for, and against the immediate hop because a
	// policy that only looked at the origin would let a chain launder itself
	// through an allowed http host.
	if to.Scheme == "http" && !p.AllowDowngrade &&
		(strings.EqualFold(from.Scheme, "https") || strings.EqualFold(upstream.Scheme, "https")) {
		return &RedirectError{
			From:   redacted(from),
			To:     redacted(to),
			Reason: "refuses to downgrade https to http",
		}
	}
	if err := p.Allow(upstream, to); err != nil {
		var refusal *RedirectError
		if errors.As(err, &refusal) {
			refusal.From = redacted(from)
		}
		return err
	}
	return nil
}

// Allow reports whether the client may send a request to u at all.
//
// Follow calls it for the target of every redirect, and the authentication
// exchange calls it for the realm out of a WWW-Authenticate challenge. The
// realm matters as much as the redirect does and is easier to forget: it is
// where the client is about to send the upstream's password, so an unchecked
// realm turns a compromised or hostile registry into a credential exfiltration
// channel.
func (p RedirectPolicy) Allow(upstream, u *url.URL) error {
	refuse := func(reason string) error {
		return &RedirectError{To: redacted(u), Reason: reason}
	}

	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return refuse(fmt.Sprintf("scheme %q is not http or https", u.Scheme))
	case u.Host == "":
		return refuse("no host")
	case u.User != nil:
		return refuse("carries credentials in the URL")
	}

	host := strings.ToLower(u.Hostname())
	upstreamHost := strings.ToLower(upstream.Hostname())

	// Same host as the upstream is always allowed, including a different port:
	// it is the machine the operator configured, and refusing it would break a
	// registry that serves blobs from a second port on the same box.
	if host == upstreamHost {
		return nil
	}

	// A private, loopback, or link-local address that is not the upstream
	// itself is refused before the trusted-host list is even consulted. This
	// is the rule that stops 169.254.169.254 and a metadata service behind it,
	// and it is unconditional so that a broad TrustedHosts entry cannot open
	// the door by accident.
	if ip := net.ParseIP(host); ip != nil && !isGlobalUnicast(ip) {
		return refuse("private, loopback, or link-local address")
	}

	// A subdomain of the upstream is the same family: reaching it requires
	// control of the domain the operator already pointed us at.
	if strings.HasSuffix(host, "."+upstreamHost) && upstreamHost != "" {
		return nil
	}

	for _, trusted := range p.TrustedHosts {
		if matchesHost(host, trusted) {
			return nil
		}
	}
	return refuse(fmt.Sprintf("host is outside the upstream's family (%s) and is not trusted", upstreamHost))
}

// matchesHost reports whether host matches one TrustedHosts entry: an exact
// host, or "*.domain" over that domain's subdomains. A wildcard entry does not
// match the bare domain, because "*.example.com" and "example.com" are
// different grants and an operator who wants both writes both.
func matchesHost(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	// A pattern with a port is compared on its host part alone: the policy is
	// about which machine we talk to, not which port it listens on.
	if h, _, err := net.SplitHostPort(pattern); err == nil {
		pattern = h
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return suffix != "" && strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

// isGlobalUnicast reports whether an IP literal is one we will talk to when it
// is not the configured upstream. Everything an SSRF wants -- loopback, the
// RFC 1918 ranges, the link-local metadata address, the unspecified address,
// and their IPv6 equivalents including the IPv4-mapped forms, which net's own
// predicates unwrap -- fails it.
func isGlobalUnicast(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast())
}

// redacted renders a URL for an error message without its query string, which
// on a redirect to object storage carries a signature.
func redacted(u *url.URL) string {
	clean := *u
	clean.RawQuery = ""
	clean.Fragment = ""
	clean.User = nil
	return clean.String()
}
