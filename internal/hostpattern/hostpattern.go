// Package hostpattern is the grammar for naming a host a proxy client may be
// sent to: an exact host, or a wildcard over one domain's subdomains.
//
// It is a leaf package for the reason internal/reponame is one. The grammar has
// two users that cannot import each other -- internal/proxy's redirect policy,
// which is the SSRF boundary that matches against it, and internal/repo, which
// validates the patterns an operator writes into a proxy's configuration -- and
// a security grammar with two implementations is a security grammar with two
// meanings. One definition, one fuzzer (§9).
//
// The grammar is deliberately small:
//
//	auth.docker.io      an exact host
//	*.docker.com        that domain's subdomains, at any depth
//
// A wildcard does not match the bare domain: "*.example.com" and "example.com"
// are different grants, and an operator who wants both writes both. Matching is
// case-insensitive, because DNS is.
//
// Nothing here decides whether a host is *safe* to reach. The redirect policy
// refuses private, loopback, and link-local addresses before it consults any
// pattern, so a broad entry here cannot open that door.
package hostpattern

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrInvalidPattern reports a pattern this package refuses. Callers assert with
// errors.Is; the message says which rule was broken.
var ErrInvalidPattern = errors.New("invalid host pattern")

// maxima from DNS: a name is at most 253 characters and a label at most 63.
const (
	maxNameLength  = 253
	maxLabelLength = 63
)

// Validate reports whether a pattern is one an operator may store.
//
// It is stricter than Match on purpose. Match is lenient because it runs
// against whatever a policy was built with at a moment when refusing would mean
// failing a pull; Validate runs at the edge, where a pattern that does not mean
// what its author thought is worth refusing outright. The clearest case is a
// port: Match ignores one, and an operator who wrote "cdn.example.com:443"
// believing it restricted the port would be wrong in a way nothing would ever
// tell them.
func Validate(pattern string) error {
	if strings.TrimSpace(pattern) != pattern {
		return refuse(pattern, "must not have leading or trailing whitespace")
	}
	if pattern == "" {
		return refuse(pattern, "must not be empty")
	}
	if len(pattern) > maxNameLength {
		return refuse(pattern, fmt.Sprintf("is longer than %d characters", maxNameLength))
	}

	switch {
	case strings.Contains(pattern, "://"):
		return refuse(pattern, "is a host, not a URL")
	case strings.ContainsAny(pattern, "/?#"):
		return refuse(pattern, "is a host, not a URL path")
	case strings.Contains(pattern, "@"):
		return refuse(pattern, "must not carry credentials")
	case strings.Contains(pattern, ":"):
		// Covers a port and an IPv6 literal alike. Both are refused, and for
		// the same underlying reason: this list says which machine we will
		// talk to, and neither form says that more precisely than a name does.
		return refuse(pattern, "must not carry a port: the list names a host, and a port here would be ignored")
	}

	host := pattern
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		if suffix == "" {
			return refuse(pattern, `must name a domain after "*."`)
		}
		host = suffix
	}
	if strings.Contains(host, "*") {
		// One leading label, or none. "a.*.com" would read as a grant over
		// something, and every reading of it is a guess.
		return refuse(pattern, `may only use "*" as the first label, as in "*.example.com"`)
	}

	// An IP literal is a legitimate exact entry -- a registry on a fixed
	// address -- and skips the label rules, which are about names.
	if net.ParseIP(host) != nil {
		if pattern != host {
			return refuse(pattern, "must not use a wildcard over an IP address")
		}
		return nil
	}

	for label := range strings.SplitSeq(host, ".") {
		switch {
		case label == "":
			return refuse(pattern, "has an empty label")
		case len(label) > maxLabelLength:
			return refuse(pattern, fmt.Sprintf("has a label longer than %d characters", maxLabelLength))
		case strings.HasPrefix(label, "-"), strings.HasSuffix(label, "-"):
			return refuse(pattern, "has a label starting or ending with a hyphen")
		}
		for _, r := range label {
			if !isHostRune(r) {
				return refuse(pattern, fmt.Sprintf("contains %q, which is not a letter, digit, or hyphen", r))
			}
		}
	}
	return nil
}

// Match reports whether a host matches one pattern.
//
// It is total and never fails: a pattern it cannot make sense of matches
// nothing. That is the safe direction at a boundary whose answer decides
// whether a request is sent -- an unparseable entry must not become a grant --
// and it is why Validate exists separately, to catch such an entry when it is
// written rather than when it silently stops working.
func Match(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}

	// A pattern carrying a port is compared on its host part alone: the policy
	// is about which machine we talk to, not which port it listens on.
	if h, _, err := net.SplitHostPort(pattern); err == nil {
		pattern = h
	}

	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return suffix != "" && strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

// isHostRune reports whether r may appear in a hostname label.
func isHostRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		return true
	default:
		return false
	}
}

func refuse(pattern, reason string) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidPattern, pattern, reason)
}
