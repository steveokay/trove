package proxy

import (
	"errors"
	"net"
)

// Degraded mode (C-008).
//
// An upstream that cannot be reached is not an emergency for a pull-through
// cache: the content it would have confirmed is already here, and refusing to
// serve it fails every deploy in a cluster because somebody else's registry is
// having a bad day. The default is therefore to serve what we hold, marked
// stale and reported (ADR 0008), and `strict` exists for deployments that would
// rather stop than serve an answer they could not confirm.
//
// What this file adds to that decision is the *reason*, because "the upstream
// is down" and "the upstream refused our credentials" call for completely
// different responses from an operator and only one of them is degraded mode's
// business.

// DegradedCause names why an upstream could not answer, for the event, the log,
// and C-009's backoff.
//
// The set is small on purpose. An operator acts on "is it us, them, or the
// network" and on "will waiting help"; a taxonomy of every errno underneath
// would be a list nobody could route on, and the underlying error is still
// there for anybody who wants it.
type DegradedCause string

// The causes. Each is a value the cache.stale-served payload carries verbatim.
const (
	// CauseUnreachable is the network saying no: refused, reset, or a name
	// that does not resolve. Waiting may help; nothing about the request will.
	CauseUnreachable DegradedCause = "unreachable"

	// CauseTimeout is the upstream not answering in time -- our own header
	// deadline, or a context that expired underneath it. It is separate from
	// unreachable because a registry that is merely slow is one an operator
	// may want to wait for rather than replace.
	CauseTimeout DegradedCause = "timeout"

	// CauseUpstreamError is the upstream answering with something it cannot
	// serve content through: a 5xx, or any other status this client will not
	// read a manifest out of. The remote is up and cannot help us, which is a
	// different page in the runbook from the network being down.
	CauseUpstreamError DegradedCause = "upstream-error"

	// CauseRateLimited is a 429. It is the one cause where the upstream told
	// us exactly what to do about it, and C-009 is what acts on that.
	CauseRateLimited DegradedCause = "rate-limited"
)

// Classify reports why a failure counts as degraded, and whether it does.
//
// Only these four do. A rejected credential, a refused redirect, an invalid
// reference, and a manifest too large are all failures that no amount of
// waiting fixes: serving stale content through them would replace a loud,
// actionable failure with a quiet one, and an SSRF attempt in particular must
// not end up behind a stale-content warning (C-002).
//
// The classification reads the client's typed errors rather than guessing from
// text: a transport failure carries the net error it wrapped, and a status
// failure carries the status. That is why this can distinguish a timeout from a
// refusal at all -- by the time an error is a string, it cannot be.
func Classify(err error) (DegradedCause, bool) {
	if err == nil {
		return "", false
	}

	// The sentinel rather than the typed error, so a Client this package did
	// not write is classified by the contract it is held to rather than by
	// which struct it happened to return (C-002).
	if errors.Is(err, ErrRateLimited) {
		return CauseRateLimited, true
	}

	var transport *TransportError
	if errors.As(err, &transport) {
		if isTimeout(transport.Err) {
			return CauseTimeout, true
		}
		return CauseUnreachable, true
	}

	var status *StatusError
	if errors.As(err, &status) && errors.Is(status, ErrUpstreamUnavailable) {
		return CauseUpstreamError, true
	}

	// Anything else that still claims unavailability is one, for the same
	// reason: treating an unrecognised implementation's outage as "not
	// degraded" would quietly disable stale-serving for it.
	if errors.Is(err, ErrUpstreamUnavailable) {
		return CauseUnreachable, true
	}
	return "", false
}

// isTimeout reports whether a transport failure was a deadline rather than a
// refusal. A DNS lookup that timed out is a timeout; one that answered "no such
// host" is not, which is the distinction net.DNSError draws and the reason it
// is checked before the generic net.Error.
func isTimeout(err error) bool {
	// Our own header deadline is a timeout by definition. It is a plain
	// sentinel rather than a net.Error because the client reports it in place
	// of the cancellation that enforced it -- telling a caller its own context
	// was cancelled would name a different fault with a different fix.
	if errors.Is(err, errHeaderTimeout) {
		return true
	}

	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dns.IsTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
