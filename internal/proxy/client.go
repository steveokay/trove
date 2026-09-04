package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/steveokay/trove/internal/blob"
)

// Sentinel errors every Client implementation returns for these conditions.
// Callers assert with errors.Is and errors.As; no caller may branch on an HTTP
// status code, because the status is a transport detail that differs between
// upstreams and the decision -- serve stale, back off, cache the negative,
// fail the pull -- does not.
//
// The set is closed and total: every failure this package produces satisfies
// exactly one of them.
var (
	// ErrNotFound reports that the upstream does not have the repository,
	// tag, manifest, or blob that was asked for. It is what C-007 caches
	// negatively for name and tag lookups, and what it must never cache for a
	// digest lookup (ADR 0008).
	ErrNotFound = errors.New("upstream content not found")

	// ErrUnauthorized reports that the upstream refused the request even after
	// the token exchange: no credentials were configured and the content is
	// not public, or the configured credentials were rejected. It is a
	// configuration problem, not an outage, and retrying does not help.
	ErrUnauthorized = errors.New("upstream refused our credentials")

	// ErrRateLimited reports a 429. The error carries the honest Retry-After
	// the upstream sent, reachable with errors.As on *RateLimitedError; C-009
	// owns the backoff that acts on it. The client itself neither sleeps nor
	// retries.
	ErrRateLimited = errors.New("upstream rate limited us")

	// ErrDigestMismatch reports that content did not hash to the digest it was
	// requested under. It is blob.ErrDigestMismatch under a local name, not a
	// second sentinel: the verification is blob's (ADR 0007), so the error is
	// blob's too, and errors.Is against either name gives the same answer.
	ErrDigestMismatch = blob.ErrDigestMismatch

	// ErrUpstreamUnavailable reports that the upstream did not serve us usable
	// content for a reason that is not one of the above: the connection failed,
	// DNS failed, the header phase timed out, or the upstream answered with a
	// status this client cannot use. It is what C-008 classifies as degraded
	// and serves stale against.
	//
	// Every unmapped status satisfies it, including 4xx statuses that are not
	// 401/403/404/429. An upstream that answers 400 to a well-formed
	// distribution request is not serving us content, and treating that as
	// "unavailable" keeps the cluster running on cached content instead of
	// failing pulls on a distinction the operator cannot act on either way.
	ErrUpstreamUnavailable = errors.New("upstream unavailable")

	// ErrRedirectRefused reports that the upstream tried to send us somewhere
	// the redirect policy would not follow: too many hops, a scheme downgrade,
	// a host outside the upstream's family, or a private address. It is
	// deliberately NOT an unavailability -- a refused redirect is a security
	// event an operator has to see, and folding it into the degraded-mode
	// bucket would hide an SSRF attempt behind a stale-content warning.
	ErrRedirectRefused = errors.New("upstream redirect refused")

	// ErrInvalidReference reports a repository name, tag, or digest this
	// client will not put in an upstream URL (§11: validated at the edge,
	// before anything is built out of it). It is the caller's bug, never the
	// upstream's.
	ErrInvalidReference = errors.New("invalid upstream reference")

	// ErrManifestTooLarge reports a manifest body above the configured cap. It
	// is separate from unavailability on purpose: it will not fix itself, so
	// backing off and retrying is the wrong response to it.
	ErrManifestTooLarge = errors.New("upstream manifest too large")
)

// Client fetches content from one configured upstream registry.
//
// One Client serves one proxy repository's upstream. It holds no cache, keeps
// no leases, and applies no policy beyond validating what it is given and
// verifying what it receives; everything else in the proxy subsystem is a
// caller of this interface.
//
// The repository argument is the *upstream* path -- "library/nginx", not the
// trove repository the request arrived at. Namespace rewriting and routing
// rules (C-010) happen before the client is called, so a name that reaches here
// has already been decided to be allowed; the client validates it again anyway,
// because it is about to become part of a URL.
//
// Implementations are safe for concurrent use.
type Client interface {
	// ResolveTag resolves a tag to a digest, conditionally.
	//
	// With a zero Conditional it fetches the manifest outright and returns it
	// with Changed true. With a Conditional carrying what the caller's lease
	// already holds, it revalidates: against any upstream that answers HEAD
	// with Docker-Content-Digest or honours If-None-Match, an unchanged tag
	// transfers no manifest body at all (ADR 0008), and the result is Changed
	// false with a nil Manifest.
	//
	// The digest in the result is always one the client computed from the
	// bytes it received, or one the upstream reported for content the client
	// did not transfer. When the upstream both sends a manifest and declares a
	// digest for it, the two are compared and a disagreement is
	// ErrDigestMismatch -- an upstream that mislabels its own content is not
	// one we cache from.
	//
	// Errors: ErrInvalidReference for a name or tag outside the grammar;
	// ErrNotFound when the repository or tag does not exist upstream;
	// ErrUnauthorized, ErrRateLimited, ErrRedirectRefused,
	// ErrManifestTooLarge, ErrDigestMismatch, ErrUpstreamUnavailable as
	// documented on each. A cancelled or expired caller context surfaces as
	// itself (errors.Is against context.Canceled or context.DeadlineExceeded),
	// never as an upstream failure -- our own header-phase timeout is what
	// becomes ErrUpstreamUnavailable.
	ResolveTag(ctx context.Context, repository, tag string, cond Conditional) (Resolution, error)

	// FetchManifest fetches a manifest by digest and returns its bytes and
	// media type.
	//
	// The bytes are verified against the digest before they are returned. On a
	// mismatch the manifest is discarded and (nil, "", ErrDigestMismatch) is
	// returned: content that failed verification is never handed to a caller,
	// because the caller is the thing that would cache it.
	//
	// The media type is the response Content-Type with any parameters
	// stripped. It is empty when the upstream declared none; the caller
	// decides what to do about that, because "reject it" and "read it out of
	// the manifest body" are both defensible and only the caller knows which
	// of its paths is running.
	//
	// Errors are those of ResolveTag, plus ErrInvalidReference for a digest
	// blob will not parse.
	FetchManifest(ctx context.Context, repository string, digest blob.Digest) ([]byte, string, error)

	// FetchBlob opens a blob by digest for streaming.
	//
	// The reader verifies as it streams (blob.VerifiedReader): a body that does
	// not hash to the digest ends one byte short with ErrDigestMismatch rather
	// than reaching the caller intact. That is the whole point of streaming it
	// rather than buffering -- a layer is too big to hold in memory, so the
	// guarantee has to survive being handed out incrementally.
	//
	// The size is the upstream's Content-Length, or -1 when it sent none. It is
	// advisory: the digest is the authority, and a body that disagrees with the
	// length fails verification anyway.
	//
	// The caller must Close the reader, which releases the upstream connection
	// and the request's context. Errors are those of FetchManifest.
	FetchBlob(ctx context.Context, repository string, digest blob.Digest) (io.ReadCloser, int64, error)

	// RateLimit reports what the upstream last told us about our quota.
	//
	// It is a snapshot, safe to call concurrently with requests, and it is
	// read-only: the client records headers and never acts on them. C-009
	// polls it for the gauges (§8) and owns the backoff.
	RateLimit() RateLimitState
}

// Conditional is what the caller already knows about a tag, so the client can
// ask the upstream whether it still holds.
//
// A zero Conditional means "I know nothing" and produces an unconditional
// fetch. Callers fill it from the lease they are revalidating (ADR 0008).
type Conditional struct {
	// Digest is the digest the caller's lease currently maps the tag to. It is
	// compared against the upstream's Docker-Content-Digest on revalidation.
	Digest blob.Digest

	// ETag is the entity tag the upstream returned last time, sent back as
	// If-None-Match. Registries differ in whether they answer 304 to it, which
	// is why the digest comparison exists alongside it rather than instead.
	ETag string
}

// IsZero reports whether the caller knows nothing about the tag yet.
func (c Conditional) IsZero() bool { return c.Digest == "" && c.ETag == "" }

// Resolution is the answer to a tag resolution.
type Resolution struct {
	// Changed reports whether the tag now points somewhere other than the
	// digest the Conditional carried. It is true for every unconditional
	// resolution.
	Changed bool

	// Digest is what the tag resolves to now.
	Digest blob.Digest

	// MediaType is the manifest's media type, with parameters stripped. It may
	// be empty if the upstream declared none.
	MediaType string

	// ETag is the upstream's entity tag for this manifest, to be stored with
	// the lease and sent back on the next revalidation. Empty when the upstream
	// sent none.
	ETag string

	// Size is the manifest's length in bytes, or -1 when it is not known.
	Size int64

	// Manifest is the manifest body. It is set when Changed is true and nil
	// when it is false: an unchanged tag returns no content, whether or not
	// the upstream made the client pay for it.
	Manifest []byte
}

// RateLimitState is what the upstream last told us about our remaining quota.
//
// Docker Hub's rate limit is a primary reason operators deploy a pull-through
// cache (§4), so the headroom is recorded even though nothing in this package
// acts on it. All fields are zero until an upstream sends the headers; Known
// distinguishes "we have quota 0 left" from "this upstream does not report
// quota", which is a difference a gauge must not blur.
type RateLimitState struct {
	// Known reports whether the upstream has ever sent rate-limit headers.
	Known bool

	// Limit is the quota for the window, from RateLimit-Limit.
	Limit int64

	// Remaining is what is left of it, from RateLimit-Remaining.
	Remaining int64

	// Window is the quota period, from the "w=" parameter on either header.
	// Zero when the upstream did not say.
	Window time.Duration

	// RetryAfter is the delay the upstream last demanded on a 429. Zero when
	// no 429 has been seen, or when the 429 carried no Retry-After.
	RetryAfter time.Duration

	// Until is when the last 429's Retry-After expires, on the injected clock.
	// Zero when no 429 has been seen. C-009 turns it into backoff; the client
	// records it and keeps serving.
	Until time.Time

	// Observed is when this state was recorded, on the injected clock.
	Observed time.Time
}

// Credentials supplies the username and password for one upstream.
//
// It is an interface so that the storage of the secret is somebody else's
// problem: C-003 supplies an implementation that decrypts from the metadata
// store on demand (ADR 0016), and this package never sees a plaintext secret
// for longer than one request, never logs one, and has no code path that
// returns one.
//
// A nil Credentials means anonymous, which is the normal case for a public
// upstream.
type Credentials interface {
	// Basic returns the username and password to authenticate with. It takes a
	// context because a real implementation reads and decrypts; an error means
	// the request fails rather than proceeding anonymously, because silently
	// downgrading to anonymous turns a broken keyfile into a confusing 404.
	Basic(ctx context.Context) (username, password string, err error)
}

// StaticCredentials is a fixed username and password, for tests and for a
// configuration that holds the secret in memory already.
type StaticCredentials struct {
	// Username is the upstream account.
	Username string
	// Password is its password or token.
	Password string
}

// Basic returns the fixed pair.
func (c StaticCredentials) Basic(context.Context) (string, string, error) {
	return c.Username, c.Password, nil
}

// StatusError reports an upstream response the client cannot use. It carries
// the status for the operator; callers match the sentinels.
type StatusError struct {
	// Status is the HTTP status code the upstream answered with.
	Status int
	// Method and Path are what was asked for, for the log line.
	Method string
	// Path is the upstream path that produced the status.
	Path string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("upstream %s %s: unexpected status %d", e.Method, e.Path, e.Status)
}

// Is maps the status onto the package's sentinels. The mapping is total: a
// status that names none of the specific conditions is an unavailability, so
// that no caller is ever handed an error it cannot classify.
func (e *StatusError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == 404 || e.Status == 410
	case ErrUnauthorized:
		return e.Status == 401 || e.Status == 403
	case ErrUpstreamUnavailable:
		return e.Status != 404 && e.Status != 410 && e.Status != 401 && e.Status != 403
	default:
		return false
	}
}

// RateLimitedError reports a 429 and the delay the upstream asked for.
type RateLimitedError struct {
	// RetryAfter is how long the upstream asked us to wait. It is zero when the
	// response carried no Retry-After, which HasRetryAfter distinguishes from
	// an honest "retry immediately".
	RetryAfter time.Duration
	// HasRetryAfter reports whether the upstream sent a Retry-After at all.
	HasRetryAfter bool
	// Path is the upstream path that was throttled.
	Path string
}

func (e *RateLimitedError) Error() string {
	if e.HasRetryAfter {
		return fmt.Sprintf("upstream %s: rate limited, retry after %s", e.Path, e.RetryAfter)
	}
	return fmt.Sprintf("upstream %s: rate limited, no retry-after given", e.Path)
}

// Is makes errors.Is(err, ErrRateLimited) true for this typed error.
func (e *RateLimitedError) Is(target error) bool { return target == ErrRateLimited }

// TransportError reports a failure below HTTP: the connection, DNS, TLS, or
// the client's own header-phase timeout.
type TransportError struct {
	// Op names what was being attempted, for the log line.
	Op string
	// Err is the underlying failure.
	Err error
}

func (e *TransportError) Error() string { return fmt.Sprintf("upstream %s: %v", e.Op, e.Err) }

// Unwrap exposes the underlying failure so a caller that wants the detail --
// C-008 classifying dial versus DNS versus timeout -- can have it.
func (e *TransportError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrUpstreamUnavailable) true for this typed error.
func (e *TransportError) Is(target error) bool { return target == ErrUpstreamUnavailable }

// RedirectError reports a redirect or an authentication realm the policy would
// not follow. It names both ends, because the pair is the whole story an
// operator needs.
type RedirectError struct {
	// From is where the redirect came from, empty for an authentication realm
	// that was refused before any redirect happened.
	From string
	// To is where it pointed.
	To string
	// Reason is why the policy refused.
	Reason string
}

func (e *RedirectError) Error() string {
	if e.From == "" {
		return fmt.Sprintf("upstream sent us to %s: %s", e.To, e.Reason)
	}
	return fmt.Sprintf("upstream redirect %s -> %s: %s", e.From, e.To, e.Reason)
}

// Is makes errors.Is(err, ErrRedirectRefused) true for this typed error.
func (e *RedirectError) Is(target error) bool { return target == ErrRedirectRefused }

// ReferenceError names the argument the client would not put in a URL.
type ReferenceError struct {
	// Kind is "repository", "tag", or "digest".
	Kind string
	// Value is what was rejected.
	Value string
	// Reason explains it for the operator.
	Reason string
}

func (e *ReferenceError) Error() string {
	return fmt.Sprintf("invalid %s %q: %s", e.Kind, e.Value, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidReference) true for this typed error.
func (e *ReferenceError) Is(target error) bool { return target == ErrInvalidReference }

// TooLargeError reports a body above the client's cap.
type TooLargeError struct {
	// Limit is the cap that was exceeded, in bytes.
	Limit int64
	// Path is the upstream path that produced the oversized body.
	Path string
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("upstream %s: manifest exceeds %d bytes", e.Path, e.Limit)
}

// Is makes errors.Is(err, ErrManifestTooLarge) true for this typed error.
func (e *TooLargeError) Is(target error) bool { return target == ErrManifestTooLarge }

// AuthError reports that authentication against the upstream could not be
// completed: a challenge that could not be parsed, a token endpoint that
// refused, or credentials that were rejected.
type AuthError struct {
	// Reason explains what went wrong, without ever naming the secret.
	Reason string
	// Err is the underlying failure, if there was one. It is never one of this
	// package's own classified errors: a token endpoint that was unreachable
	// or throttled is reported as unreachable or throttled, so that unwrapping
	// this cannot produce a second classification for one failure.
	Err error
}

func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("upstream authentication failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("upstream authentication failed: %s", e.Reason)
}

// Unwrap exposes the underlying failure.
func (e *AuthError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrUnauthorized) true for this typed error.
func (e *AuthError) Is(target error) bool { return target == ErrUnauthorized }
