package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/reponame"
)

// DefaultRequestTimeout bounds the header phase of one upstream exchange,
// redirects included. It does not bound a blob body: a layer legitimately
// takes minutes on a slow link, so once the headers are in, the transfer is
// bounded by the caller's context instead. That seam is deliberate -- the
// caller filling a cache entry (C-004) is the only layer that knows how long a
// pull may reasonably take.
const DefaultRequestTimeout = 30 * time.Second

// DefaultMaxManifestBytes caps a manifest body. It matches the registry's own
// push-side cap (internal/config): a manifest we would refuse to store is one
// there is no point transferring.
const DefaultMaxManifestBytes = 4 << 20

// tagPattern is the distribution spec's tag grammar, anchored.
//
// It is a second copy of the grammar the registry handlers enforce on the way
// in, which is a copy too many; the right home is a leaf package beside
// internal/reponame, and moving it is a follow-up rather than part of this
// task because it edits a package this one is not allowed to touch. Until
// then, the two are identical and a change to either must change both.
var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// acceptManifests is the Accept header the client sends when asking for a
// manifest. Every media type trove can store is offered, so an upstream that
// content-negotiates gives us something we can keep rather than a converted
// schema 1 document.
var acceptManifests = strings.Join([]string{
	artifact.MediaTypeOCIManifest,
	artifact.MediaTypeOCIIndex,
	artifact.MediaTypeDockerManifest,
	artifact.MediaTypeDockerList,
}, ", ")

// Options configures a RegistryClient. Only Upstream is required.
type Options struct {
	// Upstream is the remote registry's root URL: scheme and host, nothing
	// else. It is validated the same way repo.ProxyConfig validates it, so a
	// configuration that stored cleanly builds a client cleanly.
	Upstream string

	// Credentials authenticate to the upstream. Nil is anonymous.
	Credentials Credentials

	// Redirects is the SSRF posture. The zero value is the strict one.
	Redirects RedirectPolicy

	// Transport is the HTTP transport. Nil means http.DefaultTransport. It is
	// injectable so that the whole client can be tested without a network, and
	// so that an operator's proxy or CA settings arrive from one place.
	Transport http.RoundTripper

	// Now is the clock. Nil means time.Now. Token expiry, Retry-After dates,
	// and the rate-limit state all read it, and nothing in this package reads
	// the wall clock directly (§7).
	Now func() time.Time

	// RequestTimeout bounds the header phase of one exchange. Zero means
	// DefaultRequestTimeout.
	RequestTimeout time.Duration

	// MaxManifestBytes caps a manifest body. Zero means
	// DefaultMaxManifestBytes.
	MaxManifestBytes int64

	// UserAgent identifies trove to the upstream. Empty means Go's default.
	UserAgent string
}

// RegistryClient is a Client over the distribution API, spoken with net/http.
type RegistryClient struct {
	base        *url.URL
	creds       Credentials
	redirects   RedirectPolicy
	http        *http.Client
	now         func() time.Time
	timeout     time.Duration
	maxManifest int64
	userAgent   string

	// mu guards everything the client learns from an upstream while running.
	mu         sync.Mutex
	auth       map[string]cachedAuth
	basicUntil time.Time
	rate       RateLimitState
}

// RegistryClient implements Client.
var _ Client = (*RegistryClient)(nil)

// New builds a client for one upstream.
//
// It refuses an upstream URL that is anything but a scheme and a host: the
// /v2/ prefix and the repository path are added per request, credentials in a
// URL are a leak waiting to be logged, and a query string on a registry root
// means the operator meant something the client cannot honour.
func New(opts Options) (*RegistryClient, error) {
	base, err := url.Parse(opts.Upstream)
	switch {
	case opts.Upstream == "":
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: "required"}
	case err != nil:
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: err.Error()}
	case base.Scheme != "http" && base.Scheme != "https":
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: "scheme must be http or https"}
	case base.Host == "":
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: "must name a host"}
	case base.User != nil:
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: "must not carry credentials"}
	case base.Path != "" && base.Path != "/":
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: "must be the registry root"}
	case base.RawQuery != "" || base.Fragment != "":
		return nil, &ReferenceError{Kind: "upstream", Value: opts.Upstream, Reason: "must not carry a query or fragment"}
	}
	base.Path = ""

	client := &RegistryClient{
		base:        base,
		creds:       opts.Credentials,
		redirects:   opts.Redirects,
		now:         opts.Now,
		timeout:     opts.RequestTimeout,
		maxManifest: opts.MaxManifestBytes,
		userAgent:   opts.UserAgent,
		auth:        make(map[string]cachedAuth),
	}
	if client.now == nil {
		client.now = time.Now
	}
	if client.timeout <= 0 {
		client.timeout = DefaultRequestTimeout
	}
	if client.maxManifest <= 0 {
		client.maxManifest = DefaultMaxManifestBytes
	}
	client.http = &http.Client{
		Transport: opts.Transport,
		// Redirects are followed by hand so that every hop is checked against
		// the policy and so that credentials are dropped when the chain leaves
		// the upstream's family. Delegating that to net/http would mean
		// trusting a default nobody in this project chose.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, nil
}

// ResolveTag resolves a tag to a digest, conditionally. See Client.
func (c *RegistryClient) ResolveTag(ctx context.Context, repository, tag string, cond Conditional) (Resolution, error) {
	if err := validateRepository(repository); err != nil {
		return Resolution{}, err
	}
	if err := validateTag(tag); err != nil {
		return Resolution{}, err
	}
	if cond.Digest != "" {
		if err := cond.Digest.Validate(); err != nil {
			return Resolution{}, &ReferenceError{Kind: "digest", Value: cond.Digest.String(), Reason: err.Error()}
		}
	}

	path := manifestPath(repository, tag)
	scope := scopeFor(repository)

	if !cond.IsZero() {
		resolution, settled, err := c.revalidate(ctx, path, scope, cond)
		if err != nil {
			return Resolution{}, err
		}
		if settled {
			return resolution, nil
		}
	}
	return c.fetchTag(ctx, path, scope, cond)
}

// revalidate asks the upstream whether the tag still points where the caller
// thinks, without transferring a manifest.
//
// It reports settled=false when the upstream answered in a way that does not
// decide the question -- no digest header, or a status that says the upstream
// dislikes HEAD rather than that the tag is gone -- and the caller falls
// through to a full fetch. Falling through rather than failing is what keeps
// the client working against the several registries and corporate proxies that
// answer HEAD with 405.
func (c *RegistryClient) revalidate(ctx context.Context, path, scope string, cond Conditional) (Resolution, bool, error) {
	header := http.Header{}
	header.Set("Accept", acceptManifests)
	if cond.ETag != "" {
		header.Set("If-None-Match", cond.ETag)
	}

	resp, err := c.request(ctx, http.MethodHead, path, header, scope)
	if err != nil {
		return Resolution{}, false, err
	}
	defer closeBody(resp)

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return Resolution{
			Changed:   false,
			Digest:    cond.Digest,
			MediaType: mediaTypeOf(resp),
			ETag:      firstNonEmpty(resp.Header.Get("ETag"), cond.ETag),
			Size:      resp.ContentLength,
		}, true, nil

	case resp.StatusCode == http.StatusOK:
		declared := resp.Header.Get("Docker-Content-Digest")
		if declared == "" || cond.Digest == "" {
			return Resolution{}, false, nil
		}
		digest, err := blob.ParseDigest(declared)
		if err != nil {
			// An upstream that cannot spell its own digest gets no benefit of
			// the doubt on the cheap path; the full fetch verifies what it
			// actually sends.
			return Resolution{}, false, nil
		}
		if digest != cond.Digest {
			return Resolution{}, false, nil
		}
		return Resolution{
			Changed:   false,
			Digest:    cond.Digest,
			MediaType: mediaTypeOf(resp),
			ETag:      firstNonEmpty(resp.Header.Get("ETag"), cond.ETag),
			Size:      resp.ContentLength,
		}, true, nil

	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		// Definitive: the tag is gone, and a GET would only ask again.
		return Resolution{}, false, c.statusError(resp, http.MethodHead, path)

	default:
		err := c.statusError(resp, http.MethodHead, path)
		if isUnauthorized(err) || isRateLimited(err) {
			return Resolution{}, false, err
		}
		// Anything else -- 405, 501, a broken middlebox -- is not an answer to
		// the question that was asked. The GET decides.
		return Resolution{}, false, nil
	}
}

// fetchTag fetches a manifest by tag and works out whether it changed.
func (c *RegistryClient) fetchTag(ctx context.Context, path, scope string, cond Conditional) (Resolution, error) {
	header := http.Header{}
	header.Set("Accept", acceptManifests)
	if cond.ETag != "" {
		header.Set("If-None-Match", cond.ETag)
	}

	resp, err := c.request(ctx, http.MethodGet, path, header, scope)
	if err != nil {
		return Resolution{}, err
	}
	defer closeBody(resp)

	if resp.StatusCode == http.StatusNotModified {
		return Resolution{
			Changed:   false,
			Digest:    cond.Digest,
			MediaType: mediaTypeOf(resp),
			ETag:      firstNonEmpty(resp.Header.Get("ETag"), cond.ETag),
			Size:      -1,
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, c.statusError(resp, http.MethodGet, path)
	}

	body, err := c.readManifest(resp, path)
	if err != nil {
		return Resolution{}, err
	}

	// The digest is computed, never taken on trust. When the upstream also
	// declares one, the two must agree: a registry that labels content with a
	// digest it does not hash to is either broken or lying, and both are
	// reasons not to cache from it.
	digest := blob.FromBytes(blob.SHA256, body)
	if declared := resp.Header.Get("Docker-Content-Digest"); declared != "" {
		parsed, err := blob.ParseDigest(declared)
		if err != nil {
			return Resolution{}, &ReferenceError{
				Kind:   "digest",
				Value:  declared,
				Reason: "upstream declared an unparseable Docker-Content-Digest",
			}
		}
		if err := verifyBytes(body, parsed); err != nil {
			return Resolution{}, err
		}
		digest = parsed
	}

	resolution := Resolution{
		Changed:   digest != cond.Digest,
		Digest:    digest,
		MediaType: mediaTypeOf(resp),
		ETag:      resp.Header.Get("ETag"),
		Size:      int64(len(body)),
	}
	if resolution.Changed {
		resolution.Manifest = body
	}
	return resolution, nil
}

// FetchManifest fetches a manifest by digest. See Client.
func (c *RegistryClient) FetchManifest(ctx context.Context, repository string, digest blob.Digest) ([]byte, string, error) {
	if err := validateRepository(repository); err != nil {
		return nil, "", err
	}
	if err := digest.Validate(); err != nil {
		return nil, "", &ReferenceError{Kind: "digest", Value: digest.String(), Reason: err.Error()}
	}

	path := manifestPath(repository, digest.String())
	header := http.Header{}
	header.Set("Accept", acceptManifests)

	resp, err := c.request(ctx, http.MethodGet, path, header, scopeFor(repository))
	if err != nil {
		return nil, "", err
	}
	defer closeBody(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, "", c.statusError(resp, http.MethodGet, path)
	}
	body, err := c.readManifest(resp, path)
	if err != nil {
		return nil, "", err
	}
	if err := verifyBytes(body, digest); err != nil {
		// Nothing is returned alongside the error. A caller holding both the
		// bytes and the error is a caller that can cache the bytes by
		// accident, and this is the exact content an attacker would want
		// cached.
		return nil, "", err
	}
	return body, mediaTypeOf(resp), nil
}

// FetchBlob opens a blob by digest for streaming. See Client.
func (c *RegistryClient) FetchBlob(ctx context.Context, repository string, digest blob.Digest) (io.ReadCloser, int64, error) {
	if err := validateRepository(repository); err != nil {
		return nil, 0, err
	}
	if err := digest.Validate(); err != nil {
		return nil, 0, &ReferenceError{Kind: "digest", Value: digest.String(), Reason: err.Error()}
	}

	path := "/v2/" + repository + "/blobs/" + digest.String()
	resp, err := c.request(ctx, http.MethodGet, path, http.Header{}, scopeFor(repository))
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		defer closeBody(resp)
		return nil, 0, c.statusError(resp, http.MethodGet, path)
	}

	// The body is handed to blob's verified reader rather than copied through
	// anything here: verification of untrusted bytes is ADR 0007's job, and a
	// second implementation of it in this package would be a second place for
	// it to be subtly wrong.
	reader, err := blob.NewVerifiedReader(ctx, resp.Body, blob.Descriptor{
		Digest: digest,
		Size:   resp.ContentLength,
	}, nil)
	if err != nil {
		defer closeBody(resp)
		return nil, 0, &ReferenceError{Kind: "digest", Value: digest.String(), Reason: err.Error()}
	}
	return reader, resp.ContentLength, nil
}

// readManifest reads a bounded manifest body.
func (c *RegistryClient) readManifest(resp *http.Response, path string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxManifest+1))
	if err != nil {
		return nil, &TransportError{Op: "read manifest " + path, Err: err}
	}
	if int64(len(body)) > c.maxManifest {
		return nil, &TooLargeError{Limit: c.maxManifest, Path: path}
	}
	return body, nil
}

// verifyBytes checks a buffered body against the digest it was requested
// under, using blob's verifier so that the comparison, the error type, and the
// truncation semantics are the same ones the rest of trove uses.
func verifyBytes(body []byte, digest blob.Digest) error {
	_, err := blob.Copy(io.Discard, bytes.NewReader(body), digest)
	return err
}

// request performs one logical upstream request, including the token dance.
//
// A 401 is answered once: the challenge is parsed, an authorization is
// obtained, and the request is repeated. A second 401 is returned as one --
// retrying an authentication that just failed is how a client turns a
// misconfiguration into a lockout.
func (c *RegistryClient) request(ctx context.Context, method, path string, header http.Header, scope string) (*http.Response, error) {
	target := *c.base
	target.Path = path

	auth, err := c.authorizationFor(ctx, scope)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, method, &target, header, auth, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	ch, ok := parseChallenge(resp.Header.Values("Www-Authenticate"))
	closeBody(resp)
	if !ok {
		return nil, &AuthError{Reason: "upstream demanded authentication with no challenge we understand"}
	}
	auth, err = c.authorize(ctx, ch, scope)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, method, &target, header, auth, "")
}

// send performs one HTTP exchange, following redirects under the policy.
//
// credentialHost, when not empty, is one host outside the upstream's family
// that may receive the Authorization header on the first hop: the
// authorization server a challenge named, which at every large registry lives
// on a different host from the registry itself. It never applies to a redirect
// target, so a token endpoint cannot bounce our password onward.
func (c *RegistryClient) send(ctx context.Context, method string, target *url.URL, header http.Header, auth authorization, credentialHost string) (*http.Response, error) {
	// The timeout covers the header phase of the whole chain and is stopped
	// the moment the final response's headers arrive, so that a large blob is
	// not cut off mid-body by a timeout meant for a stalled connection. The
	// cancel travels with the body and fires when the caller closes it.
	reqCtx, cancel := context.WithCancel(ctx)
	// The timeout is recorded as well as acted on: cancelling the request
	// context is how a timeout is enforced, but a caller must be able to tell
	// "the upstream went quiet" from "I cancelled this myself", and both look
	// like context.Canceled from inside net/http.
	var timedOut atomic.Bool
	timer := time.AfterFunc(c.timeout, func() {
		timedOut.Store(true)
		cancel()
	})
	abandon := func() {
		timer.Stop()
		cancel()
	}

	current := target
	for hop := 0; ; hop++ {
		req, err := http.NewRequestWithContext(reqCtx, method, current.String(), nil)
		if err != nil {
			abandon()
			return nil, &TransportError{Op: "build request", Err: err}
		}
		c.applyHeaders(req, header, auth, current, hop == 0 && credentialHost != "")

		resp, err := c.http.Do(req)
		if err != nil {
			abandon()
			return nil, c.transportError(ctx, method+" "+redacted(current), err, timedOut.Load())
		}
		if !isRedirect(resp.StatusCode) {
			timer.Stop()
			c.observeRateLimit(resp)
			resp.Body = &releasingBody{ReadCloser: resp.Body, release: cancel}
			return resp, nil
		}

		location := resp.Header.Get("Location")
		drain(resp)
		next, err := current.Parse(location)
		if err != nil || location == "" {
			abandon()
			return nil, &RedirectError{
				From:   redacted(current),
				To:     location,
				Reason: "unusable Location header",
			}
		}
		if err := c.redirects.Follow(c.base, current, next, hop+1); err != nil {
			abandon()
			return nil, err
		}
		current = next
	}
}

// applyHeaders builds one request's headers, deciding in one place whether the
// Authorization header may travel to this host.
func (c *RegistryClient) applyHeaders(req *http.Request, header http.Header, auth authorization, current *url.URL, trustHost bool) {
	credential := auth.header
	for key, values := range header {
		if strings.EqualFold(key, "Authorization") {
			if credential == "" && len(values) > 0 {
				credential = values[0]
			}
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if credential != "" && (trustHost || c.sameFamily(current)) {
		req.Header.Set("Authorization", credential)
	}
}

// sameFamily reports whether a URL is the upstream itself or one of its
// subdomains. Only those hosts see a credential: a CDN a registry redirects
// blobs to is reached with a signed URL and has no business holding the
// operator's registry password.
func (c *RegistryClient) sameFamily(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	base := strings.ToLower(c.base.Hostname())
	return host == base || (base != "" && strings.HasSuffix(host, "."+base))
}

// errHeaderTimeout is what a request that ran out of time reports underneath
// the TransportError, in place of the context.Canceled that enforcing the
// timeout produced. Reporting the cancellation would tell a caller its own
// context was cancelled, which is a different fault with a different fix.
var errHeaderTimeout = errors.New("timed out waiting for response headers")

// transportError classifies a failure below HTTP. The caller's own
// cancellation is returned as itself so that errors.Is against context.Canceled
// or context.DeadlineExceeded still works; our timeout and the real network
// failures become unavailability.
func (c *RegistryClient) transportError(ctx context.Context, op string, err error, timedOut bool) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("upstream %s: %w", op, ctxErr)
	}
	if timedOut {
		return &TransportError{Op: op, Err: fmt.Errorf("%w after %s", errHeaderTimeout, c.timeout)}
	}
	return &TransportError{Op: op, Err: err}
}

// statusError maps a response the client cannot use onto the sentinels.
func (c *RegistryClient) statusError(resp *http.Response, method, path string) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter, ok := parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
		return &RateLimitedError{RetryAfter: retryAfter, HasRetryAfter: ok, Path: path}
	}
	return &StatusError{Status: resp.StatusCode, Method: method, Path: path}
}

// releasingBody releases the request's context when the body is closed, so a
// streamed blob does not leak a context for as long as the caller holds it.
type releasingBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

// Close closes the underlying body and releases the request context.
func (b *releasingBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

// manifestPath builds the manifest URL path for a reference that has already
// been validated.
func manifestPath(repository, reference string) string {
	return "/v2/" + repository + "/manifests/" + reference
}

// validateRepository refuses anything that is not a legal repository name
// before it becomes part of an upstream URL (§11). The grammar is
// internal/reponame's, shared with authorization and the registry handlers.
func validateRepository(repository string) error {
	if err := reponame.Validate(repository); err != nil {
		return &ReferenceError{Kind: "repository", Value: repository, Reason: err.Error()}
	}
	return nil
}

// validateTag refuses anything that is not a legal tag.
func validateTag(tag string) error {
	if !tagPattern.MatchString(tag) {
		return &ReferenceError{
			Kind:   "tag",
			Value:  tag,
			Reason: "must match the distribution spec tag grammar",
		}
	}
	return nil
}

// mediaTypeOf reads the response's media type with parameters stripped.
func mediaTypeOf(resp *http.Response) string {
	value, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	return strings.TrimSpace(value)
}

// firstNonEmpty returns the first of its arguments that is not empty.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// isRedirect reports whether a status is one the client follows.
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// isUnauthorized and isRateLimited keep the revalidation fallback honest: a
// HEAD that failed for a reason a GET would also fail for is returned, not
// retried with a different verb.
func isUnauthorized(err error) bool { return errors.Is(err, ErrUnauthorized) }

func isRateLimited(err error) bool { return errors.Is(err, ErrRateLimited) }

// drain reads a little of a response body before closing it, so the
// connection can be reused. The bound is there because the body belongs to an
// upstream that may not have meant well.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	closeBody(resp)
}

// closeBody closes a response body, discarding the error: there is nothing a
// caller can do about a failed close on a body it has finished with.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
