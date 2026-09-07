// Package proxyserve serves a proxy repository's reads over the distribution
// API (C-018).
//
// It is the adapter between two packages that must not know about each other:
// internal/registry renders the wire format and knows nothing about upstreams,
// and internal/proxy fetches and caches and knows nothing about HTTP. This
// package is where a request becomes a fetch.
//
// It sits above both rather than inside either. internal/registry stays free
// of an upstream client, and internal/proxy stays free of the handler's
// vocabulary, which is what has let both be tested the way they have been --
// the fill path against a contract-equivalent fake, the handlers against
// golden responses.
//
// Three things happen here that happen nowhere else:
//
//   - **The namespace rewrite.** `nginx` becomes `library/nginx` on a Docker
//     Hub proxy (ADR 0005). Nothing before this point rewrites a remainder,
//     which is why C-015's traversal scenario has an assertion waiting for it.
//   - **Routing rules decide.** They evaluate the *rewritten* path, settled at
//     C-010's reconcile, and a refusal is reported as content that is not
//     there rather than as a rule that exists.
//   - **The error vocabulary collapses.** A proxy distinguishes a rejected
//     credential from a refused redirect from an unparseable manifest; a
//     client can act on "not here", "not now" and "try later". Collapsing the
//     first into the second is this package's job precisely so that the
//     handler's set can stay three wide.
package proxyserve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/repo"
)

// Store is the slice of the metadata store this package reads: the repository
// row, for its configuration. Declared by the consumer (§11).
type Store interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
}

// Clients supplies the upstream client for a proxy entity.
//
// It is an interface rather than a map because building one is not free and is
// not this package's business: a client carries decrypted credentials
// (C-003), a redirect policy with the entity's trusted hosts (C-014), and a
// rate-limit standing shared across every request to that upstream (C-009).
// The wiring that owns those (C-020) owns their lifetime too.
type Clients interface {
	// ClientFor returns the client for a proxy entity, or an error when one
	// cannot be built -- an unreadable credential, an upstream that does not
	// parse. That is a configuration failure, not a missing repository, and it
	// is reported as such rather than as a 404.
	ClientFor(ctx context.Context, entity string) (proxy.Client, error)
}

// Filler is the caching fetcher (C-004, C-005). *proxy.Filler satisfies it.
type Filler interface {
	ResolveTag(ctx context.Context, t proxy.Target, tag string) (proxy.TagResolution, error)
	Manifest(ctx context.Context, t proxy.Target, digest blob.Digest) (proxy.ManifestResult, error)
	Blob(ctx context.Context, t proxy.Target, digest blob.Digest) (proxy.BlobResult, error)
}

// TouchRecorder notes that cached content was served, so the LRU knows it is
// wanted (C-013). *cache.TouchBatcher satisfies it; nil records nothing.
type TouchRecorder interface {
	Touch(repo string, digest meta.Digest, kind meta.CachedKind)
}

// Server serves proxy repositories.
type Server struct {
	meta    Store
	clients Clients
	filler  Filler
	touches TouchRecorder

	tagTTL      time.Duration
	negativeTTL time.Duration
	offline     proxy.OfflineMode
	log         *slog.Logger
}

// Options configures a Server. Meta, Clients, and Filler are required.
type Options struct {
	// Meta reads repository rows for their configuration.
	Meta Store

	// Clients supplies per-entity upstream clients.
	Clients Clients

	// Filler fetches and caches.
	Filler Filler

	// Touches records cache hits for the LRU. Nil records none, which costs a
	// pull nothing and makes eviction rank on fill times alone.
	Touches TouchRecorder

	// TagTTL, NegativeTTL, and Offline are the deployment-wide defaults a
	// repository's own configuration overrides (ADR 0008).
	//
	// They are passed in rather than read from config here because a zero TTL
	// means "revalidate every pull" and is therefore not a missing value this
	// package may fill in -- whoever builds these from configuration applies
	// the 15-minute default, and a Server built with zeroes is deliberately
	// the conservative one.
	TagTTL      time.Duration
	NegativeTTL time.Duration
	Offline     proxy.OfflineMode

	// Log is the fallback logger. Nil means slog.Default.
	Log *slog.Logger
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Meta == nil:
		return nil, errInvalid("a metadata store is required")
	case opts.Clients == nil:
		return nil, errInvalid("an upstream client source is required")
	case opts.Filler == nil:
		return nil, errInvalid("a filler is required")
	}

	s := &Server{
		meta: opts.Meta, clients: opts.Clients, filler: opts.Filler, touches: opts.Touches,
		tagTTL: opts.TagTTL, negativeTTL: opts.NegativeTTL, offline: opts.Offline, log: opts.Log,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// ErrInvalidOptions reports a Server that cannot be built from what it was
// given. Callers assert with errors.Is.
var ErrInvalidOptions = errors.New("proxyserve: invalid options")

func errInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOptions, fmt.Sprintf(format, args...))
}

// Manifest serves a manifest read by tag or by digest.
//
// A digest is fetched directly: digests are immutable, so a cached one is
// served forever and never revalidated (ADR 0008). A tag goes through the
// lease first, which is the only mutable thing a proxy holds and the one place
// a stale answer can be served knowingly.
func (s *Server) Manifest(ctx context.Context, name, reference string) (registry.ServedManifest, error) {
	target, err := s.target(ctx, name)
	if err != nil {
		return registry.ServedManifest{}, err
	}

	digest, err := blob.ParseDigest(reference)
	if err != nil {
		// Not a digest, so a tag. Resolving it is what a pull-through cache is
		// for and where its TTL lives.
		resolution, resolveErr := s.filler.ResolveTag(ctx, target, reference)
		if resolveErr != nil {
			return registry.ServedManifest{}, s.classify(ctx, name, reference, resolveErr)
		}
		digest = resolution.Digest
	}

	result, err := s.filler.Manifest(ctx, target, digest)
	if err != nil {
		return registry.ServedManifest{}, s.classify(ctx, name, reference, err)
	}
	if result.Hit {
		s.touch(name, digest, meta.CachedManifestKind)
	}

	return registry.ServedManifest{
		Digest:    result.Digest,
		MediaType: result.MediaType,
		Payload:   result.Payload,
	}, nil
}

// Blob opens a blob by digest, streaming from the upstream and into the cache
// at once on a miss (C-004).
func (s *Server) Blob(ctx context.Context, name string, digest blob.Digest) (registry.ServedBlob, error) {
	target, err := s.target(ctx, name)
	if err != nil {
		return registry.ServedBlob{}, err
	}

	result, err := s.filler.Blob(ctx, target, digest)
	if err != nil {
		return registry.ServedBlob{}, s.classify(ctx, name, digest.String(), err)
	}
	if result.Hit {
		s.touch(name, digest, meta.CachedBlobKind)
	}

	return registry.ServedBlob{Content: result.Content, Size: result.Size, Digest: digest}, nil
}

// target builds the per-call Target for a content name: which upstream, under
// what path, with which TTLs.
//
// It reads the repository's configuration on every request. That is a store
// read per pull, and it is the honest starting point: a configuration change
// takes effect on the next request rather than whenever a cache happened to
// expire, and there is no invalidation to get wrong. A cache in front of it is
// a later optimisation with its own correctness argument to make.
func (s *Server) target(ctx context.Context, name string) (proxy.Target, error) {
	entity, remainder, err := repo.Split(name)
	if err != nil {
		// The handler validated the name before it decided anything, so this
		// is unreachable from a request; it fails closed rather than building
		// an upstream path from a name nothing checked.
		return proxy.Target{}, fmt.Errorf("%w: %s", registry.ErrContentUnknown, err)
	}

	record, err := s.meta.GetRepository(ctx, entity)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return proxy.Target{}, registry.ErrContentUnknown
	case err != nil:
		return proxy.Target{}, fmt.Errorf("read the repository configuration: %w", err)
	case record.Type != meta.Proxy:
		// The dispatcher only sends proxies here, so this is a wiring error
		// rather than a client's. It is checked anyway: this is the function
		// that decides which upstream to contact.
		return proxy.Target{}, fmt.Errorf("%w: %q is a %s, not a proxy",
			registry.ErrContentUnknown, entity, record.Type)
	}

	config, err := parseProxyConfig(record)
	if err != nil {
		return proxy.Target{}, err
	}

	upstreamPath, err := s.route(config, remainder)
	if err != nil {
		return proxy.Target{}, err
	}

	client, err := s.clients.ClientFor(ctx, entity)
	if err != nil {
		return proxy.Target{}, fmt.Errorf("build the upstream client for %q: %w", entity, err)
	}

	return proxy.Target{
		Repository:  name,
		Upstream:    upstreamPath,
		Remote:      remoteName(config.Upstream),
		Client:      client,
		TagTTL:      durationOr(config.TagTTL, s.tagTTL),
		NegativeTTL: durationOr(config.NegativeTTL, s.negativeTTL),
		Offline:     offlineOr(config.OfflineMode, s.offline),
	}, nil
}

// route applies the namespace rewrite and then the routing rules, in that
// order.
//
// The order is C-010's reconciled decision: rules exist so a proxy cannot
// become an open relay, which is a statement about what we fetch *from the
// upstream*, and under the other reading a `library/*` rule would deny `nginx`
// on the Docker Hub preset -- the single most common pull there is.
func (s *Server) route(config repo.ProxyConfig, remainder string) (string, error) {
	upstreamPath := rewriteNamespace(config.DefaultNamespace, remainder)

	rules, err := repo.CompileRoutingRules(config)
	if err != nil {
		return "", fmt.Errorf("compile the routing rules: %w", err)
	}
	decision, err := rules.Evaluate(upstreamPath)
	if err != nil {
		// A rewritten path the grammar refuses. It cannot become a request.
		return "", fmt.Errorf("%w: %s", registry.ErrContentUnknown, err)
	}
	if !decision.Allowed {
		// Reported as absent rather than as refused: which paths a proxy
		// admits is configuration, and a client that could tell "blocked"
		// from "not there" could map the rules by asking (ADR 0003).
		return "", registry.ErrContentUnknown
	}
	return upstreamPath, nil
}

// rewriteNamespace prefixes a single-segment remainder with the configured
// default namespace: the Docker Hub behaviour where `nginx` means
// `library/nginx` (ADR 0005).
//
// Only a single segment is rewritten. `library/nginx` and `myorg/app` already
// name their namespace, and prefixing those would make `library/library/nginx`
// -- which is why the rule is about the *shape* of the remainder rather than
// about whether it happens to resolve.
func rewriteNamespace(namespace, remainder string) string {
	if namespace == "" || strings.Contains(remainder, "/") {
		return remainder
	}
	return namespace + "/" + remainder
}

// parseProxyConfig reads a proxy entity's stored configuration.
func parseProxyConfig(record meta.Repository) (repo.ProxyConfig, error) {
	config, err := repo.ParseProxyConfig(record.Config)
	if err != nil {
		return repo.ProxyConfig{}, fmt.Errorf("parse the configuration of %q: %w", record.Name, err)
	}
	return config, nil
}

// classify collapses a proxy's error vocabulary into the three answers a
// client can act on.
//
// Everything that is not one of those is left to the handler to report as an
// internal error, and logged here with what it was: a rejected credential and
// a refused redirect are an operator's problem, and turning them into a 404
// would hide the one kind of failure that needs somebody to act.
func (s *Server) classify(ctx context.Context, name, reference string, err error) error {
	switch {
	case errors.Is(err, proxy.ErrNotFound):
		return registry.ErrContentUnknown
	case errors.Is(err, proxy.ErrRateLimited):
		return registry.ErrUpstreamThrottled
	case errors.Is(err, proxy.ErrUpstreamUnavailable):
		// Includes a manifest this registry cannot parse: a member answering
		// with something unusable is a member that did not serve the request
		// (C-004).
		return registry.ErrUpstreamUnavailable
	case errors.Is(err, proxy.ErrDigestMismatch):
		// The upstream served bytes that are not what it claimed. Nothing was
		// cached and nothing is served; to the client the content is not
		// available, and the incident is in the events and the log.
		s.log.ErrorContext(ctx, "upstream served content that did not match its digest",
			"repository", name, "reference", reference)
		return registry.ErrUpstreamUnavailable
	case errors.Is(err, proxy.ErrUnauthorized):
		// A configuration problem, not a missing image. It is reported as an
		// unavailable upstream so a client retries rather than caches a
		// not-found, and loudly so an operator sees it.
		s.log.ErrorContext(ctx, "upstream refused our credentials",
			"repository", name, "reference", reference, "error", err)
		return registry.ErrUpstreamUnavailable
	default:
		// Left as it is. The handler renders an unclassified failure as an
		// internal error, which is what a failure nobody classified deserves:
		// turning it into a 404 would hide a bug in a pull path.
		return err
	}
}

// touch records that cached content was served. It never blocks and never
// fails: the caller is a pull that has already succeeded (C-013).
func (s *Server) touch(name string, digest blob.Digest, kind meta.CachedKind) {
	if s.touches == nil {
		return
	}
	s.touches.Touch(name, meta.Digest(digest), kind)
}

// durationOr parses a repository's override, falling back to the deployment
// default when it is unset.
//
// A malformed value cannot reach here -- the configuration was validated when
// it was stored (C-001) -- and if one somehow did, the deployment default is
// the safe reading rather than zero, which for a tag TTL would silently mean
// "revalidate every pull" and for a negative TTL "never cache an absence".
func durationOr(override string, fallback time.Duration) time.Duration {
	if override == "" {
		return fallback
	}
	// The error is deliberately dropped rather than branched on. A stored
	// configuration was validated when it was written (C-001), so an
	// unparseable duration here means a row nothing wrote through the API --
	// and such a row is refused earlier, when the configuration is parsed.
	// What time.ParseDuration returns for one is zero, which is the
	// conservative reading in both places it lands: revalidate every pull, and
	// remember no absence at all.
	parsed, _ := time.ParseDuration(override)
	return parsed
}

// offlineOr resolves the degraded-mode setting the same way.
func offlineOr(override string, fallback proxy.OfflineMode) proxy.OfflineMode {
	switch proxy.OfflineMode(override) {
	case proxy.ServeStale, proxy.Strict:
		return proxy.OfflineMode(override)
	default:
		return fallback
	}
}

// remoteName is the upstream's host, for events and logs. A URL can carry
// credentials and these strings leave the process (§4).
func remoteName(upstream string) string {
	return strings.TrimPrefix(strings.TrimPrefix(upstream, "https://"), "http://")
}

// Server implements the registry's delegate contract.
var _ registry.ContentServer = (*Server)(nil)
