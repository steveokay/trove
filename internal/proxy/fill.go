package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
)

// CacheStore is the slice of the metadata store the fill path uses: the cached
// content family and nothing else (ADR 0009).
//
// It is declared here, by the consumer, and it names no hosted method. A filler
// therefore cannot read, write, or delete hosted content however it is wired,
// and the wiring cannot hand it the ability by mistake -- there is no argument
// through which the hosted half arrives.
type CacheStore interface {
	GetCachedManifest(ctx context.Context, repo string, digest meta.Digest) (meta.CachedManifest, error)
	PutCachedManifest(ctx context.Context, m meta.CachedManifest, refs []meta.CachedManifestRef) error
	GetCachedBlob(ctx context.Context, repo string, digest meta.Digest) (meta.CachedBlob, error)
	PutCachedBlob(ctx context.Context, b meta.CachedBlob) error

	// The lease half (C-005). It is in the same interface because it is the
	// same table family and the same subsystem: a resolution writes a lease and
	// the manifest it names, and splitting them would mean two views of one
	// cache that could be wired to different stores.
	GetTagLease(ctx context.Context, repo, tag string) (meta.TagLease, error)
	PutTagLease(ctx context.Context, lease meta.TagLease) error
	DeleteTagLease(ctx context.Context, repo, tag string) error
}

// CacheBlobStore is the cache-rooted blob store (ADR 0007): a store that can
// also open upload sessions, because a fill streams to the client and to disk
// at once and only publishes the bytes once the whole of them verified.
//
// It is a different instance from the hosted store, over a disjoint root,
// chosen at wiring time. Nothing here can name the hosted one.
type CacheBlobStore interface {
	blob.Store
	blob.Uploader
}

// Publisher accepts events. The bus satisfies it; a nil Publisher means the
// fills happen unobserved, which is the right behaviour for a test and for a
// deployment whose event system is not wired yet.
type Publisher interface {
	Publish(ctx context.Context, e event.Event)
}

// Target names one proxy repository's upstream for a single fill.
//
// It is a per-call argument rather than a field on the Filler because the
// repository, its upstream namespace, and its client are all per-repository
// configuration, and one process serves many proxies. The filler holds only
// what every fill shares: the cache, the clock, and the event sink.
type Target struct {
	// Repository is the full trove content name the fill is stored under,
	// e.g. `dockerhub/library/nginx`. Its entity must be a proxy; the store
	// refuses the write otherwise.
	Repository string

	// Upstream is the repository path at the remote, e.g. `library/nginx`.
	// Namespace rewriting and routing rules (C-010) have already run: a name
	// that reaches here has been decided to be allowed.
	Upstream string

	// Remote names the upstream registry for events and logs -- `docker.io`,
	// not a URL. A URL can carry credentials and these payloads leave the
	// process (§4).
	Remote string

	// Client fetches from that remote.
	Client Client

	// TagTTL is how long a tag's resolution may be reused before it is
	// revalidated against the upstream (ADR 0008). It is the repository's
	// current setting, read on every resolution rather than taken from the
	// stored lease, so lowering it takes effect on the next pull.
	//
	// **Zero means revalidate on every pull** (Q11) and is therefore not a
	// missing value the package can fill in: the deployment-wide default of 15
	// minutes is applied by whoever builds the Target from configuration, and
	// a zero-value Target is deliberately the conservative one.
	TagTTL time.Duration

	// Offline is what to do when the upstream cannot be reached and the lease
	// has expired. The zero value is serve-stale, which is the configured
	// default and the one that keeps a cluster running.
	Offline OfflineMode
}

// OfflineMode is a proxy's degraded-mode behaviour (ADR 0008).
type OfflineMode string

// The modes. The zero value is ServeStale on purpose: an unset mode must keep
// pulls working, because the alternative fails a cluster's deploys over a
// configuration field somebody did not know to set.
const (
	// ServeStale serves cached content past its revalidation deadline when the
	// upstream is unreachable, marked stale and reported as an event.
	ServeStale OfflineMode = "serve-stale"

	// Strict fails the pull instead. It exists for deployments that would
	// rather stop than serve an answer they could not confirm.
	Strict OfflineMode = "strict"
)

// strict reports whether the mode refuses to serve stale content.
func (m OfflineMode) strict() bool { return m == Strict }

func (t Target) validate() error {
	switch {
	case t.Repository == "":
		return &ReferenceError{Kind: "repository", Value: t.Repository, Reason: "required"}
	case t.Upstream == "":
		return &ReferenceError{Kind: "repository", Value: t.Upstream, Reason: "upstream repository is required"}
	case t.Client == nil:
		return &ReferenceError{Kind: "repository", Value: t.Repository, Reason: "no upstream client"}
	default:
		return nil
	}
}

// ManifestResult is a manifest served from a proxy repository.
type ManifestResult struct {
	// Digest is what the payload hashes to. It is the digest that was asked
	// for: content that did not verify never becomes a result.
	Digest blob.Digest

	// MediaType is the manifest's media type.
	MediaType string

	// Payload is the manifest body.
	Payload []byte

	// Hit reports that the cache answered without an upstream request.
	Hit bool

	// Cached reports that the content is in the cache now -- true for a hit,
	// and true for a fill that stored what it fetched. It is false when the
	// fill served content it could not store, which is a degraded state worth
	// seeing rather than an error worth failing a pull for.
	Cached bool
}

// BlobResult is a blob opened from a proxy repository.
type BlobResult struct {
	// Content streams the blob and verifies as it goes: an upstream body that
	// does not hash to the requested digest ends short with ErrDigestMismatch
	// rather than reaching the client intact (ADR 0007). The caller must Close
	// it, which is also what cancels an incomplete fill.
	Content io.ReadCloser

	// Size is the blob's length, or -1 when an upstream sent none.
	Size int64

	// Hit reports that the cache answered without an upstream request.
	Hit bool
}

// Filler fetches content from an upstream by digest and caches it (C-004).
//
// Digests are immutable, so everything here is cached indefinitely and never
// revalidated: eviction is the only way it leaves (ADR 0008). Tags are leases
// and are C-005's; nothing in this file knows what a tag is.
//
// Two rules run through it:
//
//   - Content that did not verify is never cached and never served. The client
//     verifies (C-002) and this package does not repeat the check, because one
//     verification with one error is what makes a mismatch mean the same thing
//     everywhere it is handled.
//   - A cache failure is not a pull failure. The bytes are already correct and
//     already in hand; refusing to serve them because the disk or the metadata
//     store would not take a copy turns a degraded cache into an outage. Those
//     failures are logged and reported through the result rather than returned.
//     The asymmetry is deliberate and is the reason both result types carry a
//     flag saying whether the cache actually holds what was served.
type Filler struct {
	blobs     CacheBlobStore
	meta      CacheStore
	events    Publisher
	coalescer Coalescer
	now       func() time.Time
	log       *slog.Logger
}

// FillerOptions configures a Filler.
type FillerOptions struct {
	// Blobs is the cache-rooted blob store. Required.
	Blobs CacheBlobStore

	// Meta is the cached-content half of the metadata store. Required.
	Meta CacheStore

	// Events receives cache.filled and blob.corrupt. Nil means nobody is
	// listening.
	Events Publisher

	// Coalescer collapses concurrent identical fills (C-006). Nil means a
	// fresh in-process group, which is the v1 answer (ADR 0018); the field
	// exists so a deployment that later coordinates across processes can
	// supply one without this package changing.
	Coalescer Coalescer

	// Now is the clock. Nil means time.Now. Cached-at and last-accessed
	// timestamps read it and nothing in this package reads the wall clock
	// directly (§7).
	Now func() time.Time

	// Log is the logger. Nil means slog.Default.
	Log *slog.Logger
}

// NewFiller builds a Filler. It fails when the cache it is supposed to fill is
// missing, because a filler with no cache would silently be a pass-through
// proxy -- correct on every request and wrong about the whole point.
func NewFiller(opts FillerOptions) (*Filler, error) {
	switch {
	case opts.Blobs == nil:
		return nil, fmt.Errorf("%w: a cache blob store is required", ErrInvalidReference)
	case opts.Meta == nil:
		return nil, fmt.Errorf("%w: a cache metadata store is required", ErrInvalidReference)
	}

	f := &Filler{
		blobs:     opts.Blobs,
		meta:      opts.Meta,
		events:    opts.Events,
		coalescer: opts.Coalescer,
		now:       opts.Now,
		log:       opts.Log,
	}
	if f.coalescer == nil {
		f.coalescer = NewSingleFlight()
	}
	if f.now == nil {
		f.now = time.Now
	}
	if f.log == nil {
		f.log = slog.Default()
	}
	return f, nil
}

// Manifest returns a manifest by digest, from the cache or from the upstream.
//
// A cache miss fetches, verifies, parses, and stores the manifest before
// returning it. Parsing is not decoration: the edges it produces are what
// records the layers this fill brought in, and a manifest trove cannot parse is
// one it cannot account for, gate, or scan -- so it is refused as an unusable
// upstream answer rather than cached as an opaque blob. It is the same refusal
// the push path makes for the same media types (R-002).
//
// Errors are the Client's closed sentinel set, so a caller -- group resolution
// especially (C-011) -- classifies a fill exactly as it classifies a fetch.
func (f *Filler) Manifest(ctx context.Context, t Target, digest blob.Digest) (ManifestResult, error) {
	if err := t.validate(); err != nil {
		return ManifestResult{}, err
	}
	if err := digest.Validate(); err != nil {
		return ManifestResult{}, &ReferenceError{Kind: "digest", Value: string(digest), Reason: err.Error()}
	}

	result, err := coalesce(ctx, f.coalescer, manifestKey(t.Repository, digest),
		func(ctx context.Context) (ManifestResult, error) { return f.manifest(ctx, t, digest) })
	if err != nil {
		return ManifestResult{}, err
	}

	// The payload is copied out of the shared result. Without coalescing every
	// caller held its own bytes -- each store read returns a fresh slice -- and
	// a caller that could suddenly be handed somebody else's buffer, depending
	// on whether it happened to race, is a data race waiting for the first
	// caller that writes into what it was given.
	result.Payload = append([]byte(nil), result.Payload...)
	return result, nil
}

// manifest is Manifest's body, run once per digest across concurrent callers.
func (f *Filler) manifest(ctx context.Context, t Target, digest blob.Digest) (ManifestResult, error) {
	cached, err := f.meta.GetCachedManifest(ctx, t.Repository, meta.Digest(digest))
	switch {
	case err == nil:
		return ManifestResult{
			Digest:    digest,
			MediaType: cached.MediaType,
			Payload:   cached.Payload,
			Hit:       true,
			Cached:    true,
		}, nil
	case !errors.Is(err, meta.ErrNotFound):
		// The cache could not be consulted. Falling through to the upstream
		// would work, but it would also turn a broken metadata store into a
		// silent stampede against somebody else's registry, which is the
		// failure mode a pull-through cache exists to prevent.
		return ManifestResult{}, fmt.Errorf("read the cached manifest: %w", err)
	}

	payload, mediaType, err := t.Client.FetchManifest(ctx, t.Upstream, digest)
	if err != nil {
		if errors.Is(err, ErrDigestMismatch) {
			f.publishCorrupt(ctx, t, digest)
		}
		return ManifestResult{}, err
	}

	return f.storeManifest(ctx, t, digest, payload, mediaType)
}

// storeManifest parses upstream manifest bytes, caches them, and reports what
// was served.
//
// It is shared with tag resolution (C-005), which arrives at the same point by
// a different road: a revalidation that found the tag moved already holds the
// new manifest, and re-fetching it by digest to reach this code would pay for
// the same bytes twice.
func (f *Filler) storeManifest(ctx context.Context, t Target, digest blob.Digest,
	payload []byte, mediaType string,
) (ManifestResult, error) {
	parsed, err := artifact.Parse(mediaType, payload)
	if err != nil {
		return ManifestResult{}, &UnusableContentError{
			Repository: t.Upstream,
			Digest:     digest,
			Reason:     err.Error(),
		}
	}

	result := ManifestResult{Digest: digest, MediaType: parsed.MediaType, Payload: payload}

	at := f.now()
	record := meta.CachedManifest{
		Repository:   t.Repository,
		Digest:       meta.Digest(digest),
		MediaType:    parsed.MediaType,
		ArtifactType: parsed.ArtifactType,
		Payload:      payload,
		Size:         int64(len(payload)),
		CachedAt:     at,
		LastAccessAt: at,
	}
	if parsed.Subject != nil {
		record.Subject = meta.Digest(parsed.Subject.Digest)
	}

	if err := f.meta.PutCachedManifest(ctx, record, cachedRefs(parsed)); err != nil {
		f.log.ErrorContext(ctx, "could not cache an upstream manifest",
			"repository", t.Repository, "digest", digest.String(), "error", err)
		return result, nil
	}

	result.Cached = true
	f.publishFilled(ctx, t, digest, record.Size)
	return result, nil
}

// Blob opens a blob by digest, from the cache or from the upstream.
//
// A miss streams from the upstream to the caller and into the cache at the same
// time: the pull that triggers a fill is served immediately (Q24), not after
// the layer has landed on disk. Nothing is published to the cache until the
// stream ends and the whole of it verified, so a client that disconnects
// halfway leaves no partial blob and no row claiming one.
func (f *Filler) Blob(ctx context.Context, t Target, digest blob.Digest) (BlobResult, error) {
	if err := t.validate(); err != nil {
		return BlobResult{}, err
	}
	if err := digest.Validate(); err != nil {
		return BlobResult{}, &ReferenceError{Kind: "digest", Value: string(digest), Reason: err.Error()}
	}

	// The row is consulted before the bytes. Whether a layer is cached is a
	// per-proxy question: the bytes are content-addressed and shared, so
	// serving them because *somebody* fetched them would let this proxy answer
	// for content its own routing rules never admitted (C-010).
	_, err := f.meta.GetCachedBlob(ctx, t.Repository, meta.Digest(digest))
	switch {
	case err == nil:
		reader, err := f.blobs.Get(ctx, digest)
		switch {
		case err == nil:
			return BlobResult{Content: reader, Size: reader.Descriptor().Size, Hit: true}, nil
		case errors.Is(err, blob.ErrNotFound), errors.Is(err, blob.ErrDigestMismatch):
			// A row whose bytes are gone or no longer verify. Both are
			// recoverable by definition -- that is what cached content is --
			// so the fill runs again rather than failing a pull over it.
			f.log.WarnContext(ctx, "cached blob is unusable, refilling from the upstream",
				"repository", t.Repository, "digest", digest.String(), "error", err)
		default:
			return BlobResult{}, fmt.Errorf("open the cached blob: %w", err)
		}
	case !errors.Is(err, meta.ErrNotFound):
		return BlobResult{}, fmt.Errorf("read the cached blob: %w", err)
	}

	upstream, size, err := t.Client.FetchBlob(ctx, t.Upstream, digest)
	if err != nil {
		if errors.Is(err, ErrDigestMismatch) {
			f.publishCorrupt(ctx, t, digest)
		}
		return BlobResult{}, err
	}

	return BlobResult{Content: f.tee(ctx, t, digest, upstream), Size: size}, nil
}

// tee wraps the upstream stream so that what the client reads is also written
// to the cache. A session that cannot be opened means the content is served and
// not cached, which is the degraded behaviour every cache failure here takes.
func (f *Filler) tee(ctx context.Context, t Target, digest blob.Digest, src io.ReadCloser) io.ReadCloser {
	session, err := f.blobs.CreateUpload(ctx, uploadID())
	if err != nil {
		f.log.ErrorContext(ctx, "could not open a cache upload, serving without caching",
			"repository", t.Repository, "digest", digest.String(), "error", err)
		return src
	}
	return &fill{filler: f, target: t, digest: digest, src: src, session: session, ctx: ctx}
}

// fill is one blob being streamed to a client and into the cache at once.
//
// It is not safe for concurrent use, which is the same contract the reader it
// wraps has: one response body, one goroutine.
type fill struct {
	filler  *Filler
	target  Target
	digest  blob.Digest
	src     io.ReadCloser
	session blob.UploadSession

	// ctx is the request's. A fill that outlived its request would be writing
	// bytes nobody is reading, so the session dies with it -- the client
	// disconnecting is exactly the case where nothing should be published.
	ctx context.Context

	// abandoned marks a fill whose cache side failed. The client keeps
	// reading; the session is already cancelled.
	abandoned bool

	// settled marks a fill that has committed or cancelled, so Close does not
	// do it twice.
	settled bool
}

// Read passes bytes to the caller and copies them into the cache session.
//
// The order matters: the bytes are written to the session before they are
// returned, so a stream that ends at EOF has already had everything the caller
// saw handed to the session, and the commit that follows covers exactly what
// was served.
func (f *fill) Read(p []byte) (int, error) {
	n, err := f.src.Read(p)
	if n > 0 && !f.abandoned {
		if _, wErr := f.session.Write(f.ctx, bytes.NewReader(p[:n])); wErr != nil {
			f.abandon(wErr)
		}
	}

	switch {
	case errors.Is(err, io.EOF):
		f.complete()
	case err != nil:
		// Any other error ends the fill: a short body, a verification failure
		// one byte from the end, a cancelled request. None of them is content
		// worth keeping, and the client is getting the error too.
		//
		// A verification failure is reported as well as discarded. It is the
		// one failure here that says somebody else's registry served bytes that
		// are not what it claimed, and it surfaces mid-stream rather than at
		// the fetch, because a layer is verified as it streams (ADR 0007).
		if errors.Is(err, blob.ErrDigestMismatch) {
			f.filler.publishCorrupt(f.ctx, f.target, f.digest)
		}
		f.cancel()
	}
	return n, err
}

// Close ends the fill. A stream closed before EOF cached nothing: the session
// is cancelled, and the client's own retry is what fills the cache next time.
func (f *fill) Close() error {
	f.cancel()
	return f.src.Close()
}

// abandon gives up on caching while the client keeps reading.
func (f *fill) abandon(err error) {
	f.abandoned = true
	f.filler.log.ErrorContext(f.ctx, "could not write to the cache, serving without caching",
		"repository", f.target.Repository, "digest", f.digest.String(), "error", err)
	f.cancel()
}

// cancel discards the session unless it has already been settled.
func (f *fill) cancel() {
	if f.settled {
		return
	}
	f.settled = true
	if err := f.session.Cancel(context.WithoutCancel(f.ctx)); err != nil {
		f.filler.log.WarnContext(f.ctx, "could not cancel a cache upload",
			"repository", f.target.Repository, "digest", f.digest.String(), "error", err)
	}
}

// complete publishes what the session holds: bytes first, then the row.
//
// The order is deliberate and its two failure modes are not symmetric. A row
// with no bytes would claim a cache hit that then misses, which every read here
// has to handle anyway; bytes with no row are invisible to this proxy and are
// reclaimed by the eviction sweep's orphan pass (C-013). Leaking recoverable
// bytes is the cheaper of the two, and neither loses anything irreplaceable --
// which is the whole difference between this path and the hosted one.
func (f *fill) complete() {
	if f.settled || f.abandoned {
		return
	}
	f.settled = true

	// The commit outlives the request deliberately: the client has its bytes,
	// and cancelling the copy at that moment would throw away a fetch that
	// already cost the upstream's bandwidth.
	ctx := context.WithoutCancel(f.ctx)
	desc, err := f.session.Commit(ctx, f.digest)
	if err != nil {
		f.filler.log.ErrorContext(ctx, "could not commit a cache fill",
			"repository", f.target.Repository, "digest", f.digest.String(), "error", err)
		return
	}

	at := f.filler.now()
	if err := f.filler.meta.PutCachedBlob(ctx, meta.CachedBlob{
		Repository:   f.target.Repository,
		Digest:       meta.Digest(f.digest),
		Size:         desc.Size,
		CachedAt:     at,
		LastAccessAt: at,
	}); err != nil {
		f.filler.log.ErrorContext(ctx, "could not record a cache fill",
			"repository", f.target.Repository, "digest", f.digest.String(), "error", err)
		return
	}

	f.filler.publishFilled(ctx, f.target, f.digest, desc.Size)
}

// cachedRefs turns a parsed manifest into the edges the cached row records.
//
// It is the cached twin of what the push path builds, and it is written out
// again rather than shared: the hosted edges are the reachability graph
// garbage collection walks before deleting something irreplaceable, and a
// shared helper would be a seam through which one traversal could be handed the
// other's rows (ADR 0009). Foreign layers are skipped for the reason the push
// path skips them -- the registry never holds those bytes, so there is nothing
// to account for.
func cachedRefs(parsed artifact.Manifest) []meta.CachedManifestRef {
	refs := make([]meta.CachedManifestRef, 0, len(parsed.Layers)+len(parsed.Children)+2)
	if parsed.Config != nil {
		refs = append(refs, meta.CachedManifestRef{
			Child: meta.Digest(parsed.Config.Digest), Kind: meta.RefConfig,
		})
	}
	for _, layer := range parsed.Layers {
		if layer.External {
			continue
		}
		refs = append(refs, meta.CachedManifestRef{
			Child: meta.Digest(layer.Digest), Kind: meta.RefLayer,
		})
	}
	for _, child := range parsed.Children {
		refs = append(refs, meta.CachedManifestRef{
			Child: meta.Digest(child.Digest), Kind: meta.RefChild,
		})
	}
	if parsed.Subject != nil {
		refs = append(refs, meta.CachedManifestRef{
			Child: meta.Digest(parsed.Subject.Digest), Kind: meta.RefSubject,
		})
	}
	return refs
}

func (f *Filler) publishFilled(ctx context.Context, t Target, digest blob.Digest, size int64) {
	if f.events == nil {
		return
	}
	f.events.Publish(ctx, event.Event{
		Type:       event.CacheFilled,
		Repository: t.Repository,
		Resource:   digest.String(),
		Payload: event.CacheFilledPayload{
			Repository: t.Repository,
			Upstream:   t.Remote,
			Digest:     digest.String(),
			Size:       size,
		},
	})
}

// publishCorrupt reports an upstream that answered with bytes that are not what
// it was asked for. Source is "upstream" because that is the operator's first
// question: content that does not match its digest here is somebody else's
// incident, not this deployment's storage failing.
//
// The actual digest is deliberately absent. Verification streams, so the bytes
// that did not match were discarded rather than hashed to the end, and
// reporting a digest computed from a truncated body would name content that
// does not exist.
func (f *Filler) publishCorrupt(ctx context.Context, t Target, digest blob.Digest) {
	if f.events == nil {
		return
	}
	f.events.Publish(ctx, event.Event{
		Type:       event.BlobCorrupt,
		Repository: t.Repository,
		Resource:   digest.String(),
		Payload: event.BlobCorruptPayload{
			Repository: t.Repository,
			Expected:   digest.String(),
			Source:     "upstream",
		},
	})
}

// uploadID mints an identifier for one cache upload session. It is random
// rather than derived from the digest: two concurrent fills of one blob must
// not share a session, or one of them cancelling would discard the other's
// bytes.
//
// The read cannot fail -- crypto/rand.Read panics rather than returning an
// error since Go 1.24 -- so there is no failure branch here to test, which is
// why the return is discarded explicitly rather than checked.
func uploadID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return "cachefill-" + hex.EncodeToString(raw[:])
}

// UnusableContentError reports upstream content this registry will not cache:
// a manifest whose media type or shape it does not implement.
//
// It satisfies errors.Is(err, ErrUpstreamUnavailable) rather than introducing a
// sentinel of its own, because every caller of this package classifies failures
// through that closed set (C-002) and a group member answering with something
// unusable is a member that did not serve the request -- which is exactly what
// group resolution already does with an unavailable one (C-011).
type UnusableContentError struct {
	// Repository is the upstream repository path.
	Repository string
	// Digest is the content that could not be used.
	Digest blob.Digest
	// Reason explains what about it could not be used.
	Reason string
}

func (e *UnusableContentError) Error() string {
	return fmt.Sprintf("upstream %s@%s: unusable content: %s", e.Repository, e.Digest, e.Reason)
}

// Is makes errors.Is(err, ErrUpstreamUnavailable) true for this typed error.
func (e *UnusableContentError) Is(target error) bool { return target == ErrUpstreamUnavailable }
