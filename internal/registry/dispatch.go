package registry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// Reads are dispatched by repository type (C-017).
//
// Every read handler resolves the request's entity before it does anything
// else, and until now it threw the entity's *type* away and served from hosted
// storage regardless -- which is why a pull through a proxy or a group 404s
// today even though the machinery behind both exists. This file is the branch
// that was missing.
//
// Two rules shape it:
//
//   - **One renderer.** A proxy or a group returns content; the handler writes
//     the response. The OCI wire format is contract and is golden-tested
//     (R-008), so a second place that assembles those headers would be a second
//     place for them to drift.
//   - **An unwired seam is a repository that does not exist.** A deployment
//     that has not been given a proxy server answers 404 / NAME_UNKNOWN, byte
//     for byte what an unknown repository answers, because "we have not wired
//     that yet" is not something a stranger may learn from a response
//     (ADR 0003).

// ContentServer serves reads for a repository whose content this registry does
// not hold: a proxy, which fetches and caches from an upstream, or a group,
// which resolves an ordered member list.
//
// It is declared here by the consumer and named for what it does rather than
// for which kind implements it, because the handler's branch is the only place
// that needs to tell them apart. Implementations arrive with C-018 and C-019.
type ContentServer interface {
	// Manifest returns a manifest by tag or by digest, exactly as the client
	// asked for it. The reference is passed through unparsed: a proxy resolves
	// a tag against its lease and a group asks its members, and neither
	// decision belongs to the handler.
	Manifest(ctx context.Context, repo, reference string) (ServedManifest, error)

	// Blob opens a blob by digest. The caller closes the content.
	Blob(ctx context.Context, repo string, digest blob.Digest) (ServedBlob, error)
}

// ServedManifest is a manifest a ContentServer produced.
type ServedManifest struct {
	// Digest is what the payload hashes to, and what the response reports as
	// Docker-Content-Digest. It is the server's answer rather than the
	// client's request, because a tag pull learns the digest here.
	Digest blob.Digest
	// MediaType is the manifest's media type.
	MediaType string
	// Payload is the manifest body, byte for byte as it will be served: a
	// client verifies the digest of what it receives.
	Payload []byte
}

// ServedBlob is a blob a ContentServer opened.
type ServedBlob struct {
	// Content streams the bytes. The handler closes it, and closing it early
	// is how a client disconnect reaches a proxy fill (C-004).
	Content io.ReadCloser
	// Size is the length in bytes, or -1 when the server does not know it --
	// an upstream that sent no Content-Length. The handler omits the header
	// rather than guessing.
	Size int64
	// Digest is what the content hashes to.
	Digest blob.Digest
}

// The closed set of failures a ContentServer may report. A handler maps these
// to the spec's error codes; anything else is an internal error, because an
// unclassified failure in a pull path is a bug rather than a condition to
// render.
var (
	// ErrContentUnknown is content the repository does not have and could not
	// get: an absent tag, an unknown digest, a group whose every member said
	// no. It renders as the same not-found a hosted miss does.
	ErrContentUnknown = errors.New("registry: content unknown to this repository")

	// ErrUpstreamUnavailable is a repository that could not be consulted: an
	// unreachable upstream, a group's required member that is down. It is
	// deliberately distinct from ErrContentUnknown -- "we could not ask" and
	// "the answer is no" are different, and collapsing them would let an
	// outage look like a deletion.
	ErrUpstreamUnavailable = errors.New("registry: upstream unavailable")

	// ErrUpstreamThrottled is an upstream refusing us for rate reasons, or a
	// local backoff standing in for one (C-009).
	ErrUpstreamThrottled = errors.New("registry: upstream throttled")
)

// ContentServers are the delegates for the repository types this registry does
// not serve from its own storage. A nil member means that type is not wired,
// and a read for it answers as though the repository did not exist.
type ContentServers struct {
	// Proxy serves proxy repositories (C-018).
	Proxy ContentServer
	// Group serves group repositories (C-019).
	Group ContentServer
}

// serverFor returns the delegate for a repository type, or nil for hosted --
// which the caller serves itself -- and for a type nothing is wired for.
func (s ContentServers) serverFor(typ meta.RepositoryType) ContentServer {
	switch typ {
	case meta.Proxy:
		return s.Proxy
	case meta.Group:
		return s.Group
	default:
		return nil
	}
}

// delegated reports whether a read must be served by a delegate rather than
// from hosted storage, and returns the delegate to serve it.
//
// A hosted repository returns (nil, false) and the caller proceeds as it
// always has. A proxy or group with no delegate wired returns (nil, true) and
// the caller must not fall through to hosted storage: serving a proxy pull
// from the hosted tables would answer for content this registry does not have.
func (s ContentServers) delegated(typ meta.RepositoryType) (ContentServer, bool) {
	if typ == meta.Hosted {
		return nil, false
	}
	return s.serverFor(typ), true
}

// writeDelegateError renders a ContentServer's failure in the spec's envelope.
//
// The mapping is small and closed on purpose. A proxy's own error vocabulary
// is richer -- a rejected credential, a refused redirect, a manifest it could
// not parse -- and it is the adapter's job to collapse that into these three
// before it reaches a client, because the client can act on "not here", "try
// later" and "not now" and can act on nothing else.
func writeDelegateError(w http.ResponseWriter, r *http.Request, kind, name string, err error, log *slog.Logger) {
	switch {
	case errors.Is(err, ErrContentUnknown):
		writeError(w, http.StatusNotFound, notFoundCodeFor(kind), kind+" unknown to registry")
	case errors.Is(err, ErrUpstreamThrottled):
		// The upstream's own Retry-After, when there was one, is the proxy's
		// to carry; without it a client's own backoff is the honest answer.
		writeError(w, http.StatusTooManyRequests, CodeTooManyRequests, "upstream is rate limiting this registry")
	case errors.Is(err, ErrUpstreamUnavailable):
		// 504 rather than 404: the repository exists and could not be
		// consulted. A client that retries is doing the right thing, and one
		// that treats this as a deletion is not.
		writeError(w, http.StatusGatewayTimeout, CodeUnknown, "upstream unavailable")
	default:
		server.Logger(r.Context(), log).Error("serve "+kind+" through a delegate",
			"repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
	}
}

// notFoundCodeFor is the spec code for a missing thing of each kind.
func notFoundCodeFor(kind string) string {
	if kind == "blob" {
		return CodeBlobUnknown
	}
	return CodeManifestUnknown
}

// statThrough answers HEAD /v2/<name>/blobs/<digest> for a delegated
// repository.
//
// It opens the content and closes it without reading: a proxy answers "is this
// blob available" by being able to produce it, and there is no cheaper honest
// question to ask an upstream. The body is what HEAD omits, not the work.
func (b *Blobs) statThrough(w http.ResponseWriter, r *http.Request, delegate ContentServer, name string, digest blob.Digest) {
	if delegate == nil {
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return
	}

	served, err := delegate.Blob(r.Context(), name, digest)
	if err != nil {
		writeDelegateError(w, r, "blob", name, err, b.Log)
		return
	}
	defer func() { _ = served.Content.Close() }()

	blobHeaders(w, served.Digest, served.Size)
	w.WriteHeader(http.StatusOK)
}

// getThrough streams GET /v2/<name>/blobs/<digest> from a delegate.
//
// The stream is the point: a proxy fills its cache from the same bytes it is
// serving (C-004), so the client waits for the upstream rather than for the
// upstream and then the disk. Closing the reader is what tells a fill that the
// client went away.
func (b *Blobs) getThrough(w http.ResponseWriter, r *http.Request, delegate ContentServer, name string, digest blob.Digest) {
	if delegate == nil {
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return
	}

	served, err := delegate.Blob(r.Context(), name, digest)
	if err != nil {
		writeDelegateError(w, r, "blob", name, err, b.Log)
		return
	}
	defer func() { _ = served.Content.Close() }()

	blobHeaders(w, served.Digest, served.Size)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, served.Content); err != nil {
		// The status is already sent, so this cannot become an error response.
		// It is logged because a stream that ended short is either a client
		// that hung up or an upstream that lied, and the second one matters.
		server.Logger(r.Context(), b.Log).Error("stream a delegated blob",
			"repo", name, "digest", digest.String(), "error", err)
	}
}

// manifestThrough answers a manifest read for a delegated repository, for both
// GET and HEAD.
func (m *Manifests) manifestThrough(w http.ResponseWriter, r *http.Request, delegate ContentServer, name, reference string, body bool) {
	if delegate == nil {
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return
	}

	served, err := delegate.Manifest(r.Context(), name, reference)
	if err != nil {
		writeDelegateError(w, r, "manifest", name, err, m.Log)
		return
	}

	// Counted for the reason the hosted path counts: a GET is a pull and a
	// HEAD is a probe, and a proxy's pulls feed the same statistics and the
	// same retention rules as a hosted one's.
	if body && m.Pulls != nil {
		m.Pulls.Record(name, reference)
	}

	writeManifestHeaders(w, served.MediaType, int64(len(served.Payload)), served.Digest.String())
	w.WriteHeader(http.StatusOK)
	if !body {
		return
	}
	if _, err := w.Write(served.Payload); err != nil {
		server.Logger(r.Context(), m.Log).Error("write a delegated manifest",
			"repo", name, "digest", served.Digest.String(), "error", err)
	}
}
