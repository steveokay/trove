package registry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// Meta is the slice of the metadata store the blob handlers need, declared by
// the consumer (§11).
type Meta interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
	PutBlob(ctx context.Context, b meta.Blob) error
	GetBlob(ctx context.Context, digest meta.Digest) (meta.Blob, error)
	CreateUpload(ctx context.Context, session meta.UploadSession) error
	GetUpload(ctx context.Context, id string) (meta.UploadSession, error)
	UpdateUpload(ctx context.Context, id string, bytes int64, at time.Time) error
	DeleteUpload(ctx context.Context, id string) error
}

// BlobStore is the hosted blob store with its upload sessions. It is one
// value on purpose: the wiring hands the registry the hosted store, and there
// is no parameter through which a cache store could arrive (ADR 0009).
type BlobStore interface {
	blob.Store
	blob.Uploader
}

// QuotaChecker admits or refuses new bytes. P-009 implements it; until then
// NoQuota stands in, and the seam is where enforcement lands without the
// handlers changing.
type QuotaChecker interface {
	// Check is called before content is accepted, with the bytes about to be
	// added when known and zero when not.
	Check(ctx context.Context, repo string, addedBytes int64) error
}

// NoQuota admits everything.
type NoQuota struct{}

// Check reports no limit.
func (NoQuota) Check(context.Context, string, int64) error { return nil }

// Blobs serves the distribution API's blob content and upload routes
// (R-001): push is POST/PATCH/PUT under uploads, pull is HEAD/GET by digest.
type Blobs struct {
	// Store holds the bytes; Meta holds the rows.
	Store BlobStore
	Meta  Meta
	// Bindings supplies effective bindings where a handler makes its own
	// authorization sub-decision -- the cross-repo mount's read check.
	Bindings server.BindingStore
	// Quota admits new content. Nil means NoQuota.
	Quota QuotaChecker
	// Now supplies timestamps. Nil means time.Now.
	Now func() time.Time
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the blob routes on the table. Push routes take repo:write,
// pull routes repo:read (ADR 0002's mapping); the upload-status and cancel
// routes are part of the push flow and share its verb.
func (b *Blobs) Register(r *server.Router) {
	repo := func(req *http.Request) (authz.Resource, error) {
		return authz.Repository(server.OCIName(req))
	}
	read := server.Permission{Verb: authz.RepoRead, Resource: repo}
	write := server.Permission{Verb: authz.RepoWrite, Resource: repo}

	r.HandleOCI(http.MethodHead, "/blobs/{digest}", read, http.HandlerFunc(b.stat))
	r.HandleOCI(http.MethodGet, "/blobs/{digest}", read, http.HandlerFunc(b.get))
	r.HandleOCI(http.MethodPost, "/blobs/uploads/", write, http.HandlerFunc(b.start))
	r.HandleOCI(http.MethodPatch, "/blobs/uploads/{id}", write, http.HandlerFunc(b.patch))
	r.HandleOCI(http.MethodPut, "/blobs/uploads/{id}", write, http.HandlerFunc(b.commit))
	r.HandleOCI(http.MethodGet, "/blobs/uploads/{id}", write, http.HandlerFunc(b.status))
	r.HandleOCI(http.MethodDelete, "/blobs/uploads/{id}", write, http.HandlerFunc(b.cancel))
}

func (b *Blobs) now() time.Time {
	if b.Now == nil {
		return time.Now()
	}
	return b.Now()
}

func (b *Blobs) quota() QuotaChecker {
	if b.Quota == nil {
		return NoQuota{}
	}
	return b.Quota
}

// repoGetter is the one store method repository resolution needs.
type repoGetter interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
}

// hostedRepo resolves the request's repository for a client write. An absent
// repository answers exactly like an unreadable one (the guard already turned
// unreadable into this same 404), and a repository that is not hosted refuses
// client writes unconditionally (ADR 0005).
func hostedRepo(w http.ResponseWriter, r *http.Request, store repoGetter, log *slog.Logger) (string, bool) {
	name := server.OCIName(r)
	repo, err := store.GetRepository(r.Context(), name)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return "", false
	case err != nil:
		server.Logger(r.Context(), log).Error("read repository", "repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return "", false
	case repo.Type != meta.Hosted:
		writeError(w, http.StatusForbidden, CodeDenied, "repository does not accept client writes")
		return "", false
	}
	return name, true
}

// knownRepo resolves the request's repository for a read.
func knownRepo(w http.ResponseWriter, r *http.Request, store repoGetter, log *slog.Logger) (string, bool) {
	name := server.OCIName(r)
	_, err := store.GetRepository(r.Context(), name)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return "", false
	case err != nil:
		server.Logger(r.Context(), log).Error("read repository", "repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return "", false
	}
	return name, true
}

// parsedDigest validates a digest out of the request, refusing anything the
// strict parser does not accept before it can reach a path or a query.
func parsedDigest(w http.ResponseWriter, raw string) (blob.Digest, bool) {
	digest, err := blob.ParseDigest(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
		return "", false
	}
	return digest, true
}

// stat serves HEAD /v2/<name>/blobs/<digest>.
func (b *Blobs) stat(w http.ResponseWriter, r *http.Request) {
	if _, ok := knownRepo(w, r, b.Meta, b.Log); !ok {
		return
	}
	digest, ok := parsedDigest(w, server.OCIValue(r, "digest"))
	if !ok {
		return
	}
	record, err := b.Meta.GetBlob(r.Context(), meta.Digest(digest))
	switch {
	case errors.Is(err, meta.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob unknown to registry")
		return
	case err != nil:
		server.Logger(r.Context(), b.Log).Error("read blob row", "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(record.Size, 10))
	w.Header().Set("Docker-Content-Digest", digest.String())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
}

// get serves GET /v2/<name>/blobs/<digest>, streaming through the verifying
// reader: corrupt content ends the stream short instead of arriving with a
// clean EOF (ADR 0007).
func (b *Blobs) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := knownRepo(w, r, b.Meta, b.Log); !ok {
		return
	}
	digest, ok := parsedDigest(w, server.OCIValue(r, "digest"))
	if !ok {
		return
	}
	if _, err := b.Meta.GetBlob(r.Context(), meta.Digest(digest)); err != nil {
		if errors.Is(err, meta.ErrNotFound) {
			writeError(w, http.StatusNotFound, CodeBlobUnknown, "blob unknown to registry")
			return
		}
		server.Logger(r.Context(), b.Log).Error("read blob row", "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	reader, err := b.Store.Get(r.Context(), digest)
	if err != nil {
		// A row without bytes is meta-blob drift: a server problem, never
		// "blob unknown" (P-012's scrub finds these; serving a lie would not).
		server.Logger(r.Context(), b.Log).Error("open blob", "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	defer func() { _ = reader.Close() }()

	w.Header().Set("Content-Length", strconv.FormatInt(reader.Descriptor().Size, 10))
	w.Header().Set("Docker-Content-Digest", digest.String())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, reader); err != nil {
		// The status line is gone; the short body fails the client's own
		// digest check, which is the design (ADR 0007).
		server.Logger(r.Context(), b.Log).Error("stream blob", "digest", digest, "error", err)
	}
}
