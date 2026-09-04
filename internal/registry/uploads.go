package registry

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
	"github.com/steveokay/trove/internal/server"
)

// start serves POST /v2/<name>/blobs/uploads/: a new session, a monolithic
// push when ?digest= is present, or a cross-repo mount.
func (b *Blobs) start(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, b.Meta, b.Log)
	if !ok {
		return
	}
	query := r.URL.Query()

	if raw := query.Get("digest"); raw != "" {
		b.monolithic(w, r, name, raw)
		return
	}
	if mount := query.Get("mount"); mount != "" {
		if b.mount(w, r, name, mount, query.Get("from")) {
			return
		}
		// Every failed mount falls back to an ordinary session (the spec's
		// 202 path). That is also the disclosure answer: an unreadable
		// source, an absent blob, and a bad request all look identical,
		// so the mount cannot be used to probe either (ADR 0003).
	}

	if err := b.quota().Check(r.Context(), name, r.ContentLength); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}

	id, err := newUploadID()
	if err != nil {
		server.Logger(r.Context(), b.Log).Error("mint upload id", "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	now := b.now()
	// The row lands first (ADR 0010): a session the metadata store does not
	// know about could not be reaped, and its eventual digest could not be
	// pinned against GC.
	if err := b.Meta.CreateUpload(r.Context(), meta.UploadSession{
		ID: id, Repository: name, StartedAt: now, LastChunkAt: now,
	}); err != nil {
		server.Logger(r.Context(), b.Log).Error("record upload", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	if _, err := b.Store.CreateUpload(r.Context(), id); err != nil {
		_ = b.Meta.DeleteUpload(r.Context(), id)
		server.Logger(r.Context(), b.Log).Error("open upload", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	w.Header().Set("Location", uploadLocation(name, id))
	w.Header().Set("Range", "0-0")
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

// monolithic accepts a whole blob in the POST body.
func (b *Blobs) monolithic(w http.ResponseWriter, r *http.Request, name, raw string) {
	digest, ok := parsedDigest(w, raw)
	if !ok {
		return
	}
	if err := b.quota().Check(r.Context(), name, r.ContentLength); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}

	counted := &countingReader{r: r.Body}
	if err := b.Store.Put(r.Context(), digest, counted); err != nil {
		switch {
		case errors.Is(err, blob.ErrDigestMismatch):
			writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
		default:
			server.Logger(r.Context(), b.Log).Error("store blob", "digest", digest, "error", err)
			writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		}
		return
	}
	if err := b.Meta.PutBlob(r.Context(), meta.Blob{
		Digest: meta.Digest(digest), Size: counted.n, CreatedAt: b.now(),
	}); err != nil {
		server.Logger(r.Context(), b.Log).Error("record blob", "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	blobCreated(w, name, digest)
}

// mount serves the cross-repo mount: reuse a blob the subject can already
// reach through the source repository. It reports whether it answered.
func (b *Blobs) mount(w http.ResponseWriter, r *http.Request, name, rawDigest, from string) bool {
	digest, err := blob.ParseDigest(rawDigest)
	if err != nil {
		return false
	}
	source, err := authz.Repository(from)
	if err != nil {
		return false
	}
	subject, ok := server.SubjectFrom(r.Context())
	if !ok {
		return false
	}
	// The mount is gated on reading the source (R-001): the same live
	// bindings a pull from it would check. The check is on the full name,
	// because that is what a binding scope matches.
	bindings, err := server.FetchBindings(r.Context(), b.Bindings, subject.Name)
	if err != nil || !authz.Allows(bindings, authz.RepoRead, source) {
		return false
	}
	// The source has to route somewhere, and what routes is its entity
	// (ADR 0005): a pull from `from` would resolve the same first segment.
	sourceEntity, _, err := repo.Split(from)
	if err != nil {
		return false
	}
	if _, err := b.Meta.GetRepository(r.Context(), sourceEntity); err != nil {
		return false
	}
	if _, err := b.Meta.GetBlob(r.Context(), meta.Digest(digest)); err != nil {
		return false
	}

	blobCreated(w, name, digest)
	return true
}

// openSession resolves an upload id under the request's repository. The row
// is the binding between the two: a session started under another repository
// answers unknown, so an upload cannot be moved somewhere its push
// permission was never checked.
func (b *Blobs) openSession(w http.ResponseWriter, r *http.Request, name string) (blob.UploadSession, string, bool) {
	id := server.OCIValue(r, "id")
	if err := blob.ValidateUploadID(id); err != nil {
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "blob upload unknown to registry")
		return nil, "", false
	}
	row, err := b.Meta.GetUpload(r.Context(), id)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "blob upload unknown to registry")
		return nil, "", false
	case err != nil:
		server.Logger(r.Context(), b.Log).Error("read upload row", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return nil, "", false
	case row.Repository != name:
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "blob upload unknown to registry")
		return nil, "", false
	}

	session, err := b.Store.OpenUpload(r.Context(), id)
	switch {
	case errors.Is(err, blob.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeBlobUploadUnknown, "blob upload unknown to registry")
		return nil, "", false
	case err != nil:
		server.Logger(r.Context(), b.Log).Error("open upload", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return nil, "", false
	}
	return session, id, true
}

// patch serves PATCH <upload>: one chunk appended at the current offset.
func (b *Blobs) patch(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, b.Meta, b.Log)
	if !ok {
		return
	}
	session, id, ok := b.openSession(w, r, name)
	if !ok {
		return
	}

	// A stated range must agree with what the session holds: out-of-order
	// chunks are the client's bug and 416 is the spec's answer.
	if header := r.Header.Get("Content-Range"); header != "" {
		start, parseErr := contentRangeStart(header)
		if parseErr != nil || start != session.Offset() {
			w.Header().Set("Range", rangeHeader(session.Offset()))
			writeError(w, http.StatusRequestedRangeNotSatisfiable, CodeBlobUploadInvalid,
				fmt.Sprintf("chunk must continue at offset %d", session.Offset()))
			return
		}
	}
	if err := b.quota().Check(r.Context(), name, r.ContentLength); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}

	offset, err := session.Write(r.Context(), r.Body)
	if err != nil {
		server.Logger(r.Context(), b.Log).Error("append chunk", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	if err := b.Meta.UpdateUpload(r.Context(), id, offset, b.now()); err != nil {
		server.Logger(r.Context(), b.Log).Error("record chunk", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	w.Header().Set("Location", uploadLocation(name, id))
	w.Header().Set("Range", rangeHeader(offset))
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

// commit serves PUT <upload>?digest=: the optional final chunk, then
// verification and publication. On mismatch nothing is published and the
// session is gone -- a retry into a half-committed session would be a way to
// smuggle content past the check (ADR 0007).
func (b *Blobs) commit(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, b.Meta, b.Log)
	if !ok {
		return
	}
	digest, ok := parsedDigest(w, r.URL.Query().Get("digest"))
	if !ok {
		return
	}
	session, id, ok := b.openSession(w, r, name)
	if !ok {
		return
	}

	if _, err := session.Write(r.Context(), r.Body); err != nil {
		server.Logger(r.Context(), b.Log).Error("append final chunk", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	desc, err := session.Commit(r.Context(), digest)
	if err != nil {
		if errors.Is(err, blob.ErrDigestMismatch) {
			// The driver discarded the bytes; the row follows, so nothing
			// remembers an upload that never became content.
			_ = b.Meta.DeleteUpload(r.Context(), id)
			writeError(w, http.StatusBadRequest, CodeDigestInvalid, err.Error())
			return
		}
		server.Logger(r.Context(), b.Log).Error("commit upload", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	// Blob row before upload-row deletion (ADR 0010): at every instant the
	// content is either pinned by the session or recorded as a blob.
	if err := b.Meta.PutBlob(r.Context(), meta.Blob{
		Digest: meta.Digest(digest), Size: desc.Size, CreatedAt: b.now(),
	}); err != nil {
		server.Logger(r.Context(), b.Log).Error("record blob", "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	if err := b.Meta.DeleteUpload(r.Context(), id); err != nil && !errors.Is(err, meta.ErrNotFound) {
		// The blob is real; a leftover row is the reaper's to collect.
		server.Logger(r.Context(), b.Log).Error("clear upload row", "id", id, "error", err)
	}
	blobCreated(w, name, digest)
}

// status serves GET <upload>: where the session stands, for resumption.
func (b *Blobs) status(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, b.Meta, b.Log)
	if !ok {
		return
	}
	session, id, ok := b.openSession(w, r, name)
	if !ok {
		return
	}
	w.Header().Set("Location", uploadLocation(name, id))
	w.Header().Set("Range", rangeHeader(session.Offset()))
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusNoContent)
}

// cancel serves DELETE <upload>.
func (b *Blobs) cancel(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, b.Meta, b.Log)
	if !ok {
		return
	}
	session, id, ok := b.openSession(w, r, name)
	if !ok {
		return
	}
	if err := session.Cancel(r.Context()); err != nil {
		server.Logger(r.Context(), b.Log).Error("cancel upload", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	if err := b.Meta.DeleteUpload(r.Context(), id); err != nil && !errors.Is(err, meta.ErrNotFound) {
		server.Logger(r.Context(), b.Log).Error("clear upload row", "id", id, "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// blobCreated answers every path that ends with a stored blob.
func blobCreated(w http.ResponseWriter, name string, digest blob.Digest) {
	w.Header().Set("Location", "/v2/"+name+"/blobs/"+digest.String())
	w.Header().Set("Docker-Content-Digest", digest.String())
	w.WriteHeader(http.StatusCreated)
}

func uploadLocation(name, id string) string {
	return "/v2/" + name + "/blobs/uploads/" + id
}

// rangeHeader renders the spec's inclusive range for a session offset. An
// empty session answers 0-0, which is also what the spec's start answers.
func rangeHeader(offset int64) string {
	if offset == 0 {
		return "0-0"
	}
	return "0-" + strconv.FormatInt(offset-1, 10)
}

// contentRangeStart parses the start of a "start-end" Content-Range.
func contentRangeStart(header string) (int64, error) {
	start, _, found := strings.Cut(header, "-")
	if !found {
		return 0, fmt.Errorf("malformed Content-Range %q", header)
	}
	return strconv.ParseInt(strings.TrimSpace(start), 10, 64)
}

// newUploadID mints a session identifier that passes the upload-id gate.
func newUploadID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("upload id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// countingReader counts what Put consumed, which is the size the blob row
// records.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
