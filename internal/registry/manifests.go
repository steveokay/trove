package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// DefaultManifestMaxBytes caps a manifest payload when no limit is configured
// (R-002). Real manifests are kilobytes; the cap exists so the registry never
// buffers an adversarial payload.
const DefaultManifestMaxBytes = 4 << 20

// tagPattern is the distribution spec's tag grammar, anchored.
var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// ManifestMeta is the slice of the metadata store the manifest handlers need,
// declared by the consumer (§11).
type ManifestMeta interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
	GetBlob(ctx context.Context, digest meta.Digest) (meta.Blob, error)
	PutManifest(ctx context.Context, m meta.Manifest, refs []meta.ManifestRef) error
	GetManifest(ctx context.Context, repo string, digest meta.Digest) (meta.Manifest, error)
	DeleteManifest(ctx context.Context, repo string, digest meta.Digest) error
	ListReferrers(ctx context.Context, repo string, subject meta.Digest, artifactType string) ([]meta.Manifest, error)
	ListIndexParents(ctx context.Context, repo string, child meta.Digest) ([]meta.Digest, error)
	PutTag(ctx context.Context, tag meta.Tag) error
	GetTag(ctx context.Context, repo, name string) (meta.Tag, error)
}

// Manifests serves the distribution API's manifest routes (R-002): PUT with
// media-type and reference validation, HEAD/GET by tag or digest, DELETE by
// digest with the ADR 0011 referrer cascade and the Q10 index-child refusal.
type Manifests struct {
	Meta ManifestMeta
	// MaxBytes caps the accepted payload size. Zero means
	// DefaultManifestMaxBytes.
	MaxBytes int64
	// Now supplies timestamps. Nil means time.Now.
	Now func() time.Time
	// Pulls counts served pulls (R-010). Nil disables recording, which costs
	// the pull path nothing: there is no writer to hand the observation to.
	Pulls PullRecorder
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the manifest routes on the table. Pulls take repo:read,
// pushes repo:write; deletion is its own verb, never implied by write
// (ADR 0002).
func (m *Manifests) Register(r *server.Router) {
	resource := func(req *http.Request) (authz.Resource, error) {
		return authz.Repository(server.OCIName(req))
	}
	read := server.Permission{Verb: authz.RepoRead, Resource: resource}
	write := server.Permission{Verb: authz.RepoWrite, Resource: resource}
	del := server.Permission{Verb: authz.ManifestDelete, Resource: resource}

	r.HandleOCI(http.MethodHead, "/manifests/{reference}", read, http.HandlerFunc(m.head))
	r.HandleOCI(http.MethodGet, "/manifests/{reference}", read, http.HandlerFunc(m.get))
	r.HandleOCI(http.MethodPut, "/manifests/{reference}", write, http.HandlerFunc(m.put))
	r.HandleOCI(http.MethodDelete, "/manifests/{reference}", del, http.HandlerFunc(m.delete))
}

func (m *Manifests) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

func (m *Manifests) maxBytes() int64 {
	if m.MaxBytes <= 0 {
		return DefaultManifestMaxBytes
	}
	return m.MaxBytes
}

// isDigestReference tells a digest reference from a tag: a tag can never
// contain a colon, so the two grammars cannot collide.
func isDigestReference(reference string) bool { return strings.Contains(reference, ":") }

// put serves PUT /v2/<name>/manifests/<reference>: parse, validate every
// referenced blob and child, then store manifest and edges transactionally
// (ADR 0010) and point the tag if the reference was one.
func (m *Manifests) put(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, m.Meta, m.Log)
	if !ok {
		return
	}
	reference := server.OCIValue(r, "reference")
	var byDigest blob.Digest
	if isDigestReference(reference) {
		if byDigest, ok = parsedDigest(w, reference); !ok {
			return
		}
	} else if !tagPattern.MatchString(reference) {
		writeError(w, http.StatusBadRequest, CodeManifestInvalid, fmt.Sprintf("invalid tag %q", reference))
		return
	}

	limit := m.maxBytes()
	payload, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		server.Logger(r.Context(), m.Log).Error("read manifest payload", "repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	if int64(len(payload)) > limit {
		writeError(w, http.StatusBadRequest, CodeManifestInvalid,
			fmt.Sprintf("manifest exceeds the size limit of %d bytes", limit))
		return
	}

	parsed, err := artifact.Parse(r.Header.Get("Content-Type"), payload)
	if err != nil {
		if errors.Is(err, artifact.ErrInvalid) {
			writeError(w, http.StatusBadRequest, CodeManifestInvalid, err.Error())
			return
		}
		server.Logger(r.Context(), m.Log).Error("parse manifest", "repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	// The stored digest is computed here, in the reference's algorithm when
	// one was given, so a push by digest cannot store under a digest the
	// payload does not hash to.
	algo := blob.SHA256
	if byDigest != "" {
		algo = byDigest.Algorithm()
	}
	digest := blob.FromBytes(algo, payload)
	if byDigest != "" && digest != byDigest {
		writeError(w, http.StatusBadRequest, CodeDigestInvalid, "manifest payload does not match the digest reference")
		return
	}

	refs, ok := m.verifyReferences(w, r, name, parsed)
	if !ok {
		return
	}

	record := meta.Manifest{
		Repository:   name,
		Digest:       meta.Digest(digest),
		MediaType:    parsed.MediaType,
		ArtifactType: parsed.ArtifactType,
		Payload:      payload,
		Size:         int64(len(payload)),
		CreatedAt:    m.now(),
	}
	if parsed.Subject != nil {
		record.Subject = meta.Digest(parsed.Subject.Digest)
	}
	if err := m.Meta.PutManifest(r.Context(), record, refs); err != nil {
		if errors.Is(err, meta.ErrNotFound) {
			// The repository vanished between resolution and the write.
			writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
			return
		}
		server.Logger(r.Context(), m.Log).Error("store manifest", "repo", name, "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}
	if byDigest == "" {
		now := m.now()
		if err := m.Meta.PutTag(r.Context(), meta.Tag{
			Repository: name, Name: reference, Digest: meta.Digest(digest), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			server.Logger(r.Context(), m.Log).Error("point tag", "repo", name, "tag", reference, "error", err)
			writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
			return
		}
	}

	w.Header().Set("Location", "/v2/"+name+"/manifests/"+digest.String())
	w.Header().Set("Docker-Content-Digest", digest.String())
	if parsed.Subject != nil {
		// The spec's signal that the referrers API will list this manifest.
		w.Header().Set("OCI-Subject", parsed.Subject.Digest.String())
	}
	w.WriteHeader(http.StatusCreated)
}

// verifyReferences checks that everything the manifest points at exists and
// returns the reference edges to record. A missing blob or child is the
// client's error (MANIFEST_BLOB_UNKNOWN); a subject is exempt on purpose —
// the spec requires accepting a subject that does not exist yet, because
// attachments may arrive before the thing they attach to.
func (m *Manifests) verifyReferences(w http.ResponseWriter, r *http.Request, name string, parsed artifact.Manifest) ([]meta.ManifestRef, bool) {
	var refs []meta.ManifestRef

	blobDescriptor := func(kind meta.RefKind, desc artifact.Descriptor) bool {
		if desc.External {
			// A foreign layer lives outside the registry: nothing to verify,
			// no edge to record, nothing for GC to keep.
			return true
		}
		record, err := m.Meta.GetBlob(r.Context(), meta.Digest(desc.Digest))
		switch {
		case errors.Is(err, meta.ErrNotFound):
			writeError(w, http.StatusNotFound, CodeManifestBlobUnknown,
				fmt.Sprintf("manifest references blob %s which is unknown to the registry", desc.Digest))
			return false
		case err != nil:
			server.Logger(r.Context(), m.Log).Error("read blob row", "digest", desc.Digest, "error", err)
			writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
			return false
		case record.Size != desc.Size:
			writeError(w, http.StatusBadRequest, CodeManifestInvalid,
				fmt.Sprintf("descriptor for %s states size %d but the blob is %d bytes", desc.Digest, desc.Size, record.Size))
			return false
		}
		refs = append(refs, meta.ManifestRef{Child: meta.Digest(desc.Digest), Kind: kind})
		return true
	}

	if parsed.Config != nil {
		if !blobDescriptor(meta.RefConfig, *parsed.Config) {
			return nil, false
		}
	}
	for _, layer := range parsed.Layers {
		if !blobDescriptor(meta.RefLayer, layer) {
			return nil, false
		}
	}
	for _, child := range parsed.Children {
		record, err := m.Meta.GetManifest(r.Context(), name, meta.Digest(child.Digest))
		switch {
		case errors.Is(err, meta.ErrNotFound):
			writeError(w, http.StatusNotFound, CodeManifestBlobUnknown,
				fmt.Sprintf("index references manifest %s which is unknown to the registry", child.Digest))
			return nil, false
		case err != nil:
			server.Logger(r.Context(), m.Log).Error("read child manifest", "digest", child.Digest, "error", err)
			writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
			return nil, false
		case record.Size != child.Size:
			// The same rule blob descriptors get: a size that lies breaks the
			// clients that trust it (R-006 closed the gap for children).
			writeError(w, http.StatusBadRequest, CodeManifestInvalid,
				fmt.Sprintf("descriptor for %s states size %d but the manifest is %d bytes", child.Digest, child.Size, record.Size))
			return nil, false
		}
		refs = append(refs, meta.ManifestRef{Child: meta.Digest(child.Digest), Kind: meta.RefChild})
	}
	if parsed.Subject != nil {
		refs = append(refs, meta.ManifestRef{Child: meta.Digest(parsed.Subject.Digest), Kind: meta.RefSubject})
	}
	return refs, true
}

// resolve turns a reference into the stored manifest for a read, verifying
// the stored payload still hashes to its digest: drift between the row and
// the payload is a server problem and must never be served as content
// (ADR 0007).
func (m *Manifests) resolve(w http.ResponseWriter, r *http.Request, name string) (meta.Manifest, bool) {
	reference := server.OCIValue(r, "reference")
	var digest meta.Digest
	if isDigestReference(reference) {
		parsed, ok := parsedDigest(w, reference)
		if !ok {
			return meta.Manifest{}, false
		}
		digest = meta.Digest(parsed)
	} else {
		if !tagPattern.MatchString(reference) {
			// An illegal tag cannot name anything; it is unknown, not invalid,
			// so probing with garbage looks like probing with a real name.
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown to registry")
			return meta.Manifest{}, false
		}
		tag, err := m.Meta.GetTag(r.Context(), name, reference)
		switch {
		case errors.Is(err, meta.ErrNotFound):
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown to registry")
			return meta.Manifest{}, false
		case err != nil:
			server.Logger(r.Context(), m.Log).Error("resolve tag", "repo", name, "tag", reference, "error", err)
			writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
			return meta.Manifest{}, false
		}
		digest = tag.Digest
	}

	record, err := m.Meta.GetManifest(r.Context(), name, digest)
	switch {
	case errors.Is(err, meta.ErrNotFound) && isDigestReference(reference):
		writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown to registry")
		return meta.Manifest{}, false
	case err != nil:
		// A tag pointing at a missing manifest is drift, never "unknown": the
		// store guarantees the edge, so a miss here means the data is wrong
		// (P-012's scrub finds these; serving a lie would not).
		server.Logger(r.Context(), m.Log).Error("read manifest", "repo", name, "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return meta.Manifest{}, false
	}

	stored, err := blob.ParseDigest(string(record.Digest))
	if err != nil || blob.FromBytes(stored.Algorithm(), record.Payload) != stored {
		server.Logger(r.Context(), m.Log).Error("manifest payload does not match its digest",
			"repo", name, "digest", record.Digest)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return meta.Manifest{}, false
	}
	return record, true
}

func manifestHeaders(w http.ResponseWriter, record meta.Manifest) {
	w.Header().Set("Content-Type", record.MediaType)
	w.Header().Set("Content-Length", strconv.FormatInt(record.Size, 10))
	w.Header().Set("Docker-Content-Digest", string(record.Digest))
}

// head serves HEAD /v2/<name>/manifests/<reference>.
func (m *Manifests) head(w http.ResponseWriter, r *http.Request) {
	name, ok := knownRepo(w, r, m.Meta, m.Log)
	if !ok {
		return
	}
	record, ok := m.resolve(w, r, name)
	if !ok {
		return
	}
	manifestHeaders(w, record)
	w.WriteHeader(http.StatusOK)
}

// get serves GET /v2/<name>/manifests/<reference>: the exact stored bytes
// under the stored media type, because clients verify the digest of what they
// receive.
//
// A successful GET is the pull that pull statistics count, and only a GET:
// HEAD is a probe -- an existence check, a `docker manifest inspect`, a
// mirror's revalidation -- and counting it would let a polling loop hold a tag
// alive against a last-pulled retention rule (§7) without anything ever having
// been fetched.
func (m *Manifests) get(w http.ResponseWriter, r *http.Request) {
	name, ok := knownRepo(w, r, m.Meta, m.Log)
	if !ok {
		return
	}
	record, ok := m.resolve(w, r, name)
	if !ok {
		return
	}
	// Recorded once the reference resolved and before the bytes go out: what
	// was pulled is already decided, a client that hangs up mid-body still
	// pulled it, and the call is a channel send that never reaches the store
	// (R-010). The reference is kept as the client wrote it, tag or digest,
	// because both are pulls and they are counted apart.
	if m.Pulls != nil {
		m.Pulls.Record(name, server.OCIValue(r, "reference"))
	}
	manifestHeaders(w, record)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(record.Payload); err != nil {
		server.Logger(r.Context(), m.Log).Error("write manifest", "digest", record.Digest, "error", err)
	}
}

// delete serves DELETE /v2/<name>/manifests/<digest>: the manifest, its tags,
// and its whole referrer tree in one operation (ADR 0011, Q22). Deleting by
// tag is not supported; the error says what to do instead.
func (m *Manifests) delete(w http.ResponseWriter, r *http.Request) {
	name, ok := hostedRepo(w, r, m.Meta, m.Log)
	if !ok {
		return
	}
	reference := server.OCIValue(r, "reference")
	if !isDigestReference(reference) {
		writeError(w, http.StatusBadRequest, CodeUnsupported,
			"deleting by tag is not supported: delete by digest instead")
		return
	}
	digest, ok := parsedDigest(w, reference)
	if !ok {
		return
	}

	if _, err := m.Meta.GetManifest(r.Context(), name, meta.Digest(digest)); err != nil {
		if errors.Is(err, meta.ErrNotFound) {
			writeError(w, http.StatusNotFound, CodeManifestUnknown, "manifest unknown to registry")
			return
		}
		server.Logger(r.Context(), m.Log).Error("read manifest", "repo", name, "digest", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	// The referrer tree, collected breadth-first: level 0 is the subject,
	// deeper levels attach to the ones above (a signature on an SBOM on the
	// image). Deletion walks it deepest-first so at every instant the tree
	// that remains is internally consistent; a crash mid-walk leaves orphans
	// for GC's sweep, never a dangling reference (ADR 0011).
	levels, ok := m.collectReferrerTree(w, r, name, meta.Digest(digest))
	if !ok {
		return
	}

	// Q10 fails the whole cascade closed before anything is deleted: if any
	// member — the subject or a referrer — is still a child of a live index
	// outside the tree, nothing happens until that index is deleted.
	if !m.refuseIfIndexed(w, r, name, levels) {
		return
	}

	for i := len(levels) - 1; i >= 0; i-- {
		for _, member := range levels[i] {
			err := m.Meta.DeleteManifest(r.Context(), name, member)
			switch {
			case errors.Is(err, meta.ErrNotFound):
				// Deleted concurrently; the outcome is what was asked for.
			case errors.Is(err, meta.ErrReferenced):
				// An index appeared between the pre-check and here. Fail
				// closed; anything already deleted was a referrer of this
				// subject and ages out through GC's orphan sweep (ADR 0011).
				writeError(w, http.StatusForbidden, CodeDenied, err.Error()+"; delete the index first")
				return
			case err != nil:
				server.Logger(r.Context(), m.Log).Error("delete manifest", "repo", name, "digest", member, "error", err)
				writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
				return
			}
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// collectReferrerTree returns the manifests to cascade-delete, grouped by
// depth: level 0 holds the subject alone, level n+1 everything attached to
// level n. Digests are content addresses, so the graph cannot cycle; the seen
// set is there so a diamond is deleted once.
func (m *Manifests) collectReferrerTree(w http.ResponseWriter, r *http.Request, name string, subject meta.Digest) ([][]meta.Digest, bool) {
	levels := [][]meta.Digest{{subject}}
	seen := map[meta.Digest]bool{subject: true}

	for current := levels[0]; len(current) > 0; {
		var next []meta.Digest
		for _, digest := range current {
			referrers, err := m.Meta.ListReferrers(r.Context(), name, digest, "")
			if err != nil {
				server.Logger(r.Context(), m.Log).Error("list referrers", "repo", name, "digest", digest, "error", err)
				writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
				return nil, false
			}
			for _, referrer := range referrers {
				if !seen[referrer.Digest] {
					seen[referrer.Digest] = true
					next = append(next, referrer.Digest)
				}
			}
		}
		if len(next) > 0 {
			levels = append(levels, next)
		}
		current = next
	}
	return levels, true
}

// refuseIfIndexed answers the Q10 refusal when any member of the deletion
// tree is still listed as a child by an index outside the tree, naming the
// indexes so the operator knows what to delete first (ADR 0005).
func (m *Manifests) refuseIfIndexed(w http.ResponseWriter, r *http.Request, name string, levels [][]meta.Digest) bool {
	inTree := map[meta.Digest]bool{}
	for _, level := range levels {
		for _, digest := range level {
			inTree[digest] = true
		}
	}
	for _, level := range levels {
		for _, member := range level {
			parents, err := m.Meta.ListIndexParents(r.Context(), name, member)
			if err != nil {
				server.Logger(r.Context(), m.Log).Error("list index parents", "repo", name, "digest", member, "error", err)
				writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
				return false
			}
			var outside []string
			for _, parent := range parents {
				if !inTree[parent] {
					outside = append(outside, string(parent))
				}
			}
			if len(outside) > 0 {
				writeError(w, http.StatusForbidden, CodeDenied, fmt.Sprintf(
					"manifest %s is referenced by index %s; delete the index first",
					member, strings.Join(outside, ", ")))
				return false
			}
		}
	}
	return true
}
