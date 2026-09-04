package registry

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// ReferrerMeta is the slice of the metadata store the referrers handler needs,
// declared by the consumer (§11).
type ReferrerMeta interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
	ListReferrers(ctx context.Context, repo string, subject meta.Digest, artifactType string) ([]meta.Manifest, error)
}

// Referrers serves the distribution API's referrers route (R-005): the index
// of manifests attached to a subject digest -- SBOMs, signatures, scan
// attestations -- optionally narrowed to one artifact type.
//
// Two permissions gate it, not one. The route carries referrer:read, and the
// handler additionally requires repo:read on the repository holding the
// subject, because a referrer inherits the permission of the artifact it
// attaches to (ADR 0002, §5.7): a subject that cannot pull an image must not
// be able to read its SBOM. Failing that second check answers with the
// hidden-or-absent 404, byte-identical to the one an unknown repository gets
// (ADR 0003 surface 3).
type Referrers struct {
	// Meta resolves the repository and answers the subject_digest query.
	Meta ReferrerMeta
	// Bindings supplies the effective bindings for the handler's own
	// authorization sub-decision -- the repo:read half of the conjunction.
	Bindings server.BindingStore
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the referrers route on the table under referrer:read. The
// second half of the check is the handler's, because the route table holds one
// verb per route by design (ADR 0002).
func (rf *Referrers) Register(r *server.Router) {
	repo := func(req *http.Request) (authz.Resource, error) {
		return authz.Repository(server.OCIName(req))
	}
	read := server.Permission{Verb: authz.ReferrerRead, Resource: repo}

	r.HandleOCI(http.MethodGet, "/referrers/{digest}", read, http.HandlerFunc(rf.list))
}

// referrerDescriptor is one entry of the returned index. It is a descriptor of
// the referring manifest, not of its content: artifactType and annotations are
// what clients filter and display by without fetching each attachment.
type referrerDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// referrerIndex is the image index the spec returns for a referrers query. It
// is assembled here rather than stored: the referrers of a subject change as
// attachments arrive, so the index is a view, never content with a digest of
// its own.
type referrerIndex struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Manifests     []referrerDescriptor `json:"manifests"`
}

// list serves GET /v2/<name>/referrers/<digest>.
//
// A subject with no attachments -- including a digest that was never pushed --
// answers an empty index with 200. The spec requires that, and it is also the
// disclosure-safe answer: an absent subject and an empty one are the same
// response, so the endpoint cannot be used to test whether a digest exists in
// a repository the caller can already read.
func (rf *Referrers) list(w http.ResponseWriter, r *http.Request) {
	// The guard already turned unreadable-for-referrer:read into this 404;
	// what is left to catch is a repository that is truly absent.
	name, ok := knownRepo(w, r, rf.Meta, rf.Log)
	if !ok {
		return
	}
	if !rf.readsSubjectRepository(w, r, name) {
		return
	}
	digest, ok := parsedDigest(w, server.OCIValue(r, "digest"))
	if !ok {
		return
	}

	artifactType := r.URL.Query().Get("artifactType")
	rows, err := rf.Meta.ListReferrers(r.Context(), name, meta.Digest(digest), artifactType)
	if err != nil {
		server.Logger(r.Context(), rf.Log).Error("list referrers",
			"repo", name, "subject", digest, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	// Never nil: an empty index must render "manifests":[], because a client
	// that receives null has to special-case what is an ordinary answer.
	index := referrerIndex{
		SchemaVersion: 2,
		MediaType:     artifact.MediaTypeOCIIndex,
		Manifests:     make([]referrerDescriptor, 0, len(rows)),
	}
	for _, row := range rows {
		index.Manifests = append(index.Manifests, referrerDescriptor{
			MediaType:    row.MediaType,
			Digest:       string(row.Digest),
			Size:         row.Size,
			ArtifactType: row.ArtifactType,
			Annotations:  referrerAnnotations(row.Payload),
		})
	}

	w.Header().Set("Content-Type", artifact.MediaTypeOCIIndex)
	if artifactType != "" {
		// Declared only when a filter was actually applied, so a client can
		// tell "no matches" from "the filter was ignored" and re-filter itself.
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(index); err != nil {
		// The status line is gone; the client sees a truncated body, which its
		// own JSON parser rejects.
		server.Logger(r.Context(), rf.Log).Error("write referrers index",
			"repo", name, "subject", digest, "error", err)
	}
}

// readsSubjectRepository answers the ADR 0002 conjunction: referrer:read got
// the request through the guard, and repo:read on the same repository is what
// makes the attachments readable. It reports whether the caller may proceed,
// having already written the refusal when not.
//
// The refusal is the exact 404 an absent repository gets, from the same
// constructor, so hidden and absent stay byte-identical (ADR 0003).
func (rf *Referrers) readsSubjectRepository(w http.ResponseWriter, r *http.Request, name string) bool {
	// The guard put the subject there. Outside a guarded route the zero
	// subject holds no bindings, so the check below still fails closed.
	subject, _ := server.SubjectFrom(r.Context())

	bindings, err := server.FetchBindings(r.Context(), rf.Bindings, subject.Name)
	if err != nil {
		// A check that could not read its bindings has decided nothing;
		// treating that as a grant is how an outage becomes a disclosure.
		server.Logger(r.Context(), rf.Log).Error("authorization could not read bindings",
			"subject", subject.Name, "repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return false
	}

	// A name the resource grammar rejects cannot be readable either, so it
	// takes the same answer rather than a second, distinguishable one.
	resource, err := authz.Repository(name)
	if err != nil || !authz.Allows(bindings, authz.RepoRead, resource) {
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return false
	}
	return true
}

// referrerAnnotations lifts the annotations out of a stored referrer payload.
//
// Only that one field is read: the rest of the manifest is the attachment's
// business, and internal/artifact's parsed form is deliberately about what the
// registry validates rather than what a listing renders. A payload that no
// longer parses -- drift, or a row written by something older -- contributes no
// annotations rather than failing the whole listing.
func referrerAnnotations(payload []byte) map[string]string {
	var envelope struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil
	}
	return envelope.Annotations
}
