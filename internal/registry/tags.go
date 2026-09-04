package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// TagMeta is the slice of the metadata store the tag listing needs, declared
// by the consumer (§11).
type TagMeta interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
	ListTags(ctx context.Context, repo string, opts meta.ListOptions) (meta.TagPage, error)
}

// Tags serves the distribution API's tag listing (R-003):
// GET /v2/<name>/tags/list, lexically ordered, cursor-paginated through the
// spec's `n` and `last` parameters and its `Link` header.
//
// The page is built by a permission-filtered query, never by filtering what
// came back (§0.5): the subject's bindings compile into the Visibility the
// store runs the listing under, so a repository the subject cannot read has
// no tags to answer with, and says so with the same 404 an absent repository
// gets (ADR 0003 surface 2).
type Tags struct {
	Meta TagMeta
	// Bindings supplies the effective bindings the listing is filtered by. It
	// is the handler's own query-layer filter, not a second authorization
	// decision: the guard has already allowed repo:read on this repository.
	Bindings server.BindingStore
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the tag route on the table. Listing tags is reading the
// repository, so it takes repo:read (ADR 0002's mapping) -- the same verb the
// pull of any one of those tags would take.
func (t *Tags) Register(r *server.Router) {
	repo := func(req *http.Request) (authz.Resource, error) {
		return authz.Repository(server.OCIName(req))
	}
	read := server.Permission{Verb: authz.RepoRead, Resource: repo}

	r.HandleOCI(http.MethodGet, "/tags/list", read, http.HandlerFunc(t.list))
}

// tagList is the spec's response body. Tags is never null: clients iterate it
// without checking, so an empty repository answers with an empty array.
type tagList struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// list serves GET /v2/<name>/tags/list.
func (t *Tags) list(w http.ResponseWriter, r *http.Request) {
	name, ok := knownRepo(w, r, t.Meta, t.Log)
	if !ok {
		return
	}
	limit, ok := tagPageSize(w, r)
	if !ok {
		return
	}

	// The guard put the subject in the context before this handler ran. If it
	// somehow did not, the zero subject fetches no bindings and the visibility
	// that follows shows nothing -- the listing fails closed rather than
	// falling back to an unfiltered query, which is the one mistake ADR 0003
	// cannot survive.
	subject, _ := server.SubjectFrom(r.Context())
	bindings, err := server.FetchBindings(r.Context(), t.Bindings, subject.Name)
	if err != nil {
		server.Logger(r.Context(), t.Log).Error("read bindings for a tag listing",
			"repo", name, "subject", subject.Name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	page, err := t.Meta.ListTags(r.Context(), name, meta.ListOptions{
		Visibility: server.VisibilityFor(bindings, authz.RepoRead),
		Limit:      limit,
		Cursor:     r.URL.Query().Get("last"),
	})
	switch {
	case errors.Is(err, meta.ErrNotFound):
		// The store answers not-found for a repository the visibility does not
		// allow exactly as it does for one that is not there, and this is the
		// answer both deserve: byte-identical to the guard's own 404.
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return
	case err != nil:
		server.Logger(r.Context(), t.Log).Error("list tags", "repo", name, "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	// The store orders the page; re-sorting here would be a second ordering to
	// disagree with the cursor the store handed back.
	names := make([]string, 0, len(page.Tags))
	for _, tag := range page.Tags {
		names = append(names, tag.Name)
	}
	if page.NextCursor != "" {
		w.Header().Set("Link", tagPageLink(name, page.NextCursor, limit))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tagList{Name: name, Tags: names}); err != nil {
		server.Logger(r.Context(), t.Log).Error("write tag list", "repo", name, "error", err)
	}
}

// tagPageSize reads the spec's `n` parameter. Absent means the store's default
// page size, and so does n=0: clients send it for "no preference", and a page
// of nothing would be an infinite pagination loop rather than an answer.
//
// Anything else that is not a non-negative number is refused rather than
// ignored -- a client that asked for a page size and silently got a different
// one has no way to notice.
func tagPageSize(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("n")
	if raw == "" {
		return 0, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		writeError(w, http.StatusBadRequest, CodeUnsupported,
			fmt.Sprintf("invalid page size %q: n must be a non-negative integer", raw))
		return 0, false
	}
	return n, true
}

// tagPageLink builds the spec's next-page Link header. The cursor is a tag
// name and the repository name has already passed the strict allowlist, but
// the query values are escaped anyway: the header is a URL the client will
// send back, and building one by concatenation is how a stored name becomes an
// injected parameter.
//
// `n` is echoed only when the client sent one, so following the link keeps the
// page size the client chose without inventing one it did not.
func tagPageLink(name, cursor string, limit int) string {
	query := url.Values{}
	query.Set("last", cursor)
	if limit > 0 {
		query.Set("n", strconv.Itoa(limit))
	}
	return fmt.Sprintf("</v2/%s/tags/list?%s>; rel=\"next\"", name, query.Encode())
}
