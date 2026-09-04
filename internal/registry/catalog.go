package registry

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/server"
)

// CatalogMeta is the slice of the metadata store the catalog needs, declared
// by the consumer (§11). It is one method, and that is the point: the catalog
// can read repository names and nothing else, through a call that will not
// compile without a Visibility.
type CatalogMeta interface {
	ListRepositories(ctx context.Context, opts meta.ListOptions) (meta.RepositoryPage, error)
}

// Catalog serves GET /v2/_catalog (R-004): the spec's list of repository
// names, filtered to what the subject may list and paginated with the spec's
// `n` and `last`.
//
// The filtering is not this handler's work and deliberately so. The route is
// registered as a Listing, so the guard has already compiled the subject's
// bindings into the Visibility its verb grants and put it in the context; the
// handler passes that value to the store and the store builds its WHERE clause
// from it. There is no unfiltered read to forget to filter, which is what
// ADR 0003 surface 1 asks for -- counts and cursors included, since both come
// out of the same filtered query.
type Catalog struct {
	// Meta supplies the names.
	Meta CatalogMeta
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the catalog route on the table. It is a plain mux route rather
// than an OCI suffix route: `_catalog` is registry-wide and names no
// repository, so there is no resource to decide against and the permission is
// a Listing on repo:list (ADR 0002).
func (c *Catalog) Register(r *server.Router) {
	r.Handle(http.MethodGet, "/v2/_catalog",
		server.Permission{Verb: authz.RepoList, Listing: true}, c)
}

// catalogResponse is the spec's wire shape. The slice is always non-nil so an
// empty catalog marshals as `[]` rather than `null`: clients iterate it, and a
// null would make "nothing you may list" look like a malformed answer.
type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

// ServeHTTP answers GET /v2/_catalog. The handler is the whole route, so it
// is the http.Handler itself rather than a method Register wraps -- which
// also means the fail-closed path below can be exercised directly.
//
// Every repository type is listed -- hosted, proxy, and group alike -- because
// each is a pullable endpoint and the catalog names endpoints. ADR 0005's
// per-type semantics (a proxy enumerates cached content only, a group the
// union of its readable members) govern *content* enumeration and arrive with
// the Phase 4 router; entities are exact names, so listing the visible
// entities is the whole of the catalog until then.
func (c *Catalog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	visibility, ok := server.VisibilityFrom(r.Context())
	if !ok {
		// Unreachable on the route Register puts down: the guard stores a
		// Visibility for every Listing it admits. Reaching here means the
		// handler was mounted somewhere else, and without a Visibility there
		// is no filter -- so it refuses. An empty catalog would hide the
		// mistake behind a plausible page, and a full one would be the leak.
		server.Logger(r.Context(), c.Log).Error("the catalog ran outside a listing route")
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	query := r.URL.Query()
	limit, ok := catalogPageSize(w, query.Get("n"))
	if !ok {
		return
	}

	page, err := c.Meta.ListRepositories(r.Context(), meta.ListOptions{
		Visibility: visibility,
		Limit:      limit,
		Cursor:     query.Get("last"),
	})
	if err != nil {
		server.Logger(r.Context(), c.Log).Error("list repositories", "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	names := make([]string, 0, len(page.Repositories))
	for _, repo := range page.Repositories {
		// The store ordered them; re-sorting here would be a second opinion
		// about the order the cursor already encodes.
		names = append(names, repo.Name)
	}
	if page.NextCursor != "" {
		w.Header().Set("Link", catalogNextLink(page.NextCursor, limit))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(catalogResponse{Repositories: names}); err != nil {
		server.Logger(r.Context(), c.Log).Error("write catalog", "error", err)
	}
}

// catalogPageSize reads the spec's `n`. Absent means the store's default, and
// so does an explicit zero -- a client asking for nothing is asking for the
// default rather than for an empty page it could not paginate out of. Anything
// unparseable or negative is the client's mistake and is named as such: a
// silent fallback would page differently from what the client asked for.
func catalogPageSize(w http.ResponseWriter, raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		writeError(w, http.StatusBadRequest, CodeUnsupported,
			"the n parameter must be a non-negative integer")
		return 0, false
	}
	return n, true
}

// catalogNextLink builds the spec's `Link` header for the next page. The
// cursor is whatever the store handed back and the values are escaped, so a
// repository name carrying a reserved character cannot break the URL the
// client parses. `n` is echoed only when the client sent one, so following the
// link keeps the page size it chose without inventing one it did not.
func catalogNextLink(cursor string, limit int) string {
	next := url.Values{}
	next.Set("last", cursor)
	if limit > 0 {
		next.Set("n", strconv.Itoa(limit))
	}
	return "</v2/_catalog?" + next.Encode() + `>; rel="next"`
}
