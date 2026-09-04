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
// can read the names that hold content and nothing else, through a call that
// will not compile without a Visibility.
type CatalogMeta interface {
	ListContentNames(ctx context.Context, opts meta.ListOptions) (meta.ContentNamePage, error)
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
// What it lists is full OCI repository names that hold content, not repository
// entities. An entity is mounted at the first path segment of a name, so the
// entity `team-a` may hold `team-a/api` and `team-a/web`, and a client pulls
// from the latter (ADR 0005). Listing entities would name endpoints that
// resolve nothing, and would hide the ones that resolve something.
//
// ADR 0005 assembles that list per entity type, and only the hosted half of it
// exists today:
//
//   - hosted entities enumerate their manifests, which is the query below;
//   - proxies enumerate cached content only, never the upstream -- the cached
//     tables do not exist yet (ADR 0009 keeps them a separate family), so a
//     proxy contributes nothing here until C-004;
//   - groups enumerate the union of the members their subject may read, which
//     is C-012's permission-filtered resolution and contributes nothing yet.
//
// Both gaps are silence rather than a wrong answer: a name that cannot be
// pulled from is not listed.
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

	page, err := c.Meta.ListContentNames(r.Context(), meta.ListOptions{
		Visibility: visibility,
		Limit:      limit,
		Cursor:     query.Get("last"),
	})
	if err != nil {
		server.Logger(r.Context(), c.Log).Error("list content names", "error", err)
		writeError(w, http.StatusInternalServerError, CodeUnknown, "internal error")
		return
	}

	// The store ordered them and the cursor encodes that order; re-sorting
	// here would be a second opinion about it. The copy is only so an empty
	// page marshals as `[]` rather than `null`.
	names := make([]string, 0, len(page.Names))
	names = append(names, page.Names...)
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
