package disclosure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// ADR 0003 surface 1, end to end: the real guard in front of the real
// /v2/_catalog handler, over a store whose hidden repositories are placed
// where a leak would show -- lexically between visible ones, and precisely at
// the page boundaries, where a limit-then-filter implementation gives itself
// away through a short page or a cursor.

// catalogHiddenSuffix marks the repositories nobody in this file may list. It
// is a suffix rather than a separate prefix so the hidden names interleave
// with the visible ones instead of sorting into their own block.
const catalogHiddenSuffix = "-hidden"

// catalogPageSize is small enough that every boundary is exercised.
const catalogPageSize = 2

// catalogVisible is what the scoped subject may list, in the order the store
// must return it.
var catalogVisible = []string{
	"team-a/api-1", "team-a/api-2", "team-a/api-3", "team-a/api-4", "team-a/api-5",
}

// catalogFixture is the catalog served the way serve wires it: one guard, the
// spec's error envelope on the /v2/ tree, and the handler reading only the
// Visibility the guard compiled.
type catalogFixture struct {
	store  *memory.Store
	router *server.Router
}

func catalogNewFixture(t *testing.T) catalogFixture {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	if err := store.CreateSubject(ctx, meta.Subject{
		ID: "u-catalog-carol", Kind: meta.User, Name: "catalog-carol",
	}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{
		Name: "catalog-developer", Verbs: []string{"repo:list", "repo:read"},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	// One entity, mounted at the first path segment, holding every name below
	// (ADR 0005). Visible and hidden alike route through it, so nothing here
	// can pass by being unroutable rather than unreadable.
	if _, err := store.CreateRepository(ctx, meta.Repository{Name: "team-a", Type: meta.Hosted}); err != nil {
		t.Fatalf("CreateRepository(team-a): %v", err)
	}
	for i, name := range catalogVisible {
		for _, repo := range []string{name, name + catalogHiddenSuffix} {
			// The catalog lists the names content can be pulled from, not the
			// repositories an operator configured (ADR 0005), so every name
			// here -- hidden ones included -- holds a manifest. A hidden name
			// with nothing in it would be filtered out by having no content
			// rather than by the visibility, and the test would prove nothing.
			if err := store.PutManifest(ctx, meta.Manifest{
				Repository: repo,
				Digest:     meta.Digest(fmt.Sprintf("sha256:%064x", i*2+len(repo))),
				MediaType:  "application/vnd.oci.image.manifest.v1+json",
				Payload:    []byte(`{"schemaVersion":2}`),
				Size:       19,
			}, nil); err != nil {
				t.Fatalf("PutManifest(%q): %v", repo, err)
			}
		}
		// One exact-scope binding per visible repository. A prefix scope would
		// sweep the hidden neighbours in with them, and then the test would be
		// asserting nothing.
		if err := store.CreateBinding(ctx, meta.Binding{
			ID:            fmt.Sprintf("cb-catalog-%d", i),
			PrincipalKind: meta.PrincipalSubject,
			PrincipalID:   "u-catalog-carol",
			Role:          "catalog-developer",
			Scope:         name,
		}); err != nil {
			t.Fatalf("CreateBinding(%q): %v", name, err)
		}
	}

	router := server.NewRouter(&server.Guard{
		Subjects: store,
		Bindings: store,
		// /v2/_catalog must speak the distribution envelope, not problem+json
		// (ADR 0015): a docker client parses the refusal too.
		Errors: server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Catalog{Meta: store}).Register(router)
	return catalogFixture{store: store, router: router}
}

func (f catalogFixture) get(t *testing.T, as, target string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// catalogPage decodes one page and returns its names alongside the target of
// the Link header, empty on the last page.
func catalogPage(t *testing.T, rec *httptest.ResponseRecorder) ([]string, string) {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("catalog page: %d %s, want 200", rec.Code, rec.Body)
	}
	var body struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body, err)
	}

	link := rec.Header().Get("Link")
	if link == "" {
		return body.Repositories, ""
	}
	target, ok := strings.CutPrefix(link, "<")
	if !ok {
		t.Fatalf("Link = %q, want the target in angle brackets", link)
	}
	target, rest, ok := strings.Cut(target, ">")
	if !ok || rest != `; rel="next"` {
		t.Fatalf("Link = %q, want a bracketed rel=next target", link)
	}
	return body.Repositories, target
}

// A scoped subject's catalog never contains, counts, or cursors past a hidden
// repository -- through the guard, through the handler, page by page.
func TestCatalogSurfaceHidesUnreadableRepositories(t *testing.T) {
	t.Parallel()
	f := catalogNewFixture(t)

	var got []string
	pages := 0
	for target := fmt.Sprintf("/v2/_catalog?n=%d", catalogPageSize); target != ""; {
		pages++
		if pages > len(catalogVisible) {
			t.Fatal("pagination did not terminate")
		}
		names, next := catalogPage(t, f.get(t, "catalog-carol", target))
		for _, name := range names {
			if strings.HasSuffix(name, catalogHiddenSuffix) {
				t.Fatalf("page %d names hidden repository %q", pages, name)
			}
		}
		if next == "" {
			got = append(got, names...)
			break
		}
		// A full page every time until the last: a page cut short because
		// hidden rows were filtered out of it would disclose their count.
		if len(names) != catalogPageSize {
			t.Fatalf("page %d holds %d names, want %d: a short page leaks a filtered count",
				pages, len(names), catalogPageSize)
		}
		if strings.Contains(next, catalogHiddenSuffix) {
			t.Fatalf("cursor %q names a hidden repository", next)
		}
		got = append(got, names...)
		target = next
	}

	if strings.Join(got, ",") != strings.Join(catalogVisible, ",") {
		t.Fatalf("catalog = %v, want exactly %v", got, catalogVisible)
	}
	// Five names, two a page: three pages, two of which end on a boundary a
	// hidden repository sits at. A single-page answer would slip every
	// boundary assertion above.
	if want := (len(catalogVisible) + catalogPageSize) / catalogPageSize; pages != want {
		t.Fatalf("stitched %d pages, want %d", pages, want)
	}
}

// Anonymous holding nothing gets the challenge rather than an empty catalog:
// it may be able to authenticate into visibility, and the empty page would be
// a claim about what exists (ADR 0003).
func TestCatalogSurfaceChallengesAnonymous(t *testing.T) {
	t.Parallel()
	f := catalogNewFixture(t)

	rec := f.get(t, "", "/v2/_catalog")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous catalog: %d %s, want 401", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want a bearer challenge", got)
	}
	if !strings.Contains(rec.Body.String(), registry.CodeUnauthorized) {
		t.Errorf("body = %s, want the spec envelope on the /v2/ tree", rec.Body)
	}
}

// The catalog is the union of hosted and cached content (C-021), which means
// the cached half is a tenth surface for the same leak. It is worth its own
// walk rather than a store-level assertion: the union happens inside one
// query, and an implementation that filtered only the hosted branch would
// still return the right *names* to an unrestricted subject and leak only to a
// scoped one, through exactly the pages, counts and cursors ADR 0003 names.

// catalogCachedVisible is the proxied content the scoped subject may list.
// The names interleave with their hidden neighbours because the hidden ones
// share their prefixes.
var catalogCachedVisible = []string{
	"dockerhub/library/nginx", "dockerhub/library/redis", "ghcr/steveokay/trove",
}

// catalogCachedFixture is catalogNewFixture plus two proxy entities holding
// cached content, half of it unreadable by the subject.
func catalogCachedFixture(t *testing.T) catalogFixture {
	t.Helper()

	ctx := context.Background()
	f := catalogNewFixture(t)

	for _, entity := range []string{"dockerhub", "ghcr"} {
		if _, err := f.store.CreateRepository(ctx, meta.Repository{
			Name: entity, Type: meta.Proxy,
		}); err != nil {
			t.Fatalf("CreateRepository(%q): %v", entity, err)
		}
	}

	for i, name := range catalogCachedVisible {
		for _, repo := range []string{name, name + catalogHiddenSuffix} {
			if err := f.store.PutCachedManifest(ctx, meta.CachedManifest{
				Repository: repo,
				Digest:     meta.Digest(fmt.Sprintf("sha256:%064x", 1000+i*2+len(repo))),
				MediaType:  "application/vnd.oci.image.manifest.v1+json",
				Payload:    []byte(`{"schemaVersion":2}`),
				Size:       19,
			}, nil); err != nil {
				t.Fatalf("PutCachedManifest(%q): %v", repo, err)
			}
		}
		// Exact scopes again, for the same reason: a prefix would sweep in the
		// hidden neighbour and the test would assert nothing.
		if err := f.store.CreateBinding(ctx, meta.Binding{
			ID:            fmt.Sprintf("cb-catalog-cached-%d", i),
			PrincipalKind: meta.PrincipalSubject,
			PrincipalID:   "u-catalog-carol",
			Role:          "catalog-developer",
			Scope:         name,
		}); err != nil {
			t.Fatalf("CreateBinding(%q): %v", name, err)
		}
	}
	return f
}

func TestCatalogSurfaceHidesUnreadableCachedContent(t *testing.T) {
	t.Parallel()
	f := catalogCachedFixture(t)

	// Both kinds, in one lexical order, because that is what a client walks.
	want := append(append([]string{}, catalogCachedVisible...), catalogVisible...)
	sort.Strings(want)

	var got []string
	pages := 0
	for target := fmt.Sprintf("/v2/_catalog?n=%d", catalogPageSize); target != ""; {
		pages++
		if pages > len(want) {
			t.Fatal("pagination did not terminate")
		}
		names, next := catalogPage(t, f.get(t, "catalog-carol", target))
		for _, name := range names {
			if strings.HasSuffix(name, catalogHiddenSuffix) {
				t.Fatalf("page %d names hidden content %q", pages, name)
			}
		}
		got = append(got, names...)
		if next == "" {
			break
		}
		if len(names) != catalogPageSize {
			t.Fatalf("page %d holds %d names, want %d: a short page leaks a filtered count",
				pages, len(names), catalogPageSize)
		}
		if strings.Contains(next, catalogHiddenSuffix) {
			t.Fatalf("cursor %q names hidden content", next)
		}
		target = next
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog = %v, want exactly %v", got, want)
	}
}

// TestCatalogSurfaceListsCachedContentAtAll is the positive half, and it is
// here rather than in the store suite because a leak is only interesting if
// the feature works: a handler that returned nothing for proxied content would
// pass every assertion above while making the union pointless.
func TestCatalogSurfaceListsCachedContentAtAll(t *testing.T) {
	t.Parallel()
	f := catalogCachedFixture(t)

	names, _ := catalogPage(t, f.get(t, "catalog-carol", "/v2/_catalog?n=100"))
	for _, want := range catalogCachedVisible {
		if !slices.Contains(names, want) {
			t.Errorf("catalog = %v, want it to include cached content %q", names, want)
		}
	}
}
