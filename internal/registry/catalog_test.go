package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// catalogListerRole is the only role in these tests that carries repo:list.
// None of the fixture's own roles do, which is what makes carol the
// verb-negative case without any extra setup.
const catalogListerRole = "catalog-lister"

// catalogStack is the shared fixture with the catalog handler registered on
// it, plus a role that can list.
func catalogStack(t *testing.T) stack {
	t.Helper()

	s := newStack(t)
	if err := s.metaDB.CreateRole(context.Background(), meta.Role{
		Name: catalogListerRole, Verbs: []string{"repo:list", "repo:read"},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	(&registry.Catalog{Meta: s.metaDB}).Register(s.router)
	return s
}

// catalogLister creates a subject holding catalogListerRole at every given
// scope, and returns its name.
func catalogLister(t *testing.T, s stack, name string, scopes ...string) string {
	t.Helper()

	ctx := context.Background()
	id := "u-" + name
	if err := s.metaDB.CreateSubject(ctx, meta.Subject{ID: id, Kind: meta.User, Name: name}); err != nil {
		t.Fatalf("CreateSubject(%q): %v", name, err)
	}
	catalogBind(t, s, id, scopes...)
	return name
}

// catalogBind grants catalogListerRole to a principal at each scope.
func catalogBind(t *testing.T, s stack, principal string, scopes ...string) {
	t.Helper()

	for i, scope := range scopes {
		if err := s.metaDB.CreateBinding(context.Background(), meta.Binding{
			ID:            fmt.Sprintf("cb-%s-%d", principal, i),
			PrincipalKind: meta.PrincipalSubject,
			PrincipalID:   principal,
			Role:          catalogListerRole,
			Scope:         scope,
		}); err != nil {
			t.Fatalf("CreateBinding(%q, %q): %v", principal, scope, err)
		}
	}
}

// catalogRepos creates repositories of the given type, holding no content.
func catalogRepos(t *testing.T, s stack, kind meta.RepositoryType, names ...string) {
	t.Helper()

	for _, name := range names {
		if _, err := s.metaDB.CreateRepository(context.Background(),
			meta.Repository{Name: name, Type: kind}); err != nil {
			t.Fatalf("CreateRepository(%q): %v", name, err)
		}
	}
}

// catalogSeed puts one manifest under each full content name, creating the
// entity that name is mounted under if nothing has yet. The catalog lists the
// names content can be pulled from (ADR 0005), so seeding a catalog entry
// means storing content -- and content needs its entity, never a row of its
// own.
func catalogSeed(t *testing.T, s stack, names ...string) {
	t.Helper()

	for _, name := range names {
		entity, _, _ := strings.Cut(name, "/")
		if _, err := s.metaDB.GetRepository(context.Background(), entity); errors.Is(err, meta.ErrNotFound) {
			catalogRepos(t, s, meta.Hosted, entity)
		}
		payload := imageManifest(fmt.Sprintf(`"annotations": {"repo": %q}`, name))
		if err := s.metaDB.PutManifest(context.Background(), meta.Manifest{
			Repository: name,
			Digest:     meta.Digest(manifestDigest(payload)),
			MediaType:  artifact.MediaTypeOCIManifest,
			Payload:    []byte(payload),
			Size:       int64(len(payload)),
			CreatedAt:  fixedTime,
		}, nil); err != nil {
			t.Fatalf("PutManifest(%q): %v", name, err)
		}
	}
}

// catalogNames decodes a catalog response, insisting on the spec's shape and
// on a 200: a body read from a refusal is how a disclosure test passes by
// accident.
func catalogNames(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("catalog: %d %s, want 200", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body, err)
	}
	return body.Repositories
}

// catalogNextPage returns the target the Link header points at, or "" on the
// last page.
func catalogNextPage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	link := rec.Header().Get("Link")
	if link == "" {
		return ""
	}
	if !strings.HasSuffix(link, `; rel="next"`) {
		t.Fatalf("Link = %q, want a rel=next link", link)
	}
	target, ok := strings.CutPrefix(link, "<")
	if !ok {
		t.Fatalf("Link = %q, want the target in angle brackets", link)
	}
	target, _, ok = strings.Cut(target, ">")
	if !ok {
		t.Fatalf("Link = %q, want the target in angle brackets", link)
	}
	return target
}

// A scoped subject sees its subtree and nothing beside it. secret/vault holds
// content and is readable by nobody in the fixture, so its absence here is the
// whole of ADR 0003 surface 1 at the handler.
func TestCatalogListsExactlyTheSubjectsScope(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)
	catalogSeed(t, s, "team-a/api", "secret/vault")
	catalogLister(t, s, "catalog-scoped", "team-a/*")

	got := catalogNames(t, s.do(t, http.MethodGet, "/v2/_catalog", "catalog-scoped", ""))
	want := []string{"team-a/api"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog = %v, want %v in lexical order", got, want)
	}
}

// The catalog names what can be pulled, not what has been configured
// (ADR 0005). A hosted repository enumerates its manifests; one holding
// nothing names no endpoint and is absent, as are the types whose content
// enumeration has not landed -- a proxy lists cached content only (C-004) and
// a group the union of its readable members (C-012), and neither has any yet.
func TestCatalogListsContentNotEntities(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)
	catalogSeed(t, s, "team-a/web")
	// A configured hosted repository nobody has pushed to, a group, and the
	// fixture's proxy: three endpoints, no content between them.
	catalogRepos(t, s, meta.Hosted, "team-a/pending")
	catalogRepos(t, s, meta.Group, "team-a/group")
	catalogSeed(t, s, "team-a/api", "secret/vault")
	catalogLister(t, s, "catalog-wide", "*")

	got := catalogNames(t, s.do(t, http.MethodGet, "/v2/_catalog", "catalog-wide", ""))
	want := []string{"secret/vault", "team-a/api", "team-a/web"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog = %v, want %v", got, want)
	}
}

// A subject with no listing grants gets its empty page, and the empty list is
// `[]` rather than `null`: clients iterate it, and the two are not the same
// answer to a client that checks.
func TestCatalogWithoutRepoListIsEmpty(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)

	// carol holds repo:read and repo:write across team-a/*, and no repo:list
	// anywhere: scope breadth is not the verb.
	rec := s.do(t, http.MethodGet, "/v2/_catalog", "carol", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog without repo:list: %d %s, want 200", rec.Code, rec.Body)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"repositories":[]}` {
		t.Fatalf("body = %s, want a literal empty list", got)
	}
}

// Anonymous with nothing visible gets the challenge, not an empty page: the
// client may be able to authenticate into visibility (ADR 0003). The guard
// does this, and the assertion is that it still holds on the real route.
func TestCatalogAnonymousWithNothingIsChallenged(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)

	rec := s.do(t, http.MethodGet, "/v2/_catalog", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous catalog: %d %s, want 401", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want a bearer challenge", got)
	}
	if !strings.Contains(rec.Body.String(), registry.CodeUnauthorized) {
		t.Errorf("body = %s, want the spec envelope", rec.Body)
	}
}

// Anonymous is a subject like any other: bound, it is served its slice, and
// the slice is still a slice (the anonymous-reader deployment shape).
func TestCatalogAnonymousWithGrantsIsFiltered(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)
	catalogSeed(t, s, "team-a/api", "secret/vault")
	catalogSeed(t, s, "team-a/web")
	catalogBind(t, s, meta.AnonymousSubjectID, "team-a/*")

	got := catalogNames(t, s.do(t, http.MethodGet, "/v2/_catalog", "", ""))
	if len(got) != 2 || got[0] != "team-a/api" || got[1] != "team-a/web" {
		t.Fatalf("anonymous catalog = %v, want team-a/* alone", got)
	}
}

// Pagination, stitched through the Link header the client actually follows:
// the pages concatenate to the full visible set with no duplicate and no gap,
// the last page carries no Link, and no page or cursor ever names a hidden
// repository -- the hidden ones sit lexically between visible ones and at the
// page boundaries themselves, which is where a naive limit-then-filter
// implementation leaks a count or a cursor (ADR 0003).
func TestCatalogPaginationNeverNamesAHiddenRepository(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)

	const visibleCount = 25
	var want []string
	for i := range visibleCount {
		want = append(want, fmt.Sprintf("page/r%02d", i))
	}
	catalogSeed(t, s, want...)
	// With n=7 the pages break after r06, r13 and r20; a hidden repository
	// sits immediately after each break and one more mid-page.
	catalogSeed(t, s, "page/r03x", "page/r06x", "page/r13x", "page/r20x")

	// Exact scopes, one per visible repository: a prefix scope could not
	// interleave hidden names inside the visible range.
	catalogLister(t, s, "catalog-pager", want...)

	var got []string
	seen := map[string]bool{}
	pages := 0
	for target := "/v2/_catalog?n=7"; target != ""; {
		pages++
		if pages > visibleCount {
			t.Fatal("pagination did not terminate")
		}
		rec := s.do(t, http.MethodGet, target, "catalog-pager", "")
		names := catalogNames(t, rec)
		for _, name := range names {
			if strings.HasSuffix(name, "x") {
				t.Fatalf("page %d names hidden repository %q", pages, name)
			}
			if seen[name] {
				t.Fatalf("page %d repeats %q", pages, name)
			}
			seen[name] = true
			got = append(got, name)
		}
		next := catalogNextPage(t, rec)
		if next == "" {
			if len(names) != visibleCount%7 {
				t.Fatalf("last page holds %d names, want the remainder", len(names))
			}
			break
		}
		if len(names) != 7 {
			t.Fatalf("page %d holds %d names, want the requested 7", pages, len(names))
		}
		if !strings.Contains(next, "n=7") {
			t.Errorf("next link %q dropped the page size the client chose", next)
		}
		if strings.Contains(next, "x") {
			t.Fatalf("cursor %q names a hidden repository", next)
		}
		target = next
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stitched pages = %v, want the full visible set in order", got)
	}
	// 25 names at 7 a page is four pages. Asserting the count is what stops
	// this test passing on a single unpaginated answer.
	if pages != 4 {
		t.Fatalf("stitched %d pages, want 4", pages)
	}
}

// The page size is the client's, so an unusable one is named rather than
// silently replaced -- a client that asked for 10 and got 100 pages wrong.
func TestCatalogRejectsABadPageSize(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)
	catalogSeed(t, s, "team-a/api")
	catalogSeed(t, s, "team-a/web")
	catalogLister(t, s, "catalog-sizer", "team-a/*")

	// "%207" is a padded number: Atoi refuses it, and so must we -- accepting
	// it would mean two spellings of one page size.
	for _, n := range []string{"abc", "-1", "7.5", "%207"} {
		t.Run("n="+n, func(t *testing.T) {
			rec := s.do(t, http.MethodGet, "/v2/_catalog?n="+n, "catalog-sizer", "")
			if rec.Code != http.StatusBadRequest ||
				!strings.Contains(rec.Body.String(), registry.CodeUnsupported) {
				t.Fatalf("n=%q: %d %s, want 400 UNSUPPORTED", n, rec.Code, rec.Body)
			}
		})
	}

	// Zero is not an error: a client asking for nothing gets the default page
	// rather than an empty one it could never paginate out of.
	got := catalogNames(t, s.do(t, http.MethodGet, "/v2/_catalog?n=0", "catalog-sizer", ""))
	if len(got) != 2 {
		t.Fatalf("n=0 returned %v, want the default page", got)
	}
}

// catalogFaultyMeta is a store whose only broken method is the one the catalog
// calls, so the guard's own lookups still succeed and the failure lands in the
// handler under test.
type catalogFaultyMeta struct {
	*metamem.Store
}

var errCatalogDisk = errors.New("catalog store on fire")

func (catalogFaultyMeta) ListContentNames(context.Context, meta.ListOptions) (meta.ContentNamePage, error) {
	return meta.ContentNamePage{}, errCatalogDisk
}

// A store that cannot answer is a spec-shaped 500, never an empty catalog: an
// empty page is a claim that the subject may list nothing, and a disk hiccup
// is not entitled to make that claim.
func TestCatalogStoreFailureIsAServerError(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)
	catalogLister(t, s, "catalog-unlucky", "team-a/*")

	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Catalog{Meta: catalogFaultyMeta{Store: s.metaDB}}).Register(router)
	armed := stack{handler: router, router: router, metaDB: s.metaDB, blobs: s.blobs}

	rec := armed.do(t, http.MethodGet, "/v2/_catalog", "catalog-unlucky", "")
	if rec.Code != http.StatusInternalServerError ||
		!strings.Contains(rec.Body.String(), registry.CodeUnknown) {
		t.Fatalf("broken store: %d %s, want a spec-shaped 500", rec.Code, rec.Body)
	}
}

// Mounted anywhere but behind the guard's listing route there is no
// Visibility, and without one there is no filter: the handler refuses rather
// than answering with a page nobody bounded. The store is nil here, which is
// the assertion -- it is never reached.
func TestCatalogRefusesWithoutAVisibility(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	(&registry.Catalog{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusInternalServerError ||
		!strings.Contains(rec.Body.String(), registry.CodeUnknown) {
		t.Fatalf("catalog off a listing route: %d %s, want a spec-shaped 500", rec.Code, rec.Body)
	}
}

// catalogDeadWriter is a client that hung up mid-response.
type catalogDeadWriter struct {
	http.ResponseWriter
}

func (catalogDeadWriter) Write([]byte) (int, error) { return 0, errCatalogDisk }

// A connection that dies while the page is being written is the client's
// business, not a panic: the status is already out and there is nothing left
// to say.
func TestCatalogSurvivesADeadConnection(t *testing.T) {
	t.Parallel()

	s := catalogStack(t)
	catalogSeed(t, s, "team-a/api")
	catalogLister(t, s, "catalog-hangup", "team-a/*")

	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
	req.Header.Set("X-Test-Subject", "catalog-hangup")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(catalogDeadWriter{ResponseWriter: rec}, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status before the write failed: %d, want 200", rec.Code)
	}
}
