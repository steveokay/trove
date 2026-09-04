package disclosure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// Surface 2, HTTP half (R-003): the tag list endpoint, walked through a real
// guard and the real handler.
//
// The fixture's own router renders refusals as problem+json, which is the
// admin API's shape; the /v2/ tree speaks the distribution envelope, so this
// file wires its own router with the spec renderer -- the same SplitErrors
// wiring `trove serve` uses -- over the fixture's store.

// tagsRegistry is the fixture's data behind the distribution API's tag route.
type tagsRegistry struct {
	fixture
	router *server.Router
}

func tagsFixture(t *testing.T) tagsRegistry {
	t.Helper()

	f := newFixture(t)
	router := server.NewRouter(&server.Guard{
		Subjects: f.store,
		Bindings: f.store,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Tags{Meta: f.store, Bindings: f.store}).Register(router)

	// Both subtrees carry tags, so nothing below can pass by accident: the
	// hidden repository has content to leak and does not leak it.
	tagsSeedRepository(t, f, "team-a/api", "alpha", "beta", "gamma")
	tagsSeedRepository(t, f, "secret/vault", "alpha", "classified", "zulu")
	return tagsRegistry{fixture: f, router: router}
}

// tagsSeedRepository puts one manifest and the named tags into a repository.
func tagsSeedRepository(t *testing.T, f fixture, repo string, names ...string) {
	t.Helper()

	ctx := context.Background()
	digest := meta.Digest("sha256:" + strings.Repeat("a", 64))
	if err := f.store.PutManifest(ctx, meta.Manifest{
		Repository: repo, Digest: digest, MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload: []byte("{}"), Size: 2, CreatedAt: time.Unix(0, 0).UTC(),
	}, nil); err != nil {
		t.Fatalf("PutManifest into %s: %v", repo, err)
	}
	for _, name := range names {
		if err := f.store.PutTag(ctx, meta.Tag{Repository: repo, Name: name, Digest: digest}); err != nil {
			t.Fatalf("PutTag %s:%s: %v", repo, name, err)
		}
	}
}

func (r tagsRegistry) list(t *testing.T, as, target string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	r.router.ServeHTTP(rec, req)
	return rec
}

// A tag list for a repository the subject cannot read is byte-identical to
// one for a repository that does not exist -- and the hidden one holds tags,
// so there is something for a leak to be made of.
func TestTagsSurfaceHiddenAndAbsentAreIdentical(t *testing.T) {
	t.Parallel()
	r := tagsFixture(t)

	hidden := r.list(t, "carol", "/v2/secret/vault/tags/list")
	absent := r.list(t, "carol", "/v2/ghost/none/tags/list")
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("hidden repository: %d %s, want 404", hidden.Code, hidden.Body)
	}
	if hidden.Code != absent.Code || hidden.Body.String() != absent.Body.String() {
		t.Fatalf("hidden: %d %s\nabsent: %d %s\nwant byte-identical answers",
			hidden.Code, hidden.Body, absent.Code, absent.Body)
	}
	if fmt.Sprint(hidden.Header()) != fmt.Sprint(absent.Header()) {
		t.Fatalf("headers differ: %v vs %v", hidden.Header(), absent.Header())
	}
	for _, name := range []string{"classified", "zulu"} {
		if strings.Contains(hidden.Body.String(), name) {
			t.Fatalf("the refusal names %q, a tag of the hidden repository", name)
		}
	}

	// A subject with no bindings at all learns no more about a readable-to-
	// someone-else repository than about a fictional one.
	unbound := r.list(t, "bob", "/v2/team-a/api/tags/list")
	if unbound.Code != http.StatusNotFound || unbound.Body.String() != absent.Body.String() {
		t.Fatalf("unbound subject: %d %s, want the absent answer", unbound.Code, unbound.Body)
	}
}

// The readable repository's pages, and every cursor that stitches them, hold
// only what the subject may read: a Link naming hidden content would disclose
// it as surely as listing it.
func TestTagsSurfacePagesAndLinksHoldOnlyReadableContent(t *testing.T) {
	t.Parallel()
	r := tagsFixture(t)

	var seen []string
	target := "/v2/team-a/api/tags/list?n=1"
	for pages := 0; ; pages++ {
		if pages > 8 {
			t.Fatal("pagination did not terminate")
		}
		rec := r.list(t, "carol", target)
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", pages, rec.Code, rec.Body)
		}
		var page struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page %d: %v", pages, err)
		}
		if page.Name != "team-a/api" {
			t.Fatalf("page %d names %q", pages, page.Name)
		}
		seen = append(seen, page.Tags...)

		link := rec.Header().Get("Link")
		for _, leak := range []string{"secret", "classified", "zulu"} {
			if strings.Contains(rec.Body.String(), leak) || strings.Contains(link, leak) {
				t.Fatalf("page %d body %q or link %q names hidden content", pages, rec.Body, link)
			}
		}
		if link == "" {
			break
		}
		end := strings.Index(link, ">")
		if !strings.HasPrefix(link, "<") || end < 0 {
			t.Fatalf("Link = %q", link)
		}
		target = link[1:end]
	}

	if len(seen) != 3 || seen[0] != "alpha" || seen[1] != "beta" || seen[2] != "gamma" {
		t.Fatalf("carol's tags = %v, want exactly her repository's three", seen)
	}
}

// Anonymous gets the challenge rather than the 404: it may be able to
// authenticate into visibility, and that is the `docker login` contract.
func TestTagsSurfaceAnonymousGetsChallenge(t *testing.T) {
	t.Parallel()
	r := tagsFixture(t)

	for _, target := range []string{
		"/v2/team-a/api/tags/list",
		"/v2/secret/vault/tags/list",
		"/v2/ghost/none/tags/list",
	} {
		rec := r.list(t, "", target)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous GET %s: %d %s, want 401", target, rec.Code, rec.Body)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("anonymous GET %s: 401 without a challenge", target)
		}
	}
}
