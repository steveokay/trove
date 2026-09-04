package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// tagsStack is the shared fixture with the tag listing registered on it: the
// fixture itself wires blobs and manifests, and R-003's route is registered
// here so this file owns it.
func tagsStack(t *testing.T) stack {
	t.Helper()

	s := newStack(t)
	router, ok := s.handler.(*server.Router)
	if !ok {
		t.Fatalf("fixture handler is %T, not the router tag routes register on", s.handler)
	}
	(&registry.Tags{Meta: s.metaDB, Bindings: s.metaDB}).Register(router)
	return s
}

// tagsResponse mirrors the wire shape the handler writes.
type tagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// tagsSeed points the given tag names at one manifest, straight through the
// store: the listing is about names, order, and paging, and a hundred pushes
// would only be a slower way to make the same rows.
func tagsSeed(t *testing.T, s stack, repo string, names ...string) {
	t.Helper()

	ctx := context.Background()
	payload := imageManifest()
	digest := meta.Digest(manifestDigest(payload))
	if err := s.metaDB.PutManifest(ctx, meta.Manifest{
		Repository: repo, Digest: digest, MediaType: artifact.MediaTypeOCIManifest,
		Payload: []byte(payload), Size: int64(len(payload)), CreatedAt: fixedTime,
	}, nil); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	for _, name := range names {
		if err := s.metaDB.PutTag(ctx, meta.Tag{
			Repository: repo, Name: name, Digest: digest, CreatedAt: fixedTime, UpdatedAt: fixedTime,
		}); err != nil {
			t.Fatalf("PutTag %q: %v", name, err)
		}
	}
}

// tagsDecode reads the spec's response body, insisting the answer is JSON.
func tagsDecode(t *testing.T, body string) tagsResponse {
	t.Helper()

	var list tagsResponse
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return list
}

// tagsEqual compares two tag sequences, order included: the order is half of
// what the listing promises.
func tagsEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// tagsNextTarget pulls the request target out of a next-page Link header,
// insisting on the spec's exact shape rather than accepting anything that
// happens to contain a URL.
func tagsNextTarget(t *testing.T, link string) string {
	t.Helper()

	end := strings.Index(link, ">")
	if !strings.HasPrefix(link, "<") || end < 0 || link[end:] != `>; rel="next"` {
		t.Fatalf("Link = %q, want <target>; rel=\"next\"", link)
	}
	return link[1:end]
}

// The round trip: tags pushed as manifest references come back named, in
// lexical order, to a subject who can only read.
func TestTagsListRoundTrip(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	seedImageBlobs(t, s)
	for i, tag := range []string{"v2", "latest", "v1"} {
		putManifest(t, s, "carol", tag, artifact.MediaTypeOCIManifest,
			imageManifest(fmt.Sprintf(`"annotations": {"push": "%d"}`, i)))
	}

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/tags/list", "rita", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET tags/list: %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if link := rec.Header().Get("Link"); link != "" {
		t.Errorf("Link = %q on a single complete page", link)
	}

	list := tagsDecode(t, rec.Body.String())
	if list.Name != "team-a/api" {
		t.Errorf("name = %q", list.Name)
	}
	if want := []string{"latest", "v1", "v2"}; !tagsEqual(list.Tags, want) {
		t.Errorf("tags = %v, want %v in lexical order", list.Tags, want)
	}
}

// Stitching every page together must reproduce the whole set exactly: no
// duplicate across a boundary, no name skipped by one, and no Link once the
// last page has been served.
func TestTagsPaginationStitchesTheWholeSet(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	var seeded []string
	for i := range 25 {
		// Mixed shapes so what is under test is the store's byte ordering
		// rather than the order the rows were written in.
		seeded = append(seeded, []string{
			fmt.Sprintf("v1.%d.0", i),
			fmt.Sprintf("Release_%d", i),
			fmt.Sprintf("nightly-2026-09-%02d", i),
		}[i%3])
	}
	tagsSeed(t, s, "team-a/api", seeded...)
	want := append([]string(nil), seeded...)
	sort.Strings(want)

	var got []string
	target := "/v2/team-a/api/tags/list?n=7"
	for pages := 0; ; pages++ {
		if pages > len(seeded) {
			t.Fatalf("pagination did not terminate after %d pages", pages)
		}
		rec := s.do(t, http.MethodGet, target, "rita", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", pages, rec.Code, rec.Body)
		}
		page := tagsDecode(t, rec.Body.String())
		if len(page.Tags) > 7 {
			t.Fatalf("page %d holds %d tags, more than the 7 requested", pages, len(page.Tags))
		}
		got = append(got, page.Tags...)

		link := rec.Header().Get("Link")
		if link == "" {
			if len(page.Tags) == 0 {
				t.Fatalf("page %d is both empty and final", pages)
			}
			break
		}
		target = tagsNextTarget(t, link)
		if !strings.Contains(target, "n=7") {
			t.Fatalf("next link %q dropped the page size the client chose", target)
		}
	}

	if !tagsEqual(got, want) {
		t.Fatalf("stitched pages = %v\nwant %v", got, want)
	}
}

// A page size the client did not ask for is not echoed back at it: following
// the link keeps the store's default rather than inventing a number.
func TestTagsLinkOmitsUnrequestedPageSize(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	total := meta.DefaultPageSize + 1
	names := make([]string, 0, total)
	for i := range total {
		names = append(names, fmt.Sprintf("v%04d", i))
	}
	tagsSeed(t, s, "team-a/api", names...)

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/tags/list", "rita", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	if got := len(tagsDecode(t, rec.Body.String()).Tags); got != meta.DefaultPageSize {
		t.Fatalf("default page holds %d tags, want %d", got, meta.DefaultPageSize)
	}
	target := tagsNextTarget(t, rec.Header().Get("Link"))
	if want := "/v2/team-a/api/tags/list?last=v0099"; target != want {
		t.Fatalf("next link = %q, want %q", target, want)
	}

	last := s.do(t, http.MethodGet, target, "rita", "")
	if link := last.Header().Get("Link"); link != "" {
		t.Errorf("Link = %q on the final page", link)
	}
	if got := tagsDecode(t, last.Body.String()).Tags; !tagsEqual(got, []string{"v0100"}) {
		t.Errorf("final page = %v", got)
	}
}

// A repository with no tags is a 200 with an empty array, never null: clients
// range over the field without checking it.
func TestTagsEmptyRepositoryAnswersEmptyArray(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	rec := s.do(t, http.MethodGet, "/v2/team-a/mirror/tags/list", "rita", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"tags":[]`) {
		t.Fatalf("body = %q, want an empty array rather than null", rec.Body)
	}
}

// ADR 0003 surface 2: an unreadable repository, an absent one outside the
// subject's scope, and an absent one inside it all answer identically -- body
// and headers both, because a differing header is a differing answer.
func TestTagsHiddenAndAbsentAreIdentical(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	tagsSeed(t, s, "secret/vault", "v1", "v2")

	hidden := s.do(t, http.MethodGet, "/v2/secret/vault/tags/list", "carol", "")
	absent := s.do(t, http.MethodGet, "/v2/secret/absent/tags/list", "carol", "")
	// This one reaches the handler: carol may read team-a/*, so the guard
	// admits her and the repository lookup is what refuses.
	inScope := s.do(t, http.MethodGet, "/v2/team-a/ghost/tags/list", "carol", "")

	for _, tt := range []struct {
		name string
		body string
		code int
		head string
	}{
		{"hidden", hidden.Body.String(), hidden.Code, fmt.Sprint(hidden.Header())},
		{"in-scope absent", inScope.Body.String(), inScope.Code, fmt.Sprint(inScope.Header())},
	} {
		if tt.code != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", tt.name, tt.code)
		}
		if tt.body != absent.Body.String() {
			t.Errorf("%s body %q differs from absent %q", tt.name, tt.body, absent.Body)
		}
		if tt.head != fmt.Sprint(absent.Header()) {
			t.Errorf("%s headers %s differ from absent %s", tt.name, tt.head, absent.Header())
		}
	}
	if !strings.Contains(hidden.Body.String(), registry.CodeNameUnknown) {
		t.Errorf("hidden body = %q, want NAME_UNKNOWN", hidden.Body)
	}
}

// Anonymous gets the challenge, not a 404: it may be able to authenticate
// into visibility, and `docker login` steers by this header.
func TestTagsAnonymousGetsChallenge(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	rec := s.do(t, http.MethodGet, "/v2/team-a/api/tags/list", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d %s, want 401", rec.Code, rec.Body)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 without a WWW-Authenticate challenge")
	}
}

// A page size that is not one is the client's error, not something to ignore:
// a client that asked for a size and silently got another cannot notice.
func TestTagsPageSizeParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		query string
		code  int
	}{
		{query: "?n=abc", code: http.StatusBadRequest},
		{query: "?n=-1", code: http.StatusBadRequest},
		{query: "?n=1.5", code: http.StatusBadRequest},
		{query: "?n=99999999999999999999", code: http.StatusBadRequest},
		// Zero and an empty value both mean "no preference".
		{query: "?n=0", code: http.StatusOK},
		{query: "?n=", code: http.StatusOK},
		{query: "?n=1", code: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			t.Parallel()

			s := tagsStack(t)
			tagsSeed(t, s, "team-a/api", "v1", "v2")
			rec := s.do(t, http.MethodGet, "/v2/team-a/api/tags/list"+tt.query, "rita", "")
			if rec.Code != tt.code {
				t.Fatalf("%s: %d %s, want %d", tt.query, rec.Code, rec.Body, tt.code)
			}
			if tt.code == http.StatusBadRequest && !strings.Contains(rec.Body.String(), registry.CodeUnsupported) {
				t.Fatalf("body = %q, want %s", rec.Body, registry.CodeUnsupported)
			}
		})
	}
}

// The cursor rides through untouched: `last` names the tag to continue after.
func TestTagsCursorContinuesAfterTheNamedTag(t *testing.T) {
	t.Parallel()

	s := tagsStack(t)
	tagsSeed(t, s, "team-a/api", "a", "b", "c")

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/tags/list?last=b", "rita", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	if got := tagsDecode(t, rec.Body.String()).Tags; !tagsEqual(got, []string{"c"}) {
		t.Fatalf("tags after b = %v, want [c]", got)
	}
}

var tagsErrDisk = errors.New("disk on fire")

// tagsFaultyMeta rigs the two store calls the listing makes, one at a time.
type tagsFaultyMeta struct {
	*metamem.Store
	failRepo bool
	failList bool
	// listVanished makes the filtered listing answer not-found for a
	// repository the lookup just returned: what one deleted or unbound
	// between the two calls looks like.
	listVanished bool
}

func (f *tagsFaultyMeta) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if f.failRepo {
		return meta.Repository{}, tagsErrDisk
	}
	return f.Store.GetRepository(ctx, name)
}

func (f *tagsFaultyMeta) ListTags(ctx context.Context, repo string, opts meta.ListOptions) (meta.TagPage, error) {
	switch {
	case f.failList:
		return meta.TagPage{}, tagsErrDisk
	case f.listVanished:
		return meta.TagPage{}, meta.NotFound("repository", repo)
	}
	return f.Store.ListTags(ctx, repo, opts)
}

// tagsFaultyBindings cannot say what the subject may see. The guard keeps the
// healthy store, so the request is admitted and the failure lands in the
// handler's own query-layer filter rather than in the decision.
type tagsFaultyBindings struct {
	*metamem.Store
}

func (tagsFaultyBindings) ListEffectiveBindings(context.Context, string) ([]meta.EffectiveBinding, error) {
	return nil, tagsErrDisk
}

// tagsArmedStack builds the listing over whatever the caller rigs, guarded by
// the healthy store so only the handler's own calls can fail.
func tagsArmedStack(t *testing.T, build func(s stack) *registry.Tags) stack {
	t.Helper()

	s := newStack(t)
	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	build(s).Register(router)
	return stack{handler: router, metaDB: s.metaDB, blobs: s.blobs}
}

// A store that cannot answer is a spec-shaped 500, never a confident "no such
// repository" and never an unfiltered page.
func TestTagsStoreFailuresAreServerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(s stack) *registry.Tags
	}{
		{
			name: "repository lookup",
			build: func(s stack) *registry.Tags {
				return &registry.Tags{
					Meta:     &tagsFaultyMeta{Store: s.metaDB, failRepo: true},
					Bindings: s.metaDB,
				}
			},
		},
		{
			name: "tag listing",
			build: func(s stack) *registry.Tags {
				return &registry.Tags{
					Meta:     &tagsFaultyMeta{Store: s.metaDB, failList: true},
					Bindings: s.metaDB,
				}
			},
		},
		{
			name: "binding fetch",
			build: func(s stack) *registry.Tags {
				return &registry.Tags{Meta: s.metaDB, Bindings: tagsFaultyBindings{Store: s.metaDB}}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			armed := tagsArmedStack(t, tt.build)
			rec := armed.do(t, http.MethodGet, "/v2/team-a/api/tags/list", "carol", "")
			if rec.Code != http.StatusInternalServerError ||
				!strings.Contains(rec.Body.String(), registry.CodeUnknown) {
				t.Fatalf("%s failing: %d %s, want a spec-shaped 500", tt.name, rec.Code, rec.Body)
			}
		})
	}
}

// A repository that disappears between the lookup and the filtered listing
// answers with the ordinary 404: the same bytes an absent one gets.
func TestTagsVanishedRepositoryIsNotFound(t *testing.T) {
	t.Parallel()

	armed := tagsArmedStack(t, func(s stack) *registry.Tags {
		return &registry.Tags{
			Meta:     &tagsFaultyMeta{Store: s.metaDB, listVanished: true},
			Bindings: s.metaDB,
		}
	})

	rec := armed.do(t, http.MethodGet, "/v2/team-a/api/tags/list", "carol", "")
	absent := armed.do(t, http.MethodGet, "/v2/team-a/ghost/tags/list", "carol", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("vanished repository: %d %s, want 404", rec.Code, rec.Body)
	}
	if rec.Body.String() != absent.Body.String() {
		t.Errorf("vanished %q differs from absent %q", rec.Body, absent.Body)
	}
}
