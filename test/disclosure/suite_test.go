// Package disclosure is the living disclosure suite (Z-018, ADR 0003).
//
// Existence is information: if a subject cannot read a repository, no
// surface may reveal that it exists -- not a listing, not a count, not a
// cursor, not a status code that differs by a byte from the genuinely-absent
// answer. The ten surfaces ADR 0003 enumerates are subtests here; the ones
// whose endpoints have not landed are skipped through a tracked list that
// names the task that will land them, and marking that task done in
// status.md fails this suite until the skip is replaced with a test.
package disclosure

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authn/token"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// pendingSurfaces is the skip-list: ADR 0003 surfaces whose endpoints do not
// exist yet, each naming the status.md task that ships them. The ratchet
// below fails the suite when a named task is done, so a surface cannot land
// without its disclosure test landing in the same breath.
var pendingSurfaces = map[string]string{
	"catalog endpoint":                     "R-004",
	"referrers listing":                    "R-005",
	"cross-repo search":                    "E-010",
	"webhook event delivery":               "E-004",
	"metric label values":                  "E-006",
	"group resolution":                     "C-012",
	"scan and policy reports":              "S-006",
	"audit log (the deliberate exception)": "E-009",
}

// fixture is the registry every surface walks: carol reads team-a/*, the
// secret/* repositories exist and are readable by nobody but root, and
// anonymous holds nothing.
type fixture struct {
	store  *memory.Store
	router *server.Router
	signer *token.Signer
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	for _, subject := range []meta.Subject{
		{ID: "u-carol", Kind: meta.User, Name: "carol"},
		{ID: "u-bob", Kind: meta.User, Name: "bob"},
		{ID: "u-root", Kind: meta.User, Name: "root"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	for _, name := range []string{"team-a/api", "team-a/web", "secret/vault", "secret/keys"} {
		if _, err := store.CreateRepository(ctx, meta.Repository{Name: name, Type: meta.Hosted}); err != nil {
			t.Fatalf("CreateRepository: %v", err)
		}
	}
	for _, role := range []meta.Role{
		{Name: "developer", Verbs: []string{"repo:list", "repo:read"}},
		{Name: "everything", Verbs: []string{"repo:list", "repo:read", "user:read"}},
	} {
		if err := store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-carol", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-carol", Role: "developer", Scope: "team-a/*"},
		{ID: "b-root", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-root", Role: "everything", Scope: "*"},
		{ID: "b-root-sys", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-root", Role: "everything", Scope: "system"},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}

	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := token.NewSigner(key, 0, nil, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	credentials := func(r *http.Request) (string, error) {
		return r.Header.Get("X-Test-Subject"), nil
	}
	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store, Credentials: credentials})
	(&server.AuthExplain{Subjects: store, Bindings: store}).Register(router)
	(&server.TokenEndpoint{
		Credentials: credentials, Subjects: store, Bindings: store, Signer: signer,
	}).Register(router)
	// The repository-resource stand-in every content route will look like:
	// guarded by repo:read with the name out of the path.
	router.HandleFunc(http.MethodGet, "/api/v1/repos/{name...}", server.Permission{
		Verb: authz.RepoRead,
		Resource: func(r *http.Request) (authz.Resource, error) {
			return authz.Repository(r.PathValue("name"))
		},
	}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	return fixture{store: store, router: router, signer: signer}
}

func (f fixture) get(t *testing.T, as, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// visible runs the exact pipeline a catalog handler will: the subject's
// effective bindings, compiled into a visibility, filtering in the query.
func visible(t *testing.T, store *memory.Store, subject string, limit int, cursor string) meta.RepositoryPage {
	t.Helper()
	bindings, err := server.FetchBindings(context.Background(), store, subject)
	if err != nil {
		t.Fatalf("FetchBindings: %v", err)
	}
	page, err := store.ListRepositories(context.Background(), meta.ListOptions{
		Visibility: server.VisibilityFor(bindings, authz.RepoList),
		Limit:      limit,
		Cursor:     cursor,
	})
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	return page
}

// Surface 1: repository listings. The hidden subtree is absent from the
// results, from the counts, and from every cursor -- a cursor naming a
// hidden repository would disclose it as surely as listing it.
func TestSurfaceCatalog(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	var names []string
	cursor := ""
	for {
		page := visible(t, f.store, "carol", 1, cursor)
		for _, repo := range page.Repositories {
			names = append(names, repo.Name)
		}
		if page.NextCursor == "" {
			break
		}
		if strings.HasPrefix(page.NextCursor, "secret/") {
			t.Fatalf("cursor %q names a hidden repository", page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if len(names) != 2 || names[0] != "team-a/api" || names[1] != "team-a/web" {
		t.Fatalf("carol's catalog = %v, want exactly her subtree", names)
	}

	if got := visible(t, f.store, "bob", 0, ""); len(got.Repositories) != 0 {
		t.Fatalf("bob's catalog = %v, want empty: he holds no bindings", got.Repositories)
	}
}

// Surface 2, store half: an unreadable repository's tag list answers exactly
// like an absent one -- the same sentinel, never an empty page that admits
// the repository exists with no tags.
func TestSurfaceTagList(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	bindings, err := server.FetchBindings(context.Background(), f.store, "carol")
	if err != nil {
		t.Fatalf("FetchBindings: %v", err)
	}
	visibility := server.VisibilityFor(bindings, authz.RepoRead)

	hidden := func(repo string) error {
		_, err := f.store.ListTags(context.Background(), repo, meta.ListOptions{Visibility: visibility})
		return err
	}
	if err := hidden("secret/vault"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("hidden repository's tags = %v, want not-found", err)
	}
	if err := hidden("ghost/none"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("absent repository's tags = %v, want not-found", err)
	}
}

// The core ADR 0003 assertion at the HTTP layer: for an authenticated
// subject, a repository that exists but is unreadable and one that does not
// exist produce byte-identical responses.
func TestHiddenAndAbsentAreIdentical(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	hidden := f.get(t, "carol", "/api/v1/repos/secret/vault")
	absent := f.get(t, "carol", "/api/v1/repos/ghost/none")

	if hidden.Code != http.StatusNotFound {
		t.Fatalf("hidden repository: %d, want 404", hidden.Code)
	}
	if hidden.Code != absent.Code || hidden.Body.String() != absent.Body.String() {
		t.Fatalf("hidden: %d %s\nabsent: %d %s\nwant byte-identical answers",
			hidden.Code, hidden.Body, absent.Code, absent.Body)
	}
	for _, header := range []string{"Content-Type", "WWW-Authenticate"} {
		if hidden.Header().Get(header) != absent.Header().Get(header) {
			t.Errorf("%s differs between hidden and absent", header)
		}
	}
}

// Surface 8: the effective-permissions endpoint. Subjects see only their own
// permissions without user:read, and the refusal cannot say whether the
// subject they asked about exists.
func TestSurfaceEffectivePermissions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	if rec := f.get(t, "carol", "/api/v1/auth/explain?verb=repo:read&resource=team-a/api"); rec.Code != http.StatusOK {
		t.Fatalf("self-explain: %d", rec.Code)
	}
	real := f.get(t, "carol", "/api/v1/auth/explain?subject=bob&verb=repo:read")
	ghost := f.get(t, "carol", "/api/v1/auth/explain?subject=nobody&verb=repo:read")
	if real.Code != http.StatusForbidden {
		t.Fatalf("explaining another subject without user:read: %d, want 403", real.Code)
	}
	if real.Code != ghost.Code || real.Body.String() != ghost.Body.String() {
		t.Fatal("the refusal differs between an existing and a missing subject: an enumeration oracle")
	}

	if rec := f.get(t, "root", "/api/v1/auth/explain?subject=bob&verb=repo:read"); rec.Code != http.StatusOK {
		t.Fatalf("explain with user:read: %d", rec.Code)
	}
}

// The token endpoint's granted scopes derive from the subject's bindings
// alone, never from what exists: asking for an unreadable-but-real
// repository and a fictional one produces identical grants (none), so the
// mint is not a probe.
func TestTokenGrantsDoNotProbeExistence(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	mint := func(scope string) []token.ResourceActions {
		rec := f.get(t, "carol", "/token?scope=repository:"+scope+":pull")
		if rec.Code != http.StatusOK {
			t.Fatalf("mint: %d %s", rec.Code, rec.Body)
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		claims, err := f.signer.Verify(body.Token)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		return claims.Access
	}

	hidden := mint("secret/vault")
	absent := mint("ghost/none")
	if len(hidden) != 0 || len(absent) != 0 {
		t.Fatalf("grants: hidden %+v, absent %+v; want none for either", hidden, absent)
	}
}

// TestPendingSurfacesStayHonest is the ratchet: each skipped surface names
// the task that ships it, and once status.md marks that task done, the skip
// itself fails -- a surface cannot land without its disclosure test.
func TestPendingSurfacesStayHonest(t *testing.T) {
	t.Parallel()

	status, err := os.ReadFile(filepath.Join(repositoryRoot(t), "status.md"))
	if err != nil {
		t.Fatalf("read status.md: %v", err)
	}

	for surface, task := range pendingSurfaces {
		t.Run(surface, func(t *testing.T) {
			state, ok := taskStatus(string(status), task)
			if !ok {
				t.Fatalf("skip for %q names task %s, which is not in status.md", surface, task)
			}
			if state == "done" {
				t.Fatalf("%s is done but %q is still on the skip-list: wire the surface into this suite and remove the skip", task, surface)
			}
			t.Skipf("surface ships with %s (status: %s)", task, state)
		})
	}
}

// taskStatus reads a task's status cell out of status.md's tables.
func taskStatus(status, task string) (string, bool) {
	for line := range strings.SplitSeq(status, "\n") {
		if !strings.HasPrefix(line, "| "+task+" ") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			return "", false
		}
		return strings.TrimSpace(cells[3]), true
	}
	return "", false
}

// The parser the ratchet trusts gets its own sanity check against tasks
// whose state is known: a done one and a pending one.
func TestTaskStatusParser(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "status.md"))
	if err != nil {
		t.Fatalf("read status.md: %v", err)
	}
	if state, ok := taskStatus(string(raw), "Z-012"); !ok || state != "done" {
		t.Errorf("taskStatus(Z-012) = %q, %v; want done", state, ok)
	}
	if _, ok := taskStatus(string(raw), "Z-999"); ok {
		t.Error("taskStatus invented a task that does not exist")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
