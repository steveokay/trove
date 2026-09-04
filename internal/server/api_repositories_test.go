package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

var reposTime = time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)

// The repository admin fixture. Subjects hold deliberately narrow grants so
// each ADR 0002 split has a subject that proves it both ways:
//
//	root      every verb at system scope -- the operator
//	creator   repo:create + repo:list at system: may create, may not configure
//	keeper    repo:configure + repo:list on the entities: may reconfigure a
//	          hosted one, may not touch a proxy's config (no proxy:write) and
//	          may not delete
//	purger    repo:delete + repo:list: may delete, may not configure
//	watcher   repo:list alone: sees entities, never a proxy's configuration
//	prowler   repo:write + repo:read at `*` and system, and nothing else --
//	          the subject that proves push does not imply administration
type reposFixture struct {
	store  *memory.Store
	router *server.Router
}

func newReposFixture(t *testing.T) reposFixture {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	subjects := []string{"root", "creator", "keeper", "purger", "watcher", "prowler", "proxyadmin"}
	for _, name := range subjects {
		if err := store.CreateSubject(ctx, meta.Subject{ID: "u-" + name, Kind: meta.User, Name: name}); err != nil {
			t.Fatalf("CreateSubject(%q): %v", name, err)
		}
	}

	everyVerb := make([]string, 0, len(authz.AllVerbs()))
	for _, verb := range authz.AllVerbs() {
		everyVerb = append(everyVerb, string(verb))
	}
	for _, role := range []meta.Role{
		{Name: "root", Verbs: everyVerb},
		{Name: "creator", Verbs: []string{"repo:create", "repo:list"}},
		{Name: "keeper", Verbs: []string{"repo:configure", "repo:list"}},
		{Name: "purger", Verbs: []string{"repo:delete", "repo:list"}},
		{Name: "watcher", Verbs: []string{"repo:list"}},
		{Name: "pusher", Verbs: []string{"repo:read", "repo:write", "repo:list"}},
		{Name: "proxyadmin", Verbs: []string{"repo:list", "repo:configure", "proxy:read", "proxy:write"}},
	} {
		if err := store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole(%q): %v", role.Name, err)
		}
	}

	// Every binding is granted at both `*` and `system`, so no refusal below
	// can be an artifact of scope shape rather than of the verb.
	bind := func(id, subject, role string) {
		for i, scope := range []string{"*", "system"} {
			if err := store.CreateBinding(ctx, meta.Binding{
				ID: fmt.Sprintf("%s-%d", id, i), PrincipalKind: meta.PrincipalSubject,
				PrincipalID: "u-" + subject, Role: role, Scope: scope,
			}); err != nil {
				t.Fatalf("CreateBinding(%s): %v", id, err)
			}
		}
	}
	bind("b-root", "root", "root")
	bind("b-creator", "creator", "creator")
	bind("b-keeper", "keeper", "keeper")
	bind("b-purger", "purger", "purger")
	bind("b-watcher", "watcher", "watcher")
	bind("b-prowler", "prowler", "pusher")
	bind("b-proxyadmin", "proxyadmin", "proxyadmin")

	router := server.NewRouter(&server.Guard{
		Subjects: store,
		Bindings: store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
		Challenge: func(*http.Request) string { return `Bearer realm="trove"` },
	})
	(&server.Repositories{
		Store: store, Bindings: store, Now: func() time.Time { return reposTime },
	}).Register(router)

	return reposFixture{store: store, router: router}
}

func (f reposFixture) do(t *testing.T, method, target, as, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// reposCreate creates an entity as root and requires success.
func reposCreate(t *testing.T, f reposFixture, name, typ, config string) reposResource {
	t.Helper()
	body := fmt.Sprintf(`{"name": %q, "type": %q`, name, typ)
	if config != "" {
		body += `, "config": ` + config
	}
	rec := f.do(t, http.MethodPost, "/api/v1/repositories", "root", body+"}")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", name, rec.Code, rec.Body)
	}
	return reposDecode(t, rec)
}

type reposResource struct {
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	ConfigVersion int64           `json:"config_version"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Config        json.RawMessage `json:"config"`
}

func reposDecode(t *testing.T, rec *httptest.ResponseRecorder) reposResource {
	t.Helper()
	var resource reposResource
	if err := json.Unmarshal(rec.Body.Bytes(), &resource); err != nil {
		t.Fatalf("decode resource from %s: %v", rec.Body, err)
	}
	return resource
}

const reposProxyConfig = `{"upstream": "https://registry-1.docker.io", "default_namespace": "library"}`

// The CRUD matrix, one pass per entity type through the real guard.
func TestReposCRUDPerType(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.RepoCreate)
	verbtest.Positive(t, authz.RepoDelete)

	tests := []struct {
		typ            string
		config         string
		deleteTarget   string // the query the delete must carry
		wantConfigBack bool
	}{
		{typ: "hosted", config: "", deleteTarget: "?confirm=", wantConfigBack: false},
		{typ: "proxy", config: reposProxyConfig, deleteTarget: "", wantConfigBack: true},
		{typ: "group", config: "", deleteTarget: "", wantConfigBack: false},
	}

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			t.Parallel()
			f := newReposFixture(t)
			name := "ent-" + tt.typ

			created := reposCreate(t, f, name, tt.typ, tt.config)
			if created.Name != name || created.Type != tt.typ || created.ConfigVersion != 1 {
				t.Fatalf("created = %+v", created)
			}
			if !created.CreatedAt.Equal(reposTime) {
				t.Errorf("CreatedAt = %s, want the injected clock", created.CreatedAt)
			}

			got := f.do(t, http.MethodGet, "/api/v1/repositories/"+name, "root", "")
			if got.Code != http.StatusOK {
				t.Fatalf("get: %d %s", got.Code, got.Body)
			}
			if resource := reposDecode(t, got); resource.Name != name || resource.Type != tt.typ {
				t.Errorf("get = %+v", resource)
			}

			listed := f.do(t, http.MethodGet, "/api/v1/repositories", "root", "")
			if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), name) {
				t.Fatalf("list: %d %s", listed.Code, listed.Body)
			}
			// A listing never carries configurations: the per-entity route is
			// where the proxy:read decision can be made.
			if strings.Contains(listed.Body.String(), "upstream") {
				t.Errorf("the listing inlined a configuration: %s", listed.Body)
			}

			target := "/api/v1/repositories/" + name + tt.deleteTarget
			if tt.deleteTarget == "?confirm=" {
				target += name
			}
			if rec := f.do(t, http.MethodDelete, target, "root", ""); rec.Code != http.StatusNoContent {
				t.Fatalf("delete: %d %s", rec.Code, rec.Body)
			}
			if rec := f.do(t, http.MethodGet, "/api/v1/repositories/"+name, "root", ""); rec.Code != http.StatusNotFound {
				t.Errorf("get after delete: %d", rec.Code)
			}
		})
	}
}

// Creation validates the name through internal/repo, so `system` is reserved
// and an entity is one path segment.
func TestReposCreateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		detail string
	}{
		{name: "reserved system name", body: `{"name": "system", "type": "hosted"}`, status: 400, detail: "reserved"},
		{name: "multi-segment name", body: `{"name": "team-a/api", "type": "hosted"}`, status: 400, detail: "one path segment"},
		{name: "uppercase name", body: `{"name": "TeamA", "type": "hosted"}`, status: 400, detail: "lowercase"},
		{name: "empty name", body: `{"type": "hosted"}`, status: 400, detail: "empty"},
		{name: "unknown type", body: `{"name": "x", "type": "virtual"}`, status: 400, detail: "hosted, proxy, or group"},
		{name: "proxy without upstream", body: `{"name": "x", "type": "proxy"}`, status: 400, detail: "upstream"},
		{
			name:   "proxy with credentials in the upstream",
			body:   `{"name": "x", "type": "proxy", "config": {"upstream": "https://u:p@ghcr.io"}}`,
			status: 400, detail: "credentials",
		},
		{
			name:   "hosted with a stray config field",
			body:   `{"name": "x", "type": "hosted", "config": {"upstream": "https://ghcr.io"}}`,
			status: 400, detail: "unknown field",
		},
		{name: "malformed body", body: `{"name":`, status: 400, detail: "must be JSON"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newReposFixture(t)
			rec := f.do(t, http.MethodPost, "/api/v1/repositories", "root", tt.body)
			if rec.Code != tt.status {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, tt.status)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
				t.Errorf("Content-Type = %q, want problem+json (ADR 0015)", ct)
			}
			if !strings.Contains(rec.Body.String(), tt.detail) {
				t.Errorf("problem %s does not mention %q", rec.Body, tt.detail)
			}
		})
	}
}

func TestReposCreateConflict(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "taken", "hosted", "")

	rec := f.do(t, http.MethodPost, "/api/v1/repositories", "root", `{"name": "taken", "type": "hosted"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: %d %s, want 409", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), server.ProblemConflict) {
		t.Errorf("problem %s is not the conflict type", rec.Body)
	}
}

// The ADR 0002 splits, at the routes that enforce them: creating, configuring
// and deleting are three permissions, and holding one never implies another.
func TestReposVerbSplits(t *testing.T) {
	t.Parallel()
	verbtest.Negative(t, authz.RepoCreate)
	verbtest.Negative(t, authz.RepoConfigure)
	verbtest.Negative(t, authz.RepoDelete)

	f := newReposFixture(t)
	reposCreate(t, f, "subject", "hosted", "")

	tests := []struct {
		name   string
		as     string
		method string
		target string
		body   string
		status int
	}{
		{
			name: "repo:write does not imply repo:create", as: "prowler",
			method: http.MethodPost, target: "/api/v1/repositories",
			body: `{"name": "sneaky", "type": "hosted"}`, status: http.StatusForbidden,
		},
		{
			name: "repo:configure does not imply repo:create", as: "keeper",
			method: http.MethodPost, target: "/api/v1/repositories",
			body: `{"name": "sneaky", "type": "hosted"}`, status: http.StatusForbidden,
		},
		{
			name: "repo:write does not imply repo:configure", as: "prowler",
			method: http.MethodPut, target: "/api/v1/repositories/subject/config",
			body: `{"config": {}, "expected_version": 1}`, status: http.StatusForbidden,
		},
		{
			name: "repo:create does not imply repo:configure", as: "creator",
			method: http.MethodPut, target: "/api/v1/repositories/subject/config",
			body: `{"config": {}, "expected_version": 1}`, status: http.StatusForbidden,
		},
		{
			name: "repo:write does not imply repo:delete", as: "prowler",
			method: http.MethodDelete, target: "/api/v1/repositories/subject?confirm=subject",
			status: http.StatusForbidden,
		},
		{
			name: "repo:configure does not imply repo:delete", as: "keeper",
			method: http.MethodDelete, target: "/api/v1/repositories/subject?confirm=subject",
			status: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.do(t, tt.method, tt.target, tt.as, tt.body)
			if rec.Code != tt.status {
				t.Fatalf("%s: %d %s, want %d", tt.name, rec.Code, rec.Body, tt.status)
			}
		})
	}

	// The positives, so the refusals above are about the verb rather than a
	// fixture that refuses everything.
	if rec := f.do(t, http.MethodPost, "/api/v1/repositories", "creator",
		`{"name": "allowed", "type": "hosted"}`); rec.Code != http.StatusCreated {
		t.Fatalf("creator may create: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, http.MethodPut, "/api/v1/repositories/subject/config", "keeper",
		`{"config": {}, "expected_version": 1}`); rec.Code != http.StatusOK {
		t.Fatalf("keeper may configure: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, http.MethodDelete, "/api/v1/repositories/subject?confirm=subject", "purger",
		""); rec.Code != http.StatusNoContent {
		t.Fatalf("purger may delete: %d %s", rec.Code, rec.Body)
	}
}

// A proxy's configuration is its upstream and routing rules: readable only
// with proxy:read, and the key is omitted rather than nulled so "you may not
// see this" and "there is nothing here" are the same absence (ADR 0002).
func TestReposProxyConfigNeedsProxyRead(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.ProxyRead)
	verbtest.Negative(t, authz.ProxyRead)

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)
	reposCreate(t, f, "plain", "hosted", "")

	withRead := f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "proxyadmin", "")
	if withRead.Code != http.StatusOK {
		t.Fatalf("get as proxyadmin: %d %s", withRead.Code, withRead.Body)
	}
	if !strings.Contains(withRead.Body.String(), "registry-1.docker.io") {
		t.Errorf("proxy:read did not get the configuration: %s", withRead.Body)
	}

	without := f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "watcher", "")
	if without.Code != http.StatusOK {
		t.Fatalf("get as watcher: %d %s", without.Code, without.Body)
	}
	body := without.Body.String()
	if strings.Contains(body, "upstream") || strings.Contains(body, "docker.io") {
		t.Errorf("a subject without proxy:read saw the upstream: %s", body)
	}
	if strings.Contains(body, `"config"`) {
		t.Errorf("the config key is present rather than omitted: %s", body)
	}
	// The rest of the resource still answers: existence was already disclosed.
	if resource := reposDecode(t, without); resource.Name != "mirror" || resource.Type != "proxy" {
		t.Errorf("watcher's view = %+v, want the entity without its config", resource)
	}

	// A hosted entity's (empty) configuration is not behind proxy:read.
	hosted := f.do(t, http.MethodGet, "/api/v1/repositories/plain", "watcher", "")
	if resource := reposDecode(t, hosted); resource.Type != "hosted" {
		t.Errorf("hosted view = %+v", resource)
	}
}

// Changing a proxy's configuration is repo:configure AND proxy:write. The
// refusal is 403, not 404: repo:configure already admitted the request, so the
// entity's existence is not what is being withheld.
func TestReposProxyConfigWriteNeedsProxyWrite(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.ProxyWrite)
	verbtest.Negative(t, authz.ProxyWrite)
	verbtest.Positive(t, authz.RepoConfigure)

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	newConfig := `{"config": {"upstream": "https://ghcr.io"}, "expected_version": 1}`

	// keeper holds repo:configure and not proxy:write.
	refused := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "keeper", newConfig)
	if refused.Code != http.StatusForbidden {
		t.Fatalf("keeper reconfiguring a proxy: %d %s, want 403", refused.Code, refused.Body)
	}
	// Nothing changed.
	current := f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "root", "")
	if !strings.Contains(current.Body.String(), "docker.io") {
		t.Fatalf("the refused write changed the config: %s", current.Body)
	}

	allowed := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "proxyadmin", newConfig)
	if allowed.Code != http.StatusOK {
		t.Fatalf("proxyadmin reconfiguring a proxy: %d %s", allowed.Code, allowed.Body)
	}
	if resource := reposDecode(t, allowed); resource.ConfigVersion != 2 ||
		!strings.Contains(string(resource.Config), "ghcr.io") {
		t.Errorf("updated = %+v", resource)
	}
}

// Optimistic concurrency: the version a caller read is the version it may
// replace, and losing says how to recover.
func TestReposConfigStaleVersion(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	first := `{"config": {"upstream": "https://ghcr.io"}, "expected_version": 1}`
	if rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "root", first); rec.Code != http.StatusOK {
		t.Fatalf("first write: %d %s", rec.Code, rec.Body)
	}
	// A second writer still holding version 1 must lose.
	rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "root", first)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale write: %d %s, want 409", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), server.ProblemStaleVersion) ||
		!strings.Contains(rec.Body.String(), "config_version") {
		t.Errorf("problem %s does not tell the client how to recover", rec.Body)
	}
}

// A configuration is validated against the entity's own type before the store
// sees it: nothing unusable is stored even for a moment.
func TestReposConfigValidationOnUpdate(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	for _, body := range []string{
		`{"config": {"upstream": "ftp://nope"}, "expected_version": 1}`,
		`{"config": {"upstream": "https://ghcr.io", "offline_mode": "pretend"}, "expected_version": 1}`,
		`{"config": {"nonsense": true}, "expected_version": 1}`,
	} {
		rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "root", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: %d %s, want 400", body, rec.Code, rec.Body)
		}
	}
	if rec := f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "root", ""); !strings.Contains(rec.Body.String(), "docker.io") {
		t.Fatalf("a refused update reached the store: %s", rec.Body)
	}
}

// Hosted deletion destroys content that exists nowhere else, so it takes the
// name back as confirmation; proxy and group deletions do not.
func TestReposHostedDeleteNeedsConfirmation(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	ctx := context.Background()
	reposCreate(t, f, "team-a", "hosted", "")

	// Real content under the entity, so the cascade is observable.
	digest := meta.Digest("sha256:" + strings.Repeat("ab", 32))
	if err := f.store.PutManifest(ctx, meta.Manifest{
		Repository: "team-a/api", Digest: digest,
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   []byte(`{"schemaVersion":2}`), Size: 19, CreatedAt: reposTime,
	}, nil); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	for _, target := range []string{
		"/api/v1/repositories/team-a",
		"/api/v1/repositories/team-a?confirm=",
		"/api/v1/repositories/team-a?confirm=team-b",
		"/api/v1/repositories/team-a?confirm=team-a%20",
	} {
		rec := f.do(t, http.MethodDelete, target, "root", "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("DELETE %s: %d %s, want 400", target, rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "irreversible") {
			t.Errorf("refusal %s does not explain the stakes", rec.Body)
		}
	}
	if _, err := f.store.GetRepository(ctx, "team-a"); err != nil {
		t.Fatalf("a refused delete removed the entity: %v", err)
	}

	rec := f.do(t, http.MethodDelete, "/api/v1/repositories/team-a?confirm=team-a", "root", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete: %d %s", rec.Code, rec.Body)
	}
	// The cascade reached content keyed by the full name under the entity.
	if _, err := f.store.GetManifest(ctx, "team-a/api", digest); err == nil {
		t.Error("the manifest survived its entity's deletion")
	}
}

func TestReposProxyAndGroupDeleteNeedNoConfirmation(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)
	reposCreate(t, f, "members", "hosted", "")
	reposCreate(t, f, "everything", "group", "")

	for _, name := range []string{"mirror", "everything"} {
		if rec := f.do(t, http.MethodDelete, "/api/v1/repositories/"+name, "root", ""); rec.Code != http.StatusNoContent {
			t.Errorf("DELETE %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// A group deletion never touches what its members hold.
	if rec := f.do(t, http.MethodGet, "/api/v1/repositories/members", "root", ""); rec.Code != http.StatusOK {
		t.Errorf("a member entity died with its group: %d", rec.Code)
	}
}

// ADR 0003 at the admin API: an entity the subject may not list and one that
// is not there answer identically, byte for byte.
func TestReposHiddenAndAbsentAreIdentical(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "secret", "hosted", "")

	ctx := context.Background()
	if err := f.store.CreateSubject(ctx, meta.Subject{ID: "u-blind", Kind: meta.User, Name: "blind"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := f.store.CreateBinding(ctx, meta.Binding{
		ID: "b-blind", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-blind",
		Role: "watcher", Scope: "elsewhere/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	hidden := f.do(t, http.MethodGet, "/api/v1/repositories/secret", "blind", "")
	absent := f.do(t, http.MethodGet, "/api/v1/repositories/nothinghere", "blind", "")
	if hidden.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
		t.Fatalf("hidden %d, absent %d, want both 404", hidden.Code, absent.Code)
	}
	if hidden.Body.String() != absent.Body.String() {
		t.Errorf("bodies differ:\nhidden: %s\nabsent: %s", hidden.Body, absent.Body)
	}
	if fmt.Sprint(hidden.Header()) != fmt.Sprint(absent.Header()) {
		t.Errorf("headers differ: %v vs %v", hidden.Header(), absent.Header())
	}
}

// The listing is permission-filtered in the query, and anonymous with nothing
// visible is challenged rather than handed an empty page (ADR 0003).
func TestReposListingIsFiltered(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "visible", "hosted", "")
	reposCreate(t, f, "secret", "hosted", "")

	ctx := context.Background()
	if err := f.store.CreateSubject(ctx, meta.Subject{ID: "u-narrow", Kind: meta.User, Name: "narrow"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := f.store.CreateBinding(ctx, meta.Binding{
		ID: "b-narrow", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-narrow",
		Role: "watcher", Scope: "visible",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	rec := f.do(t, http.MethodGet, "/api/v1/repositories", "narrow", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("narrow listing: %d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "visible") || strings.Contains(body, "secret") {
		t.Errorf("listing leaked or lost content: %s", body)
	}

	anonymous := f.do(t, http.MethodGet, "/api/v1/repositories", "", "")
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous listing: %d, want 401", anonymous.Code)
	}
	if anonymous.Header().Get("WWW-Authenticate") == "" {
		t.Error("the 401 carries no challenge")
	}
}

func TestReposListingPaginates(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	for i := range 7 {
		reposCreate(t, f, fmt.Sprintf("ent-%d", i), "hosted", "")
	}

	seen := map[string]bool{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		target := "/api/v1/repositories?limit=3"
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		rec := f.do(t, http.MethodGet, target, "root", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", pages, rec.Code, rec.Body)
		}
		var page struct {
			Repositories []reposResource `json:"repositories"`
			NextCursor   string          `json:"next_cursor"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page: %v", err)
		}
		if len(page.Repositories) > 3 {
			t.Fatalf("page holds %d entries, want at most 3", len(page.Repositories))
		}
		for _, resource := range page.Repositories {
			if seen[resource.Name] {
				t.Errorf("%s appeared twice", resource.Name)
			}
			seen[resource.Name] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 7 {
		t.Errorf("stitched %d entities, want 7", len(seen))
	}

	if rec := f.do(t, http.MethodGet, "/api/v1/repositories?limit=nonsense", "root", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad limit: %d, want 400", rec.Code)
	}
}

// Config history is the lineage a support bundle shows: one row per superseded
// revision, naming who replaced it, and it dies with the repository so a
// recreated name inherits nothing.
func TestReposConfigHistory(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	ctx := context.Background()
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	// Creation writes no history: the live row is revision 1.
	history, err := f.store.ListConfigHistory(ctx, "mirror")
	if err != nil {
		t.Fatalf("ListConfigHistory: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("history after create = %d rows, want none", len(history))
	}

	if rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "proxyadmin",
		`{"config": {"upstream": "https://ghcr.io"}, "expected_version": 1}`); rec.Code != http.StatusOK {
		t.Fatalf("first update: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "root",
		`{"config": {"upstream": "https://quay.io"}, "expected_version": 2}`); rec.Code != http.StatusOK {
		t.Fatalf("second update: %d %s", rec.Code, rec.Body)
	}

	history, err = f.store.ListConfigHistory(ctx, "mirror")
	if err != nil {
		t.Fatalf("ListConfigHistory: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history = %d rows, want 2 superseded revisions", len(history))
	}
	if history[0].Version != 1 || !strings.Contains(string(history[0].Config), "docker.io") ||
		history[0].Actor != "proxyadmin" {
		t.Errorf("revision 1 = %+v, want the original config replaced by proxyadmin", history[0])
	}
	if history[1].Version != 2 || !strings.Contains(string(history[1].Config), "ghcr.io") ||
		history[1].Actor != "root" {
		t.Errorf("revision 2 = %+v, want ghcr replaced by root", history[1])
	}

	// The lineage dies with the entity: a name is free once deleted, and the
	// next repository at that name is a different repository.
	if rec := f.do(t, http.MethodDelete, "/api/v1/repositories/mirror", "root", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)
	history, err = f.store.ListConfigHistory(ctx, "mirror")
	if err != nil {
		t.Fatalf("ListConfigHistory after recreate: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("a recreated repository inherited %d revisions", len(history))
	}
}

// Anonymous is refused with a challenge on every mutating route: `docker
// login`'s contract, and the admin API's too (ADR 0003).
func TestReposAnonymousIsChallenged(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "thing", "hosted", "")

	for _, tt := range []struct{ method, target, body string }{
		{http.MethodPost, "/api/v1/repositories", `{"name": "x", "type": "hosted"}`},
		{http.MethodGet, "/api/v1/repositories/thing", ""},
		{http.MethodPut, "/api/v1/repositories/thing/config", `{"config": {}, "expected_version": 1}`},
		{http.MethodDelete, "/api/v1/repositories/thing?confirm=thing", ""},
	} {
		rec := f.do(t, tt.method, tt.target, "", tt.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous: %d, want 401", tt.method, tt.target, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s %s: no challenge", tt.method, tt.target)
		}
	}
}

// A name the grammar rejects is refused by the guard's own resolve step,
// before anything is looked up.
func TestReposUnusableNameInPath(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	rec := f.do(t, http.MethodGet, "/api/v1/repositories/NotALegalName", "root", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("illegal name: %d %s, want 400", rec.Code, rec.Body)
	}
}
