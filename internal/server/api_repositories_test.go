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
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/secretbox"
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
//	keymaster repo:list + proxy:credentials and nothing else: may set and
//	          remove an upstream credential, may not read one, and may not
//	          even see the configuration it belongs to
type reposFixture struct {
	store  *memory.Store
	router *server.Router
	// keys is the fixture's secrets keyring, the same one the handler seals
	// with. Tests use it to prove what was stored really is the credential --
	// and, in the AAD probe, that it opens under one repository only.
	keys *secretbox.Keyring
}

func newReposFixture(t *testing.T) reposFixture {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	subjects := []string{"root", "creator", "keeper", "purger", "watcher", "prowler", "proxyadmin", "keymaster"}
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
		{Name: "keymaster", Verbs: []string{"repo:list", "proxy:credentials"}},
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
	bind("b-keymaster", "keymaster", "keymaster")

	keys := reposKeyring(t)
	router := server.NewRouter(&server.Guard{
		Subjects: store,
		Bindings: store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
		Challenge: func(*http.Request) string { return `Bearer realm="trove"` },
	})
	(&server.Repositories{
		Store: store, Bindings: store, Keys: keys, Now: func() time.Time { return reposTime },
	}).Register(router)

	return reposFixture{store: store, router: router, keys: keys}
}

// reposKeyring builds fresh key material for one fixture. A generated key
// rather than a fixed one, so nothing in these tests can come to depend on a
// particular ciphertext: what is asserted is that a value never appears, and
// that is true of whichever key sealed it.
func reposKeyring(t *testing.T) *secretbox.Keyring {
	t.Helper()

	key, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring, err := secretbox.NewKeyring(key)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return ring
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
	Credential    *struct {
		Set       bool      `json:"set"`
		RotatedAt time.Time `json:"rotated_at"`
	} `json:"credential"`
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

// --- upstream credentials (C-003) ---
//
// C-003's acceptance criterion is a negative one -- no read path returns a
// credential -- so most of what follows probes reads and asserts an absence.
// The assertions are over whole serialized response bodies rather than over
// named fields: a field nobody thought to check is exactly how this leaks, and
// a body-wide scan catches a value that arrives through a field added later.

const (
	// The fixture's upstream credential. Both halves are distinctive strings
	// that appear nowhere else, so finding either in a response body is
	// unambiguous rather than a coincidence.
	reposCredentialUser = "robot$upstream-fixture"
	reposCredentialPass = "correct-horse-battery-staple-9271"

	// reposCredentialBody is that pair as a request body, for the tables that
	// only care that a well-formed write was refused.
	reposCredentialBody = `{"username": "` + reposCredentialUser + `", "password": "` + reposCredentialPass + `"}`
)

// reposSetCredential writes the fixture credential as root and requires
// success, returning the sealed value the store ended up holding.
func reposSetCredential(t *testing.T, f reposFixture, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{"username": %q, "password": %q}`, reposCredentialUser, reposCredentialPass)
	rec := f.do(t, http.MethodPut, "/api/v1/repositories/"+name+"/credentials", "root", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set credential on %s: %d %s", name, rec.Code, rec.Body)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("a credential write answered with a body: %s", rec.Body)
	}

	// Reaching past the handler to prove the probes below are not vacuous: the
	// value really is stored, and it really is the one that must not appear
	// anywhere.
	stored, err := f.store.GetProxyCredential(context.Background(), name)
	if err != nil {
		t.Fatalf("GetProxyCredential: %v", err)
	}
	username, password, err := proxy.StoredCredentials{
		Repository: name, Store: f.store, Keys: f.keys,
	}.Basic(context.Background())
	if err != nil {
		t.Fatalf("Basic: %v", err)
	}
	if username != reposCredentialUser || password != reposCredentialPass {
		t.Fatalf("stored credential opened to (%q, %q), want the pair that was written", username, password)
	}
	return stored.Sealed
}

// requireNoCredential asserts that a response body carries no part of the
// credential: neither half of the pair, and no sealed value -- the `v1:`
// prefix ADR 0016 says every stored secret begins with.
func requireNoCredential(t *testing.T, where, sealed, body string) {
	t.Helper()

	for _, forbidden := range []struct{ what, value string }{
		{"the password", reposCredentialPass},
		{"the username", reposCredentialUser},
		{"the sealed value", sealed},
		{"a sealed-value prefix", "v1:"},
	} {
		if forbidden.value != "" && strings.Contains(body, forbidden.value) {
			t.Errorf("%s leaked %s:\n%s", where, forbidden.what, body)
		}
	}
}

// Every read path the repository resource has, probed against a repository
// that really does hold a credential -- including the two subjects that might
// plausibly be thought to earn one: proxy:read, and proxy:credentials itself.
// ADR 0016 is stronger than the verb: the API returns set/unset and a rotation
// time at every verb, and a value at none.
func TestReposCredentialsAppearInNoReadPath(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.ProxyCredentials)

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)
	sealed := reposSetCredential(t, f, "mirror")

	// The single-entity read, as every subject that can reach it: the operator
	// holding every verb in the vocabulary, the proxy administrator, the
	// credential holder itself, and subjects with less.
	for _, as := range []string{"root", "proxyadmin", "keymaster", "watcher", "keeper"} {
		rec := f.do(t, http.MethodGet, "/api/v1/repositories/mirror", as, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("get as %s: %d %s", as, rec.Code, rec.Body)
		}
		requireNoCredential(t, "GET the repository as "+as, sealed, rec.Body.String())
	}

	// The listing, which carries no configuration at all and must carry no
	// credential either.
	listing := f.do(t, http.MethodGet, "/api/v1/repositories", "root", "")
	if listing.Code != http.StatusOK {
		t.Fatalf("list: %d %s", listing.Code, listing.Body)
	}
	requireNoCredential(t, "the repository listing", sealed, listing.Body.String())

	// The reconfigure echo, which returns the document the caller supplied.
	echo := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/config", "proxyadmin",
		`{"config": {"upstream": "https://ghcr.io"}, "expected_version": 1}`)
	if echo.Code != http.StatusOK {
		t.Fatalf("reconfigure: %d %s", echo.Code, echo.Body)
	}
	requireNoCredential(t, "the config write's echo", sealed, echo.Body.String())

	// And the refusals, which are the paths most likely to echo a request body
	// back at a client.
	for _, tt := range []struct{ what, as, body string }{
		{"a refused write", "proxyadmin", fmt.Sprintf(`{"username": %q, "password": %q}`,
			reposCredentialUser, reposCredentialPass)},
		{"a rejected body", "root", fmt.Sprintf(`{"username": %q, "password": ""}`, reposCredentialUser)},
		{"unparseable JSON", "root", `{"username": "` + reposCredentialUser + `"`},
	} {
		rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/credentials", tt.as, tt.body)
		if rec.Code == http.StatusNoContent {
			t.Fatalf("%s was accepted: %d %s", tt.what, rec.Code, rec.Body)
		}
		requireNoCredential(t, tt.what+"'s problem document", sealed, rec.Body.String())
	}
}

// What a read path does return: set/unset and a rotation time, on the same
// proxy:read decision that serves the configuration. Reading whether a proxy
// authenticates at all is part of reading how it is configured.
func TestReposCredentialStatusRidesProxyRead(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)
	reposCreate(t, f, "plain", "hosted", "")

	unset := reposDecode(t, f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "root", ""))
	if unset.Credential == nil || unset.Credential.Set {
		t.Fatalf("before any write, credential = %+v, want present and unset", unset.Credential)
	}

	reposSetCredential(t, f, "mirror")

	set := reposDecode(t, f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "root", ""))
	if set.Credential == nil || !set.Credential.Set {
		t.Fatalf("after the write, credential = %+v, want set", set.Credential)
	}
	if !set.Credential.RotatedAt.Equal(reposTime) {
		t.Errorf("RotatedAt = %s, want the injected clock %s", set.Credential.RotatedAt, reposTime)
	}

	// Without proxy:read the whole field is absent, for the reason the config
	// is: a null would say a credential state exists that the subject may not
	// see, which is the disclosure omitting it avoids (ADR 0003).
	hidden := reposDecode(t, f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "watcher", ""))
	if hidden.Credential != nil {
		t.Errorf("watcher saw credential = %+v, want the field omitted", hidden.Credential)
	}
	// proxy:credentials alone does not buy the configuration, and so does not
	// buy the status either: the verb gates writing, not reading.
	byVerb := reposDecode(t, f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "keymaster", ""))
	if byVerb.Credential != nil {
		t.Errorf("keymaster saw credential = %+v, want the field omitted", byVerb.Credential)
	}

	// A hosted entity has no upstream, so it has no credential field at all.
	hosted := reposDecode(t, f.do(t, http.MethodGet, "/api/v1/repositories/plain", "root", ""))
	if hosted.Credential != nil {
		t.Errorf("hosted entity carried credential = %+v", hosted.Credential)
	}
}

// The §9 scenario, at the handler: reaching a proxy secret with proxy:write
// alone. proxy:credentials is implied by nothing (ADR 0002), so the subject
// who may repoint this proxy at another registry still cannot touch the
// password it presents there.
func TestReposCredentialsNotImpliedByProxyWrite(t *testing.T) {
	t.Parallel()
	verbtest.Negative(t, authz.ProxyCredentials)

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	body := fmt.Sprintf(`{"username": %q, "password": %q}`, reposCredentialUser, reposCredentialPass)
	for _, tt := range []struct{ method, body string }{
		{http.MethodPut, body},
		{http.MethodDelete, ""},
	} {
		// proxyadmin holds repo:configure, proxy:read and proxy:write: every
		// verb that governs this repository except the one that governs its
		// secret. The refusal is 403 rather than 404 because repo:list already
		// disclosed the entity.
		rec := f.do(t, tt.method, "/api/v1/repositories/mirror/credentials", "proxyadmin", tt.body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s credentials as proxyadmin: %d %s, want 403", tt.method, rec.Code, rec.Body)
		}
	}
	// Nothing was written by the refusal.
	if status, err := f.store.ProxyCredentialStatus(context.Background(), "mirror"); err != nil || status.Set {
		t.Fatalf("after the refusals, status = %+v (err %v), want unset", status, err)
	}

	// And the verb on its own is enough: keymaster holds repo:list and
	// proxy:credentials and nothing else.
	rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/credentials", "keymaster", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set credential as keymaster: %d %s, want 204", rec.Code, rec.Body)
	}
}

// Setting, rotating, and removing one. Removal reverts the proxy to anonymous
// and leaves the repository alone.
func TestReposCredentialLifecycle(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	first := reposSetCredential(t, f, "mirror")
	second := reposSetCredential(t, f, "mirror")
	if first == second {
		// A fresh nonce per seal, so the same pair written twice produces
		// different bytes: an observer cannot tell that two rows hold the same
		// credential (ADR 0016).
		t.Errorf("rotating the same pair produced an identical sealed value")
	}

	removed := f.do(t, http.MethodDelete, "/api/v1/repositories/mirror/credentials", "root", "")
	if removed.Code != http.StatusNoContent {
		t.Fatalf("delete credential: %d %s", removed.Code, removed.Body)
	}
	status, err := f.store.ProxyCredentialStatus(context.Background(), "mirror")
	if err != nil {
		t.Fatalf("ProxyCredentialStatus: %v", err)
	}
	if status.Set {
		t.Errorf("status after delete = %+v, want unset", status)
	}
	// The repository is untouched: removing a credential is not deleting a
	// proxy.
	if rec := f.do(t, http.MethodGet, "/api/v1/repositories/mirror", "root", ""); rec.Code != http.StatusOK {
		t.Errorf("get after credential delete: %d %s", rec.Code, rec.Body)
	}
	// A second delete has nothing to remove, and says so.
	again := f.do(t, http.MethodDelete, "/api/v1/repositories/mirror/credentials", "root", "")
	if again.Code != http.StatusNotFound {
		t.Errorf("second delete: %d %s, want 404", again.Code, again.Body)
	}
}

// Only a proxy authenticates to an upstream, so the route refuses every other
// entity type -- and an entity that does not exist at all answers the way an
// unreadable one does (ADR 0003).
func TestReposCredentialsRequireAProxy(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "plain", "hosted", "")
	reposCreate(t, f, "everything", "group", "")

	body := fmt.Sprintf(`{"username": %q, "password": %q}`, reposCredentialUser, reposCredentialPass)
	for _, name := range []string{"plain", "everything"} {
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			sent := ""
			if method == http.MethodPut {
				sent = body
			}
			rec := f.do(t, method, "/api/v1/repositories/"+name+"/credentials", "root", sent)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s credentials on %s: %d %s, want 400", method, name, rec.Code, rec.Body)
			}
		}
	}

	absent := f.do(t, http.MethodPut, "/api/v1/repositories/nothing-here/credentials", "root", body)
	if absent.Code != http.StatusNotFound {
		t.Errorf("credential write on an absent entity: %d %s, want 404", absent.Code, absent.Body)
	}
}

// Both halves are required. A credential with one of them missing
// authenticates as nobody and comes back from the upstream as a 401 that reads
// like a wrong password rather than a missing one.
func TestReposCredentialValidation(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	for _, tt := range []struct{ what, body string }{
		{"not JSON at all", `nope`},
		{"an empty object", `{}`},
		{"no password", `{"username": "robot"}`},
		{"no username", `{"password": "s3cret"}`},
		{"an oversized body", `{"username": "robot", "password": "` + strings.Repeat("a", 1<<21) + `"}`},
	} {
		rec := f.do(t, http.MethodPut, "/api/v1/repositories/mirror/credentials", "root", tt.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", tt.what, rec.Code, rec.Body)
		}
	}
	if status, err := f.store.ProxyCredentialStatus(context.Background(), "mirror"); err != nil || status.Set {
		t.Fatalf("a refused body still wrote something: %+v (err %v)", status, err)
	}
}

// There is no endpoint that returns a credential, so there is none to
// authorize. The route table is what proves it: a GET added here later would
// fail this walk before it could serve anything.
func TestReposCredentialsHaveNoReadRoute(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	found := 0
	for _, route := range f.router.Routes() {
		if !strings.HasSuffix(route.Pattern, "/credentials") {
			continue
		}
		found++
		if route.Method != http.MethodPut && route.Method != http.MethodDelete {
			t.Errorf("%s %s: the credential resource is write-only (ADR 0016)", route.Method, route.Pattern)
		}
		if route.Permission.Verb != authz.ProxyCredentials {
			t.Errorf("%s %s is guarded by %q, want proxy:credentials",
				route.Method, route.Pattern, route.Permission.Verb)
		}
	}
	if found != 2 {
		t.Fatalf("found %d credential routes, want the write and the delete", found)
	}
	// And the mux agrees: nothing answers a GET there.
	if rec := f.do(t, http.MethodGet, "/api/v1/repositories/mirror/credentials", "root", ""); rec.Code == http.StatusOK {
		t.Errorf("GET credentials answered 200: %s", rec.Body)
	}
}

// A deployment with no key material must not store a password in the clear. It
// cannot happen through serve, which loads or creates a keyring before it
// builds the router, so the refusal is the last line of defence rather than
// the first.
func TestReposCredentialWriteWithoutAKeyringRefuses(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	router := server.NewRouter(&server.Guard{
		Subjects: f.store,
		Bindings: f.store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&server.Repositories{
		Store: f.store, Bindings: f.store, Now: func() time.Time { return reposTime },
	}).Register(router)
	keyless := reposFixture{store: f.store, router: router}

	body := fmt.Sprintf(`{"username": %q, "password": %q}`, reposCredentialUser, reposCredentialPass)
	rec := keyless.do(t, http.MethodPut, "/api/v1/repositories/mirror/credentials", "root", body)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("credential write with no keyring: %d %s, want 500", rec.Code, rec.Body)
	}
	if status, err := f.store.ProxyCredentialStatus(context.Background(), "mirror"); err != nil || status.Set {
		t.Fatalf("the refused write stored something: %+v (err %v)", status, err)
	}
}
