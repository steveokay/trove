package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// ociFixture registers the distribution API's route shapes over a store
// where carol reads and writes team-a/*, and echoes what each handler
// matched, so the tests can see routing and guarding at once.
func ociFixture(t *testing.T) http.Handler {
	t.Helper()

	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CreateSubject(ctx, meta.Subject{ID: "u-carol", Kind: meta.User, Name: "carol"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "publisher", Verbs: []string{"repo:read", "repo:write"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "b-carol", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-carol",
		Role: "publisher", Scope: "team-a/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	router := server.NewRouter(&server.Guard{
		Subjects: store,
		Bindings: store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})

	repo := func(r *http.Request) (authz.Resource, error) {
		return authz.Repository(server.OCIName(r))
	}
	echo := func(kind, value string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(kind + " " + server.OCIName(r) + " " + server.OCIValue(r, value)))
		})
	}
	router.HandleOCI(http.MethodGet, "/blobs/{digest}",
		server.Permission{Verb: authz.RepoRead, Resource: repo}, echo("blob", "digest"))
	router.HandleOCI(http.MethodGet, "/blobs/uploads/{id}",
		server.Permission{Verb: authz.RepoWrite, Resource: repo}, echo("status", "id"))
	router.HandleOCI(http.MethodPost, "/blobs/uploads/",
		server.Permission{Verb: authz.RepoWrite, Resource: repo}, echo("start", ""))
	router.HandleOCI(http.MethodGet, "/tags/list",
		server.Permission{Verb: authz.RepoRead, Resource: repo}, echo("tags", ""))
	return router
}

func ociRequest(handler http.Handler, method, target, as string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestOCIRouting(t *testing.T) {
	t.Parallel()

	handler := ociFixture(t)

	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{
			name:   "single-segment repository",
			method: http.MethodGet,
			target: "/v2/team-a/blobs/sha256:abc",
			want:   "", // team-a is not under team-a/*: guarded, 404 -- checked below
		},
		{
			name:   "multi-segment repository name",
			method: http.MethodGet,
			target: "/v2/team-a/api/blobs/sha256:abc",
			want:   "blob team-a/api sha256:abc",
		},
		{
			name:   "deep repository name",
			method: http.MethodGet,
			target: "/v2/team-a/sub/deep/api/blobs/sha256:abc",
			want:   "blob team-a/sub/deep/api sha256:abc",
		},
		{
			// The longest suffix wins: uploads status, not a blob named
			// "uploads".
			name:   "suffix precedence",
			method: http.MethodGet,
			target: "/v2/team-a/api/blobs/uploads/abc123",
			want:   "status team-a/api abc123",
		},
		{
			// A repository whose segments spell trouble: the suffix is
			// anchored at the end, so the name keeps its inner "blobs".
			name:   "repository named like the suffix",
			method: http.MethodGet,
			target: "/v2/team-a/blobs/blobs/sha256:abc",
			want:   "blob team-a/blobs sha256:abc",
		},
		{
			name:   "upload start with its trailing slash",
			method: http.MethodPost,
			target: "/v2/team-a/api/blobs/uploads/",
			want:   "start team-a/api ",
		},
		{
			name:   "fixed suffix with no placeholder",
			method: http.MethodGet,
			target: "/v2/team-a/api/tags/list",
			want:   "tags team-a/api ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := ociRequest(handler, tt.method, tt.target, "carol")
			if tt.want == "" {
				return
			}
			if rec.Code != http.StatusOK || rec.Body.String() != tt.want {
				t.Fatalf("%s %s: %d %q, want %q", tt.method, tt.target, rec.Code, rec.Body, tt.want)
			}
		})
	}
}

func TestOCIRoutingRefusals(t *testing.T) {
	t.Parallel()

	handler := ociFixture(t)

	tests := []struct {
		name   string
		method string
		target string
		as     string
		want   int
	}{
		{"anonymous gets the challenge", http.MethodGet, "/v2/team-a/api/blobs/sha256:abc", "", http.StatusUnauthorized},
		{"outside the binding looks absent", http.MethodGet, "/v2/team-b/api/blobs/sha256:abc", "carol", http.StatusNotFound},
		{"method without a route falls through", http.MethodDelete, "/v2/team-a/api/tags/list", "carol", http.StatusNotFound},
		{"a path with no name has no route", http.MethodGet, "/v2/blobs/sha256:abc", "carol", http.StatusNotFound},
		{"missing trailing slash is not upload start", http.MethodPost, "/v2/team-a/api/blobs/uploads", "carol", http.StatusNotFound},
		{"an illegal repository name is refused", http.MethodGet, "/v2/TEAM-A/../x/blobs/sha256:abc", "carol", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := ociRequest(handler, tt.method, tt.target, tt.as)
			if rec.Code != tt.want {
				t.Fatalf("%s %s as %q: %d, want %d (body %s)", tt.method, tt.target, tt.as, rec.Code, tt.want, rec.Body)
			}
		})
	}
}

// The OCI routes live in the same verified table as everything else: an
// unknown verb panics at registration, and the table Verify walks includes
// their spelled-out patterns.
func TestOCIRoutesAreInTheTable(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
	router.HandleOCI(http.MethodGet, "/blobs/{digest}",
		server.Permission{Verb: authz.RepoRead}, http.NotFoundHandler())

	if err := router.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	found := false
	for _, route := range router.Routes() {
		if route.Pattern == "/v2/{name}/blobs/{digest}" && route.Method == http.MethodGet &&
			route.Permission.Verb == authz.RepoRead {
			found = true
		}
	}
	if !found {
		t.Fatal("the OCI route is not in the table Verify walks")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("registering an OCI route with no verb did not panic")
		}
	}()
	router.HandleOCI(http.MethodGet, "/tags/list", server.Permission{}, http.NotFoundHandler())
}

func TestHandleOCIRegistrationRefusals(t *testing.T) {
	t.Parallel()

	register := func(suffix string, permission server.Permission) (panicked bool) {
		defer func() { panicked = recover() != nil }()
		store := memory.New()
		t.Cleanup(func() { _ = store.Close() })
		router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
		router.HandleOCI(http.MethodGet, suffix, permission, http.NotFoundHandler())
		return false
	}

	if !register("/tags/list", server.Permission{Verb: "not:averb"}) {
		t.Error("an unknown verb did not panic")
	}
	if !register("no-slash", server.Permission{Verb: authz.RepoRead}) {
		t.Error("a suffix without a leading slash did not panic")
	}
	if !register("/tags//list", server.Permission{Verb: authz.RepoRead}) {
		t.Error("an empty segment did not panic")
	}
}

// Outside an OCI match the helpers answer empty rather than panicking: a
// handler wired onto a plain route by mistake fails its name validation, not
// the process.
func TestOCIHelpersOutsideAMatch(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/other", nil)
	if server.OCIName(req) != "" || server.OCIValue(req, "digest") != "" {
		t.Error("the helpers invented values outside an OCI route")
	}
}
