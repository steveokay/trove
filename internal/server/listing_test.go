package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// listingServer wires one Listing route guarded by repo:list. The handler
// reports what the guard's Visibility lets it see, which is exactly how the
// catalog will use it (R-004).
func listingServer(t *testing.T, store *memory.Store, credentials server.CredentialFunc) *server.Router {
	t.Helper()

	router := server.NewRouter(&server.Guard{
		Subjects:    store,
		Bindings:    store,
		Credentials: credentials,
		Challenge: func(*http.Request) string {
			return `Bearer realm="trove",service="registry"`
		},
	})
	router.HandleFunc(http.MethodGet, "/v2/_catalog",
		server.Permission{Verb: authz.RepoList, Listing: true},
		func(w http.ResponseWriter, r *http.Request) {
			visibility, ok := server.VisibilityFrom(r.Context())
			if !ok {
				t.Error("a listing handler cannot see its visibility")
			}
			if _, ok := server.SubjectFrom(r.Context()); !ok {
				t.Error("a listing handler cannot see its subject")
			}
			if _, ok := server.DecisionFrom(r.Context()); ok {
				t.Error("a listing route carries a Decision: nothing was decided")
			}
			var visible []string
			for _, name := range []string{"team-a/api", "secret/vault"} {
				if visibility.Allows(name) {
					visible = append(visible, name)
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Join(visible, ",")))
		})
	return router
}

func listingGet(t *testing.T, router *server.Router) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	return rec
}

// The guard compiles the subject's own bindings into the handler's view: a
// scoped subject sees its slice, and nothing else exists as far as the
// handler can tell.
func TestListingVisibilityIsTheSubjects(t *testing.T) {
	t.Parallel()

	store := world(t)
	rec := listingGet(t, listingServer(t, store, asSubject("reader")))
	if rec.Code != http.StatusOK || rec.Body.String() != "team-a/api" {
		t.Fatalf("reader's listing: %d %q, want team-a/api alone", rec.Code, rec.Body)
	}
}

// An authenticated subject with no listing grants gets its empty page: an
// empty listing disclosed nothing, and a refusal would only say "you exist".
func TestListingWithNoGrantsIsEmpty(t *testing.T) {
	t.Parallel()

	store := world(t)
	rec := listingGet(t, listingServer(t, store, asSubject("nobody")))
	if rec.Code != http.StatusOK || rec.Body.String() != "" {
		t.Fatalf("grantless listing: %d %q, want an empty 200", rec.Code, rec.Body)
	}
}

// Scope breadth is not the verb: a *-scoped role without repo:list still
// sees nothing (the same reading Z-012 pinned for the query layer).
func TestListingScopeBreadthIsNotTheVerb(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := world(t)
	if err := store.CreateRole(ctx, meta.Role{Name: "wide-writer", Verbs: []string{"repo:write"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "b-wide", PrincipalKind: meta.PrincipalSubject, PrincipalID: "id-nobody",
		Role: "wide-writer", Scope: "*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	rec := listingGet(t, listingServer(t, store, asSubject("nobody")))
	if rec.Code != http.StatusOK || rec.Body.String() != "" {
		t.Fatalf("*-scoped writer's listing: %d %q, want an empty 200", rec.Code, rec.Body)
	}
}

// Anonymous with nothing visible gets the challenge, not an empty page: the
// client may be able to authenticate into visibility (ADR 0003).
func TestListingAnonymousWithNothingIsChallenged(t *testing.T) {
	t.Parallel()

	store := world(t)
	rec := listingGet(t, listingServer(t, store, server.NoCredentials))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous empty listing: %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q", got)
	}
}

// Anonymous with a real grant is a subject like any other and sees its slice
// (the anonymous-reader deployment shape).
func TestListingAnonymousWithGrantsIsServed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := world(t)
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "b-anon", PrincipalKind: meta.PrincipalSubject, PrincipalID: "anonymous",
		Role: authz.RoleDeveloper, Scope: "team-a/*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	rec := listingGet(t, listingServer(t, store, server.NoCredentials))
	if rec.Code != http.StatusOK || rec.Body.String() != "team-a/api" {
		t.Fatalf("anonymous-reader listing: %d %q, want team-a/api", rec.Code, rec.Body)
	}
}

// A broken bindings store fails the listing closed, like every other guard
// path: visibility that could not be computed shows nothing and answers 500.
func TestListingFailsClosedOnBrokenBindings(t *testing.T) {
	t.Parallel()

	store := world(t)
	router := server.NewRouter(&server.Guard{
		Subjects:    store,
		Bindings:    brokenBindings{},
		Credentials: asSubject("reader"),
	})
	router.HandleFunc(http.MethodGet, "/v2/_catalog",
		server.Permission{Verb: authz.RepoList, Listing: true},
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("the handler ran with no bindings readable")
		})

	rec := listingGet(t, router)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("broken bindings: %d, want 500", rec.Code)
	}
}

// VisibilityFrom answers false outside a listing route, so a handler cannot
// mistake an ordinary route for one and query with a zero Visibility.
func TestVisibilityFromOutsideAListingRoute(t *testing.T) {
	t.Parallel()

	if _, ok := server.VisibilityFrom(context.Background()); ok {
		t.Error("VisibilityFrom reported a visibility on a bare context")
	}
}

// The registration rules: a listing is about no single resource, and an OCI
// route is always about the repository in its path.
func TestListingRegistrationRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		register func(router *server.Router)
	}{
		{
			name: "listing with a resource extractor",
			register: func(router *server.Router) {
				router.HandleFunc(http.MethodGet, "/api/v1/things", server.Permission{
					Verb: authz.RepoList, Listing: true,
					Resource: func(*http.Request) (authz.Resource, error) { return authz.System(), nil },
				}, func(http.ResponseWriter, *http.Request) {})
			},
		},
		{
			name: "listing with a subject extractor",
			register: func(router *server.Router) {
				router.HandleFunc(http.MethodGet, "/api/v1/things", server.Permission{
					Verb: authz.RepoList, Listing: true,
					Self: func(*http.Request) (string, error) { return "", nil },
				}, func(http.ResponseWriter, *http.Request) {})
			},
		},
		{
			name: "OCI route as listing",
			register: func(router *server.Router) {
				router.HandleOCI(http.MethodGet, "/tags/list", server.Permission{
					Verb: authz.RepoList, Listing: true,
				}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("registration did not panic")
				}
			}()
			tt.register(server.NewRouter(&server.Guard{}))
		})
	}
}

// brokenBindings is a BindingStore that cannot answer.
type brokenBindings struct{}

func (brokenBindings) ListEffectiveBindings(context.Context, string) ([]meta.EffectiveBinding, error) {
	return nil, context.DeadlineExceeded
}

func (brokenBindings) GetRole(context.Context, string) (meta.Role, error) {
	return meta.Role{}, context.DeadlineExceeded
}
