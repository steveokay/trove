package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

func router(t *testing.T) *server.Router {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	return server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
}

func noop(http.ResponseWriter, *http.Request) {}

// The route table is what Z-011 walks. Every entry is either guarded by a verb
// or public with a written reason -- one of the two is always true, which is
// what makes "no route is unguarded" checkable rather than asserted.
func TestRouteTable(t *testing.T) {
	t.Parallel()

	r := router(t)
	r.HandleFunc(http.MethodPut, "/api/v1/repositories/{name}",
		server.Permission{Verb: authz.RepoConfigure}, noop)
	r.HandleFunc(http.MethodGet, "/api/v1/repositories/{name}",
		server.Permission{Verb: authz.RepoRead}, noop)
	r.HandlePublic(http.MethodGet, "/healthz", "liveness answers before anything is configured",
		http.HandlerFunc(noop))

	routes := r.Routes()
	if len(routes) != 3 {
		t.Fatalf("%d routes, want 3", len(routes))
	}
	// Ordered by pattern then method, so the table reads the same every time.
	if routes[0].Pattern != "/api/v1/repositories/{name}" || routes[0].Method != http.MethodGet {
		t.Errorf("routes[0] = %s %s, want GET on the repository", routes[0].Method, routes[0].Pattern)
	}

	for _, route := range routes {
		guarded := route.Permission.Verb != ""
		if guarded == route.Public() {
			t.Errorf("%s %s is neither guarded nor declared public, or both",
				route.Method, route.Pattern)
		}
	}

	// The returned table is a copy: a caller walking it must not be able to
	// rewrite what the server enforces.
	routes[0].Permission.Verb = authz.GateOverride
	if again := r.Routes(); again[0].Permission.Verb == authz.GateOverride {
		t.Error("Routes hands out the router's own table")
	}
}

// Registration is the enforcement point. A missing verb is a programming
// error, and it fails at startup rather than becoming a route that denies
// everything and looks like a permissions bug.
func TestRegistrationRefusesUnguardedRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		register func(*server.Router)
	}{
		{
			name: "no verb",
			register: func(r *server.Router) {
				r.HandleFunc(http.MethodGet, "/a", server.Permission{}, noop)
			},
		},
		{
			name: "unknown verb",
			register: func(r *server.Router) {
				r.HandleFunc(http.MethodGet, "/a", server.Permission{Verb: "repo:admin"}, noop)
			},
		},
		{
			name: "public without a reason",
			register: func(r *server.Router) {
				r.HandlePublic(http.MethodGet, "/a", "", http.HandlerFunc(noop))
			},
		},
		{
			name: "registered twice",
			register: func(r *server.Router) {
				perm := server.Permission{Verb: authz.RepoRead}
				r.HandleFunc(http.MethodGet, "/a", perm, noop)
				r.HandleFunc(http.MethodGet, "/a", perm, noop)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("registration was accepted")
				}
			}()
			tt.register(router(t))
		})
	}
}

// A method the route does not handle is the mux's answer, not the guard's:
// nothing is decided about a request that matched no route.
func TestUnregisteredMethod(t *testing.T) {
	t.Parallel()

	r := router(t)
	r.HandleFunc(http.MethodGet, "/api/v1/thing", server.Permission{Verb: authz.RepoRead}, noop)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/thing", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", recorder.Code)
	}
}
