package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// The fixture is one repository, team-a/api, and three subjects: one holding
// nothing, one with read access to it, and one with write access.

// world builds a store with the subjects, roles and bindings the matrix needs.
func world(t *testing.T) *memory.Store {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	for _, role := range authz.BuiltinRoles() {
		verbs := make([]string, 0, len(role.Verbs))
		for _, verb := range role.Verbs {
			verbs = append(verbs, string(verb))
		}
		if err := store.CreateRole(ctx, meta.Role{Name: role.Name, Builtin: true, Verbs: verbs}); err != nil {
			t.Fatalf("CreateRole(%s): %v", role.Name, err)
		}
	}

	subjects := []struct {
		name string
		role string
	}{
		{name: "nobody"},
		{name: "reader", role: authz.RoleDeveloper},
		{name: "writer", role: authz.RolePublisher},
	}
	for i, s := range subjects {
		if err := store.CreateSubject(ctx, meta.Subject{
			ID: "id-" + s.name, Kind: meta.User, Name: s.name,
		}); err != nil {
			t.Fatalf("CreateSubject(%s): %v", s.name, err)
		}
		if s.role == "" {
			continue
		}
		if err := store.CreateBinding(ctx, meta.Binding{
			ID:            "b" + string(rune('1'+i)),
			PrincipalKind: meta.PrincipalSubject,
			PrincipalID:   "id-" + s.name,
			Role:          s.role,
			Scope:         "team-a/*",
		}); err != nil {
			t.Fatalf("CreateBinding(%s): %v", s.name, err)
		}
	}
	return store
}

// guardedServer wires a router with a read route and a write route over the
// repository in the path.
func guardedServer(t *testing.T, store *memory.Store, credentials server.CredentialFunc) *server.Router {
	t.Helper()

	guard := &server.Guard{
		Subjects:    store,
		Bindings:    store,
		Credentials: credentials,
		Challenge: func(*http.Request) string {
			return `Bearer realm="trove",service="registry"`
		},
	}
	router := server.NewRouter(guard)

	repository := func(r *http.Request) (authz.Resource, error) {
		return authz.Repository(r.PathValue("name") + "/" + r.PathValue("sub"))
	}
	ok := func(w http.ResponseWriter, r *http.Request) {
		// Proving the handler ran, and that it can see who it is serving.
		subject, found := server.SubjectFrom(r.Context())
		if !found {
			t.Error("a guarded handler cannot see its subject")
		}
		if _, found := server.DecisionFrom(r.Context()); !found {
			t.Error("a guarded handler cannot see the decision that admitted it")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(subject.Name))
	}

	router.HandleFunc(http.MethodGet, "/api/v1/repositories/{name}/{sub}",
		server.Permission{Verb: authz.RepoRead, Resource: repository}, ok)
	router.HandleFunc(http.MethodPut, "/api/v1/repositories/{name}/{sub}",
		server.Permission{Verb: authz.RepoWrite, Resource: repository}, ok)
	router.HandleFunc(http.MethodPost, "/api/v1/system/gc",
		server.Permission{Verb: authz.GCRun}, ok)
	// A public route runs without a guard, so it has no subject in context --
	// which is why it cannot share the handler above.
	router.HandlePublic(http.MethodGet, "/healthz",
		"liveness must answer before anything is configured",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, found := server.SubjectFrom(r.Context()); found {
				t.Error("a public route carries a subject: it never resolved one")
			}
			w.WriteHeader(http.StatusOK)
		}))

	return router
}

// asSubject makes every request appear to come from one subject.
func asSubject(name string) server.CredentialFunc {
	return func(*http.Request) (string, error) { return name, nil }
}

// This is ADR 0003's status-code matrix, cell by cell. Each row is a decision
// somebody has to be able to rely on, and the reasoning for the surprising
// ones is in the comments rather than in a document nobody opens.
func TestAuthorizationMatrix(t *testing.T) {
	t.Parallel()

	verbtest.Positive(t, authz.RepoRead)
	verbtest.Negative(t, authz.RepoRead)
	verbtest.Positive(t, authz.RepoWrite)
	verbtest.Negative(t, authz.RepoWrite)
	verbtest.Positive(t, authz.GCRun)
	verbtest.Negative(t, authz.GCRun)

	tests := []struct {
		name       string
		subject    string // empty means the request presents no credentials
		method     string
		target     string
		wantStatus int
		wantType   string
		challenge  bool
	}{
		{
			name:       "reader reads",
			subject:    "reader",
			method:     http.MethodGet,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusOK,
		},
		{
			name:       "writer writes",
			subject:    "writer",
			method:     http.MethodPut,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusOK,
		},
		{
			// Readability already disclosed existence, so a helpful answer
			// costs nothing: the reader learns it may not push, which it could
			// have guessed.
			name:       "reader writes",
			subject:    "reader",
			method:     http.MethodPut,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusForbidden,
			wantType:   server.ProblemForbidden,
		},
		{
			// Existence is information. A 403 here would let any authenticated
			// probe enumerate repository names by watching the status change.
			name:       "no access reads",
			subject:    "nobody",
			method:     http.MethodGet,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusNotFound,
			wantType:   server.ProblemNotFound,
		},
		{
			name:       "no access writes",
			subject:    "nobody",
			method:     http.MethodPut,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusNotFound,
			wantType:   server.ProblemNotFound,
		},
		{
			// The same answer for a repository nobody has bound at all: the
			// hidden and the absent must be indistinguishable.
			name:       "reader reads elsewhere",
			subject:    "reader",
			method:     http.MethodGet,
			target:     "/api/v1/repositories/team-b/api",
			wantStatus: http.StatusNotFound,
			wantType:   server.ProblemNotFound,
		},
		{
			// Anonymous gets the challenge rather than a 404: the client may
			// be able to authenticate into visibility, and `docker login`
			// depends on being told so.
			name:       "anonymous reads",
			method:     http.MethodGet,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusUnauthorized,
			wantType:   server.ProblemUnauthorized,
			challenge:  true,
		},
		{
			name:       "anonymous writes",
			method:     http.MethodPut,
			target:     "/api/v1/repositories/team-a/api",
			wantStatus: http.StatusUnauthorized,
			wantType:   server.ProblemUnauthorized,
			challenge:  true,
		},
		{
			// The system's existence is not a secret, so an authenticated
			// subject that lacks the verb is told plainly.
			name:       "reader runs gc",
			subject:    "reader",
			method:     http.MethodPost,
			target:     "/api/v1/system/gc",
			wantStatus: http.StatusForbidden,
			wantType:   server.ProblemForbidden,
		},
		{
			name:       "anonymous runs gc",
			method:     http.MethodPost,
			target:     "/api/v1/system/gc",
			wantStatus: http.StatusUnauthorized,
			wantType:   server.ProblemUnauthorized,
			challenge:  true,
		},
		{
			// A public route answers whoever asks, which is the point of
			// registering it as one.
			name:       "anonymous health check",
			method:     http.MethodGet,
			target:     "/healthz",
			wantStatus: http.StatusOK,
		},
	}

	store := world(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			router := guardedServer(t, store, asSubject(tt.subject))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.target, nil))

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, tt.wantStatus, recorder.Body)
			}
			challenge := recorder.Header().Get("WWW-Authenticate")
			if tt.challenge && challenge == "" {
				t.Error("a 401 without a challenge: docker login has nothing to do next")
			}
			if !tt.challenge && challenge != "" {
				t.Errorf("unexpected challenge %q", challenge)
			}
			if tt.wantType == "" {
				return
			}

			var problem server.Problem
			if err := json.NewDecoder(recorder.Body).Decode(&problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if problem.Type != tt.wantType {
				t.Errorf("problem type = %q, want %q", problem.Type, tt.wantType)
			}
			if problem.Status != tt.wantStatus {
				t.Errorf("problem status = %d, want %d", problem.Status, tt.wantStatus)
			}
			if got := recorder.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Errorf("content type = %q, want application/problem+json", got)
			}
		})
	}
}

// The unreadable and the absent must be byte-identical, or the difference is
// the disclosure (ADR 0003).
func TestHiddenAndAbsentAreIndistinguishable(t *testing.T) {
	t.Parallel()

	store := world(t)
	router := guardedServer(t, store, asSubject("nobody"))

	responses := map[string]*httptest.ResponseRecorder{}
	for _, target := range []string{
		"/api/v1/repositories/team-a/api", // exists, unreadable
		"/api/v1/repositories/team-z/api", // does not exist
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		responses[target] = recorder
	}

	hidden := responses["/api/v1/repositories/team-a/api"]
	absent := responses["/api/v1/repositories/team-z/api"]

	if hidden.Code != absent.Code {
		t.Errorf("status %d for the hidden repository, %d for the absent one", hidden.Code, absent.Code)
	}
	if hidden.Body.String() != absent.Body.String() {
		t.Errorf("bodies differ:\n hidden: %s\n absent: %s", hidden.Body, absent.Body)
	}
	if hidden.Header().Get("Content-Type") != absent.Header().Get("Content-Type") {
		t.Error("content types differ between the hidden and the absent case")
	}
}

// A repository name that could not be legal is refused before anything is
// looked up: it arrives from the URL, and the gate is the point.
func TestUnusableResourceIsRefused(t *testing.T) {
	t.Parallel()

	store := world(t)
	router := guardedServer(t, store, asSubject("writer"))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/repositories/Team-A/api", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body)
	}
}

// Credentials that are no longer good get the challenge, not a refusal: the
// client may have others.
func TestFailedAuthenticationChallenges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := world(t)
	if err := store.SetSubjectDisabled(ctx, "reader", true); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}

	for _, subject := range []string{"reader", "ghost"} {
		t.Run(subject, func(t *testing.T) {
			router := guardedServer(t, store, asSubject(subject))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/repositories/team-a/api", nil))

			if recorder.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", recorder.Code)
			}
			if recorder.Header().Get("WWW-Authenticate") == "" {
				t.Error("no challenge")
			}
		})
	}
}

// A guard that cannot read its bindings has not decided anything. Treating
// that as a grant is how a database outage becomes an incident.
func TestBrokenStoreFailsClosed(t *testing.T) {
	t.Parallel()

	store := world(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	router := guardedServer(t, store, asSubject("writer"))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/repositories/team-a/api", nil))

	if recorder.Code == http.StatusOK {
		t.Fatal("a broken store admitted a request")
	}
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}
}

// Every denial is reportable: Z-016 hangs the authz.denied event and its
// metric on this hook.
func TestDenialsAreReported(t *testing.T) {
	t.Parallel()

	store := world(t)
	var denied []authz.Decision
	guard := &server.Guard{
		Subjects:    store,
		Bindings:    store,
		Credentials: asSubject("nobody"),
		OnDenied: func(_ context.Context, subject authn.Subject, decision authz.Decision) {
			if subject.Name != "nobody" {
				t.Errorf("denial reported for %q", subject.Name)
			}
			denied = append(denied, decision)
		},
	}
	router := server.NewRouter(guard)
	router.HandleFunc(http.MethodGet, "/api/v1/repositories/{name}/{sub}",
		server.Permission{
			Verb: authz.RepoRead,
			Resource: func(r *http.Request) (authz.Resource, error) {
				return authz.Repository(r.PathValue("name") + "/" + r.PathValue("sub"))
			},
		},
		func(http.ResponseWriter, *http.Request) {})

	router.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/repositories/team-a/api", nil))

	if len(denied) != 1 {
		t.Fatalf("%d denials reported, want 1", len(denied))
	}
	if denied[0].Verb != authz.RepoRead || denied[0].Allowed {
		t.Errorf("reported decision = %s", denied[0])
	}
	// The decision explains itself, which is what the audit record carries.
	if !strings.Contains(denied[0].String(), "team-a/api") {
		t.Errorf("denial does not name the resource: %s", denied[0])
	}
}
