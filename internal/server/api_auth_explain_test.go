package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// explainFixture seeds the store the explain tests share and returns a handler
// serving the registered route. Credentials are the X-Test-Subject header: the
// CredentialFunc seam stands in for the token flow (Z-004) exactly as the
// guard will use it.
func explainFixture(t *testing.T) http.Handler {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	for _, subject := range []meta.Subject{
		{ID: "u-alice", Kind: meta.User, Name: "alice"},
		{ID: "u-bob", Kind: meta.User, Name: "bob"},
		{ID: "u-admin", Kind: meta.User, Name: "admin"},
		{ID: "u-dora", Kind: meta.User, Name: "dora"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject(%q): %v", subject.Name, err)
		}
	}
	if err := store.CreateGroup(ctx, meta.SubjectGroup{ID: "gid-platform", Name: "platform"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := store.AddGroupMember(ctx, "platform", "alice"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	for _, role := range []meta.Role{
		{Name: "publisher", Verbs: []string{"repo:read", "repo:write"}},
		{Name: "developer", Verbs: []string{"repo:read"}},
		{Name: "overseer", Verbs: []string{"user:read"}},
	} {
		if err := store.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole(%q): %v", role.Name, err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-dev", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-alice", Role: "developer", Scope: "team-a/*"},
		{ID: "b-team", PrincipalKind: meta.PrincipalGroup, PrincipalID: "gid-platform", Role: "publisher", Scope: "team-a/*"},
		{ID: "b-admin", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-admin", Role: "overseer", Scope: "system"},
		{ID: "b-dora", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-dora", Role: "developer", Scope: "team-a/*"},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding(%q): %v", binding.ID, err)
		}
	}
	// Disabled after binding, so the explainer's answer for dora shows the
	// disable winning over a grant that is still on the books.
	if err := store.SetSubjectDisabled(ctx, "dora", true); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}

	guard := &server.Guard{
		Subjects: store,
		Bindings: store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	}
	router := server.NewRouter(guard)
	explain := &server.AuthExplain{Subjects: store, Bindings: store}
	explain.Register(router)
	return router
}

func explainRequest(t *testing.T, handler http.Handler, as, query string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/explain"+query, nil)
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// The explainer's response is a wire contract: the UI renders it, the CLI
// formats it, and DOC-003 quotes it. Golden bodies rather than field checks.
func TestAuthExplainGolden(t *testing.T) {
	t.Parallel()

	handler := explainFixture(t)

	tests := []struct {
		name  string
		as    string
		query string
		want  string
	}{
		{
			name:  "allowed through a group",
			as:    "alice",
			query: "?verb=repo:write&resource=team-a/api",
			want:  `{"subject":{"name":"alice","kind":"user","disabled":false},"verb":"repo:write","resource":"team-a/api","allowed":true,"matched":[{"binding":"b-team","role":"publisher","scope":"team-a/*","via_group":"platform"}]}` + "\n",
		},
		{
			// Both grants contribute and both are named, ordered by binding id;
			// the direct one carries no via_group.
			name:  "every contributing binding is named",
			as:    "alice",
			query: "?verb=repo:read&resource=team-a/api",
			want:  `{"subject":{"name":"alice","kind":"user","disabled":false},"verb":"repo:read","resource":"team-a/api","allowed":true,"matched":[{"binding":"b-dev","role":"developer","scope":"team-a/*"},{"binding":"b-team","role":"publisher","scope":"team-a/*","via_group":"platform"}]}` + "\n",
		},
		{
			name:  "denied lists nothing",
			as:    "alice",
			query: "?verb=repo:delete&resource=team-a/api",
			want:  `{"subject":{"name":"alice","kind":"user","disabled":false},"verb":"repo:delete","resource":"team-a/api","allowed":false,"matched":[]}` + "\n",
		},
		{
			name:  "no resource means the system scope",
			as:    "admin",
			query: "?verb=user:read",
			want:  `{"subject":{"name":"admin","kind":"user","disabled":false},"verb":"user:read","resource":"system","allowed":true,"matched":[{"binding":"b-admin","role":"overseer","scope":"system"}]}` + "\n",
		},
		{
			name:  "anonymous may explain itself",
			as:    "",
			query: "?verb=repo:read&resource=team-a/api",
			want:  `{"subject":{"name":"anonymous","kind":"anonymous","disabled":false},"verb":"repo:read","resource":"team-a/api","allowed":false,"matched":[]}` + "\n",
		},
		{
			// The grant is still on the books; the disable wins, and the
			// response says why the store returned no effective bindings.
			name:  "disabled subject has no effective permissions",
			as:    "admin",
			query: "?subject=dora&verb=repo:read&resource=team-a/api",
			want:  `{"subject":{"name":"dora","kind":"user","disabled":true},"verb":"repo:read","resource":"team-a/api","allowed":false,"matched":[]}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := explainRequest(t, handler, tt.as, tt.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			if rec.Body.String() != tt.want {
				t.Errorf("body:\n got %s\nwant %s", rec.Body, tt.want)
			}
		})
	}
}

// ADR 0003 surface 8: a subject may always explain itself; explaining anybody
// else requires user:read. This is where that verb is enforced, so the §9
// marks live here.
func TestAuthExplainAuthorization(t *testing.T) {
	t.Parallel()

	verbtest.Positive(t, authz.UserRead)
	verbtest.Negative(t, authz.UserRead)

	handler := explainFixture(t)

	t.Run("user:read may explain others", func(t *testing.T) {
		t.Parallel()
		rec := explainRequest(t, handler, "admin", "?subject=bob&verb=repo:read&resource=team-a/api")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}
		want := `{"subject":{"name":"bob","kind":"user","disabled":false},"verb":"repo:read","resource":"team-a/api","allowed":false,"matched":[]}` + "\n"
		if rec.Body.String() != want {
			t.Errorf("body:\n got %s\nwant %s", rec.Body, want)
		}
	})

	t.Run("without user:read explaining another subject is refused", func(t *testing.T) {
		t.Parallel()
		rec := explainRequest(t, handler, "alice", "?subject=bob&verb=repo:read")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body)
		}
	})

	t.Run("the refusal does not depend on whether the target exists", func(t *testing.T) {
		t.Parallel()
		// The guard refuses before anything looks the target up, so a probe
		// without user:read cannot enumerate subject names.
		real := explainRequest(t, handler, "alice", "?subject=bob&verb=repo:read")
		ghost := explainRequest(t, handler, "alice", "?subject=ghost&verb=repo:read")
		if real.Code != ghost.Code || real.Body.String() != ghost.Body.String() {
			t.Errorf("existing target: %d %s\nmissing target: %d %s\nwant identical answers",
				real.Code, real.Body, ghost.Code, ghost.Body)
		}
	})

	t.Run("naming yourself is self-explain", func(t *testing.T) {
		t.Parallel()
		rec := explainRequest(t, handler, "alice", "?subject=alice&verb=repo:write&resource=team-a/api")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 without user:read; body %s", rec.Code, rec.Body)
		}
	})

	t.Run("anonymous asking about another subject gets the challenge", func(t *testing.T) {
		t.Parallel()
		rec := explainRequest(t, handler, "", "?subject=alice&verb=repo:read")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Error("401 without a WWW-Authenticate challenge")
		}
	})

	t.Run("with user:read an unknown subject is 404", func(t *testing.T) {
		t.Parallel()
		rec := explainRequest(t, handler, "admin", "?subject=ghost&verb=repo:read")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body)
		}
	})
}

func TestAuthExplainValidation(t *testing.T) {
	t.Parallel()

	handler := explainFixture(t)

	tests := []struct {
		name  string
		query string
	}{
		{"missing verb", ""},
		{"unknown verb", "?verb=repo:frobnicate"},
		{"malformed resource", "?verb=repo:read&resource=..%2Fetc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := explainRequest(t, handler, "alice", tt.query)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
			}
		})
	}
}

var errUnparsable = errors.New("unparsable request")

// faultyStore fails exactly the calls the test aims at, so the guard's own
// lookups still succeed and the failure lands inside the handler.
type faultyStore struct {
	*memory.Store
	failSubject  string // GetSubject for this name fails
	failBindings string // ListEffectiveBindings for this name fails
}

func (f *faultyStore) GetSubject(ctx context.Context, name string) (meta.Subject, error) {
	if name == f.failSubject {
		return meta.Subject{}, errors.New("disk on fire")
	}
	return f.Store.GetSubject(ctx, name)
}

func (f *faultyStore) ListEffectiveBindings(ctx context.Context, subject string) ([]meta.EffectiveBinding, error) {
	if subject == f.failBindings {
		return nil, errors.New("disk on fire")
	}
	return f.Store.ListEffectiveBindings(ctx, subject)
}

// An explainer that cannot read is a failure, never an answer: rendering
// "denied" for a broken store would send an operator hunting for a binding
// that exists.
func TestAuthExplainFailsClosedOnABrokenStore(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, faulty *faultyStore) http.Handler {
		t.Helper()
		ctx := context.Background()
		store := memory.New()
		t.Cleanup(func() { _ = store.Close() })
		for _, subject := range []meta.Subject{
			{ID: "u-alice", Kind: meta.User, Name: "alice"},
			{ID: "u-bob", Kind: meta.User, Name: "bob"},
			{ID: "u-admin", Kind: meta.User, Name: "admin"},
		} {
			if err := store.CreateSubject(ctx, subject); err != nil {
				t.Fatalf("CreateSubject: %v", err)
			}
		}
		if err := store.CreateRole(ctx, meta.Role{Name: "overseer", Verbs: []string{"user:read"}}); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if err := store.CreateBinding(ctx, meta.Binding{
			ID: "b-admin", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-admin",
			Role: "overseer", Scope: "system",
		}); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
		faulty.Store = store

		router := server.NewRouter(&server.Guard{
			Subjects: faulty,
			Bindings: faulty,
			Credentials: func(r *http.Request) (string, error) {
				return r.Header.Get("X-Test-Subject"), nil
			},
		})
		explain := &server.AuthExplain{Subjects: faulty, Bindings: faulty, Errors: server.ProblemErrors{}}
		explain.Register(router)
		return router
	}

	t.Run("bindings unreadable during self-explain", func(t *testing.T) {
		t.Parallel()
		// The guard skips its own binding fetch for self-access, so the
		// handler's fetch is the first to hit the fault.
		handler := build(t, &faultyStore{failBindings: "alice"})
		rec := explainRequest(t, handler, "alice", "?verb=repo:read")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body)
		}
	})

	t.Run("target subject unreadable", func(t *testing.T) {
		t.Parallel()
		handler := build(t, &faultyStore{failSubject: "bob"})
		rec := explainRequest(t, handler, "admin", "?subject=bob&verb=repo:read")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body)
		}
	})
}

// The self extractor is part of the request surface: one that cannot make
// sense of the request refuses it before anything is decided, like a resource
// extractor does.
func TestSelfExtractorErrorIsBadRequest(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
	router.HandleFunc(http.MethodGet, "/broken", server.Permission{
		Verb: authz.UserRead,
		Self: func(*http.Request) (string, error) { return "", errUnparsable },
	}, func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran despite an unusable request")
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/broken", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
	}
}

// A route cannot be about a repository and about a subject at once: the two
// extractors would race for the same verb.
func TestSelfAndResourceAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("registering a route with both Self and Resource did not panic")
		}
	}()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
	router.HandleFunc(http.MethodGet, "/both", server.Permission{
		Verb:     authz.UserRead,
		Resource: func(*http.Request) (authz.Resource, error) { return authz.System(), nil },
		Self:     func(*http.Request) (string, error) { return "", nil },
	}, func(http.ResponseWriter, *http.Request) {})
}
