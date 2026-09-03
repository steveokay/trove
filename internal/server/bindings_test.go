package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// fakeBindings is a binding store that can be made to misbehave in ways a real
// one only manages under a race.
type fakeBindings struct {
	effective []meta.EffectiveBinding
	roles     map[string]meta.Role
	listErr   error
	roleErr   error
	roleReads int
}

func (f *fakeBindings) ListEffectiveBindings(context.Context, string) ([]meta.EffectiveBinding, error) {
	return f.effective, f.listErr
}

func (f *fakeBindings) GetRole(_ context.Context, name string) (meta.Role, error) {
	f.roleReads++
	if f.roleErr != nil {
		return meta.Role{}, f.roleErr
	}
	role, ok := f.roles[name]
	if !ok {
		return meta.Role{}, meta.NotFound("role", name)
	}
	return role, nil
}

func binding(id, role, scope, viaGroup string) meta.EffectiveBinding {
	return meta.EffectiveBinding{
		Binding:  meta.Binding{ID: id, Role: role, Scope: scope},
		ViaGroup: viaGroup,
	}
}

func TestFetchBindingsResolvesRoles(t *testing.T) {
	t.Parallel()

	store := &fakeBindings{
		effective: []meta.EffectiveBinding{
			binding("b2", "developer", "team-b/*", "platform"),
			binding("b1", "developer", "team-a/*", ""),
			binding("b3", "auditor", "system", ""),
		},
		roles: map[string]meta.Role{
			"developer": {Name: "developer", Verbs: []string{"repo:read", "repo:list"}},
			"auditor":   {Name: "auditor", Verbs: []string{"audit:read"}},
		},
	}

	bindings, err := server.FetchBindings(context.Background(), store, "alice")
	if err != nil {
		t.Fatalf("FetchBindings: %v", err)
	}
	if len(bindings) != 3 {
		t.Fatalf("%d bindings, want 3", len(bindings))
	}
	// Ordered by id, so a decision's explanation reads the same way every time.
	for i, want := range []string{"b1", "b2", "b3"} {
		if bindings[i].ID != want {
			t.Errorf("bindings[%d] = %s, want %s", i, bindings[i].ID, want)
		}
	}
	if !bindings[0].Grants(authz.RepoRead) {
		t.Error("the role's verbs did not come through")
	}
	// Provenance survives: "through the platform group" is what makes the
	// explainer useful.
	if bindings[1].ViaGroup != "platform" {
		t.Errorf("ViaGroup = %q, want platform", bindings[1].ViaGroup)
	}

	// A subject bound to one role in several scopes is ordinary, so the role
	// is read once rather than once per binding.
	if store.roleReads != 2 {
		t.Errorf("read roles %d times, want 2 (one per distinct role)", store.roleReads)
	}
}

// Deleting a role deletes the bindings that granted it, so the only way to see
// a binding to a missing role is to race that delete. It grants nothing either
// way, and treating it as an error would fail requests during an ordinary
// administrative change.
func TestFetchBindingsSkipsMissingRoles(t *testing.T) {
	t.Parallel()

	store := &fakeBindings{
		effective: []meta.EffectiveBinding{
			binding("b1", "deleted", "*", ""),
			binding("b2", "developer", "team-a/*", ""),
			binding("b3", "deleted", "team-b/*", ""),
		},
		roles: map[string]meta.Role{
			"developer": {Name: "developer", Verbs: []string{"repo:read"}},
		},
	}

	bindings, err := server.FetchBindings(context.Background(), store, "alice")
	if err != nil {
		t.Fatalf("FetchBindings: %v", err)
	}
	if len(bindings) != 1 || bindings[0].ID != "b2" {
		t.Fatalf("bindings = %+v, want only b2", bindings)
	}
	// The missing role is looked up once, not once per binding that names it.
	if store.roleReads != 2 {
		t.Errorf("read roles %d times, want 2", store.roleReads)
	}
}

// A failure to read bindings is a failure, never an empty set: an empty set is
// a valid answer meaning "this subject may do nothing", and returning it for a
// broken store would deny confidently instead of failing honestly.
func TestFetchBindingsReportsFailures(t *testing.T) {
	t.Parallel()

	listFailure := errors.New("connection reset")
	if _, err := server.FetchBindings(context.Background(),
		&fakeBindings{listErr: listFailure}, "alice"); !errors.Is(err, listFailure) {
		t.Errorf("FetchBindings = %v, want the store's error", err)
	}

	roleFailure := errors.New("connection reset")
	store := &fakeBindings{
		effective: []meta.EffectiveBinding{binding("b1", "developer", "*", "")},
		roleErr:   roleFailure,
	}
	if _, err := server.FetchBindings(context.Background(), store, "alice"); !errors.Is(err, roleFailure) {
		t.Errorf("FetchBindings = %v, want the store's error", err)
	}
}

// The guard's defaults have to be safe, because a caller that fills in nothing
// is the caller most likely to be wiring it for the first time.
func TestGuardDefaults(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	// No Credentials, no Errors, no Challenge: every request is anonymous, the
	// admin API's problem shape is used, and a 401 still carries a challenge.
	guard := &server.Guard{Subjects: store, Bindings: store}
	r := server.NewRouter(guard)
	r.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun}, noop)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != server.DefaultChallenge {
		t.Errorf("challenge = %q, want the default %q", got, server.DefaultChallenge)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("content type = %q, want problem+json", got)
	}
}

// Credentials that cannot be read at all -- a malformed Authorization header,
// once Z-002 parses them -- are an authentication failure, not a server error.
func TestUnreadableCredentialsChallenge(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	guard := &server.Guard{
		Subjects: store,
		Bindings: store,
		Credentials: func(*http.Request) (string, error) {
			return "", errors.New("malformed Authorization header")
		},
	}
	r := server.NewRouter(guard)
	r.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun}, noop)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: an unrecognised resolution failure is ours, not the client's", recorder.Code)
	}
}

// Without the seeded anonymous row there is no subject an unauthenticated
// request can be. That is a broken deployment, and it says so rather than
// quietly denying.
func TestMissingAnonymousSubjectIsAServerError(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	guard := &server.Guard{Subjects: emptySubjects{}, Bindings: store}
	r := server.NewRouter(guard)
	r.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun}, noop)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}
	if recorder.Header().Get("WWW-Authenticate") != "" {
		t.Error("a broken deployment answered with a challenge, inviting the client to retry forever")
	}
}

// emptySubjects has lost its seeded anonymous row.
type emptySubjects struct{}

func (emptySubjects) GetSubject(context.Context, string) (meta.Subject, error) {
	return meta.Subject{}, meta.NotFound("subject", "anonymous")
}

// The subject resolves but the bindings cannot be read: the check has not
// decided anything, so it must not admit the request. This is the path a
// database outage takes.
func TestUnreadableBindingsFailClosed(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	guard := &server.Guard{
		Subjects: store,
		Bindings: &fakeBindings{listErr: errors.New("connection reset")},
	}
	r := server.NewRouter(guard)
	r.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun}, noop)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}
}

// The OCI routes answer with the distribution spec's envelope rather than
// problem+json (R-008), so the renderer is replaceable and the guard calls
// whichever one it was given.
func TestCustomErrorRenderer(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	spec := &recordingRenderer{}
	guard := &server.Guard{Subjects: store, Bindings: store, Errors: spec}
	r := server.NewRouter(guard)
	r.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun}, noop)

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil))

	if spec.unauthorized != 1 {
		t.Errorf("the guard called the default renderer instead of the one it was given")
	}
	if recorder.Body.String() != "UNAUTHORIZED" {
		t.Errorf("body = %q, want the custom renderer's", recorder.Body)
	}
}

// recordingRenderer stands in for the spec-shaped renderer R-008 supplies.
type recordingRenderer struct {
	unauthorized int
}

func (e *recordingRenderer) Unauthorized(w http.ResponseWriter, _ *http.Request, challenge string) {
	e.unauthorized++
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("UNAUTHORIZED"))
}

func (e *recordingRenderer) Forbidden(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusForbidden)
}

func (e *recordingRenderer) NotFound(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (e *recordingRenderer) TooManyRequests(w http.ResponseWriter, _ *http.Request, _ time.Duration) {
	w.WriteHeader(http.StatusTooManyRequests)
}

func (e *recordingRenderer) RotationRequired(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusForbidden)
}

func (e *recordingRenderer) BadRequest(w http.ResponseWriter, _ *http.Request, _ string) {
	w.WriteHeader(http.StatusBadRequest)
}

func (e *recordingRenderer) Internal(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
}
