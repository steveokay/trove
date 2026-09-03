package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// rotationCredentials is a header-based CredentialFunc, so the gate can be
// exercised for subjects that could never pass basic auth -- robots, and
// users with no password credential at all.
func rotationFixture(t *testing.T, rotation server.RotationStore, store *memory.Store) http.Handler {
	t.Helper()

	router := server.NewRouter(&server.Guard{
		Subjects: store,
		Bindings: store,
		Rotation: rotation,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	router.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun},
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	return router
}

func seedRotationSubjects(t *testing.T, store *memory.Store) {
	t.Helper()
	ctx := context.Background()

	for _, subject := range []meta.Subject{
		{ID: "u-fresh", Kind: meta.User, Name: "fresh"},
		{ID: "u-settled", Kind: meta.User, Name: "settled"},
		{ID: "u-tokenonly", Kind: meta.User, Name: "tokenonly"},
		{ID: "r-bot", Kind: meta.Robot, Name: "bot"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "runner", Verbs: []string{"gc:run"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	for i, name := range []string{"u-fresh", "u-settled", "u-tokenonly", "r-bot"} {
		if err := store.CreateBinding(ctx, meta.Binding{
			ID: "b" + string(rune('0'+i)), PrincipalKind: meta.PrincipalSubject, PrincipalID: name,
			Role: "runner", Scope: "system",
		}); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}
	for name, mustRotate := range map[string]bool{"fresh": true, "settled": false} {
		if err := store.PutUserCredential(ctx, meta.UserCredential{
			Subject: name, Hash: "$argon2id$placeholder", MustRotate: mustRotate,
		}); err != nil {
			t.Fatalf("PutUserCredential: %v", err)
		}
	}
}

// The gate: a user whose credential demands rotation is refused everywhere
// (except the rotation route, which the end-to-end test proves); everybody
// else passes untouched.
func TestMustRotateGate(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	seedRotationSubjects(t, store)
	handler := rotationFixture(t, store, store)

	tests := []struct {
		subject string
		want    int
	}{
		{"fresh", http.StatusForbidden},        // must rotate
		{"settled", http.StatusOK},             // rotated already
		{"tokenonly", http.StatusOK},           // no password credential: nothing to rotate
		{"bot", http.StatusOK},                 // robots have no passwords
		{"anonymous", http.StatusUnauthorized}, // unrelated to the gate; sanity
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil)
			if tt.subject != "anonymous" {
				req.Header.Set("X-Test-Subject", tt.subject)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tt.want, rec.Body)
			}
			if tt.want == http.StatusForbidden &&
				!strings.Contains(rec.Body.String(), server.ProblemRotationRequired) {
				t.Errorf("refusal %s does not say rotation is the reason", rec.Body)
			}
		})
	}
}

type brokenRotationStore struct{}

func (brokenRotationStore) GetUserCredential(context.Context, string) (meta.UserCredential, error) {
	return meta.UserCredential{}, errors.New("disk on fire")
}

// A gate that cannot be evaluated has not passed: same rule as an unreadable
// binding (Z-010).
func TestMustRotateGateFailsClosed(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	seedRotationSubjects(t, store)
	handler := rotationFixture(t, brokenRotationStore{}, store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil)
	req.Header.Set("X-Test-Subject", "settled")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// The whole Z-014 story on one real stack: bootstrap prints a password, that
// password opens nothing but the rotation door, rotating it opens everything,
// and the printed password is dead afterwards.
func TestBootstrapToRotatedEndToEnd(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	boot, err := authn.Bootstrap(ctx, store, authn.NewHasher(), clock)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !boot.AdminCreated {
		t.Fatal("no admin created on a fresh store")
	}

	limiter, err := authn.NewAttemptLimiter(authn.DefaultAccountLimit, authn.DefaultAddressLimit, clock)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	router := server.NewRouter(&server.Guard{
		Subjects:    store,
		Bindings:    store,
		Rotation:    store,
		Credentials: server.BasicAuth(login, nil),
	})
	explain := &server.AuthExplain{Subjects: store, Bindings: store}
	explain.Register(router)
	rotate := &server.AuthPassword{Login: login, Store: store, Hasher: authn.NewHasher(), Now: clock}
	rotate.Register(router)

	do := func(method, target, user, password, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.RemoteAddr = "203.0.113.9:40000"
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// The printed password authenticates, but reaches nothing except the
	// rotation endpoint -- not even the explainer.
	if rec := do(http.MethodGet, "/api/v1/auth/explain?verb=repo:read", "admin", boot.Password, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("explain before rotation: %d, want 403; body %s", rec.Code, rec.Body)
	}

	// Guardrails on the door itself.
	if rec := do(http.MethodPost, "/api/v1/auth/password", "admin", boot.Password,
		`{"current_password":"wrong","new_password":"correct horse battery"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotation with a wrong current password: %d, want 400", rec.Code)
	}
	if rec := do(http.MethodPost, "/api/v1/auth/password", "admin", boot.Password,
		`{"current_password":"`+boot.Password+`","new_password":"short"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotation to a short password: %d, want 400", rec.Code)
	}
	if rec := do(http.MethodPost, "/api/v1/auth/password", "admin", boot.Password,
		`{"current_password":"`+boot.Password+`","new_password":"`+boot.Password+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotation to the same password: %d, want 400", rec.Code)
	}
	if rec := do(http.MethodPost, "/api/v1/auth/password", "admin", boot.Password, `no json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotation with a malformed body: %d, want 400", rec.Code)
	}

	// A session opened under the old password, to be killed by the rotation.
	if err := store.CreateSession(ctx, meta.Session{
		ID: "old-session", Subject: "admin", CSRFToken: "t",
		CreatedAt: now, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// The rotation itself.
	if rec := do(http.MethodPost, "/api/v1/auth/password", "admin", boot.Password,
		`{"current_password":"`+boot.Password+`","new_password":"correct horse battery"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("rotation: %d, want 204; body %s", rec.Code, rec.Body)
	}

	// The old password is dead, the new one works, and the gate is open.
	if rec := do(http.MethodGet, "/api/v1/auth/explain?verb=repo:read", "admin", boot.Password, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password after rotation: %d, want 401", rec.Code)
	}
	rec := do(http.MethodGet, "/api/v1/auth/explain?verb=gc:run", "admin", "correct horse battery", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("explain after rotation: %d; body %s", rec.Code, rec.Body)
	}
	var explained struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &explained); err != nil || !explained.Allowed {
		t.Fatalf("admin gc:run after rotation = %s, want allowed", rec.Body)
	}

	// The old session died with the old password.
	if _, err := store.GetSession(ctx, "old-session", now); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetSession = %v, want the session gone after rotation", err)
	}

	// And the credential no longer demands rotation.
	cred, err := store.GetUserCredential(ctx, "admin")
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if cred.MustRotate {
		t.Error("MustRotate still set after rotation")
	}
	if !cred.RotatedAt.Equal(now) {
		t.Errorf("RotatedAt = %v, want the injected clock's %v", cred.RotatedAt, now)
	}
}

// rotationEndpoint builds the rotation route over a store with one user,
// "alice" / "sesame", optionally wrapping the password store.
func rotationEndpoint(t *testing.T, limiter *authn.AttemptLimiter, wrap func(*memory.Store) server.PasswordStore) (http.Handler, *memory.Store) {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CreateSubject(ctx, meta.Subject{ID: "u-alice", Kind: meta.User, Name: "alice"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	hash, err := authn.NewHasher().Hash("sesame")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.PutUserCredential(ctx, meta.UserCredential{Subject: "alice", Hash: hash}); err != nil {
		t.Fatalf("PutUserCredential: %v", err)
	}

	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}
	router := server.NewRouter(&server.Guard{
		Subjects: store,
		Bindings: store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	var passwords server.PasswordStore = store
	if wrap != nil {
		passwords = wrap(store)
	}
	rotate := &server.AuthPassword{
		Login: login, Store: passwords, Hasher: authn.NewHasher(), Errors: server.ProblemErrors{},
	}
	rotate.Register(router)
	return router, store
}

func rotateAs(handler http.Handler, subject, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", strings.NewReader(body))
	// Deliberately no port: the address normaliser must cope with both forms.
	req.RemoteAddr = "203.0.113.9"
	req.Header.Set("X-Test-Subject", subject)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// Proving you know the current password is an authentication attempt, so the
// limiter answers here exactly as it does at login: a stolen session must not
// be a free brute-force oracle against its own account.
func TestPasswordRotationIsRateLimited(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 2, Refill: 10 * time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 100, Refill: time.Second, MaxKeys: 16},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	handler, _ := rotationEndpoint(t, limiter, nil)

	body := `{"current_password":"wrong","new_password":"long enough"}`
	for i := 0; i < 2; i++ {
		if rec := rotateAs(handler, "alice", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: %d, want 400", i, rec.Code)
		}
	}
	rec := rotateAs(handler, "alice", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
}

type brokenPasswordStore struct {
	*memory.Store
	failPut      bool
	failSessions bool
}

func (b *brokenPasswordStore) PutUserCredential(ctx context.Context, cred meta.UserCredential) error {
	if b.failPut {
		return errors.New("disk on fire")
	}
	return b.Store.PutUserCredential(ctx, cred)
}

func (b *brokenPasswordStore) DeleteSubjectSessions(context.Context, string) (int, error) {
	return 0, errors.New("disk on fire")
}

func TestPasswordRotationStoreFailures(t *testing.T) {
	t.Parallel()

	body := `{"current_password":"sesame","new_password":"correct horse battery"}`

	t.Run("a verifier that cannot be written is a 500", func(t *testing.T) {
		t.Parallel()
		handler, _ := rotationEndpoint(t, nil, func(s *memory.Store) server.PasswordStore {
			return &brokenPasswordStore{Store: s, failPut: true}
		})
		if rec := rotateAs(handler, "alice", body); rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("a session sweep that fails does not unrotate the password", func(t *testing.T) {
		t.Parallel()
		handler, store := rotationEndpoint(t, nil, func(s *memory.Store) server.PasswordStore {
			return &brokenPasswordStore{Store: s, failSessions: true}
		})
		if rec := rotateAs(handler, "alice", body); rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204: the new password is already real", rec.Code)
		}
		cred, err := store.GetUserCredential(context.Background(), "alice")
		if err != nil {
			t.Fatalf("GetUserCredential: %v", err)
		}
		if err := authn.Verify(cred.Hash, "correct horse battery"); err != nil {
			t.Errorf("the new password does not verify: %v", err)
		}
	})

	t.Run("a corrupt stored hash is a 500, not a wrong password", func(t *testing.T) {
		t.Parallel()
		handler, store := rotationEndpoint(t, nil, nil)
		if err := store.PutUserCredential(context.Background(), meta.UserCredential{
			Subject: "alice", Hash: "garbage",
		}); err != nil {
			t.Fatalf("PutUserCredential: %v", err)
		}
		if rec := rotateAs(handler, "alice", body); rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
}

// Anonymous is self-admitted by the route's Self extractor and then refused:
// only users have passwords, and the refusal should say no rather than 500.
func TestPasswordRotationRefusesNonUsers(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}
	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
	rotate := &server.AuthPassword{Login: login, Store: store, Hasher: authn.NewHasher()}
	rotate.Register(router)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password",
		strings.NewReader(`{"current_password":"x","new_password":"long enough"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body)
	}
}
