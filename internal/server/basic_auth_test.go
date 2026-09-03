package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/secretbox"
	"github.com/steveokay/trove/internal/server"
)

// basicAuthFixture is a guarded route reachable only by alice (password
// "sesame"), served behind real basic auth with a tight, clock-injected
// limiter.
func basicAuthFixture(t *testing.T, now *time.Time) http.Handler {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	for _, subject := range []meta.Subject{
		{ID: "u-alice", Kind: meta.User, Name: "alice"},
		{ID: "u-dan", Kind: meta.User, Name: "dan"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	hash, err := authn.NewHasher().Hash("sesame")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	for _, name := range []string{"alice", "dan"} {
		if err := store.PutUserCredential(ctx, meta.UserCredential{Subject: name, Hash: hash}); err != nil {
			t.Fatalf("PutUserCredential: %v", err)
		}
	}
	if err := store.SetSubjectDisabled(ctx, "dan", true); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "runner", Verbs: []string{"gc:run"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "b-alice", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-alice",
		Role: "runner", Scope: "system",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 3, Refill: 10 * time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 100, Refill: time.Second, MaxKeys: 16},
		func() time.Time { return *now },
	)
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
		Credentials: server.BasicAuth(login, nil),
	})
	router.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun},
		func(w http.ResponseWriter, r *http.Request) {
			subject, _ := server.SubjectFrom(r.Context())
			_, _ = w.Write([]byte("ran as " + subject.Name))
		})
	return router
}

func basicRequest(handler http.Handler, user, password string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/gc", nil)
	req.RemoteAddr = "203.0.113.7:51823"
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestBasicAuth(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	t.Run("correct credentials reach the handler as the subject", func(t *testing.T) {
		t.Parallel()
		clock := now
		handler := basicAuthFixture(t, &clock)
		rec := basicRequest(handler, "alice", "sesame")
		if rec.Code != http.StatusOK || rec.Body.String() != "ran as alice" {
			t.Fatalf("status %d, body %q", rec.Code, rec.Body)
		}
	})

	t.Run("no credentials is anonymous, not an error", func(t *testing.T) {
		t.Parallel()
		clock := now
		handler := basicAuthFixture(t, &clock)
		rec := basicRequest(handler, "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for anonymous without the verb", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Error("401 without a challenge")
		}
	})

	t.Run("wrong password and unknown user are the same 401", func(t *testing.T) {
		t.Parallel()
		clock := now
		handler := basicAuthFixture(t, &clock)
		wrong := basicRequest(handler, "alice", "open barley")
		ghost := basicRequest(handler, "nobody", "sesame")
		if wrong.Code != http.StatusUnauthorized || ghost.Code != http.StatusUnauthorized {
			t.Fatalf("codes = %d, %d, want 401 for both", wrong.Code, ghost.Code)
		}
		if wrong.Body.String() != ghost.Body.String() {
			t.Error("wrong-password and unknown-user answers differ: an enumeration oracle")
		}
	})

	t.Run("a disabled subject's correct password is still refused", func(t *testing.T) {
		t.Parallel()
		clock := now
		handler := basicAuthFixture(t, &clock)
		rec := basicRequest(handler, "dan", "sesame")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("robot secrets authenticate through the same guard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		store := memory.New()
		t.Cleanup(func() { _ = store.Close() })
		if err := store.CreateSubject(ctx, meta.Subject{ID: "r-ci", Kind: meta.Robot, Name: "robot$ci"}); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
		if err := store.CreateRole(ctx, meta.Role{Name: "runner", Verbs: []string{"gc:run"}}); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if err := store.CreateBinding(ctx, meta.Binding{
			ID: "b-ci", PrincipalKind: meta.PrincipalSubject, PrincipalID: "r-ci",
			Role: "runner", Scope: "system",
		}); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}

		key, err := secretbox.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ring, err := secretbox.NewKeyring(key)
		if err != nil {
			t.Fatalf("NewKeyring: %v", err)
		}
		robots := authn.NewRobotSecrets(store, ring, nil, nil)
		secret, err := robots.Mint(ctx, "robot$ci", time.Time{})
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
		if err != nil {
			t.Fatalf("NewPasswordLogin: %v", err)
		}

		router := server.NewRouter(&server.Guard{
			Subjects:    store,
			Bindings:    store,
			Credentials: server.BasicAuth(login, robots),
		})
		router.HandleFunc(http.MethodGet, "/api/v1/system/gc", server.Permission{Verb: authz.GCRun},
			func(w http.ResponseWriter, r *http.Request) {
				subject, _ := server.SubjectFrom(r.Context())
				_, _ = w.Write([]byte("ran as " + subject.Name))
			})

		if rec := basicRequest(router, "robot$ci", secret); rec.Code != http.StatusOK ||
			rec.Body.String() != "ran as robot$ci" {
			t.Fatalf("robot login: %d %q", rec.Code, rec.Body)
		}
		if rec := basicRequest(router, "robot$ci", "trove_r_r-ci_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong robot secret: %d, want 401", rec.Code)
		}
	})

	t.Run("the limiter answers 429 with a truthful Retry-After", func(t *testing.T) {
		t.Parallel()
		clock := now
		handler := basicAuthFixture(t, &clock)
		for i := 0; i < 3; i++ {
			basicRequest(handler, "alice", "wrong")
		}

		rec := basicRequest(handler, "alice", "sesame")
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", rec.Code)
		}
		retry := rec.Header().Get("Retry-After")
		if retry == "" {
			t.Fatal("429 without Retry-After")
		}

		// Waiting the stated time makes the same request succeed: the header
		// is a promise, and this is the test that keeps it one.
		seconds, err := time.ParseDuration(retry + "s")
		if err != nil {
			t.Fatalf("Retry-After %q is not seconds: %v", retry, err)
		}
		clock = clock.Add(seconds)
		if rec := basicRequest(handler, "alice", "sesame"); rec.Code != http.StatusOK {
			t.Fatalf("status after waiting = %d, want 200", rec.Code)
		}
	})
}
