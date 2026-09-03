package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authn/token"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// tokenStack is the full token flow on one router: /token, /v2/, and a
// guarded content-shaped route, all sharing one credential path (bearer over
// basic), one signer, and one store.
func tokenStack(t *testing.T) (http.Handler, *token.Signer, *memory.Store) {
	t.Helper()

	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })

	for _, subject := range []meta.Subject{
		{ID: "u-alice", Kind: meta.User, Name: "alice"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	hash, err := authn.NewHasher().Hash("sesame")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.PutUserCredential(ctx, meta.UserCredential{Subject: "alice", Hash: hash}); err != nil {
		t.Fatalf("PutUserCredential: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "developer", Verbs: []string{"repo:read", "repo:list"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	for _, binding := range []meta.Binding{
		{ID: "b-alice", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-alice", Role: "developer", Scope: "library/*"},
		{ID: "b-anon", PrincipalKind: meta.PrincipalSubject, PrincipalID: meta.AnonymousSubjectID, Role: "developer", Scope: "public/*"},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}

	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := token.NewSigner(key, 5*time.Minute, nil, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	challenge := server.TokenChallenge("")
	credentials := server.Bearer(signer, server.BasicAuth(login, nil))
	router := server.NewRouter(&server.Guard{
		Subjects:    store,
		Bindings:    store,
		Credentials: credentials,
		Challenge:   challenge,
	})
	(&server.TokenEndpoint{
		Credentials: credentials, Subjects: store, Bindings: store,
		Signer: signer, Challenge: challenge,
	}).Register(router)
	(&server.V2Root{
		Credentials: credentials, Subjects: store, Challenge: challenge,
	}).Register(router)
	// A stand-in for a pull route, guarded like Phase 3 will guard the real
	// ones, so bearer-authenticated authorization is proven now.
	router.HandleFunc(http.MethodGet, "/api/v1/repos/{name...}", server.Permission{
		Verb: authz.RepoRead,
		Resource: func(r *http.Request) (authz.Resource, error) {
			return authz.Repository(r.PathValue("name"))
		},
	}, func(w http.ResponseWriter, r *http.Request) {
		subject, _ := server.SubjectFrom(r.Context())
		_, _ = w.Write([]byte("read by " + subject.Name))
	})
	return router, signer, store
}

func mintFor(t *testing.T, handler http.Handler, user, password, scope string) tokenResponseBody {
	t.Helper()

	target := "/token?service=trove"
	if scope != "" {
		target += "&scope=" + scope
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token endpoint: %d %s", rec.Code, rec.Body)
	}
	var body tokenResponseBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response: %v (%s)", err, rec.Body)
	}
	return body
}

type tokenResponseBody struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

// The docker login sequence, request for request (ADR 0004): probe, 401 with
// a challenge naming the realm, token via basic auth, probe again with the
// bearer, 200.
func TestDockerLoginSequence(t *testing.T) {
	t.Parallel()

	handler, _, _ := tokenStack(t)

	probe := httptest.NewRecorder()
	handler.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if probe.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous probe: %d, want 401", probe.Code)
	}
	challenge := probe.Header().Get("WWW-Authenticate")
	want := `Bearer realm="http://example.com/token",service="trove"`
	if challenge != want {
		t.Fatalf("challenge = %q, want %q", challenge, want)
	}

	minted := mintFor(t, handler, "alice", "sesame", "")
	if minted.Token == "" || minted.Token != minted.AccessToken || minted.ExpiresIn != 300 {
		t.Fatalf("token response = %+v", minted)
	}

	again := httptest.NewRecorder()
	authed := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	authed.Header.Set("Authorization", "Bearer "+minted.Token)
	handler.ServeHTTP(again, authed)
	if again.Code != http.StatusOK {
		t.Fatalf("authenticated probe: %d %s, want 200", again.Code, again.Body)
	}
	if got := again.Header().Get("Docker-Distribution-Api-Version"); got != "registry/2.0" {
		t.Errorf("api version header = %q", got)
	}
}

// Mint-time narrowing (ADR 0004): request wide, receive exactly what the
// bindings grant, nothing for what they do not.
func TestTokenScopeNarrowing(t *testing.T) {
	t.Parallel()

	handler, signer, _ := tokenStack(t)

	minted := mintFor(t, handler, "alice", "sesame",
		"repository:library/nginx:pull,push&scope=repository:secret/repo:pull")
	claims, err := signer.Verify(minted.Token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "library/nginx" ||
		strings.Join(claims.Access[0].Actions, ",") != "pull" {
		t.Errorf("Access = %+v, want library/nginx pull only: push is not held and secret/repo grants nothing", claims.Access)
	}
}

// Anonymous minting is how public pulls bootstrap: no credentials, a real
// token, and only what anonymous bindings grant inside it.
func TestAnonymousTokenMinting(t *testing.T) {
	t.Parallel()

	handler, signer, _ := tokenStack(t)

	minted := mintFor(t, handler, "", "",
		"repository:public/nginx:pull,push&scope=repository:library/nginx:pull")
	claims, err := signer.Verify(minted.Token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "anonymous" {
		t.Errorf("Subject = %q, want anonymous", claims.Subject)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "public/nginx" ||
		strings.Join(claims.Access[0].Actions, ",") != "pull" {
		t.Errorf("Access = %+v, want public/nginx pull only", claims.Access)
	}
}

// The token names the subject; authorization stays live at the handler. A
// bearer request is decided against current bindings, so a granted scope in
// the token is never the authority (ADR 0004 §5).
func TestBearerRequestsAreReAuthorized(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	handler, _, store := tokenStack(t)
	minted := mintFor(t, handler, "alice", "sesame", "repository:library/nginx:pull")

	read := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/repos/library/nginx", nil)
		req.Header.Set("Authorization", "Bearer "+minted.Token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := read(); rec.Code != http.StatusOK || rec.Body.String() != "read by alice" {
		t.Fatalf("bearer read: %d %q", rec.Code, rec.Body)
	}

	// Revoke the binding: the very same token stops working on the next
	// request, not at its expiry.
	if err := store.DeleteBinding(ctx, "b-alice"); err != nil {
		t.Fatalf("DeleteBinding: %v", err)
	}
	if rec := read(); rec.Code == http.StatusOK {
		t.Fatal("a revoked binding kept working through an outstanding token")
	}
}

func TestTokenEndpointRefusals(t *testing.T) {
	t.Parallel()

	handler, _, _ := tokenStack(t)

	t.Run("bad credentials get 401 and the challenge", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		req.SetBasicAuth("alice", "wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("status = %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("an unknown service is refused", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/token?service=other-registry", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("a garbage bearer is 401, never anonymous", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

// A disabled subject holds a valid password but gets no token and no probe:
// disabling takes effect everywhere at once.
func TestDisabledSubjectsGetNothing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	handler, signer, store := tokenStack(t)

	// Minted while enabled; the subject is disabled afterwards, so the token
	// itself is still cryptographically valid.
	minted := mintFor(t, handler, "alice", "sesame", "")
	if err := store.SetSubjectDisabled(ctx, "alice", true); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}

	t.Run("the token endpoint refuses the password", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		req.SetBasicAuth("alice", "sesame")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("the probe refuses the outstanding token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
		req.Header.Set("Authorization", "Bearer "+minted.Token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401: a token must not outlive a disable", rec.Code)
		}
	})

	_ = signer
}

// The token endpoint is a login surface and is limited like one (ADR 0004).
func TestTokenEndpointIsRateLimited(t *testing.T) {
	t.Parallel()

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

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 2, Refill: 10 * time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 100, Refill: time.Second, MaxKeys: 16},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := token.NewSigner(key, 0, nil, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	router := server.NewRouter(&server.Guard{Subjects: store, Bindings: store})
	(&server.TokenEndpoint{
		Credentials: server.BasicAuth(login, nil), Subjects: store, Bindings: store, Signer: signer,
	}).Register(router)

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		req.RemoteAddr = "203.0.113.7:1000"
		req.SetBasicAuth("alice", "wrong")
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	req.RemoteAddr = "203.0.113.7:1000"
	req.SetBasicAuth("alice", "sesame")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d, Retry-After %q; want a truthful 429", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// A store that cannot answer produces a failure, never an empty token or a
// quiet anonymous probe.
func TestTokenFlowFailsClosedOnABrokenStore(t *testing.T) {
	t.Parallel()

	broken := &faultyStore{failBindings: "alice"}
	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
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
	broken.Store = store

	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := token.NewSigner(key, 0, nil, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	router := server.NewRouter(&server.Guard{Subjects: broken, Bindings: broken})
	(&server.TokenEndpoint{
		Credentials: server.BasicAuth(login, nil), Subjects: broken, Bindings: broken, Signer: signer,
	}).Register(router)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	req.SetBasicAuth("alice", "sesame")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: an unreadable binding set must not become an empty token", rec.Code)
	}
}

// The challenge realm follows the deployment: the configured external URL
// when there is one, the client's own Host and scheme when there is not.
func TestTokenChallenge(t *testing.T) {
	t.Parallel()

	plain := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	plain.Host = "registry.example:5000"
	viaTLS := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	viaTLS.Host = "registry.example"
	viaTLS.TLS = &tls.ConnectionState{}

	tests := []struct {
		name     string
		external string
		request  *http.Request
		want     string
	}{
		{"configured external URL wins", "https://registry.corp", plain,
			`Bearer realm="https://registry.corp/token",service="trove"`},
		{"derived from the host", "", plain,
			`Bearer realm="http://registry.example:5000/token",service="trove"`},
		{"derived scheme follows TLS", "", viaTLS,
			`Bearer realm="https://registry.example/token",service="trove"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := server.TokenChallenge(tt.external)(tt.request); got != tt.want {
				t.Errorf("challenge = %q, want %q", got, tt.want)
			}
		})
	}
}
