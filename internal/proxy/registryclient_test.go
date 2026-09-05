package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// testTime is the fixed clock every test runs on: nothing in the client reads
// the wall clock, and a test that needed it to would be a bug report.
var testTime = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return testTime }

// TestClientContract runs the content half of the contract against the fake
// upstream. The same suite runs against registry:2 in container_test.go, which
// is what makes this fake usable as the upstream for the tasks built on top of
// this client.
func TestClientContract(t *testing.T) {
	t.Parallel()

	clienttest.Run(t, func(t *testing.T, seed clienttest.Fixture) clienttest.Target {
		server := newUpstream(t, seed)
		recorder := &recordingTransport{}
		client := mustClient(t, proxy.Options{
			Upstream:  server.url(),
			Transport: recorder,
			Now:       fixedNow,
		})
		return clienttest.Target{
			Client:   client,
			Retag:    server.retag,
			Requests: recorder.snapshot,
		}
	})
}

// TestClientFaults runs the behaviour half: everything a real registry will not
// do on request.
func TestClientFaults(t *testing.T) {
	t.Parallel()

	clienttest.RunFaults(t, func(t *testing.T, seed clienttest.Fixture, fault clienttest.Fault) proxy.Client {
		options := proxy.Options{Now: fixedNow}
		switch fault {
		case clienttest.FaultUnreachable:
			options.Upstream = deadUpstream(t)
		case clienttest.FaultStalledHeaders:
			options.Upstream = newFaultyUpstream(t, seed, fault).url()
			options.RequestTimeout = 50 * time.Millisecond
		default:
			options.Upstream = newFaultyUpstream(t, seed, fault).url()
		}
		return mustClient(t, options)
	})
}

// mustClient builds a client or fails the test.
//
// Every client gets its own transport unless the test supplied one. That is
// not tidiness: the default is http.DefaultTransport, whose connection pool is
// process-global, so parallel tests would share it. One test's httptest server
// closing -- and freeing a port another server then binds -- can leave a
// pooled connection in that shared pool that a different test then reuses,
// which fails as "connection broken: CloseIdleConnections called" in whichever
// test happened to draw it. The failure lands somewhere unrelated to its
// cause, which is the worst shape a flake can take (CLAUDE.md section 9: a
// flaky test is fixed the day it flakes). Per-test pools make the outcome
// independent of what else is running.
func mustClient(t *testing.T, options proxy.Options) *proxy.RegistryClient {
	t.Helper()

	if options.Transport == nil {
		transport := &http.Transport{}
		t.Cleanup(transport.CloseIdleConnections)
		options.Transport = transport
	}
	client, err := proxy.New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// deadUpstream returns the URL of a server that has stopped listening, which
// is the cheapest deterministic "connection refused".
func deadUpstream(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	return url
}

func TestNewValidatesUpstream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		upstream string
	}{
		{"empty", ""},
		{"no scheme", "registry.example.com"},
		{"unsupported scheme", "ftp://registry.example.com"},
		{"no host", "https://"},
		{"credentials in the url", "https://user:pass@registry.example.com"},
		{"a path", "https://registry.example.com/v2/"},
		{"a query", "https://registry.example.com?insecure=1"},
		{"a fragment", "https://registry.example.com#frag"},
		{"unparseable", "https://registry.example.com:port:port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := proxy.New(proxy.Options{Upstream: tc.upstream}); !errors.Is(err, proxy.ErrInvalidReference) {
				t.Errorf("New(%q) = %v, want ErrInvalidReference", tc.upstream, err)
			}
		})
	}

	for _, upstream := range []string{"https://registry.example.com", "http://127.0.0.1:5000", "https://registry.example.com/"} {
		if _, err := proxy.New(proxy.Options{Upstream: upstream}); err != nil {
			t.Errorf("New(%q) = %v, want a client", upstream, err)
		}
	}
}

// --- virtual hosts ---
//
// httptest servers all live on 127.0.0.1, so host-family behaviour cannot be
// tested against them directly: every server looks like every other server.
// The virtual transport rewrites the destination address while leaving the URL
// and the Host header alone, which is what lets a test point a client at
// "registry.example.com" and watch what it does when that host redirects it to
// "cdn.example.net".

type virtualTransport struct {
	addr string

	mu   sync.Mutex
	sent []sentRequest
}

type sentRequest struct {
	host          string
	path          string
	authorization string
}

func (t *virtualTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.sent = append(t.sent, sentRequest{
		host:          req.URL.Host,
		path:          req.URL.Path,
		authorization: req.Header.Get("Authorization"),
	})
	t.mu.Unlock()

	routed := req.Clone(req.Context())
	routed.Host = req.URL.Host
	routed.URL.Host = t.addr
	routed.URL.Scheme = "http"
	return http.DefaultTransport.RoundTrip(routed)
}

func (t *virtualTransport) requests() []sentRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]sentRequest(nil), t.sent...)
}

// virtualServer starts a handler reachable under any hostname.
func virtualServer(t *testing.T, handler http.HandlerFunc) *virtualTransport {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &virtualTransport{addr: strings.TrimPrefix(server.URL, "http://")}
}

// TestCredentialsNeverLeaveTheUpstreamFamily is the disclosure case for
// upstream secrets: a registry that redirects a blob to its CDN must not be
// able to collect the operator's registry password by doing so.
func TestCredentialsNeverLeaveTheUpstreamFamily(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	transport := virtualServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "registry.example.com" && r.Header.Get("Authorization") == "":
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.Host == "registry.example.com":
			http.Redirect(w, r, "http://cdn.example.net"+r.URL.Path, http.StatusTemporaryRedirect)
		default:
			_, _ = w.Write(seed.Layer.Bytes)
		}
	})

	client := mustClient(t, proxy.Options{
		Upstream:    "http://registry.example.com",
		Transport:   transport,
		Now:         fixedNow,
		Credentials: proxy.StaticCredentials{Username: "robot", Password: "hunter2"},
		Redirects:   proxy.RedirectPolicy{TrustedHosts: []string{"cdn.example.net"}, AllowDowngrade: true},
	})

	reader, _, err := client.FetchBlob(context.Background(), seed.Repository, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer func() { _ = reader.Close() }()
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("read blob: %v", err)
	}

	var sawCDN bool
	for _, request := range transport.requests() {
		if request.host != "cdn.example.net" {
			continue
		}
		sawCDN = true
		if request.authorization != "" {
			t.Errorf("credential sent to %s: the CDN is trusted to serve bytes, not to hold a password", request.host)
		}
	}
	if !sawCDN {
		t.Fatal("the redirect to the trusted CDN was never followed")
	}
}

// TestTokenRealmIsCheckedAgainstThePolicy is the other half of that story: the
// realm in a challenge is a URL the upstream chose, and it is where the
// password would go.
func TestTokenRealmIsCheckedAgainstThePolicy(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	transport := virtualServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://evil.example.org/token",service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	})

	client := mustClient(t, proxy.Options{
		Upstream:    "http://registry.example.com",
		Transport:   transport,
		Now:         fixedNow,
		Credentials: proxy.StaticCredentials{Username: "robot", Password: "hunter2"},
	})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrRedirectRefused) {
		t.Fatalf("ResolveTag = %v, want ErrRedirectRefused for an untrusted realm", err)
	}
	for _, request := range transport.requests() {
		if request.host == "evil.example.org" {
			t.Error("the client contacted an untrusted authorization server")
		}
		if request.authorization != "" {
			t.Errorf("credential sent to %s before any challenge was accepted", request.host)
		}
	}
}

// TestTrustedRealmReceivesTheCredential proves the same policy does not break
// the upstream every operator actually uses, whose authorization server is on
// a different host by design.
func TestTrustedRealmReceivesTheCredential(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var tokenRequests int
	var mu sync.Mutex

	transport := virtualServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "auth.example.net" {
			mu.Lock()
			tokenRequests++
			mu.Unlock()
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"granted","expires_in":300}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer granted" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://auth.example.net/token",service="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		w.Header().Set("Docker-Content-Digest", seed.Manifest.Digest.String())
		_, _ = w.Write(seed.Manifest.Bytes)
	})

	client := mustClient(t, proxy.Options{
		Upstream:    "http://registry.example.com",
		Transport:   transport,
		Now:         fixedNow,
		Credentials: proxy.StaticCredentials{Username: "robot", Password: "hunter2"},
		Redirects:   proxy.RedirectPolicy{TrustedHosts: []string{"auth.example.net"}},
	})

	ctx := context.Background()
	for i := range 2 {
		resolution, err := client.ResolveTag(ctx, seed.Repository, seed.Tag, proxy.Conditional{})
		if err != nil {
			t.Fatalf("ResolveTag %d: %v", i, err)
		}
		if resolution.Digest != seed.Manifest.Digest {
			t.Errorf("Digest = %s, want %s", resolution.Digest, seed.Manifest.Digest)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if tokenRequests != 1 {
		t.Errorf("token endpoint hit %d times for two pulls: the token is cached per scope", tokenRequests)
	}
}

func TestRedirectToAPrivateAddressIsRefused(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	transport := virtualServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusTemporaryRedirect)
	})
	client := mustClient(t, proxy.Options{
		Upstream:  "http://registry.example.com",
		Transport: transport,
		Now:       fixedNow,
		// Even a wide-open trusted-host list must not open this door.
		Redirects: proxy.RedirectPolicy{TrustedHosts: []string{"*.example.com", "169.254.169.254"}, AllowDowngrade: true},
	})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrRedirectRefused) {
		t.Fatalf("ResolveTag = %v, want ErrRedirectRefused", err)
	}
	for _, request := range transport.requests() {
		if strings.Contains(request.host, "169.254") {
			t.Error("the client contacted the link-local metadata address")
		}
	}
}

func TestRedirectDowngradeIsRefused(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(seed.Manifest.Bytes)
	}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	client := mustClient(t, proxy.Options{
		Upstream:  secure.URL,
		Transport: secure.Client().Transport,
		Now:       fixedNow,
	})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrRedirectRefused) {
		t.Fatalf("ResolveTag = %v, want ErrRedirectRefused for an https -> http redirect", err)
	}
}

func TestRedirectWithinTheHostIsFollowed(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	blobs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(seed.Layer.Bytes)
	}))
	defer blobs.Close()

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, blobs.URL+"/object", http.StatusTemporaryRedirect)
	}))
	defer registry.Close()

	client := mustClient(t, proxy.Options{Upstream: registry.URL, Now: fixedNow})
	reader, _, err := client.FetchBlob(context.Background(), seed.Repository, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(seed.Layer.Bytes) {
		t.Errorf("read %d bytes, want %d", len(got), len(seed.Layer.Bytes))
	}
}

func TestUnusableLocationIsRefused(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := mustClient(t, proxy.Options{Upstream: server.URL, Now: fixedNow})
	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrRedirectRefused) {
		t.Fatalf("ResolveTag = %v, want ErrRedirectRefused", err)
	}
}

// --- status and content handling ---

// staticHandler answers everything the same way, which is all most of these
// cases need.
func staticServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func TestStatusMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"not found", http.StatusNotFound, proxy.ErrNotFound},
		{"gone", http.StatusGone, proxy.ErrNotFound},
		{"forbidden", http.StatusForbidden, proxy.ErrUnauthorized},
		{"server error", http.StatusInternalServerError, proxy.ErrUpstreamUnavailable},
		{"bad gateway", http.StatusBadGateway, proxy.ErrUpstreamUnavailable},
		{"a status nobody expected", http.StatusTeapot, proxy.ErrUpstreamUnavailable},
		{"bad request", http.StatusBadRequest, proxy.ErrUpstreamUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			seed := clienttest.DefaultFixture()
			upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			})
			client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

			_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
			if !errors.Is(err, tc.want) {
				t.Errorf("ResolveTag on %d = %v, want %v", tc.status, err, tc.want)
			}
			if _, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest); !errors.Is(err, tc.want) {
				t.Errorf("FetchManifest on %d = %v, want %v", tc.status, err, tc.want)
			}
			if _, _, err := client.FetchBlob(context.Background(), seed.Repository, seed.Layer.Digest); !errors.Is(err, tc.want) {
				t.Errorf("FetchBlob on %d = %v, want %v", tc.status, err, tc.want)
			}
		})
	}
}

func TestManifestTooLarge(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow, MaxManifestBytes: 8})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrManifestTooLarge) {
		t.Errorf("ResolveTag = %v, want ErrManifestTooLarge", err)
	}
	if _, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest); !errors.Is(err, proxy.ErrManifestTooLarge) {
		t.Errorf("FetchManifest = %v, want ErrManifestTooLarge", err)
	}
}

// TestRevalidationFallsBackToGet covers the upstreams and middleboxes that
// refuse HEAD: the tag must still resolve, and it must still resolve to
// "unchanged" when it has not moved.
func TestRevalidationFallsBackToGet(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var heads, gets int
	var mu sync.Mutex

	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Method == http.MethodHead {
			heads++
			mu.Unlock()
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		gets++
		mu.Unlock()
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	resolution, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Changed {
		t.Error("Changed = true for a tag that did not move")
	}
	if resolution.Manifest != nil {
		t.Error("an unchanged resolution returned a manifest body")
	}
	mu.Lock()
	defer mu.Unlock()
	if heads != 1 || gets != 1 {
		t.Errorf("heads = %d, gets = %d: want one refused HEAD and one GET", heads, gets)
	}
}

func TestRevalidationByETag(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

	cold, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if cold.ETag == "" {
		t.Fatal("the upstream sent an ETag and the resolution dropped it")
	}

	// Only the ETag is known, so the digest comparison cannot settle it: the
	// upstream's 304 has to.
	warm, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{ETag: cold.ETag})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if warm.Changed {
		t.Error("Changed = true after a 304")
	}
	if warm.ETag != cold.ETag {
		t.Errorf("ETag = %q, want it carried through the 304 as %q", warm.ETag, cold.ETag)
	}
}

func TestTagResolutionRejectsAMislabelledManifest(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		// The digest of some other content entirely.
		w.Header().Set("Docker-Content-Digest", seed.Next.Digest.String())
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrDigestMismatch) {
		t.Errorf("ResolveTag = %v, want ErrDigestMismatch", err)
	}
	if !errors.Is(err, blob.ErrDigestMismatch) {
		t.Error("the package sentinel and blob's are not the same error")
	}
}

func TestTagResolutionRejectsAnUnparseableDeclaredDigest(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		w.Header().Set("Docker-Content-Digest", "sha256:not-hex")
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("ResolveTag = %v, want ErrInvalidReference", err)
	}
}

// TestRevalidationIgnoresAnUnparseableHeadDigest is the same lie told on the
// cheap path: the HEAD cannot settle anything, so the GET decides, and the GET
// verifies.
func TestRevalidationIgnoresAnUnparseableHeadDigest(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		if r.Method == http.MethodHead {
			w.Header().Set("Docker-Content-Digest", "sha256:nonsense")
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	resolution, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Changed {
		t.Error("Changed = true for a tag that did not move")
	}
}

func TestMediaTypeParametersAreStripped(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", seed.Manifest.MediaType+"; charset=utf-8")
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, mediaType, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest)
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if mediaType != seed.Manifest.MediaType {
		t.Errorf("media type = %q, want %q", mediaType, seed.Manifest.MediaType)
	}
}

// --- authentication ---

func TestBasicChallengeIsAnsweredAndRemembered(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var challenges int
	var mu sync.Mutex

	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "robot" || password != "hunter2" {
			mu.Lock()
			challenges++
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{
		Upstream:    upstream,
		Now:         fixedNow,
		Credentials: proxy.StaticCredentials{Username: "robot", Password: "hunter2"},
	})

	for i := range 2 {
		if _, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest); err != nil {
			t.Fatalf("FetchManifest %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if challenges != 1 {
		t.Errorf("upstream had to challenge %d times: an upstream known to want Basic gets it up front", challenges)
	}
}

func TestUnauthorizedWithoutCredentials(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
	}
}

// failingCredentials is a credential source that cannot produce one, which is
// what a missing or unreadable keyfile looks like from here (ADR 0016).
type failingCredentials struct{ err error }

func (c failingCredentials) Basic(context.Context) (string, string, error) { return "", "", c.err }

func TestCredentialFailureIsNotADowngradeToAnonymous(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	sentinel := errors.New("keyfile unreadable")
	client := mustClient(t, proxy.Options{
		Upstream:    upstream,
		Now:         fixedNow,
		Credentials: failingCredentials{err: sentinel},
	})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("the underlying credential failure was swallowed: %v", err)
	}
}

func TestAuthenticationIsNotRetriedTwice(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var attempts, tokens int
	var mu sync.Mutex

	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokens++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"stale","expires_in":300}`)
			return
		}
		attempts++
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	// The realm above is host-relative, so it resolves against the upstream.
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Fatalf("ResolveTag = %v, want ErrUnauthorized", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts > 2 {
		t.Errorf("the client made %d authenticated attempts: a 401 is answered once, not retried in a loop", attempts)
	}
}

func TestTokenEndpointOutageIsNotAnAuthFailure(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("ResolveTag = %v, want ErrUpstreamUnavailable", err)
	}
	if errors.Is(err, proxy.ErrUnauthorized) {
		t.Error("an unreachable token endpoint was reported as an authentication failure")
	}
}

func TestTokenEndpointGarbage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{"not json", "<html>login</html>"},
		{"no token", `{"expires_in":300}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			seed := clienttest.DefaultFixture()
			upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/token") {
					_, _ = io.WriteString(w, tc.body)
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
				w.WriteHeader(http.StatusUnauthorized)
			})
			client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

			_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
			if !errors.Is(err, proxy.ErrUnauthorized) {
				t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestBearerChallengeWithoutARealm(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer service="registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
	}
}

func TestUnauthorizedWithoutAChallenge(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	if !errors.Is(err, proxy.ErrUnauthorized) {
		t.Errorf("ResolveTag = %v, want ErrUnauthorized", err)
	}
}

func TestExpiredTokenIsRefetched(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var tokens int
	var mu sync.Mutex
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			mu.Lock()
			tokens++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"granted","expires_in":30}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer granted" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})

	// The clock is the only thing that moves: a token minted with a 30 second
	// life is not reused an hour later.
	clock := testTime
	client := mustClient(t, proxy.Options{
		Upstream: upstream,
		Now:      func() time.Time { return clock },
	})

	ctx := context.Background()
	if _, _, err := client.FetchManifest(ctx, seed.Repository, seed.Manifest.Digest); err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	clock = clock.Add(time.Hour)
	if _, _, err := client.FetchManifest(ctx, seed.Repository, seed.Manifest.Digest); err != nil {
		t.Fatalf("FetchManifest after expiry: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if tokens != 2 {
		t.Errorf("token endpoint hit %d times, want 2: an expired token must not be reused", tokens)
	}
}

// --- rate limits ---

func TestRetryAfterAsAnHTTPDate(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", testTime.Add(90*time.Second).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusTooManyRequests)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	_, err := client.ResolveTag(context.Background(), seed.Repository, seed.Tag, proxy.Conditional{})
	var limited *proxy.RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("ResolveTag = %v, want a *proxy.RateLimitedError", err)
	}
	if limited.RetryAfter != 90*time.Second {
		t.Errorf("RetryAfter = %s, want 90s computed against the injected clock", limited.RetryAfter)
	}
	if got := client.RateLimit().Until; !got.Equal(testTime.Add(90 * time.Second)) {
		t.Errorf("Until = %s, want %s", got, testTime.Add(90*time.Second))
	}
}

func TestRateLimitStateSurvivesAcrossRequests(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	var first bool
	var mu sync.Mutex
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		initial := !first
		first = true
		mu.Unlock()

		if initial {
			w.Header().Set("RateLimit-Limit", "100;w=21600")
			w.Header().Set("RateLimit-Remaining", "42;w=21600")
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	ctx := context.Background()
	for i := range 2 {
		if _, _, err := client.FetchManifest(ctx, seed.Repository, seed.Manifest.Digest); err != nil {
			t.Fatalf("FetchManifest %d: %v", i, err)
		}
	}

	state := client.RateLimit()
	if !state.Known || state.Remaining != 42 || state.Limit != 100 || state.Window != 6*time.Hour {
		t.Errorf("RateLimit() = %+v, want the headroom the upstream last reported", state)
	}
}

// --- streaming and cancellation ---

func TestFetchBlobStreamEndsWithTheCallersContext(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	release := make(chan struct{})
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(seed.Layer.Bytes)))
		_, _ = w.Write(seed.Layer.Bytes[:16])
		w.(http.Flusher).Flush()
		<-release
	})
	defer close(release)

	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})
	ctx, cancel := context.WithCancel(context.Background())

	reader, _, err := client.FetchBlob(ctx, seed.Repository, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer func() { _ = reader.Close() }()

	buffer := make([]byte, 8)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatalf("first read: %v", err)
	}
	// The header phase is long over, so nothing but the caller's own context
	// can end this stream. That is the seam C-004 owns.
	cancel()
	if _, err := io.ReadAll(reader); err == nil {
		t.Error("the stream survived the caller cancelling its context")
	}
}

func TestFetchBlobRejectsAnUnusableDigest(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	server := newUpstream(t, seed)
	client := mustClient(t, proxy.Options{Upstream: server.url(), Now: fixedNow})

	for _, digest := range []blob.Digest{"", "sha256:short", "md5:00000000000000000000000000000000"} {
		if _, _, err := client.FetchBlob(context.Background(), seed.Repository, digest); !errors.Is(err, proxy.ErrInvalidReference) {
			t.Errorf("FetchBlob(%q) = %v, want ErrInvalidReference", digest, err)
		}
	}
	if _, _, err := client.FetchBlob(context.Background(), "Bad Name", seed.Layer.Digest); !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("FetchBlob with an illegal repository = %v, want ErrInvalidReference", err)
	}
	if _, _, err := client.FetchManifest(context.Background(), "Bad Name", seed.Manifest.Digest); !errors.Is(err, proxy.ErrInvalidReference) {
		t.Errorf("FetchManifest with an illegal repository = %v, want ErrInvalidReference", err)
	}
}

func TestUserAgentIsSent(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	seen := make(chan string, 1)
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("User-Agent"):
		default:
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow, UserAgent: "trove/test"})

	if _, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest); err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if got := <-seen; got != "trove/test" {
		t.Errorf("User-Agent = %q, want %q", got, "trove/test")
	}
}

func TestAcceptOffersEveryManifestTypeTroveStores(t *testing.T) {
	t.Parallel()

	seed := clienttest.DefaultFixture()
	seen := make(chan string, 1)
	upstream := staticServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get("Accept"):
		default:
		}
		w.Header().Set("Content-Type", seed.Manifest.MediaType)
		_, _ = w.Write(seed.Manifest.Bytes)
	})
	client := mustClient(t, proxy.Options{Upstream: upstream, Now: fixedNow})

	if _, _, err := client.FetchManifest(context.Background(), seed.Repository, seed.Manifest.Digest); err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	accept := <-seen
	for _, mediaType := range []string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	} {
		if !strings.Contains(accept, mediaType) {
			t.Errorf("Accept %q does not offer %s", accept, mediaType)
		}
	}
}
