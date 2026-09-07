// Package proxyadv is the proxy subsystem's adversarial suite (C-015): the
// cases where an upstream is not merely unavailable but actively wrong.
//
// It is a living suite. Every §9 proxy bullet has a subtest here, and the
// ratchet in suite_test.go fails if one loses its coverage. What it drives is
// the *composed* pipeline -- a real client over a real filler over a real
// metadata and blob store -- because each of these failures is handled by one
// layer and has to survive the ones above it: a digest mismatch is caught in
// the client, and what matters is that nothing is cached, nothing is served,
// and the operator hears about it.
//
// The upstream here is deliberately hostile. The contract suite
// (internal/proxy/clienttest) already proves the fake behaves like registry:2
// when it behaves at all; this one is about what happens when it does not.
package proxyadv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmemory "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

const (
	// entity is the proxy repository every scenario pulls through.
	entity = "hub"

	// upstreamHost is the name the client is configured with. It is a name
	// rather than 127.0.0.1 on purpose: the redirect policy refuses private
	// addresses before it considers anything else, so a test that used
	// loopback for the upstream could not tell "refused because untrusted"
	// from "refused because private" -- and those are different rules that
	// fail differently.
	upstreamHost = "registry.example"

	// cdnHost and evilHost are the two off-upstream hosts a redirect can point
	// at: one an operator trusted, one nobody did.
	cdnHost  = "cdn.example"
	evilHost = "cdn.evil"
)

// testTime is the instant every scenario starts at. The clock is injected
// everywhere (§7), so a TTL expiring is a value a test chose.
var testTime = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

// hostile is a distribution-API upstream that serves the fixture correctly
// until a scenario tells it not to.
//
// The interceptor is one hook rather than a knob per fault: every scenario
// here is "what if the upstream did *this*", and a hook lets each one say so
// in its own terms instead of adding a flag to a growing enum.
type hostile struct {
	seed clienttest.Fixture

	mu        sync.Mutex
	requests  []string
	intercept func(w http.ResponseWriter, r *http.Request) bool
	tags      map[string]clienttest.Content
	manifests map[blob.Digest]clienttest.Content
	blobs     map[blob.Digest]clienttest.Content

	server *httptest.Server
}

// newHostile starts an upstream seeded with the contract fixture, behaving
// correctly until a scenario intercepts.
func newHostile(t *testing.T) *hostile {
	t.Helper()

	seed := clienttest.DefaultFixture()
	h := &hostile{
		seed:      seed,
		tags:      map[string]clienttest.Content{seed.Tag: seed.Manifest},
		manifests: map[blob.Digest]clienttest.Content{},
		blobs:     map[blob.Digest]clienttest.Content{},
	}
	for _, manifest := range []clienttest.Content{seed.Manifest, seed.Next} {
		h.manifests[manifest.Digest] = manifest
	}
	for _, content := range seed.Blobs {
		h.blobs[content.Digest] = content
	}

	h.server = httptest.NewServer(h)
	t.Cleanup(h.server.Close)
	return h
}

// on installs the interceptor. It returns true when it has answered the
// request; returning false falls through to the well-behaved handler.
func (h *hostile) on(fn func(w http.ResponseWriter, r *http.Request) bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.intercept = fn
}

// forget removes a blob from the upstream, for the manifest-references-a-
// missing-layer case.
func (h *hostile) forget(digest blob.Digest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.blobs, digest)
}

// publish adds content the upstream will serve.
func (h *hostile) publish(c clienttest.Content) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.manifests[c.Digest] = c
}

// hostPort is where the server actually listens, for the host router.
func (h *hostile) hostPort() string {
	return strings.TrimPrefix(h.server.URL, "http://")
}

// paths returns every request path the upstream has seen, in order. What does
// *not* reach the wire is half of what this suite asserts.
func (h *hostile) paths() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.requests...)
}

func (h *hostile) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests = append(h.requests, r.Method+" "+r.URL.Path)
	intercept := h.intercept
	h.mu.Unlock()

	if intercept != nil && intercept(w, r) {
		return
	}

	switch {
	case r.URL.Path == "/v2/", r.URL.Path == "/v2":
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		_, _ = w.Write([]byte("{}"))
	case strings.Contains(r.URL.Path, "/manifests/"):
		h.serveManifest(w, r)
	case strings.Contains(r.URL.Path, "/blobs/"):
		h.serveBlob(w, r)
	default:
		writeAPIError(w, http.StatusNotFound, "NAME_UNKNOWN", "no such path")
	}
}

func (h *hostile) serveManifest(w http.ResponseWriter, r *http.Request) {
	reference := r.URL.Path[strings.LastIndex(r.URL.Path, "/manifests/")+len("/manifests/"):]

	h.mu.Lock()
	content, ok := h.tags[reference]
	if !ok {
		content, ok = h.manifests[blob.Digest(reference)]
	}
	h.mu.Unlock()

	if !ok {
		writeAPIError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "no such manifest")
		return
	}
	writeManifest(w, r, content)
}

func (h *hostile) serveBlob(w http.ResponseWriter, r *http.Request) {
	digest := blob.Digest(r.URL.Path[strings.LastIndex(r.URL.Path, "/blobs/")+len("/blobs/"):])

	h.mu.Lock()
	content, ok := h.blobs[digest]
	h.mu.Unlock()

	if !ok {
		writeAPIError(w, http.StatusNotFound, "BLOB_UNKNOWN", "no such blob")
		return
	}
	w.Header().Set("Content-Type", content.MediaType)
	w.Header().Set("Docker-Content-Digest", content.Digest.String())
	w.Header().Set("Content-Length", strconv.Itoa(len(content.Bytes)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(content.Bytes)
}

// writeManifest answers with a manifest, headers and all.
func writeManifest(w http.ResponseWriter, r *http.Request, content clienttest.Content) {
	w.Header().Set("Content-Type", content.MediaType)
	w.Header().Set("Docker-Content-Digest", content.Digest.String())
	w.Header().Set("Content-Length", strconv.Itoa(len(content.Bytes)))
	w.Header().Set("ETag", `"`+content.Digest.String()+`"`)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(content.Bytes)
}

// writeAPIError answers in the spec's error envelope, because a client that
// only works against a fake speaking its own dialect proves nothing.
func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
}

// hostRouter dials named hosts to whatever local server a scenario mapped them
// to.
//
// It exists so the redirect rules can be told apart. Every httptest server
// listens on loopback, and the policy refuses a private address before it
// consults the trusted-host list at all -- so without a mapping, "refused
// because the host is not trusted" and "refused because it is loopback" would
// be indistinguishable, and a bug in either rule would pass as the other.
//
// An unmapped host is dialled for real, which is what makes the SSRF case
// honest: the loopback listener it points at is a genuine socket, and a policy
// that followed the redirect would leave a request on it.
type hostRouter struct {
	mu     sync.Mutex
	routes map[string]string
	base   http.RoundTripper
}

func newHostRouter() *hostRouter {
	return &hostRouter{routes: map[string]string{}, base: http.DefaultTransport}
}

func (h *hostRouter) route(name, hostPort string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.routes[name] = hostPort
}

func (h *hostRouter) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	target, ok := h.routes[r.URL.Hostname()]
	h.mu.Unlock()
	if !ok {
		return h.base.RoundTrip(r)
	}

	clone := r.Clone(r.Context())
	clone.URL.Host = target
	// The Host header keeps the name the client meant to talk to, so the
	// upstream sees what a real deployment would send.
	clone.Host = r.URL.Host
	return h.base.RoundTrip(clone)
}

// env is one scenario's world: a hostile upstream, a cache, and the filler
// that sits between them.
type env struct {
	t      *testing.T
	up     *hostile
	router *hostRouter
	meta   *metamemory.Store
	blobs  *blobmemory.Store
	events *recorder
	filler *proxy.Filler
	target proxy.Target
	clock  *clock
}

// options tweaks what a scenario needs different.
type options struct {
	// redirects is the client's SSRF posture.
	redirects proxy.RedirectPolicy
	// offline is the degraded-mode behaviour.
	offline proxy.OfflineMode
	// tagTTL is how long a lease may be reused. Zero revalidates every pull.
	tagTTL time.Duration
	// upstreamRepository overrides the upstream path, for the traversal cases.
	upstreamRepository string
	// credentials, when set, are attached to the client -- the realm cases
	// need something worth exfiltrating.
	credentials proxy.Credentials
}

// newEnv wires a client, a filler, and a cache against the upstream.
func newEnv(t *testing.T, up *hostile, opts options) *env {
	t.Helper()

	router := newHostRouter()
	router.route(upstreamHost, up.hostPort())

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: entity, Type: meta.Proxy, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	clk := &clock{now: testTime}
	client, err := proxy.New(proxy.Options{
		Upstream:    "http://" + upstreamHost,
		Credentials: opts.credentials,
		Redirects:   opts.redirects,
		Transport:   router,
		Now:         clk.Now,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	blobs := blobmemory.New(blobmemory.Options{})
	events := &recorder{}
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: blobs, Meta: store, Events: events, Now: clk.Now, Log: quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewFiller: %v", err)
	}

	upstreamRepository := up.seed.Repository
	if opts.upstreamRepository != "" {
		upstreamRepository = opts.upstreamRepository
	}

	return &env{
		t: t, up: up, router: router, meta: store, blobs: blobs,
		events: events, filler: filler, clock: clk,
		target: proxy.Target{
			Repository: entity + "/" + up.seed.Repository,
			Upstream:   upstreamRepository,
			Remote:     upstreamHost,
			Client:     client,
			TagTTL:     opts.tagTTL,
			Offline:    opts.offline,
		},
	}
}

// cached reports whether the cache holds a manifest.
func (e *env) cachedManifest(digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.meta.GetCachedManifest(context.Background(), e.target.Repository, meta.Digest(digest))
	return err == nil
}

// cachedBlobRow reports whether the cache claims a blob.
func (e *env) cachedBlobRow(digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.meta.GetCachedBlob(context.Background(), e.target.Repository, meta.Digest(digest))
	return err == nil
}

// storedBytes reports whether the cache blob store holds the bytes.
func (e *env) storedBytes(digest blob.Digest) bool {
	e.t.Helper()

	_, err := e.blobs.Stat(context.Background(), digest)
	return err == nil
}

// nothingCached asserts the whole cache is empty, which is what every "the
// upstream lied" case must leave behind.
func (e *env) nothingCached(digest blob.Digest) {
	e.t.Helper()

	if e.cachedManifest(digest) {
		t := e.t
		t.Errorf("a manifest the upstream got wrong was cached: %s", digest)
	}
	if e.cachedBlobRow(digest) {
		e.t.Errorf("a blob row was written for content that never verified: %s", digest)
	}
	if e.storedBytes(digest) {
		e.t.Errorf("bytes that never verified reached the cache store: %s", digest)
	}
}

// pullBlob reads a blob through the filler to completion and returns whatever
// went wrong -- opening it or streaming it, since verification fails mid-body.
func (e *env) pullBlob(digest blob.Digest) error {
	e.t.Helper()

	result, err := e.filler.Blob(context.Background(), e.target, digest)
	if err != nil {
		return err
	}
	defer func() { _ = result.Content.Close() }()

	_, err = io.Copy(io.Discard, result.Content)
	return err
}

// clock is the injected time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recorder collects published events.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Publish(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// ofType returns the payloads published under one event type.
func (r *recorder) ofType(want event.Type) []event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []event.Event
	for _, e := range r.events {
		if e.Type == want {
			out = append(out, e)
		}
	}
	return out
}

// listener is a socket nothing may reach: the SSRF cases point a redirect or a
// realm at it and assert it stayed silent.
//
// It is a real listener rather than a closed port because a refused connection
// and a policy refusal are different outcomes, and only one of them proves the
// policy did the refusing.
type listener struct {
	server *httptest.Server

	mu   sync.Mutex
	seen []string
}

func newListener(t *testing.T) *listener {
	t.Helper()

	l := &listener{}
	l.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.seen = append(l.seen, r.Method+" "+r.URL.Path)
		l.mu.Unlock()
		_, _ = w.Write([]byte(`{"token":"stolen"}`))
	}))
	t.Cleanup(l.server.Close)
	return l
}

// url is the loopback address the private-address cases point at.
func (l *listener) url() string { return l.server.URL }

// requests reports what reached it. Anything at all is a failure.
func (l *listener) requests() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

func (l *listener) mustBeUntouched(t *testing.T, what string) {
	t.Helper()

	if got := l.requests(); len(got) > 0 {
		t.Fatalf("%s: %d request(s) reached an address that must never be dialled: %v", what, len(got), got)
	}
}

// quietLogger keeps the filler's degraded-path logging out of the output. The
// behaviour is asserted through results and events, which is where a caller
// sees it.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// corrupt returns content whose bytes do not hash to its digest: the upstream
// claiming one thing and serving another.
func corrupt(c clienttest.Content) clienttest.Content {
	return clienttest.Content{
		Bytes:     append([]byte("tampered "), c.Bytes...),
		MediaType: c.MediaType,
		Digest:    c.Digest,
	}
}

// freePort returns a loopback address with nothing listening on it.
func freePort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("closing the reserved port: %v", err)
	}
	return addr
}

// redirectTo answers with a 307 to the given URL, which is how every hostile
// redirect in this suite is built.
func redirectTo(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

// challengeFor builds a Bearer challenge pointing at a realm.
func challengeFor(realm string) string {
	return fmt.Sprintf(`Bearer realm=%q,service="registry.example",scope="repository:x:pull"`, realm)
}
