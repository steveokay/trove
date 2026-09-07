package proxyadv_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
	"github.com/steveokay/trove/internal/proxyserve"
	"github.com/steveokay/trove/internal/repo"
)

// scenario is one adversarial case: an id the ratchet knows, the requirement
// it discharges, and the test.
//
// The requirement text is written out rather than referenced by number so that
// a reader of a failure knows what was being defended without opening
// CLAUDE.md, and so that a case whose meaning drifts is visible in review.
type scenario struct {
	id          string
	requirement string
	run         func(t *testing.T)
}

// scenarios is the suite. It is a table rather than a file of Test functions
// because the ratchet below has to enumerate it: a bullet losing its coverage
// must fail a test, not merely stop being run.
var scenarios = []scenario{
	{
		id:          "manifest-digest-mismatch",
		requirement: "upstream returning a manifest whose digest does not match what was requested",
		run:         testManifestDigestMismatch,
	},
	{
		id:          "blob-digest-mismatch",
		requirement: "digest mismatch on a streamed blob",
		run:         testBlobDigestMismatch,
	},
	{
		id:          "truncated-blob",
		requirement: "truncated blob",
		run:         testTruncatedBlob,
	},
	{
		id:          "manifest-missing-layer",
		requirement: "manifest referencing a missing layer",
		run:         testManifestReferencingAMissingLayer,
	},
	{
		id:          "malformed-manifest",
		requirement: "malformed manifests are treated as an unavailable upstream",
		run:         testMalformedManifest,
	},
	{
		id:          "redirect-loop",
		requirement: "redirect loop, capped",
		run:         testRedirectLoop,
	},
	{
		id:          "redirect-private-address",
		requirement: "redirect to a private address (SSRF) must be refused",
		run:         testRedirectToAPrivateAddress,
	},
	{
		id:          "redirect-untrusted-host",
		requirement: "redirect off the upstream's family is refused unless trusted",
		run:         testRedirectOffTheUpstreamFamily,
	},
	{
		id:          "auth-realm-private-address",
		requirement: "a WWW-Authenticate realm is an SSRF and credential-exfiltration surface",
		run:         testAuthRealmPointingAtAPrivateAddress,
	},
	{
		id:          "rate-limit-storm",
		requirement: "429 storm: back off rather than hammer, and stop calling the upstream",
		run:         testRateLimitStorm,
	},
	{
		id:          "traversal-upstream-mapping",
		requirement: "path traversal in upstream mappings",
		run:         testTraversalViaTheUpstreamMapping,
	},
	{
		id:          "traversal-remainder-rewrite",
		requirement: "path traversal through the namespace rewrite of a remainder",
		run:         testTraversalViaTheNamespaceRewrite,
	},
	{
		id:          "single-flight-under-load",
		requirement: "concurrent revalidation of one tag (single-flight)",
		run:         testSingleFlightUnderLoad,
	},
	{
		id:          "stale-tag-serve-stale",
		requirement: "stale tag past TTL, serve-stale mode",
		run:         testStaleTagPastTTLServesStale,
	},
	{
		id:          "stale-tag-strict",
		requirement: "stale tag past TTL, strict mode",
		run:         testStaleTagPastTTLStrictFails,
	},
	{
		id:          "unreachable-upstream",
		requirement: "upstream unreachable",
		run:         testUnreachableUpstream,
	},
	{
		id:          "group-member-leakage",
		requirement: "no group behaviour may depend on a member the subject cannot see",
		run:         testGroupBehaviourDoesNotLeakAMember,
	},
}

// TestProxyAdversarial runs the suite.
func TestProxyAdversarial(t *testing.T) {
	t.Parallel()

	for _, sc := range scenarios {
		t.Run(sc.id, func(t *testing.T) {
			t.Parallel()
			sc.run(t)
		})
	}
}

// requiredScenarios is the ratchet: every §9 proxy bullet and every case the
// C-015 plan names has an id here, and the suite fails if one of them stops
// existing.
//
// It is a separate list from the table on purpose. Deleting a scenario is then
// two edits -- the case and its requirement -- and the second one is the
// question "are we still defending this?" asked out loud. Adding a case needs
// no edit here: more adversarial coverage is always welcome.
var requiredScenarios = []string{
	"manifest-digest-mismatch",
	"blob-digest-mismatch",
	"truncated-blob",
	"manifest-missing-layer",
	"malformed-manifest",
	"redirect-loop",
	"redirect-private-address",
	"redirect-untrusted-host",
	"auth-realm-private-address",
	"rate-limit-storm",
	"traversal-upstream-mapping",
	"traversal-remainder-rewrite",
	"single-flight-under-load",
	"stale-tag-serve-stale",
	"stale-tag-strict",
	"unreachable-upstream",
	"group-member-leakage",
}

func TestEveryRequiredBulletHasAScenario(t *testing.T) {
	t.Parallel()

	present := make(map[string]scenario, len(scenarios))
	for _, sc := range scenarios {
		if _, duplicate := present[sc.id]; duplicate {
			t.Errorf("two scenarios share the id %q; the ratchet cannot tell them apart", sc.id)
		}
		if sc.requirement == "" {
			t.Errorf("scenario %q does not say what it defends", sc.id)
		}
		if sc.run == nil {
			t.Errorf("scenario %q has no test", sc.id)
		}
		present[sc.id] = sc
	}

	for _, id := range requiredScenarios {
		if _, ok := present[id]; !ok {
			t.Errorf("required adversarial case %q has no scenario (§9, C-015)", id)
		}
	}
}

// --- the upstream lied about content -------------------------------------

// testManifestDigestMismatch: the upstream answers a digest request with other
// bytes. Nothing may be served and nothing may be cached, and the operator
// hears about it -- content that does not match its digest is somebody else's
// incident, and silence would make it look like ours.
func testManifestDigestMismatch(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})
	wanted := up.seed.Manifest.Digest

	up.on(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/manifests/") {
			return false
		}
		writeManifest(w, r, corrupt(up.seed.Manifest))
		return true
	})

	_, err := env.filler.Manifest(context.Background(), env.target, wanted)
	if !errors.Is(err, proxy.ErrDigestMismatch) {
		t.Fatalf("Manifest error = %v, want ErrDigestMismatch", err)
	}
	env.nothingCached(wanted)

	corruptEvents := env.events.ofType(event.BlobCorrupt)
	if len(corruptEvents) != 1 {
		t.Fatalf("published %d blob.corrupt events, want 1", len(corruptEvents))
	}
	payload, ok := corruptEvents[0].Payload.(event.BlobCorruptPayload)
	if !ok {
		t.Fatalf("payload is %T, want BlobCorruptPayload", corruptEvents[0].Payload)
	}
	if payload.Source != "upstream" {
		t.Errorf("source = %q, want upstream: this is not our storage failing", payload.Source)
	}
	if payload.Expected != wanted.String() {
		t.Errorf("expected digest = %q, want %s", payload.Expected, wanted)
	}
}

// testBlobDigestMismatch: the same lie one layer down, where it surfaces
// mid-stream because a blob is verified as it is read. The client sees the
// stream end short; the cache keeps nothing.
func testBlobDigestMismatch(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})
	layer := up.seed.Layer.Digest

	up.on(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/blobs/") {
			return false
		}
		tampered := corrupt(up.seed.Layer)
		w.Header().Set("Content-Length", fmt.Sprint(len(tampered.Bytes)))
		_, _ = w.Write(tampered.Bytes)
		return true
	})

	if err := env.pullBlob(layer); !errors.Is(err, proxy.ErrDigestMismatch) {
		t.Fatalf("pull error = %v, want ErrDigestMismatch", err)
	}
	env.nothingCached(layer)
	if len(env.events.ofType(event.BlobCorrupt)) == 0 {
		t.Error("an upstream serving bytes that are not what it claimed went unreported")
	}
}

// testTruncatedBlob: the body simply stops. The distinction from a mismatch is
// worth keeping -- one is a lie and one is a broken connection -- but the
// outcome must be identical, because a short read that looked like success
// would put a half layer in the cache.
func testTruncatedBlob(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})
	layer := up.seed.Layer

	up.on(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/blobs/") {
			return false
		}
		// The declared length is the whole layer; the body is half of it.
		w.Header().Set("Content-Length", fmt.Sprint(len(layer.Bytes)))
		_, _ = w.Write(layer.Bytes[:len(layer.Bytes)/2])
		return true
	})

	if err := env.pullBlob(layer.Digest); err == nil {
		t.Fatal("a truncated blob was served as though it were whole")
	}
	env.nothingCached(layer.Digest)
}

// testManifestReferencingAMissingLayer: the manifest is well-formed and
// verifies, so it caches; the layer it names is not there. The pull of that
// layer must fail as a plain not-found -- no partial cache row, nothing that
// would later look like a hit.
func testManifestReferencingAMissingLayer(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})
	up.forget(up.seed.Layer.Digest)

	result, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest)
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if !result.Cached {
		t.Error("a manifest that verified was not cached")
	}

	// The manifest is cached and its layer is not: exactly the state a client
	// discovers on the next request, and it must be an honest miss rather
	// than anything the cache pretends to hold.
	if err := env.pullBlob(up.seed.Layer.Digest); !errors.Is(err, proxy.ErrNotFound) {
		t.Fatalf("layer pull error = %v, want ErrNotFound", err)
	}
	if env.cachedBlobRow(up.seed.Layer.Digest) || env.storedBytes(up.seed.Layer.Digest) {
		t.Error("the cache recorded a layer the upstream does not have")
	}
}

// testMalformedManifest: bytes that hash correctly but are not a manifest this
// registry implements. It is refused as an unavailable upstream rather than
// cached as an opaque blob -- a manifest trove cannot parse is one it cannot
// account for, gate, or scan, and a group member answering with one has to be
// treated exactly like a member that is down (C-011).
func testMalformedManifest(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})

	garbage := clienttest.Content{
		Bytes:     []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":`),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
	}
	garbage.Digest = blob.FromBytes(blob.SHA256, garbage.Bytes)
	up.publish(garbage)

	_, err := env.filler.Manifest(context.Background(), env.target, garbage.Digest)
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Fatalf("Manifest error = %v, want ErrUpstreamUnavailable", err)
	}
	env.nothingCached(garbage.Digest)
}

// --- the upstream sent us somewhere --------------------------------------

// testRedirectLoop: a Location header pointing back at itself. The chain has
// to terminate on the cap rather than on a timeout or a stack, and the error
// has to say that is what happened.
func testRedirectLoop(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{redirects: proxy.RedirectPolicy{MaxRedirects: 3}})

	var hops int
	var mu sync.Mutex
	up.on(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/blobs/") {
			return false
		}
		mu.Lock()
		hops++
		mu.Unlock()
		redirectTo(w, "http://"+upstreamHost+r.URL.Path)
		return true
	})

	err := env.pullBlob(up.seed.Layer.Digest)
	if err == nil {
		t.Fatal("a redirect loop was followed to a result")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error %q does not say the redirect chain was the problem", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if hops > 4 {
		t.Errorf("followed %d hops with a cap of 3", hops)
	}
	env.nothingCached(up.seed.Layer.Digest)
}

// testRedirectToAPrivateAddress is the SSRF case, and the one where asserting
// on the error is not enough: the test points the redirect at a real loopback
// listener and requires that nothing ever arrived on it.
func testRedirectToAPrivateAddress(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})
	private := newListener(t)

	up.on(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/blobs/") {
			return false
		}
		redirectTo(w, private.url()+"/metadata")
		return true
	})

	if err := env.pullBlob(up.seed.Layer.Digest); err == nil {
		t.Fatal("a redirect to a private address was followed")
	}
	private.mustBeUntouched(t, "blob redirect")
	env.nothingCached(up.seed.Layer.Digest)
}

// testRedirectOffTheUpstreamFamily: a redirect to a host nobody trusted is
// refused, and the same redirect to a host the operator listed is followed.
// Both halves matter -- a policy that refused everything would pass the first
// assertion while making every real registry unusable.
func testRedirectOffTheUpstreamFamily(t *testing.T) {
	t.Run("untrusted", func(t *testing.T) {
		t.Parallel()

		up := newHostile(t)
		cdn := newListener(t)
		env := newEnv(t, up, options{})
		env.router.route(evilHost, strings.TrimPrefix(cdn.url(), "http://"))

		up.on(func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.Contains(r.URL.Path, "/blobs/") {
				return false
			}
			redirectTo(w, "http://"+evilHost+"/layer")
			return true
		})

		if err := env.pullBlob(up.seed.Layer.Digest); err == nil {
			t.Fatal("a redirect off the upstream's family was followed")
		}
		// The host is reachable and would have answered: the refusal is the
		// policy's, not the network's.
		cdn.mustBeUntouched(t, "untrusted redirect")
	})

	t.Run("trusted", func(t *testing.T) {
		t.Parallel()

		up := newHostile(t)
		layer := up.seed.Layer
		cdn := newContentServer(t, layer)
		env := newEnv(t, up, options{
			redirects: proxy.RedirectPolicy{TrustedHosts: []string{cdnHost}},
		})
		env.router.route(cdnHost, cdn.hostPort)

		up.on(func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.Contains(r.URL.Path, "/blobs/") {
				return false
			}
			redirectTo(w, "http://"+cdnHost+"/layer")
			return true
		})

		if err := env.pullBlob(layer.Digest); err != nil {
			t.Fatalf("a redirect to a trusted host was refused: %v", err)
		}
		if !env.storedBytes(layer.Digest) {
			t.Error("the layer fetched through the CDN was not cached")
		}
	})
}

// testAuthRealmPointingAtAPrivateAddress: the realm out of a WWW-Authenticate
// header is where the client is about to send the upstream's password, so an
// unchecked realm turns a hostile registry into a credential exfiltration
// channel. It goes through the same policy as a redirect, and the listener
// proves it.
func testAuthRealmPointingAtAPrivateAddress(t *testing.T) {
	up := newHostile(t)
	private := newListener(t)
	env := newEnv(t, up, options{
		credentials: proxy.StaticCredentials{Username: "robot", Password: "hunter2"},
	})

	up.on(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/manifests/") {
			return false
		}
		w.Header().Set("WWW-Authenticate", challengeFor(private.url()+"/token"))
		w.WriteHeader(http.StatusUnauthorized)
		return true
	})

	if _, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest); err == nil {
		t.Fatal("a challenge naming a private realm was honoured")
	}
	private.mustBeUntouched(t, "token realm")
}

// --- the upstream pushed back --------------------------------------------

// testRateLimitStorm: an upstream that answers 429 to everything. The first
// pull reports it; the ones after it must not reach the wire at all, because
// the request itself is the harm. Once the window passes the proxy tries
// again -- backing off forever would be its own outage.
func testRateLimitStorm(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})

	up.on(func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Retry-After", "60")
		writeAPIError(w, http.StatusTooManyRequests, "TOOMANYREQUESTS", "slow down")
		return true
	})

	if _, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest); !errors.Is(err, proxy.ErrRateLimited) {
		t.Fatalf("first pull error = %v, want ErrRateLimited", err)
	}
	afterFirst := len(up.paths())

	for range 20 {
		if _, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest); !errors.Is(err, proxy.ErrRateLimited) {
			t.Fatalf("pull during backoff error = %v, want ErrRateLimited", err)
		}
	}
	if got := len(up.paths()); got != afterFirst {
		t.Errorf("made %d further upstream requests while backing off, want 0", got-afterFirst)
	}

	// Past the window the upstream is asked again, and this time it answers.
	up.on(nil)
	env.clock.advance(2 * time.Minute)
	if _, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest); err != nil {
		t.Fatalf("pull after the backoff window: %v", err)
	}
}

// testUnreachableUpstream: nothing is listening. It is the DNS-blackhole case
// §4 asks for, in the form a test can be sure of, and the requirement is that
// it is reported as an unavailable upstream rather than as some transport
// error every caller would have to learn to classify.
func testUnreachableUpstream(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})
	env.router.route(upstreamHost, freePort(t))

	_, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest)
	if !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, want ErrUpstreamUnavailable", err)
	}
	env.nothingCached(up.seed.Manifest.Digest)
}

// --- names that try to escape --------------------------------------------

// testTraversalViaTheUpstreamMapping: an upstream repository path carrying
// traversal segments. It must be refused before a request is built, not
// cleaned up afterwards -- a path that reaches the URL builder has already
// been trusted.
func testTraversalViaTheUpstreamMapping(t *testing.T) {
	for _, upstreamPath := range []string{
		"library/../../etc/passwd",
		"../admin",
		"library/..%2f..%2fadmin",
		"library/./../../x",
		"/absolute",
		"library//double",
	} {
		t.Run(upstreamPath, func(t *testing.T) {
			t.Parallel()

			up := newHostile(t)
			env := newEnv(t, up, options{upstreamRepository: upstreamPath})

			_, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest)
			if err == nil {
				t.Fatalf("upstream path %q was accepted", upstreamPath)
			}
			// Refused *as a name*, which is the only refusal that closes the
			// class: a path that failed for some incidental reason -- a 404, a
			// transport error -- would leave the next hostile name to chance.
			var reference *proxy.ReferenceError
			if !errors.As(err, &reference) {
				t.Fatalf("error is %T (%v), want a reference error naming the repository", err, err)
			}
			if requests := up.paths(); len(requests) > 0 {
				t.Errorf("a traversal path reached the upstream as %v", requests)
			}
		})
	}
}

// testTraversalViaTheNamespaceRewrite: a hostile remainder on its way through
// the router, the namespace rewrite, and the routing rules.
//
// Three gates, in the order a request meets them: `repo.Split` validates the
// whole name before anything is a path; the rewrite (C-018) turns a bare name
// into `library/<name>` on a Docker Hub proxy; and `RoutingRules.Evaluate`
// validates the rewritten path again as the resource its patterns match
// against. None of them may hand back a name carrying traversal, and the
// rewrite in the middle is the interesting one -- it is the only step that
// *builds* a path rather than checking one.
func testTraversalViaTheNamespaceRewrite(t *testing.T) {
	preset, err := repo.PresetByName("dockerhub")
	if err != nil {
		t.Fatalf("PresetByName: %v", err)
	}
	config, err := json.Marshal(preset.Config())
	if err != nil {
		t.Fatalf("marshal the preset config: %v", err)
	}

	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: "hub", Type: meta.Proxy, Config: config, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	filler := &recordingFiller{}
	server, err := proxyserve.New(proxyserve.Options{
		Meta: store, Clients: nowhereClients{}, Filler: filler, Log: quietLogger(),
	})
	if err != nil {
		t.Fatalf("proxyserve.New: %v", err)
	}

	for _, name := range []string{
		"hub/..",
		"hub/../admin",
		"hub/..%2fadmin",
		"hub/nginx/../../admin",
		"hub/.",
		"hub//nginx",
		"hub/nginx/",
		"hub/\\admin",
		// A NUL inside a name, built rather than written: a source file
		// carrying one is a source file most tools mangle.
		"hub/n" + string(rune(0)) + "ginx",
		"hub/nginx",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Driven through the real serving path -- router, namespace
			// rewrite, routing rules -- rather than through the rewrite alone,
			// because what must hold is a property of the path a request
			// actually takes.
			if _, err := server.Manifest(context.Background(), name, "v1"); err != nil {
				// Refused somewhere along it: the name never became an
				// upstream path.
				return
			}

			upstream := filler.upstreamFor(t, name)
			switch {
			case strings.Contains(upstream, ".."):
				t.Fatalf("%q became upstream path %q, which climbs out of the namespace", name, upstream)
			case strings.HasPrefix(upstream, "/"):
				t.Fatalf("%q became upstream path %q, which is absolute", name, upstream)
			case strings.Contains(upstream, "//"):
				t.Fatalf("%q became upstream path %q, which has an empty segment", name, upstream)
			}
			// The Docker Hub preset namespaces every bare name, so anything
			// that got through is either already namespaced or now is.
			if !strings.Contains(upstream, "/") {
				t.Fatalf("%q became upstream path %q, which is neither namespaced nor a path", name, upstream)
			}
		})
	}
}

// recordingFiller answers nothing and remembers which upstream path it was
// asked for, which is what the traversal scenario asserts on.
type recordingFiller struct {
	mu      sync.Mutex
	targets map[string]string
}

func (f *recordingFiller) note(t proxy.Target) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.targets == nil {
		f.targets = map[string]string{}
	}
	f.targets[t.Repository] = t.Upstream
}

func (f *recordingFiller) upstreamFor(t *testing.T, name string) string {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()
	upstream, ok := f.targets[name]
	if !ok {
		t.Fatalf("the filler was never asked about %q", name)
	}
	return upstream
}

func (f *recordingFiller) ResolveTag(_ context.Context, t proxy.Target, _ string) (proxy.TagResolution, error) {
	f.note(t)
	return proxy.TagResolution{Digest: blob.FromBytes(blob.SHA256, []byte("x"))}, nil
}

func (f *recordingFiller) Manifest(_ context.Context, t proxy.Target, _ blob.Digest) (proxy.ManifestResult, error) {
	f.note(t)
	return proxy.ManifestResult{}, nil
}

func (f *recordingFiller) Blob(_ context.Context, t proxy.Target, _ blob.Digest) (proxy.BlobResult, error) {
	f.note(t)
	return proxy.BlobResult{}, nil
}

// nowhereClients hands out a client nothing calls: the filler is recorded, not
// executed.
type nowhereClients struct{}

func (nowhereClients) ClientFor(context.Context, string) (proxy.Client, error) {
	return nil, nil
}

// --- concurrency and staleness -------------------------------------------

// testSingleFlightUnderLoad: fifty pods starting at once resolve `:latest`
// once. The upstream is held open until every caller is waiting, so the test
// is asserting collapse rather than racing to observe it.
func testSingleFlightUnderLoad(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{})

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	up.on(func(_ http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/manifests/") {
			return false
		}
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		return false
	})

	const callers = 50
	var wg sync.WaitGroup
	results := make([]blob.Digest, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolution, err := env.filler.ResolveTag(context.Background(), env.target, up.seed.Tag)
			results[i], errs[i] = resolution.Digest, err
		}()
	}

	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("no caller reached the upstream")
	}
	// Everyone else is now either waiting on the flight or about to be. The
	// upstream request in flight is the only one that may exist.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i] != up.seed.Manifest.Digest {
			t.Fatalf("caller %d resolved %s, want %s", i, results[i], up.seed.Manifest.Digest)
		}
	}

	var manifestRequests int
	for _, path := range up.paths() {
		if strings.Contains(path, "/manifests/") {
			manifestRequests++
		}
	}
	if manifestRequests != 1 {
		t.Errorf("%d callers made %d upstream manifest requests, want 1", callers, manifestRequests)
	}
}

// testStaleTagPastTTLServesStale: the lease has expired and the upstream is
// gone. The default keeps the cluster running: the cached mapping is served,
// marked stale, and reported -- and the lease's deadline is *not* refreshed,
// or one dead upstream would buy a full TTL of silence.
func testStaleTagPastTTLServesStale(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{tagTTL: 15 * time.Minute, offline: proxy.ServeStale})

	cold, err := env.filler.ResolveTag(context.Background(), env.target, up.seed.Tag)
	if err != nil {
		t.Fatalf("cold resolve: %v", err)
	}

	env.clock.advance(time.Hour)
	env.router.route(upstreamHost, freePort(t))

	stale, err := env.filler.ResolveTag(context.Background(), env.target, up.seed.Tag)
	if err != nil {
		t.Fatalf("stale resolve: %v", err)
	}
	if stale.Digest != cold.Digest {
		t.Errorf("stale resolve gave %s, want the cached %s", stale.Digest, cold.Digest)
	}
	if !stale.Stale {
		t.Error("content served past its deadline was not marked stale")
	}
	if stale.StaleFor <= 0 {
		t.Error("a stale resolution does not say how stale it is")
	}
	if len(env.events.ofType(event.CacheStaleServed)) == 0 {
		t.Error("serving stale content was not reported")
	}
}

// testStaleTagPastTTLStrictFails: the same situation for a deployment that
// would rather stop than serve an answer it could not confirm.
func testStaleTagPastTTLStrictFails(t *testing.T) {
	up := newHostile(t)
	env := newEnv(t, up, options{tagTTL: 15 * time.Minute, offline: proxy.Strict})

	if _, err := env.filler.ResolveTag(context.Background(), env.target, up.seed.Tag); err != nil {
		t.Fatalf("cold resolve: %v", err)
	}

	env.clock.advance(time.Hour)
	env.router.route(upstreamHost, freePort(t))

	if _, err := env.filler.ResolveTag(context.Background(), env.target, up.seed.Tag); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Fatalf("strict resolve error = %v, want ErrUpstreamUnavailable", err)
	}
	if len(env.events.ofType(event.CacheStaleServed)) != 0 {
		t.Error("strict mode reported stale content it did not serve")
	}
}

// --- groups ---------------------------------------------------------------

// testGroupBehaviourDoesNotLeakAMember: a member a subject cannot read is
// removed before resolution, and the result must be indistinguishable from one
// where that member does not exist. This is the single easiest place to leak
// (§4), so the assertion is a comparison of two whole resolutions rather than
// a spot check on one field.
func testGroupBehaviourDoesNotLeakAMember(t *testing.T) {
	// A hidden member that *would* have served, placed first so that if it
	// were consulted at all it would change the answer.
	hidden := repo.MemberState{
		Repository: "secret", Content: "secret/app", Type: meta.Proxy,
		Position: 1, Outcome: repo.MemberServed,
	}
	visible := repo.MemberState{
		Repository: "hub", Content: "hub/app", Type: meta.Proxy,
		Position: 2, Outcome: repo.MemberServed,
	}

	// The subject can read the visible member's content and nothing else, so
	// the hidden member is removed before resolution runs (C-012).
	bindings := []authz.Binding{{
		ID: "b1", Role: "developer",
		Scope: mustScope(t, visible.Content),
		Verbs: []authz.Verb{authz.RepoRead},
	}}
	filtered := repo.VisibleMembers([]repo.MemberState{hidden, visible}, bindings)
	absent := repo.AllMembers(visible)

	got := repo.Resolve(filtered, "latest")
	want := repo.Resolve(absent, "latest")

	if got.Outcome != want.Outcome || got.Member != want.Member {
		t.Fatalf("filtered resolution = %+v, want the absent-member resolution %+v", got, want)
	}
	if len(got.Skipped) != len(want.Skipped) {
		// A skipped member is an event naming it. A filtered member must not
		// produce one, or the event stream discloses what the listing hid.
		t.Errorf("filtered resolution skipped %v; the absent-member run skipped %v", got.Skipped, want.Skipped)
	}
	for _, skipped := range got.Skipped {
		if skipped.Repository == hidden.Repository {
			t.Errorf("a member the subject cannot read appears in the resolution: %v", skipped)
		}
	}
	if got.Err != nil || want.Err != nil {
		t.Errorf("errors differ or exist: %v vs %v", got.Err, want.Err)
	}
}

// mustScope parses a binding scope a test wrote.
func mustScope(t *testing.T, s string) authz.Scope {
	t.Helper()

	scope, err := authz.ParseScope(s)
	if err != nil {
		t.Fatalf("ParseScope(%q): %v", s, err)
	}
	return scope
}

// contentServer serves one blob at any path: the CDN a trusted redirect points
// at.
type contentServer struct {
	hostPort string
}

func newContentServer(t *testing.T, content clienttest.Content) *contentServer {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", content.MediaType)
		w.Header().Set("Content-Length", fmt.Sprint(len(content.Bytes)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(content.Bytes)
	}))
	t.Cleanup(server.Close)
	return &contentServer{hostPort: strings.TrimPrefix(server.URL, "http://")}
}
