package proxyadv_test

import (
	"context"
	"net/http"
	"testing"
)

// The harness's own tests. Every scenario in this suite asserts that something
// did *not* happen -- no bytes cached, no request sent, no credential leaked --
// and an assertion like that is worthless if the machinery behind it could not
// have observed the thing happening. These are the positive controls.

// TestTheUpstreamServesTheFixtureWhenItBehaves is the control for every "the
// upstream lied" case: with no interceptor installed, a pull succeeds and
// caches. Without it, a scenario could pass because the fixture is broken
// rather than because the code refused something.
func TestTheUpstreamServesTheFixtureWhenItBehaves(t *testing.T) {
	t.Parallel()

	up := newHostile(t)
	env := newEnv(t, up, options{})

	resolution, err := env.filler.ResolveTag(context.Background(), env.target, up.seed.Tag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Digest != up.seed.Manifest.Digest {
		t.Fatalf("resolved %s, want %s", resolution.Digest, up.seed.Manifest.Digest)
	}
	if !env.cachedManifest(up.seed.Manifest.Digest) {
		t.Error("a manifest that verified was not cached")
	}

	if err := env.pullBlob(up.seed.Layer.Digest); err != nil {
		t.Fatalf("pulling the layer: %v", err)
	}
	if !env.cachedBlobRow(up.seed.Layer.Digest) || !env.storedBytes(up.seed.Layer.Digest) {
		t.Error("a layer that verified was not cached")
	}

	// And the client really did go through the named host rather than
	// bypassing the router: the upstream saw the requests.
	if len(up.paths()) == 0 {
		t.Error("the upstream saw no requests; the host router is not in the path")
	}
}

// TestTheListenerNoticesARequest proves the SSRF assertion can fail. The
// listener is what stands between "the policy refused" and "the request went
// out and nobody looked", so it has to be shown recording one.
func TestTheListenerNoticesARequest(t *testing.T) {
	t.Parallel()

	private := newListener(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, private.url()+"/metadata", nil)
	if err != nil {
		t.Fatalf("building the probe: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("probing the listener: %v", err)
	}
	_ = resp.Body.Close()

	if got := private.requests(); len(got) != 1 {
		t.Fatalf("listener recorded %v, want one request", got)
	}
}

// TestTheHostRouterOnlyMapsWhatItWasTold keeps the router honest: an unmapped
// name is not silently sent somewhere. The SSRF cases depend on it, since
// their redirect targets are literal addresses that must be dialled as written
// rather than rewritten to the fixture.
func TestTheHostRouterOnlyMapsWhatItWasTold(t *testing.T) {
	t.Parallel()

	up := newHostile(t)
	env := newEnv(t, up, options{})

	// The upstream name resolves to the fixture; an unrelated one does not
	// resolve at all, so a request to it fails rather than reaching the
	// fixture by accident.
	env.router.route(upstreamHost, up.hostPort())
	if _, err := env.filler.Manifest(context.Background(), env.target, up.seed.Manifest.Digest); err != nil {
		t.Fatalf("mapped host: %v", err)
	}

	unmapped := newEnv(t, up, options{})
	unmapped.router.route(upstreamHost, freePort(t))
	if _, err := unmapped.filler.Manifest(context.Background(), unmapped.target, up.seed.Manifest.Digest); err == nil {
		t.Error("a host mapped to a dead port answered; the router is not deciding where requests go")
	}
}
