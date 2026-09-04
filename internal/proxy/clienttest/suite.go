// Package clienttest is the contract suite for proxy.Client. Every upstream
// client runs the same suite unmodified, and it runs against a real
// distribution registry as well as against a controllable fake, which is what
// makes the fake trustworthy for the cache, lease, and single-flight work built
// on top of it.
//
// The suite is in two halves because upstreams come in two kinds.
//
// Run is the content half: everything a real registry does on demand --
// conditional tag resolution, fetch by digest, not-found. It runs against
// registry:2 in a container and, in a nightly job, against a real public
// remote. A behaviour asserted here is one any Client must have against any
// spec-compliant upstream.
//
// RunFaults is the behaviour half: everything a real registry will not do
// because you asked nicely -- serving a manifest that does not hash to the
// digest it was requested under, 429 with a Retry-After, a redirect loop, a
// malformed authentication challenge, a connection that never answers. Those
// need an upstream under the test's control, so the factory builds one per
// fault.
//
// A behaviour that is not asserted here is not part of the contract.
package clienttest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/proxy"
)

// Content is one piece of addressable content the upstream must serve.
type Content struct {
	// Bytes is the content itself.
	Bytes []byte
	// MediaType is what the upstream must declare for it.
	MediaType string
	// Digest is what Bytes hashes to.
	Digest blob.Digest
}

// Fixture is the content an upstream must hold before the content half of the
// suite runs. The same value drives the container seeding and the fake, so the
// two are provably serving the same bytes.
type Fixture struct {
	// Repository is the upstream repository path everything lives under.
	Repository string
	// Tag is the tag Manifest is pushed under.
	Tag string

	// Blobs are every blob the manifests reference plus the one the streaming
	// cases fetch. All of them must exist upstream: registry:2 refuses a
	// manifest whose layers are missing, which is exactly the check that makes
	// this fixture realistic.
	Blobs []Content
	// Layer is the blob the streaming cases fetch.
	Layer Content

	// Manifest is what Tag points at when the suite starts.
	Manifest Content
	// Next is what Retag moves the tag to.
	Next Content

	// MissingRepository, MissingTag, and MissingDigest name content the
	// upstream must not have.
	MissingRepository string
	MissingTag        string
	MissingDigest     blob.Digest
}

// Request is one upstream request a target observed.
type Request struct {
	// Method and Path are what was asked for.
	Method string
	// Path is the request path.
	Path string
	// ResponseBytes is how many body bytes came back. It is what proves that
	// an unchanged tag cost no bandwidth, and it is only final once the body
	// has been read or closed.
	ResponseBytes int64
}

// Target is an upstream the content half of the suite runs against.
type Target struct {
	// Client is the client under test.
	Client proxy.Client
	// Retag repoints Fixture.Tag at the given content. It must be usable more
	// than once.
	Retag func(t *testing.T, to Content)
	// Requests returns every request the client has made so far, in order. It
	// must not be nil: the contract includes what does *not* go over the wire,
	// and that cannot be asserted from the outside any other way.
	Requests func() []Request
}

// Factory builds a target against an upstream seeded with the fixture.
//
// It is called once per case and must (re)seed the upstream every time,
// including pointing Fixture.Tag back at Fixture.Manifest: one of the cases
// moves the tag, and a case that inherited the moved tag would be asserting
// against whatever ran before it.
type Factory func(t *testing.T, seed Fixture) Target

// Fault is an upstream misbehaviour the behaviour half of the suite drives.
type Fault int

// The faults. Each one is a single, named way an upstream can be wrong; the
// case that drives it asserts exactly which sentinel the client must produce.
const (
	// FaultManifestDigestMismatch serves, for any digest, a manifest whose
	// bytes hash to something else. This is the one that matters most: it is
	// what a compromised or man-in-the-middled upstream looks like.
	FaultManifestDigestMismatch Fault = iota
	// FaultBlobCorrupt serves a blob body of the right length whose bytes hash
	// to something else.
	FaultBlobCorrupt
	// FaultBlobTruncated serves fewer bytes than it promised.
	FaultBlobTruncated
	// FaultBearerChallenge answers unauthenticated requests with a bearer
	// challenge and honours the token that comes back.
	FaultBearerChallenge
	// FaultBearerTokenRejected answers with a bearer challenge whose token
	// endpoint refuses.
	FaultBearerTokenRejected
	// FaultMalformedChallenge answers 401 with a challenge naming no scheme
	// this client speaks.
	FaultMalformedChallenge
	// FaultRateLimited answers 429 with an honest Retry-After.
	FaultRateLimited
	// FaultRateLimitedNoRetryAfter answers 429 with no Retry-After at all.
	FaultRateLimitedNoRetryAfter
	// FaultRateLimitHeaders answers normally, with Docker Hub's rate-limit
	// headers attached.
	FaultRateLimitHeaders
	// FaultRedirectLoop redirects to itself forever, on its own host.
	FaultRedirectLoop
	// FaultRedirectOffHost redirects to a host outside the upstream's family.
	FaultRedirectOffHost
	// FaultServerError answers 500.
	FaultServerError
	// FaultUnreachable cannot be connected to at all.
	FaultUnreachable
	// FaultStalledHeaders accepts the connection and never answers. A client
	// built for this fault must carry a short RequestTimeout, or the case
	// waits for the default one.
	FaultStalledHeaders
)

// String names the fault, for subtest names and failure messages.
func (f Fault) String() string {
	switch f {
	case FaultManifestDigestMismatch:
		return "ManifestDigestMismatch"
	case FaultBlobCorrupt:
		return "BlobCorrupt"
	case FaultBlobTruncated:
		return "BlobTruncated"
	case FaultBearerChallenge:
		return "BearerChallenge"
	case FaultBearerTokenRejected:
		return "BearerTokenRejected"
	case FaultMalformedChallenge:
		return "MalformedChallenge"
	case FaultRateLimited:
		return "RateLimited"
	case FaultRateLimitedNoRetryAfter:
		return "RateLimitedNoRetryAfter"
	case FaultRateLimitHeaders:
		return "RateLimitHeaders"
	case FaultRedirectLoop:
		return "RedirectLoop"
	case FaultRedirectOffHost:
		return "RedirectOffHost"
	case FaultServerError:
		return "ServerError"
	case FaultUnreachable:
		return "Unreachable"
	case FaultStalledHeaders:
		return "StalledHeaders"
	default:
		return "Fault(unknown)"
	}
}

// FaultFactory builds a client against an upstream that is seeded with the
// fixture and misbehaves in the named way.
type FaultFactory func(t *testing.T, seed Fixture, fault Fault) proxy.Client

// DefaultFixture is the content the suite uses: one OCI image manifest over a
// config and a layer, a second manifest that differs only in its config, and
// names for content that must not exist.
//
// It is a real manifest over real blobs because registry:2 validates what it
// is given, and a fixture a real registry would refuse is a fixture that
// proves nothing.
func DefaultFixture() Fixture {
	config := newContent(
		[]byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`),
		"application/vnd.oci.image.config.v1+json")
	nextConfig := newContent(
		[]byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`),
		"application/vnd.oci.image.config.v1+json")
	layer := newContent(
		bytes.Repeat([]byte("trove contract suite layer bytes\n"), 64),
		"application/vnd.oci.image.layer.v1.tar+gzip")

	return Fixture{
		Repository:        "library/trove-fixture",
		Tag:               "v1",
		Blobs:             []Content{config, nextConfig, layer},
		Layer:             layer,
		Manifest:          imageManifest(config, layer),
		Next:              imageManifest(nextConfig, layer),
		MissingRepository: "library/trove-absent",
		MissingTag:        "no-such-tag",
		MissingDigest:     blob.FromBytes(blob.SHA256, []byte("content no upstream has")),
	}
}

// newContent builds a Content with its digest computed.
func newContent(data []byte, mediaType string) Content {
	return Content{Bytes: data, MediaType: mediaType, Digest: blob.FromBytes(blob.SHA256, data)}
}

// descriptor is the OCI descriptor shape, written out here rather than
// imported so the fixture stays a plain document.
type descriptor struct {
	MediaType string      `json:"mediaType"`
	Digest    blob.Digest `json:"digest"`
	Size      int64       `json:"size"`
}

// imageManifest builds an OCI image manifest over a config and one layer.
func imageManifest(config, layer Content) Content {
	document := struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{
		SchemaVersion: 2,
		MediaType:     artifact.MediaTypeOCIManifest,
		Config:        descriptorOf(config),
		Layers:        []descriptor{descriptorOf(layer)},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		// Unreachable: the document is a closed struct of plain fields.
		panic("clienttest: cannot encode fixture manifest: " + err.Error())
	}
	return newContent(encoded, artifact.MediaTypeOCIManifest)
}

// descriptorOf describes one piece of content.
func descriptorOf(c Content) descriptor {
	return descriptor{MediaType: c.MediaType, Digest: c.Digest, Size: int64(len(c.Bytes))}
}

type contentCase struct {
	name string
	run  func(t *testing.T, target Target, seed Fixture)
}

// Run executes the content half of the contract against the upstream built by
// f.
func Run(t *testing.T, f Factory) {
	t.Helper()

	cases := []contentCase{
		{"ResolveTagCold", testResolveTagCold},
		{"ResolveTagUnchangedCostsNoBandwidth", testResolveTagUnchanged},
		{"ResolveTagChanged", testResolveTagChanged},
		{"ResolveTagUnknownTag", testResolveTagUnknownTag},
		{"ResolveTagUnknownRepository", testResolveTagUnknownRepository},
		{"ResolveTagRejectsInvalidReferences", testResolveTagRejectsInvalidReferences},
		{"FetchManifestByDigest", testFetchManifestByDigest},
		{"FetchManifestUnknownDigest", testFetchManifestUnknownDigest},
		{"FetchManifestRejectsInvalidDigest", testFetchManifestRejectsInvalidDigest},
		{"FetchBlobStreamsVerified", testFetchBlobStreamsVerified},
		{"FetchBlobUnknownDigest", testFetchBlobUnknownDigest},
		{"ContextCancellation", testContextCancellation},
	}

	seed := DefaultFixture()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := f(t, seed)
			if target.Client == nil {
				t.Fatal("factory returned no client")
			}
			if target.Requests == nil {
				t.Fatal("factory returned no request recorder: the contract includes what is not sent")
			}
			tc.run(t, target, seed)
		})
	}
}

type faultCase struct {
	fault Fault
	run   func(t *testing.T, client proxy.Client, seed Fixture)
}

// RunFaults executes the behaviour half of the contract against upstreams
// built by f.
func RunFaults(t *testing.T, f FaultFactory) {
	t.Helper()

	cases := []faultCase{
		{FaultManifestDigestMismatch, testManifestDigestMismatch},
		{FaultBlobCorrupt, testBlobCorrupt},
		{FaultBlobTruncated, testBlobTruncated},
		{FaultBearerChallenge, testBearerChallenge},
		{FaultBearerTokenRejected, testBearerTokenRejected},
		{FaultMalformedChallenge, testMalformedChallenge},
		{FaultRateLimited, testRateLimited},
		{FaultRateLimitedNoRetryAfter, testRateLimitedNoRetryAfter},
		{FaultRateLimitHeaders, testRateLimitHeaders},
		{FaultRedirectLoop, testRedirectLoop},
		{FaultRedirectOffHost, testRedirectOffHost},
		{FaultServerError, testServerError},
		{FaultUnreachable, testUnreachable},
		{FaultStalledHeaders, testStalledHeaders},
	}

	seed := DefaultFixture()
	for _, tc := range cases {
		t.Run(tc.fault.String(), func(t *testing.T) {
			client := f(t, seed, tc.fault)
			if client == nil {
				t.Fatal("factory returned no client")
			}
			tc.run(t, client, seed)
		})
	}
}

// --- helpers ---

func ctx() context.Context { return context.Background() }

func requireErrIs(t *testing.T, err, target error, what string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: got no error, want %v", what, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}

// manifestBytesSince totals the response bodies of manifest requests made
// after the marker. It is how "revalidation costs no bandwidth" is asserted
// without the suite knowing anything about the transport.
func manifestBytesSince(requests []Request, marker int) int64 {
	var total int64
	for _, request := range requests[min(marker, len(requests)):] {
		if strings.Contains(request.Path, "/manifests/") {
			total += request.ResponseBytes
		}
	}
	return total
}

// --- content cases ---

func testResolveTagCold(t *testing.T, target Target, seed Fixture) {
	resolution, err := target.Client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if !resolution.Changed {
		t.Error("Changed = false for a resolution with nothing to compare against")
	}
	if resolution.Digest != seed.Manifest.Digest {
		t.Errorf("Digest = %s, want %s", resolution.Digest, seed.Manifest.Digest)
	}
	if !bytes.Equal(resolution.Manifest, seed.Manifest.Bytes) {
		t.Errorf("Manifest = %q, want %q", resolution.Manifest, seed.Manifest.Bytes)
	}
	if resolution.MediaType != seed.Manifest.MediaType {
		t.Errorf("MediaType = %q, want %q", resolution.MediaType, seed.Manifest.MediaType)
	}
	// The digest must be the one the bytes hash to, not one taken on trust.
	if got := blob.FromBytes(blob.SHA256, resolution.Manifest); got != resolution.Digest {
		t.Errorf("returned digest %s does not describe the returned bytes (%s)", resolution.Digest, got)
	}
}

func testResolveTagUnchanged(t *testing.T, target Target, seed Fixture) {
	marker := len(target.Requests())

	resolution, err := target.Client.ResolveTag(ctx(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if resolution.Changed {
		t.Error("Changed = true for a tag that did not move")
	}
	if resolution.Digest != seed.Manifest.Digest {
		t.Errorf("Digest = %s, want %s", resolution.Digest, seed.Manifest.Digest)
	}
	if resolution.Manifest != nil {
		t.Errorf("Manifest = %q, want nil for an unchanged tag", resolution.Manifest)
	}
	if transferred := manifestBytesSince(target.Requests(), marker); transferred != 0 {
		t.Errorf("revalidation transferred %d manifest bytes, want 0: an unchanged tag must cost no bandwidth", transferred)
	}
}

func testResolveTagChanged(t *testing.T, target Target, seed Fixture) {
	target.Retag(t, seed.Next)

	resolution, err := target.Client.ResolveTag(ctx(), seed.Repository, seed.Tag,
		proxy.Conditional{Digest: seed.Manifest.Digest})
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	if !resolution.Changed {
		t.Fatal("Changed = false for a tag that moved")
	}
	if resolution.Digest != seed.Next.Digest {
		t.Errorf("Digest = %s, want %s", resolution.Digest, seed.Next.Digest)
	}
	if !bytes.Equal(resolution.Manifest, seed.Next.Bytes) {
		t.Errorf("Manifest = %q, want the new manifest", resolution.Manifest)
	}
}

func testResolveTagUnknownTag(t *testing.T, target Target, seed Fixture) {
	_, err := target.Client.ResolveTag(ctx(), seed.Repository, seed.MissingTag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrNotFound, "ResolveTag on an absent tag")
}

func testResolveTagUnknownRepository(t *testing.T, target Target, seed Fixture) {
	_, err := target.Client.ResolveTag(ctx(), seed.MissingRepository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrNotFound, "ResolveTag on an absent repository")
}

func testResolveTagRejectsInvalidReferences(t *testing.T, target Target, seed Fixture) {
	cases := []struct {
		name       string
		repository string
		tag        string
		cond       proxy.Conditional
	}{
		{"traversal in the repository", "../etc/passwd", seed.Tag, proxy.Conditional{}},
		{"uppercase repository", "Library/Nginx", seed.Tag, proxy.Conditional{}},
		{"empty repository", "", seed.Tag, proxy.Conditional{}},
		{"traversal in the tag", seed.Repository, "../../v1", proxy.Conditional{}},
		{"empty tag", seed.Repository, "", proxy.Conditional{}},
		{"tag with a slash", seed.Repository, "a/b", proxy.Conditional{}},
		{"unparseable known digest", seed.Repository, seed.Tag, proxy.Conditional{Digest: "sha256:zzzz"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := target.Client.ResolveTag(ctx(), tc.repository, tc.tag, tc.cond)
			requireErrIs(t, err, proxy.ErrInvalidReference, "ResolveTag")
		})
	}
}

func testFetchManifestByDigest(t *testing.T, target Target, seed Fixture) {
	body, mediaType, err := target.Client.FetchManifest(ctx(), seed.Repository, seed.Manifest.Digest)
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if !bytes.Equal(body, seed.Manifest.Bytes) {
		t.Errorf("manifest = %q, want %q", body, seed.Manifest.Bytes)
	}
	if mediaType != seed.Manifest.MediaType {
		t.Errorf("media type = %q, want %q", mediaType, seed.Manifest.MediaType)
	}
}

func testFetchManifestUnknownDigest(t *testing.T, target Target, seed Fixture) {
	_, _, err := target.Client.FetchManifest(ctx(), seed.Repository, seed.MissingDigest)
	requireErrIs(t, err, proxy.ErrNotFound, "FetchManifest on an absent digest")
}

func testFetchManifestRejectsInvalidDigest(t *testing.T, target Target, seed Fixture) {
	_, _, err := target.Client.FetchManifest(ctx(), seed.Repository, "sha256:not-a-digest")
	requireErrIs(t, err, proxy.ErrInvalidReference, "FetchManifest with an unparseable digest")
}

func testFetchBlobStreamsVerified(t *testing.T, target Target, seed Fixture) {
	reader, size, err := target.Client.FetchBlob(ctx(), seed.Repository, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if !bytes.Equal(got, seed.Layer.Bytes) {
		t.Errorf("blob = %d bytes, want %d", len(got), len(seed.Layer.Bytes))
	}
	if size >= 0 && size != int64(len(seed.Layer.Bytes)) {
		t.Errorf("size = %d, want %d or -1", size, len(seed.Layer.Bytes))
	}
}

func testFetchBlobUnknownDigest(t *testing.T, target Target, seed Fixture) {
	_, _, err := target.Client.FetchBlob(ctx(), seed.Repository, seed.MissingDigest)
	requireErrIs(t, err, proxy.ErrNotFound, "FetchBlob on an absent digest")
}

func testContextCancellation(t *testing.T, target Target, seed Fixture) {
	cancelled, cancel := context.WithCancel(ctx())
	cancel()

	if _, err := target.Client.ResolveTag(cancelled, seed.Repository, seed.Tag, proxy.Conditional{}); err == nil {
		t.Error("ResolveTag with a cancelled context returned no error")
	} else if !errors.Is(err, context.Canceled) {
		t.Errorf("ResolveTag with a cancelled context: got %v, want context.Canceled", err)
	}
}

// --- fault cases ---

func testManifestDigestMismatch(t *testing.T, client proxy.Client, seed Fixture) {
	body, mediaType, err := client.FetchManifest(ctx(), seed.Repository, seed.Manifest.Digest)
	requireErrIs(t, err, proxy.ErrDigestMismatch, "FetchManifest against a lying upstream")
	if body != nil || mediaType != "" {
		t.Errorf("FetchManifest returned %d bytes and media type %q alongside a mismatch: "+
			"unverified content must never reach a caller", len(body), mediaType)
	}
}

func testBlobCorrupt(t *testing.T, client proxy.Client, seed Fixture) {
	reader, _, err := client.FetchBlob(ctx(), seed.Repository, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := io.ReadAll(reader)
	requireErrIs(t, err, proxy.ErrDigestMismatch, "reading a corrupt blob")
	if len(got) >= len(seed.Layer.Bytes) {
		t.Errorf("read %d of %d bytes before failing: the stream must end short, "+
			"so a client's own digest check cannot pass", len(got), len(seed.Layer.Bytes))
	}
}

func testBlobTruncated(t *testing.T, client proxy.Client, seed Fixture) {
	reader, _, err := client.FetchBlob(ctx(), seed.Repository, seed.Layer.Digest)
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := io.ReadAll(reader)
	if err == nil {
		t.Fatal("reading a truncated blob succeeded")
	}
	if len(got) >= len(seed.Layer.Bytes) {
		t.Errorf("read %d of %d bytes from a truncated body", len(got), len(seed.Layer.Bytes))
	}
}

func testBearerChallenge(t *testing.T, client proxy.Client, seed Fixture) {
	resolution, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	if err != nil {
		t.Fatalf("ResolveTag through a bearer challenge: %v", err)
	}
	if resolution.Digest != seed.Manifest.Digest {
		t.Errorf("Digest = %s, want %s", resolution.Digest, seed.Manifest.Digest)
	}

	// The second call must reuse the token rather than dancing again; it is
	// asserted through behaviour that must not change, not through a counter,
	// because a Client is free to cache or not so long as it stays correct.
	if _, _, err := client.FetchManifest(ctx(), seed.Repository, seed.Manifest.Digest); err != nil {
		t.Errorf("FetchManifest after a completed challenge: %v", err)
	}
}

func testBearerTokenRejected(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrUnauthorized, "ResolveTag when the token endpoint refuses")
}

func testMalformedChallenge(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrUnauthorized, "ResolveTag against an unparseable challenge")
}

func testRateLimited(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrRateLimited, "ResolveTag against a throttling upstream")

	var limited *proxy.RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("error %v does not carry a *proxy.RateLimitedError", err)
	}
	if !limited.HasRetryAfter {
		t.Error("HasRetryAfter = false, but the upstream sent a Retry-After")
	}
	if limited.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %s, want the delay the upstream asked for", limited.RetryAfter)
	}

	state := client.RateLimit()
	if state.RetryAfter != limited.RetryAfter {
		t.Errorf("RateLimit().RetryAfter = %s, want %s", state.RetryAfter, limited.RetryAfter)
	}
	if state.Until.IsZero() {
		t.Error("RateLimit().Until is zero after a 429 with a Retry-After")
	}
}

func testRateLimitedNoRetryAfter(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrRateLimited, "ResolveTag against a throttling upstream")

	var limited *proxy.RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("error %v does not carry a *proxy.RateLimitedError", err)
	}
	if limited.HasRetryAfter {
		t.Error("HasRetryAfter = true, but the upstream sent none: an invented delay is a lie to the backoff")
	}
}

func testRateLimitHeaders(t *testing.T, client proxy.Client, seed Fixture) {
	if state := client.RateLimit(); state.Known {
		t.Error("RateLimit() reports known headroom before any request was made")
	}
	if _, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{}); err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}

	state := client.RateLimit()
	if !state.Known {
		t.Fatal("RateLimit().Known = false after an upstream sent rate-limit headers")
	}
	if state.Limit <= 0 || state.Remaining < 0 || state.Remaining > state.Limit {
		t.Errorf("RateLimit() = limit %d, remaining %d: not a usable gauge", state.Limit, state.Remaining)
	}
	if state.Window <= 0 {
		t.Errorf("RateLimit().Window = %s, want the window the upstream declared", state.Window)
	}
	if state.Observed.IsZero() {
		t.Error("RateLimit().Observed is zero after an observation")
	}
}

func testRedirectLoop(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrRedirectRefused, "ResolveTag into a redirect loop")
}

func testRedirectOffHost(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrRedirectRefused, "ResolveTag redirected off the upstream's host")
}

func testServerError(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrUpstreamUnavailable, "ResolveTag against a failing upstream")
}

func testUnreachable(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrUpstreamUnavailable, "ResolveTag against an unreachable upstream")

	if _, _, err := client.FetchBlob(ctx(), seed.Repository, seed.Layer.Digest); !errors.Is(err, proxy.ErrUpstreamUnavailable) {
		t.Errorf("FetchBlob against an unreachable upstream: got %v, want ErrUpstreamUnavailable", err)
	}
}

func testStalledHeaders(t *testing.T, client proxy.Client, seed Fixture) {
	_, err := client.ResolveTag(ctx(), seed.Repository, seed.Tag, proxy.Conditional{})
	requireErrIs(t, err, proxy.ErrUpstreamUnavailable, "ResolveTag against an upstream that never answers")

	// The caller's context was never cancelled, so the failure must not
	// masquerade as one: a caller that saw context.Canceled here would blame
	// itself for the upstream's silence.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a client-side timeout surfaced as a context error: %v", err)
	}
}
