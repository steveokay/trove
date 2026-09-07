package registry_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/registry"
)

// Dispatch by repository type (C-017): a read of a proxy or a group goes to a
// delegate, a read of a hosted repository does not, and a delegate that is not
// wired is a repository that does not exist.

// fakeServer is a ContentServer a test drives.
type fakeServer struct {
	manifest registry.ServedManifest
	blob     registry.ServedBlob
	err      error

	mu        sync.Mutex
	manifests []string
	blobs     []string
}

func (f *fakeServer) Manifest(_ context.Context, repo, reference string) (registry.ServedManifest, error) {
	f.mu.Lock()
	f.manifests = append(f.manifests, repo+"@"+reference)
	f.mu.Unlock()
	if f.err != nil {
		return registry.ServedManifest{}, f.err
	}
	return f.manifest, nil
}

func (f *fakeServer) Blob(_ context.Context, repo string, digest blob.Digest) (registry.ServedBlob, error) {
	f.mu.Lock()
	f.blobs = append(f.blobs, repo+"@"+digest.String())
	f.mu.Unlock()
	if f.err != nil {
		return registry.ServedBlob{}, f.err
	}
	return f.blob, nil
}

func (f *fakeServer) asked() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.manifests...), append([]string(nil), f.blobs...)
}

// countingBody is a blob body that reports whether the handler closed it.
type countingBody struct {
	*strings.Reader
	mu     sync.Mutex
	closed int
}

func newBody(content string) *countingBody {
	return &countingBody{Reader: strings.NewReader(content)}
}

func (b *countingBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed++
	return nil
}

func (b *countingBody) closes() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// servedManifest is a manifest a delegate can produce, with its real digest.
func servedManifest() registry.ServedManifest {
	payload := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	return registry.ServedManifest{
		Digest:    blob.FromBytes(blob.SHA256, payload),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   payload,
	}
}

func withServers(servers registry.ContentServers) func(*stackOptions) {
	return func(o *stackOptions) { o.servers = servers }
}

func withPulls(recorder registry.PullRecorder) func(*stackOptions) {
	return func(o *stackOptions) { o.pulls = recorder }
}

// TestProxyAndGroupReadsReachTheirDelegate is the branch itself: the same
// request that 404s against hosted storage is answered by the delegate, and
// the response is rendered by the registry rather than by the delegate.
func TestProxyAndGroupReadsReachTheirDelegate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		repo string
		wire func(*fakeServer) registry.ContentServers
	}{
		{
			name: "proxy",
			repo: "mirror/library/nginx",
			wire: func(f *fakeServer) registry.ContentServers { return registry.ContentServers{Proxy: f} },
		},
		{
			name: "group",
			repo: "fleet/library/nginx",
			wire: func(f *fakeServer) registry.ContentServers { return registry.ContentServers{Group: f} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			manifest := servedManifest()
			body := newBody("delegated layer bytes")
			layer := blob.FromBytes(blob.SHA256, []byte("delegated layer bytes"))
			delegate := &fakeServer{
				manifest: manifest,
				blob:     registry.ServedBlob{Content: body, Size: int64(body.Len()), Digest: layer},
			}
			s := newStack(t, withServers(tc.wire(delegate)))

			got := s.do(t, http.MethodGet, "/v2/"+tc.repo+"/manifests/v1", "rita", "")
			if got.Code != http.StatusOK {
				t.Fatalf("manifest GET: %d %s", got.Code, got.Body)
			}
			if got.Body.String() != string(manifest.Payload) {
				t.Errorf("body = %q, want the delegate's payload", got.Body)
			}
			// Rendered by the registry, so a delegated response is
			// indistinguishable from a hosted one on the wire (R-008).
			if h := got.Header().Get("Docker-Content-Digest"); h != manifest.Digest.String() {
				t.Errorf("Docker-Content-Digest = %q, want %s", h, manifest.Digest)
			}
			if h := got.Header().Get("Content-Type"); h != manifest.MediaType {
				t.Errorf("Content-Type = %q, want %s", h, manifest.MediaType)
			}
			if h := got.Header().Get("Content-Length"); h != strconv.Itoa(len(manifest.Payload)) {
				t.Errorf("Content-Length = %q, want %d", h, len(manifest.Payload))
			}

			blobGet := s.do(t, http.MethodGet, "/v2/"+tc.repo+"/blobs/"+layer.String(), "rita", "")
			if blobGet.Code != http.StatusOK {
				t.Fatalf("blob GET: %d %s", blobGet.Code, blobGet.Body)
			}
			if blobGet.Body.String() != "delegated layer bytes" {
				t.Errorf("blob body = %q", blobGet.Body)
			}
			if h := blobGet.Header().Get("Content-Type"); h != "application/octet-stream" {
				t.Errorf("blob Content-Type = %q", h)
			}
			if body.closes() == 0 {
				t.Error("the handler did not close the delegate's content; a fill would never learn the client left")
			}

			manifests, blobs := delegate.asked()
			if len(manifests) != 1 || manifests[0] != tc.repo+"@v1" {
				t.Errorf("delegate was asked for %v, want the full content name and the reference as written", manifests)
			}
			if len(blobs) != 1 {
				t.Errorf("delegate blob calls = %v, want 1", blobs)
			}
		})
	}
}

// TestHostedReadsNeverReachADelegate: wiring a proxy server must not change
// what a hosted repository does. The delegate fails the test if it is called
// at all.
func TestHostedReadsNeverReachADelegate(t *testing.T) {
	t.Parallel()

	delegate := &fakeServer{err: registry.ErrUpstreamUnavailable}
	s := newStack(t, withServers(registry.ContentServers{Proxy: delegate, Group: delegate}))

	// A hosted pull of content that does not exist is still the hosted 404,
	// not a delegated anything.
	got := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "rita", "")
	if got.Code != http.StatusNotFound {
		t.Fatalf("hosted GET of absent content: %d %s", got.Code, got.Body)
	}
	if manifests, blobs := delegate.asked(); len(manifests)+len(blobs) != 0 {
		t.Errorf("a hosted read reached the delegate: %v %v", manifests, blobs)
	}
}

// TestUnwiredDelegateIsIndistinguishableFromAMissingRepository is the
// disclosure rule. A deployment that has not wired proxying must not let a
// stranger learn that from a response, so the answer is the one an unknown
// repository gives -- status, code, and body.
func TestUnwiredDelegateIsIndistinguishableFromAMissingRepository(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	layer := blob.FromBytes(blob.SHA256, []byte("anything"))

	for _, tc := range []struct {
		name    string
		method  string
		unwired string
		missing string
	}{
		{
			name: "manifest GET", method: http.MethodGet,
			unwired: "/v2/mirror/library/nginx/manifests/v1",
			missing: "/v2/ghost/library/nginx/manifests/v1",
		},
		{
			name: "manifest HEAD", method: http.MethodHead,
			unwired: "/v2/mirror/library/nginx/manifests/v1",
			missing: "/v2/ghost/library/nginx/manifests/v1",
		},
		{
			name: "blob GET", method: http.MethodGet,
			unwired: "/v2/mirror/library/nginx/blobs/" + layer.String(),
			missing: "/v2/ghost/library/nginx/blobs/" + layer.String(),
		},
		{
			name: "blob HEAD", method: http.MethodHead,
			unwired: "/v2/mirror/library/nginx/blobs/" + layer.String(),
			missing: "/v2/ghost/library/nginx/blobs/" + layer.String(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// carol holds both `mirror/*` and `ghost/*`, so neither answer is
			// the guard's -- both come from the handler, which is what makes
			// them comparable.
			unwired := s.do(t, tc.method, tc.unwired, "carol", "")
			missing := s.do(t, tc.method, tc.missing, "carol", "")

			if unwired.Code != http.StatusNotFound {
				t.Fatalf("unwired proxy read: %d %s", unwired.Code, unwired.Body)
			}
			if unwired.Code != missing.Code {
				t.Errorf("status %d for an unwired proxy, %d for a missing repository", unwired.Code, missing.Code)
			}
			if unwired.Body.String() != missing.Body.String() {
				t.Errorf("bodies differ:\n unwired: %s\n missing: %s", unwired.Body, missing.Body)
			}
		})
	}
}

// TestDelegateFailuresMapToSpecCodes: the closed set a delegate may report,
// and what a client sees for each. The distinctions are the ones a client can
// act on -- not here, try later, not now -- and an unclassified failure is a
// bug rather than a condition to render.
func TestDelegateFailuresMapToSpecCodes(t *testing.T) {
	t.Parallel()

	layer := blob.FromBytes(blob.SHA256, []byte("anything"))
	for _, tc := range []struct {
		name     string
		err      error
		status   int
		code     string
		blobCode string
	}{
		{
			name: "content unknown", err: registry.ErrContentUnknown,
			status: http.StatusNotFound, code: "MANIFEST_UNKNOWN", blobCode: "BLOB_UNKNOWN",
		},
		{
			name: "throttled", err: registry.ErrUpstreamThrottled,
			status: http.StatusTooManyRequests, code: "TOOMANYREQUESTS", blobCode: "TOOMANYREQUESTS",
		},
		{
			// Not a 404: the repository exists and could not be consulted, and
			// a client that read an outage as a deletion would be wrong in the
			// most expensive direction.
			name: "unavailable", err: registry.ErrUpstreamUnavailable,
			status: http.StatusGatewayTimeout, code: "UNKNOWN", blobCode: "UNKNOWN",
		},
		{
			name: "anything else", err: io.ErrUnexpectedEOF,
			status: http.StatusInternalServerError, code: "UNKNOWN", blobCode: "UNKNOWN",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newStack(t, withServers(registry.ContentServers{Proxy: &fakeServer{err: tc.err}}))

			manifest := s.do(t, http.MethodGet, "/v2/mirror/library/nginx/manifests/v1", "rita", "")
			if manifest.Code != tc.status {
				t.Errorf("manifest status = %d, want %d (%s)", manifest.Code, tc.status, manifest.Body)
			}
			if !strings.Contains(manifest.Body.String(), tc.code) {
				t.Errorf("manifest body %s does not carry %s", manifest.Body, tc.code)
			}

			blobGet := s.do(t, http.MethodGet, "/v2/mirror/library/nginx/blobs/"+layer.String(), "rita", "")
			if blobGet.Code != tc.status {
				t.Errorf("blob status = %d, want %d (%s)", blobGet.Code, tc.status, blobGet.Body)
			}
			if !strings.Contains(blobGet.Body.String(), tc.blobCode) {
				t.Errorf("blob body %s does not carry %s", blobGet.Body, tc.blobCode)
			}
		})
	}
}

// TestDelegatedHeadSendsHeadersWithoutABody, including for a blob, where the
// content is opened and closed unread: a proxy answers "is this available" by
// being able to produce it.
func TestDelegatedHeadSendsHeadersWithoutABody(t *testing.T) {
	t.Parallel()

	manifest := servedManifest()
	body := newBody("delegated layer bytes")
	layer := blob.FromBytes(blob.SHA256, []byte("delegated layer bytes"))
	delegate := &fakeServer{
		manifest: manifest,
		blob:     registry.ServedBlob{Content: body, Size: int64(body.Len()), Digest: layer},
	}
	s := newStack(t, withServers(registry.ContentServers{Proxy: delegate}))

	head := s.do(t, http.MethodHead, "/v2/mirror/library/nginx/manifests/v1", "rita", "")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("manifest HEAD: %d, %d body bytes", head.Code, head.Body.Len())
	}
	if h := head.Header().Get("Docker-Content-Digest"); h != manifest.Digest.String() {
		t.Errorf("HEAD Docker-Content-Digest = %q", h)
	}

	blobHead := s.do(t, http.MethodHead, "/v2/mirror/library/nginx/blobs/"+layer.String(), "rita", "")
	if blobHead.Code != http.StatusOK || blobHead.Body.Len() != 0 {
		t.Errorf("blob HEAD: %d, %d body bytes", blobHead.Code, blobHead.Body.Len())
	}
	if h := blobHead.Header().Get("Content-Length"); h != strconv.Itoa(len("delegated layer bytes")) {
		t.Errorf("blob HEAD Content-Length = %q", h)
	}
	if body.closes() == 0 {
		t.Error("a HEAD opened the content and never closed it")
	}
}

// TestDelegatedBlobOfUnknownSizeOmitsContentLength: an upstream that sent no
// length leaves the header off rather than guessing one, because a wrong
// Content-Length is worse than none.
func TestDelegatedBlobOfUnknownSizeOmitsContentLength(t *testing.T) {
	t.Parallel()

	body := newBody("bytes of unknown length")
	layer := blob.FromBytes(blob.SHA256, []byte("bytes of unknown length"))
	delegate := &fakeServer{blob: registry.ServedBlob{Content: body, Size: -1, Digest: layer}}
	s := newStack(t, withServers(registry.ContentServers{Proxy: delegate}))

	got := s.do(t, http.MethodGet, "/v2/mirror/library/nginx/blobs/"+layer.String(), "rita", "")
	if got.Code != http.StatusOK {
		t.Fatalf("blob GET: %d %s", got.Code, got.Body)
	}
	if h := got.Header().Get("Content-Length"); h != "" {
		t.Errorf("Content-Length = %q, want it omitted for an unknown size", h)
	}
	if got.Body.String() != "bytes of unknown length" {
		t.Errorf("body = %q", got.Body)
	}
}

// TestDelegatedPullsAreCountedLikeHostedOnes: a GET through a proxy is a pull
// and feeds the same statistics and the same retention rules; a HEAD is a
// probe and is not counted (R-010).
func TestDelegatedPullsAreCountedLikeHostedOnes(t *testing.T) {
	t.Parallel()

	recorder := &recordingPulls{}
	delegate := &fakeServer{manifest: servedManifest()}
	s := newStack(t, withServers(registry.ContentServers{Proxy: delegate}), withPulls(recorder))

	s.do(t, http.MethodHead, "/v2/mirror/library/nginx/manifests/v1", "rita", "")
	if got := recorder.records(); len(got) != 0 {
		t.Errorf("a HEAD was counted as a pull: %v", got)
	}

	s.do(t, http.MethodGet, "/v2/mirror/library/nginx/manifests/v1", "rita", "")
	got := recorder.records()
	if len(got) != 1 || got[0] != "mirror/library/nginx@v1" {
		t.Errorf("pull records = %v, want the delegated GET counted once", got)
	}
}

// TestProxyAndGroupStillRefuseWrites: dispatch changed the read path only. A
// push is refused by type, with DENIED rather than a 404, because the
// repository does exist -- it just does not take client writes (ADR 0005).
func TestProxyAndGroupStillRefuseWrites(t *testing.T) {
	t.Parallel()

	delegate := &fakeServer{manifest: servedManifest()}
	s := newStack(t, withServers(registry.ContentServers{Proxy: delegate, Group: delegate}))

	for _, repo := range []string{"mirror/library/nginx", "fleet/library/nginx"} {
		got := s.do(t, http.MethodPost, "/v2/"+repo+"/blobs/uploads/", "carol", "")
		if got.Code != http.StatusForbidden {
			t.Errorf("%s upload start: %d %s, want 403", repo, got.Code, got.Body)
		}
		if !strings.Contains(got.Body.String(), "DENIED") {
			t.Errorf("%s refusal does not carry DENIED: %s", repo, got.Body)
		}
	}
}

// recordingPulls captures what the pull recorder was told.
type recordingPulls struct {
	mu   sync.Mutex
	seen []string
}

func (p *recordingPulls) Record(repo, reference string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, repo+"@"+reference)
}

func (p *recordingPulls) records() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

// failingWriter accepts headers and then refuses the body, standing in for a
// client that hung up mid-response.
type failingWriter struct {
	header http.Header
	code   int
}

func (f *failingWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}

func (f *failingWriter) WriteHeader(code int)      { f.code = code }
func (f *failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// TestADelegatedResponseThatCannotBeWrittenIsLoggedNotRetried: the status line
// is already gone by the time the body fails, so there is no error response to
// send. What matters is that the handler returns rather than trying to turn a
// half-sent response into an error one -- and that the failure is recorded,
// because a stream that ended short is either a client that hung up or an
// upstream that lied, and only one of those is nobody's fault.
func TestADelegatedResponseThatCannotBeWrittenIsLoggedNotRetried(t *testing.T) {
	t.Parallel()

	manifest := servedManifest()
	body := newBody("delegated layer bytes")
	layer := blob.FromBytes(blob.SHA256, []byte("delegated layer bytes"))
	delegate := &fakeServer{
		manifest: manifest,
		blob:     registry.ServedBlob{Content: body, Size: int64(body.Len()), Digest: layer},
	}
	s := newStack(t, withServers(registry.ContentServers{Proxy: delegate}))

	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "manifest", target: "/v2/mirror/library/nginx/manifests/v1"},
		{name: "blob", target: "/v2/mirror/library/nginx/blobs/" + layer.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Header.Set("X-Test-Subject", "rita")
			writer := &failingWriter{}

			s.handler.ServeHTTP(writer, req)

			// The response began: a failure to write the body cannot unsend
			// the 200 that was already committed.
			if writer.code != http.StatusOK {
				t.Errorf("status = %d, want the 200 that was already sent", writer.code)
			}
		})
	}
}

// TestADelegatedHeadFailureIsMapped: HEAD goes through the same error mapping
// as GET. It is asserted separately because it is a separate code path -- the
// one that opens the content only to close it.
func TestADelegatedHeadFailureIsMapped(t *testing.T) {
	t.Parallel()

	layer := blob.FromBytes(blob.SHA256, []byte("anything"))
	s := newStack(t, withServers(registry.ContentServers{
		Proxy: &fakeServer{err: registry.ErrContentUnknown},
	}))

	got := s.do(t, http.MethodHead, "/v2/mirror/library/nginx/blobs/"+layer.String(), "rita", "")
	if got.Code != http.StatusNotFound {
		t.Errorf("blob HEAD through a failing delegate: %d, want 404", got.Code)
	}
}
