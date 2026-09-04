package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// The fake upstream is what the behaviour half of the contract suite runs
// against, and it also runs the content half -- which is the point. A fake
// that passes the same cases a real registry:2 passes is one the cache, lease,
// and single-flight tasks can be built on without wondering whether it lies.

const fakeToken = "fake-bearer-token"

// upstream is a controllable distribution-API server.
type upstream struct {
	seed   clienttest.Fixture
	fault  clienttest.Fault
	faulty bool

	mu       sync.Mutex
	tags     map[string]clienttest.Content
	byDigest map[blob.Digest]clienttest.Content
	blobs    map[blob.Digest]clienttest.Content
	tokens   int

	server *httptest.Server
}

// newUpstream starts a well-behaved upstream seeded with the fixture.
func newUpstream(t *testing.T, seed clienttest.Fixture) *upstream {
	t.Helper()
	return startUpstream(t, seed, 0, false)
}

// newFaultyUpstream starts an upstream that misbehaves in the named way.
func newFaultyUpstream(t *testing.T, seed clienttest.Fixture, fault clienttest.Fault) *upstream {
	t.Helper()
	return startUpstream(t, seed, fault, true)
}

func startUpstream(t *testing.T, seed clienttest.Fixture, fault clienttest.Fault, faulty bool) *upstream {
	t.Helper()

	u := &upstream{
		seed:     seed,
		fault:    fault,
		faulty:   faulty,
		tags:     map[string]clienttest.Content{seed.Tag: seed.Manifest},
		byDigest: map[blob.Digest]clienttest.Content{},
		blobs:    map[blob.Digest]clienttest.Content{},
	}
	for _, manifest := range []clienttest.Content{seed.Manifest, seed.Next} {
		u.byDigest[manifest.Digest] = manifest
	}
	for _, content := range seed.Blobs {
		u.blobs[content.Digest] = content
	}

	u.server = httptest.NewServer(u)
	t.Cleanup(u.server.Close)
	return u
}

// url is the upstream's root.
func (u *upstream) url() string { return u.server.URL }

// retag repoints the fixture tag.
func (u *upstream) retag(_ *testing.T, to clienttest.Content) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tags[u.seed.Tag] = to
	u.byDigest[to.Digest] = to
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u.faulty && u.serveFault(w, r) {
		return
	}
	u.serveRegistry(w, r)
}

// serveFault applies the configured misbehaviour, reporting whether it
// answered the request itself.
func (u *upstream) serveFault(w http.ResponseWriter, r *http.Request) bool {
	switch u.fault {
	case clienttest.FaultRateLimited:
		w.Header().Set("Retry-After", "12")
		w.Header().Set("RateLimit-Limit", "100;w=21600")
		w.Header().Set("RateLimit-Remaining", "0;w=21600")
		w.WriteHeader(http.StatusTooManyRequests)
		return true

	case clienttest.FaultRateLimitedNoRetryAfter:
		w.WriteHeader(http.StatusTooManyRequests)
		return true

	case clienttest.FaultRateLimitHeaders:
		w.Header().Set("RateLimit-Limit", "100;w=21600")
		w.Header().Set("RateLimit-Remaining", "76;w=21600")
		return false

	case clienttest.FaultServerError:
		w.WriteHeader(http.StatusInternalServerError)
		return true

	case clienttest.FaultStalledHeaders:
		// Never answer. The client's own header-phase timeout is what has to
		// end this, which is exactly what the case asserts.
		<-r.Context().Done()
		return true

	case clienttest.FaultRedirectLoop:
		http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
		return true

	case clienttest.FaultRedirectOffHost:
		http.Redirect(w, r, "http://registry.example.com"+r.URL.Path, http.StatusTemporaryRedirect)
		return true

	case clienttest.FaultBearerChallenge, clienttest.FaultBearerTokenRejected:
		return u.serveBearer(w, r)

	case clienttest.FaultMalformedChallenge:
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return true

	case clienttest.FaultManifestDigestMismatch:
		if strings.Contains(r.URL.Path, "/manifests/") {
			u.serveWrongBytes(w, r, u.seed.Manifest, false)
			return true
		}
		return false

	case clienttest.FaultBlobCorrupt:
		if strings.Contains(r.URL.Path, "/blobs/") {
			u.serveWrongBytes(w, r, u.seed.Layer, false)
			return true
		}
		return false

	case clienttest.FaultBlobTruncated:
		if strings.Contains(r.URL.Path, "/blobs/") {
			u.serveWrongBytes(w, r, u.seed.Layer, true)
			return true
		}
		return false

	default:
		return false
	}
}

// serveWrongBytes answers with content that does not hash to what was asked
// for: either the right length and the wrong bytes, or a promise of more bytes
// than arrive.
func (u *upstream) serveWrongBytes(w http.ResponseWriter, r *http.Request, real clienttest.Content, truncate bool) {
	corrupt := make([]byte, len(real.Bytes))
	copy(corrupt, real.Bytes)
	for i := range corrupt {
		corrupt[i] ^= 0xff
	}

	w.Header().Set("Content-Type", real.MediaType)
	w.Header().Set("Docker-Content-Digest", real.Digest.String())
	w.Header().Set("Content-Length", strconv.Itoa(len(corrupt)))
	if truncate {
		// Promise the whole blob, send less of the real content: the caller
		// must not be able to finish the read.
		_, _ = w.Write(real.Bytes[:len(real.Bytes)/2])
		return
	}
	_, _ = w.Write(corrupt)
}

// serveBearer implements the upstream half of the token dance.
func (u *upstream) serveBearer(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/token" {
		u.mu.Lock()
		u.tokens++
		u.mu.Unlock()

		if u.fault == clienttest.FaultBearerTokenRejected {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fakeToken, "expires_in": 300})
		return true
	}

	if r.Header.Get("Authorization") != "Bearer "+fakeToken {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="`+u.server.URL+`/token",service="fake-registry",scope="repository:`+u.seed.Repository+`:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	return false
}

// serveRegistry is the well-behaved distribution API over the fixture.
func (u *upstream) serveRegistry(w http.ResponseWriter, r *http.Request) {
	repository, kind, reference, ok := splitRegistryPath(r.URL.Path)
	if !ok || repository != u.seed.Repository {
		http.Error(w, "NAME_UNKNOWN", http.StatusNotFound)
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	var content clienttest.Content
	var found bool
	switch kind {
	case "manifests":
		if digest, err := blob.ParseDigest(reference); err == nil {
			content, found = u.byDigest[digest]
		} else {
			content, found = u.tags[reference]
		}
	case "blobs":
		digest, err := blob.ParseDigest(reference)
		if err != nil {
			http.Error(w, "DIGEST_INVALID", http.StatusBadRequest)
			return
		}
		content, found = u.blobs[digest]
	}
	if !found {
		http.Error(w, "UNKNOWN", http.StatusNotFound)
		return
	}

	etag := `"` + content.Digest.String() + `"`
	w.Header().Set("Content-Type", content.MediaType)
	w.Header().Set("Docker-Content-Digest", content.Digest.String())
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(content.Bytes)))

	if r.Header.Get("If-None-Match") == etag {
		w.Header().Del("Content-Length")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(content.Bytes)
}

// splitRegistryPath takes a distribution path apart. The repository name is
// everything between /v2/ and the last /manifests/ or /blobs/, which is the
// only way to parse it: repository names contain slashes.
func splitRegistryPath(path string) (repository, kind, reference string, ok bool) {
	rest, found := strings.CutPrefix(path, "/v2/")
	if !found {
		return "", "", "", false
	}
	for _, candidate := range []string{"manifests", "blobs"} {
		marker := "/" + candidate + "/"
		if i := strings.LastIndex(rest, marker); i > 0 {
			return rest[:i], candidate, rest[i+len(marker):], true
		}
	}
	return "", "", "", false
}

// recordingTransport records every request and how many body bytes came back,
// which is what the contract suite reads to prove a revalidation transferred
// no manifest.
type recordingTransport struct {
	base http.RoundTripper

	mu       sync.Mutex
	requests []*recordedRequest
}

type recordedRequest struct {
	method string
	path   string
	bytes  atomic.Int64
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	record := &recordedRequest{method: req.Method, path: req.URL.Path}
	t.mu.Lock()
	t.requests = append(t.requests, record)
	t.mu.Unlock()

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &countingBody{ReadCloser: resp.Body, counter: &record.bytes}
	return resp, nil
}

// snapshot renders the records for the contract suite.
func (t *recordingTransport) snapshot() []clienttest.Request {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]clienttest.Request, 0, len(t.requests))
	for _, record := range t.requests {
		out = append(out, clienttest.Request{
			Method:        record.method,
			Path:          record.path,
			ResponseBytes: record.bytes.Load(),
		})
	}
	return out
}

// countingBody totals what a response body actually delivered.
type countingBody struct {
	io.ReadCloser
	counter *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.counter.Add(int64(n))
	return n, err
}
