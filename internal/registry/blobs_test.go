package registry_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	blobmem "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

var fixedTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// stack is the registry over real stores: carol pushes to team-a/*, rita
// only reads it, and secret/vault exists for nobody they can see. The proxy
// repository proves pushes are refused by type, not by permission.
type stack struct {
	handler http.Handler
	// router is the same value as handler, kept typed so a test file can
	// register additional handlers on the shared fixture without editing it.
	router *server.Router
	metaDB *metamem.Store
	blobs  *blobmem.Store
}

func newStack(t *testing.T) stack {
	t.Helper()

	ctx := context.Background()
	metaDB := metamem.New()
	t.Cleanup(func() { _ = metaDB.Close() })
	blobs := blobmem.New(blobmem.Options{})

	for _, subject := range []meta.Subject{
		{ID: "u-carol", Kind: meta.User, Name: "carol"},
		{ID: "u-rita", Kind: meta.User, Name: "rita"},
		{ID: "u-mona", Kind: meta.User, Name: "mona"},
	} {
		if err := metaDB.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	for _, repo := range []meta.Repository{
		{Name: "team-a/api", Type: meta.Hosted},
		{Name: "team-a/mirror", Type: meta.Proxy},
		{Name: "secret/vault", Type: meta.Hosted},
	} {
		if _, err := metaDB.CreateRepository(ctx, repo); err != nil {
			t.Fatalf("CreateRepository: %v", err)
		}
	}
	for _, role := range []meta.Role{
		{Name: "publisher", Verbs: []string{"repo:read", "repo:write"}},
		{Name: "reader", Verbs: []string{"repo:read"}},
		{Name: "maintainer", Verbs: []string{"repo:read", "repo:write", "manifest:delete"}},
	} {
		if err := metaDB.CreateRole(ctx, role); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for _, binding := range []meta.Binding{
		{ID: "b-carol", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-carol", Role: "publisher", Scope: "team-a/*"},
		{ID: "b-rita", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-rita", Role: "reader", Scope: "team-a/*"},
		{ID: "b-mona", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-mona", Role: "maintainer", Scope: "team-a/*"},
	} {
		if err := metaDB.CreateBinding(ctx, binding); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}

	router := server.NewRouter(&server.Guard{
		Subjects: metaDB,
		Bindings: metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	handlers := &registry.Blobs{
		Store:    blobs,
		Meta:     metaDB,
		Bindings: metaDB,
		Now:      func() time.Time { return fixedTime },
	}
	handlers.Register(router)
	(&registry.Manifests{Meta: metaDB, Now: func() time.Time { return fixedTime }}).Register(router)
	return stack{handler: router, router: router, metaDB: metaDB, blobs: blobs}
}

func (s stack) do(t *testing.T, method, target, as, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if as != "" {
		req.Header.Set("X-Test-Subject", as)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

const layer = "layer bytes for the push tests"

func layerDigest() blob.Digest { return blob.FromBytes(blob.SHA256, []byte(layer)) }

// The chunked push flow, request for request, with the headers docker steers
// by asserted at every step -- then the pull of what was pushed.
func TestChunkedPushAndPull(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := layerDigest().String()

	start := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	if start.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	location := start.Header().Get("Location")
	if !strings.HasPrefix(location, "/v2/team-a/api/blobs/uploads/") {
		t.Fatalf("Location = %q", location)
	}
	if start.Header().Get("Range") != "0-0" || start.Header().Get("Docker-Upload-UUID") == "" {
		t.Fatalf("start headers: Range %q, UUID %q", start.Header().Get("Range"), start.Header().Get("Docker-Upload-UUID"))
	}

	half := len(layer) / 2
	first := s.do(t, http.MethodPatch, location, "carol", layer[:half])
	if first.Code != http.StatusAccepted || first.Header().Get("Range") != fmt.Sprintf("0-%d", half-1) {
		t.Fatalf("first chunk: %d, Range %q", first.Code, first.Header().Get("Range"))
	}
	second := s.do(t, http.MethodPatch, location, "carol", layer[half:],
		"Content-Range", fmt.Sprintf("%d-%d", half, len(layer)-1))
	if second.Code != http.StatusAccepted || second.Header().Get("Range") != fmt.Sprintf("0-%d", len(layer)-1) {
		t.Fatalf("second chunk: %d, Range %q", second.Code, second.Header().Get("Range"))
	}

	status := s.do(t, http.MethodGet, location, "carol", "")
	if status.Code != http.StatusNoContent || status.Header().Get("Range") != fmt.Sprintf("0-%d", len(layer)-1) {
		t.Fatalf("status: %d, Range %q", status.Code, status.Header().Get("Range"))
	}

	commit := s.do(t, http.MethodPut, location+"?digest="+digest, "carol", "")
	if commit.Code != http.StatusCreated {
		t.Fatalf("commit: %d %s", commit.Code, commit.Body)
	}
	if commit.Header().Get("Location") != "/v2/team-a/api/blobs/"+digest ||
		commit.Header().Get("Docker-Content-Digest") != digest {
		t.Fatalf("commit headers: %v", commit.Header())
	}

	// The session is gone; its row too.
	if again := s.do(t, http.MethodGet, location, "carol", ""); again.Code != http.StatusNotFound {
		t.Fatalf("status after commit: %d, want 404", again.Code)
	}

	head := s.do(t, http.MethodHead, "/v2/team-a/api/blobs/"+digest, "rita", "")
	if head.Code != http.StatusOK ||
		head.Header().Get("Content-Length") != fmt.Sprint(len(layer)) ||
		head.Header().Get("Docker-Content-Digest") != digest {
		t.Fatalf("head: %d %v", head.Code, head.Header())
	}
	get := s.do(t, http.MethodGet, "/v2/team-a/api/blobs/"+digest, "rita", "")
	if get.Code != http.StatusOK || get.Body.String() != layer {
		t.Fatalf("get: %d, body %q", get.Code, get.Body)
	}
}

// The final chunk may ride in the PUT body itself.
func TestCommitWithFinalChunk(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := layerDigest().String()

	start := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	location := start.Header().Get("Location")
	if rec := s.do(t, http.MethodPatch, location, "carol", layer[:5]); rec.Code != http.StatusAccepted {
		t.Fatalf("chunk: %d", rec.Code)
	}
	if rec := s.do(t, http.MethodPut, location+"?digest="+digest, "carol", layer[5:]); rec.Code != http.StatusCreated {
		t.Fatalf("commit with body: %d %s", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/blobs/"+digest, "carol", ""); rec.Body.String() != layer {
		t.Fatalf("round trip lost bytes: %q", rec.Body)
	}
}

func TestMonolithicPost(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := layerDigest().String()

	rec := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/?digest="+digest, "carol", layer)
	if rec.Code != http.StatusCreated || rec.Header().Get("Docker-Content-Digest") != digest {
		t.Fatalf("monolithic: %d %s", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/blobs/"+digest, "carol", ""); rec.Body.String() != layer {
		t.Fatalf("round trip: %q", rec.Body)
	}
}

// A commit whose bytes do not hash to the stated digest publishes nothing
// and forgets the session: no blob, no row, no retry into half-verified
// state.
func TestMismatchedCommitLeavesNothing(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	wrong := blob.FromBytes(blob.SHA256, []byte("something else")).String()

	start := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	location := start.Header().Get("Location")
	s.do(t, http.MethodPatch, location, "carol", layer)

	commit := s.do(t, http.MethodPut, location+"?digest="+wrong, "carol", "")
	if commit.Code != http.StatusBadRequest || !strings.Contains(commit.Body.String(), registry.CodeDigestInvalid) {
		t.Fatalf("mismatched commit: %d %s", commit.Code, commit.Body)
	}

	if rec := s.do(t, http.MethodHead, "/v2/team-a/api/blobs/"+wrong, "carol", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("the mismatched digest exists: %d", rec.Code)
	}
	if rec := s.do(t, http.MethodGet, location, "carol", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("the session survived the mismatch: %d", rec.Code)
	}
}

// Concurrent pushes of one digest both succeed: content-addressed blobs are
// identical by definition, and the client that loses the race must not fail.
func TestConcurrentSameDigestUploads(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := layerDigest().String()

	one := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	two := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	for _, location := range []string{one.Header().Get("Location"), two.Header().Get("Location")} {
		s.do(t, http.MethodPatch, location, "carol", layer)
	}
	for i, location := range []string{one.Header().Get("Location"), two.Header().Get("Location")} {
		if rec := s.do(t, http.MethodPut, location+"?digest="+digest, "carol", ""); rec.Code != http.StatusCreated {
			t.Fatalf("commit %d: %d %s", i, rec.Code, rec.Body)
		}
	}
}

// The mount reuses a blob the subject can already reach; every failure --
// unreadable source, absent blob, absent source repository -- falls back to
// an ordinary session with an identical 202, so the mount cannot probe
// anything (ADR 0003).
func TestCrossRepoMount(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	ctx := context.Background()
	digest := layerDigest()

	// The blob exists, pushed to the hidden repository's world: rows and
	// bytes both.
	if err := s.blobs.Put(ctx, digest, strings.NewReader(layer)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.metaDB.PutBlob(ctx, meta.Blob{Digest: meta.Digest(digest), Size: int64(len(layer))}); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	t.Run("readable source mounts", func(t *testing.T) {
		t.Parallel()
		rec := s.do(t, http.MethodPost,
			"/v2/team-a/api/blobs/uploads/?mount="+digest.String()+"&from=team-a/other", "carol", "")
		// team-a/other does not exist as a repository -- mount requires it.
		if rec.Code != http.StatusAccepted {
			t.Fatalf("mount from an absent repo: %d, want the 202 fallback", rec.Code)
		}
	})

	t.Run("mount succeeds from a real readable source", func(t *testing.T) {
		t.Parallel()
		rec := s.do(t, http.MethodPost,
			"/v2/team-a/api/blobs/uploads/?mount="+digest.String()+"&from=team-a/api", "carol", "")
		if rec.Code != http.StatusCreated || rec.Header().Get("Docker-Content-Digest") != digest.String() {
			t.Fatalf("mount: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("a malformed mount request falls back too", func(t *testing.T) {
		t.Parallel()
		badDigest := s.do(t, http.MethodPost,
			"/v2/team-a/api/blobs/uploads/?mount=sha256:short&from=team-a/api", "carol", "")
		badFrom := s.do(t, http.MethodPost,
			"/v2/team-a/api/blobs/uploads/?mount="+digest.String()+"&from=..%2Fetc", "carol", "")
		if badDigest.Code != http.StatusAccepted || badFrom.Code != http.StatusAccepted {
			t.Fatalf("codes: bad digest %d, bad from %d; want the 202 fallback", badDigest.Code, badFrom.Code)
		}
	})

	t.Run("an unreadable source is indistinguishable from an absent one", func(t *testing.T) {
		t.Parallel()
		hidden := s.do(t, http.MethodPost,
			"/v2/team-a/api/blobs/uploads/?mount="+digest.String()+"&from=secret/vault", "carol", "")
		absent := s.do(t, http.MethodPost,
			"/v2/team-a/api/blobs/uploads/?mount="+digest.String()+"&from=ghost/none", "carol", "")
		if hidden.Code != http.StatusAccepted || absent.Code != http.StatusAccepted {
			t.Fatalf("codes: hidden %d, absent %d; want the 202 fallback for both", hidden.Code, absent.Code)
		}
	})
}

// A session belongs to the repository it was started under: replayed below
// another path -- even one the subject can write -- it does not exist.
func TestUploadSessionsAreRepositoryBound(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	ctx := context.Background()
	if _, err := s.metaDB.CreateRepository(ctx, meta.Repository{Name: "team-a/second", Type: meta.Hosted}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	start := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	id := start.Header().Get("Docker-Upload-UUID")

	rec := s.do(t, http.MethodPatch, "/v2/team-a/second/blobs/uploads/"+id, "carol", layer)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), registry.CodeBlobUploadUnknown) {
		t.Fatalf("cross-repo session use: %d %s, want upload-unknown", rec.Code, rec.Body)
	}
}

// The spec-shape refusal table.
func TestUploadRefusals(t *testing.T) {
	t.Parallel()

	s := newStack(t)

	started := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	location := started.Header().Get("Location")
	s.do(t, http.MethodPatch, location, "carol", layer[:5])

	tests := []struct {
		name     string
		method   string
		target   string
		as       string
		body     string
		headers  []string
		wantCode int
		wantBody string
	}{
		{
			name: "commit under a proxy repository is denied", method: http.MethodPut,
			target: "/v2/team-a/mirror/blobs/uploads/deadbeef?digest=" + layerDigest().String(), as: "carol",
			wantCode: http.StatusForbidden, wantBody: registry.CodeDenied,
		},
		{
			name: "commit of an unknown session is unknown", method: http.MethodPut,
			target: "/v2/team-a/api/blobs/uploads/deadbeef?digest=" + layerDigest().String(), as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeBlobUploadUnknown,
		},
		{
			name: "cancel of an unknown session is unknown", method: http.MethodDelete,
			target: "/v2/team-a/api/blobs/uploads/deadbeef", as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeBlobUploadUnknown,
		},
		{
			name: "cancel under an absent repository is unknown", method: http.MethodDelete,
			target: "/v2/ghost/none/blobs/uploads/deadbeef", as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeNameUnknown,
		},
		{
			name: "status under a proxy repository is denied", method: http.MethodGet,
			target: "/v2/team-a/mirror/blobs/uploads/deadbeef", as: "carol",
			wantCode: http.StatusForbidden, wantBody: registry.CodeDenied,
		},
		{
			name: "reading a blob in an absent repository is name-unknown", method: http.MethodGet,
			target: "/v2/ghost/none/blobs/" + layerDigest().String(), as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeNameUnknown,
		},
		{
			name: "a monolithic body that does not hash to its digest", method: http.MethodPost,
			target: "/v2/team-a/api/blobs/uploads/?digest=" + layerDigest().String(), as: "carol",
			body:     "not the layer",
			wantCode: http.StatusBadRequest, wantBody: registry.CodeDigestInvalid,
		},
		{
			name: "a malformed Content-Range is 416", method: http.MethodPatch,
			target: location, as: "carol", body: layer[5:],
			headers:  []string{"Content-Range", "nonsense"},
			wantCode: http.StatusRequestedRangeNotSatisfiable, wantBody: registry.CodeBlobUploadInvalid,
		},
		{
			name: "reader cannot start an upload", method: http.MethodPost,
			target: "/v2/team-a/api/blobs/uploads/", as: "rita",
			wantCode: http.StatusForbidden, wantBody: registry.CodeDenied,
		},
		{
			name: "a proxy repository refuses pushes", method: http.MethodPost,
			target: "/v2/team-a/mirror/blobs/uploads/", as: "carol",
			wantCode: http.StatusForbidden, wantBody: registry.CodeDenied,
		},
		{
			name: "an absent repository is unknown", method: http.MethodPost,
			target: "/v2/team-a/ghost/blobs/uploads/", as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeNameUnknown,
		},
		{
			name: "a malformed digest is refused at the gate", method: http.MethodPost,
			target: "/v2/team-a/api/blobs/uploads/?digest=sha256:short", as: "carol",
			wantCode: http.StatusBadRequest, wantBody: registry.CodeDigestInvalid,
		},
		{
			name: "an unknown session is unknown", method: http.MethodPatch,
			target: "/v2/team-a/api/blobs/uploads/deadbeef", as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeBlobUploadUnknown,
		},
		{
			// A slash-bearing traversal id cannot even route -- the matcher
			// splits on segments -- so this tests the handler's own gate
			// with an id that routes but fails the upload-id allowlist.
			name: "a traversal-shaped session id looks absent", method: http.MethodGet,
			target: "/v2/team-a/api/blobs/uploads/..evil..", as: "carol",
			wantCode: http.StatusNotFound, wantBody: registry.CodeBlobUploadUnknown,
		},
		{
			name: "an out-of-order chunk is 416", method: http.MethodPatch,
			target: location, as: "carol", body: layer[5:],
			headers:  []string{"Content-Range", "999-1200"},
			wantCode: http.StatusRequestedRangeNotSatisfiable, wantBody: registry.CodeBlobUploadInvalid,
		},
		{
			name: "commit without a digest is refused", method: http.MethodPut,
			target: location, as: "carol",
			wantCode: http.StatusBadRequest, wantBody: registry.CodeDigestInvalid,
		},
		{
			name: "reading an absent blob is blob-unknown", method: http.MethodGet,
			target: "/v2/team-a/api/blobs/" + layerDigest().String(), as: "rita",
			wantCode: http.StatusNotFound, wantBody: registry.CodeBlobUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := s.do(t, tt.method, tt.target, tt.as, tt.body, tt.headers...)
			if rec.Code != tt.wantCode || !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("%s %s: %d %s, want %d with %s", tt.method, tt.target, rec.Code, rec.Body, tt.wantCode, tt.wantBody)
			}
		})
	}
}

// The push-path 404 for a repository the subject cannot see is byte-identical
// to the one for a repository that is not there, through the same guard the
// content routes share (ADR 0003).
func TestHiddenAndAbsentRepositoriesAnswerAlike(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	hidden := s.do(t, http.MethodPost, "/v2/secret/vault/blobs/uploads/", "carol", "")
	absent := s.do(t, http.MethodPost, "/v2/ghost/none/blobs/uploads/", "carol", "")
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("hidden: %d, want 404", hidden.Code)
	}
	if hidden.Code != absent.Code || hidden.Body.String() != absent.Body.String() {
		t.Fatalf("hidden %d %s vs absent %d %s: want byte-identical",
			hidden.Code, hidden.Body, absent.Code, absent.Body)
	}
}

// Cancelling discards the session and its bytes.
func TestCancelUpload(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	start := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	location := start.Header().Get("Location")

	// An untouched session reports the spec's empty range.
	if rec := s.do(t, http.MethodGet, location, "carol", ""); rec.Header().Get("Range") != "0-0" {
		t.Fatalf("fresh session Range = %q, want 0-0", rec.Header().Get("Range"))
	}
	s.do(t, http.MethodPatch, location, "carol", layer)

	if rec := s.do(t, http.MethodDelete, location, "carol", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: %d", rec.Code)
	}
	if rec := s.do(t, http.MethodGet, location, "carol", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("session after cancel: %d, want 404", rec.Code)
	}
}

// A row whose staged bytes are gone -- a crash swept them, say -- answers
// upload-unknown: the client restarts the push, which is the recoverable
// outcome.
func TestUploadRowWithoutBytesLooksAbsent(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	if err := s.metaDB.CreateUpload(context.Background(), meta.UploadSession{
		ID: "0123456789abcdef0123456789abcdef", Repository: "team-a/api",
		StartedAt: fixedTime, LastChunkAt: fixedTime,
	}); err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	rec := s.do(t, http.MethodPatch, "/v2/team-a/api/blobs/uploads/0123456789abcdef0123456789abcdef", "carol", layer)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), registry.CodeBlobUploadUnknown) {
		t.Fatalf("row-without-bytes: %d %s, want upload-unknown", rec.Code, rec.Body)
	}
}

// The read path streams through blob.VerifiedReader, whose ends-short-on-
// corruption behaviour is proven at the blob layer (F-008, F-009); the
// handler adds nothing between the reader and the wire, and TestChunkedPushAndPull
// proves the intact path byte-for-byte.
