package registry_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// faultyMeta fails exactly one named call; everything else passes through, so
// the guard's own lookups still succeed and the failure lands in the handler
// under test.
type faultyMeta struct {
	registry.Meta
	fail string
}

var errDisk = errors.New("disk on fire")

func (f *faultyMeta) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if f.fail == "GetRepository" {
		return meta.Repository{}, errDisk
	}
	return f.Meta.GetRepository(ctx, name)
}

func (f *faultyMeta) GetBlob(ctx context.Context, digest meta.Digest) (meta.Blob, error) {
	if f.fail == "GetBlob" {
		return meta.Blob{}, errDisk
	}
	return f.Meta.GetBlob(ctx, digest)
}

func (f *faultyMeta) PutBlob(ctx context.Context, b meta.Blob) error {
	if f.fail == "PutBlob" {
		return errDisk
	}
	return f.Meta.PutBlob(ctx, b)
}

func (f *faultyMeta) CreateUpload(ctx context.Context, session meta.UploadSession) error {
	if f.fail == "CreateUpload" {
		return errDisk
	}
	return f.Meta.CreateUpload(ctx, session)
}

func (f *faultyMeta) GetUpload(ctx context.Context, id string) (meta.UploadSession, error) {
	if f.fail == "GetUpload" {
		return meta.UploadSession{}, errDisk
	}
	return f.Meta.GetUpload(ctx, id)
}

func (f *faultyMeta) UpdateUpload(ctx context.Context, id string, bytes int64, at time.Time) error {
	if f.fail == "UpdateUpload" {
		return errDisk
	}
	return f.Meta.UpdateUpload(ctx, id, bytes, at)
}

// faultyStack builds the fixture with one metadata call rigged to fail after
// the walk has already begun: the guard still resolves and decides, and only
// the handler's own read or write trips.
func faultyStack(t *testing.T, fail string) stack {
	t.Helper()
	s := newStack(t)
	faulty := &faultyMeta{Meta: s.metaDB, fail: fail}
	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	handlers := &registry.Blobs{
		Store: s.blobs, Meta: faulty, Bindings: s.metaDB,
		Now: func() time.Time { return fixedTime },
	}
	handlers.Register(router)
	return stack{handler: router, metaDB: s.metaDB, blobs: s.blobs}
}

// A store that cannot answer is a 500 in the spec's envelope, never a
// confident "unknown": telling a pusher their layer does not exist because a
// disk hiccupped would make the client delete-and-retry its way into chaos.
func TestStoreFailuresAreServerErrors(t *testing.T) {
	t.Parallel()

	digest := layerDigest().String()

	tests := []struct {
		fail    string
		method  string
		target  string
		body    string
		prepare func(t *testing.T, s stack) string
	}{
		{fail: "GetRepository", method: http.MethodPost, target: "/v2/team-a/api/blobs/uploads/"},
		{fail: "GetRepository", method: http.MethodHead, target: "/v2/team-a/api/blobs/" + digest},
		{fail: "GetBlob", method: http.MethodHead, target: "/v2/team-a/api/blobs/" + digest},
		{fail: "GetBlob", method: http.MethodGet, target: "/v2/team-a/api/blobs/" + digest},
		{fail: "CreateUpload", method: http.MethodPost, target: "/v2/team-a/api/blobs/uploads/"},
		{fail: "PutBlob", method: http.MethodPost, target: "/v2/team-a/api/blobs/uploads/?digest=" + digest, body: layer},
		{
			fail: "GetUpload", method: http.MethodPatch, body: layer,
			prepare: func(t *testing.T, s stack) string {
				return s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "").Header().Get("Location")
			},
		},
		{
			fail: "UpdateUpload", method: http.MethodPatch, body: layer,
			prepare: func(t *testing.T, s stack) string {
				return s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "").Header().Get("Location")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.fail+" "+tt.method, func(t *testing.T) {
			t.Parallel()
			armed := faultyStack(t, tt.fail)
			target := tt.target
			if tt.prepare != nil {
				// Starting the upload works on the armed stack too: the
				// start path does not touch the rigged call.
				target = tt.prepare(t, armed)
			}
			rec := armed.do(t, tt.method, target, "carol", tt.body)
			if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), registry.CodeUnknown) {
				t.Fatalf("%s with %s failing: %d %s, want a spec-shaped 500", tt.method, tt.fail, rec.Code, rec.Body)
			}
		})
	}
}

// A blob row whose bytes are gone is meta-blob drift: a server problem the
// scrub finds (P-012), never "blob unknown".
func TestMetaBlobDriftIsAServerError(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := layerDigest()
	if err := s.metaDB.PutBlob(context.Background(), meta.Blob{
		Digest: meta.Digest(digest), Size: 1,
	}); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/blobs/"+digest.String(), "carol", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("drifted blob read: %d, want 500 rather than a lie", rec.Code)
	}
}

// refusingQuota stands in for P-009: every check says no.
type refusingQuota struct{}

func (refusingQuota) Check(context.Context, string, int64) error {
	return errors.New("repository quota exceeded")
}

func TestQuotaRefusalsAreDenied(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Blobs{
		Store: s.blobs, Meta: s.metaDB, Bindings: s.metaDB, Quota: refusingQuota{},
		Now: func() time.Time { return fixedTime },
	}).Register(router)
	limited := stack{handler: router, metaDB: s.metaDB, blobs: s.blobs}

	for _, target := range []string{
		"/v2/team-a/api/blobs/uploads/",
		"/v2/team-a/api/blobs/uploads/?digest=" + layerDigest().String(),
	} {
		rec := limited.do(t, http.MethodPost, target, "carol", layer)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), registry.CodeDenied) {
			t.Fatalf("POST %s over quota: %d %s, want DENIED", target, rec.Code, rec.Body)
		}
	}

	// The chunk path checks too: an unlimited start does not exempt the bytes.
	start := s.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/", "carol", "")
	rec := limited.do(t, http.MethodPatch, start.Header().Get("Location"), "carol", layer)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PATCH over quota: %d, want DENIED", rec.Code)
	}
}

// The zero-valued handler defaults are safe: real clock, no quota.
func TestHandlerDefaults(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	router := server.NewRouter(&server.Guard{
		Subjects: s.metaDB,
		Bindings: s.metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Blobs{Store: s.blobs, Meta: s.metaDB, Bindings: s.metaDB}).Register(router)
	bare := stack{handler: router, metaDB: s.metaDB, blobs: s.blobs}

	digest := layerDigest().String()
	if rec := bare.do(t, http.MethodPost, "/v2/team-a/api/blobs/uploads/?digest="+digest, "carol", layer); rec.Code != http.StatusCreated {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
}

// The spec renderer, method by method: these bodies are what every OCI client
// parses, and R-008's goldens grow from here.
func TestSpecErrorsRendering(t *testing.T) {
	t.Parallel()

	renderers := registry.SpecErrors{}
	req := httptest.NewRequest(http.MethodGet, "/v2/x/blobs/sha256:0", nil)

	tests := []struct {
		name     string
		render   func(w http.ResponseWriter)
		status   int
		code     string
		header   string
		headerIs string
	}{
		{
			name:   "unauthorized carries the challenge",
			render: func(w http.ResponseWriter) { renderers.Unauthorized(w, req, `Bearer realm="r"`) },
			status: http.StatusUnauthorized, code: registry.CodeUnauthorized,
			header: "WWW-Authenticate", headerIs: `Bearer realm="r"`,
		},
		{
			name:   "forbidden is DENIED",
			render: func(w http.ResponseWriter) { renderers.Forbidden(w, req) },
			status: http.StatusForbidden, code: registry.CodeDenied,
		},
		{
			name:   "not found is NAME_UNKNOWN",
			render: func(w http.ResponseWriter) { renderers.NotFound(w, req) },
			status: http.StatusNotFound, code: registry.CodeNameUnknown,
		},
		{
			name:   "bad request is NAME_INVALID",
			render: func(w http.ResponseWriter) { renderers.BadRequest(w, req, "no") },
			status: http.StatusBadRequest, code: registry.CodeNameInvalid,
		},
		{
			name:   "rate limited carries a truthful Retry-After",
			render: func(w http.ResponseWriter) { renderers.TooManyRequests(w, req, 1500*time.Millisecond) },
			status: http.StatusTooManyRequests, code: registry.CodeTooManyRequests,
			header: "Retry-After", headerIs: "2",
		},
		{
			name:   "rotation required names the exit",
			render: func(w http.ResponseWriter) { renderers.RotationRequired(w, req) },
			status: http.StatusForbidden, code: registry.CodeDenied,
		},
		{
			name:   "internal explains nothing",
			render: func(w http.ResponseWriter) { renderers.Internal(w, req) },
			status: http.StatusInternalServerError, code: registry.CodeUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			tt.render(rec)
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.code) {
				t.Fatalf("%d %s, want %d with %s", rec.Code, rec.Body, tt.status, tt.code)
			}
			if tt.header != "" && rec.Header().Get(tt.header) != tt.headerIs {
				t.Errorf("%s = %q, want %q", tt.header, rec.Header().Get(tt.header), tt.headerIs)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
		})
	}
}
