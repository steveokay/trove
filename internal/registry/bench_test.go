package registry_test

// Push-latency benchmarks (R-012). Push latency is a hard SLO (CLAUDE.md
// section 6): a scan may be slow, a push may not. These measure the HTTP path
// -- router, guard, handler, store -- because that is what an operator's
// `docker push` waits on; a benchmark of the store alone would move whenever
// the store moved and never notice a regression in the middleware above it.
//
// The stores are the in-memory drivers, so what is timed is our own code and
// not the host's disk. That makes the numbers comparable run to run on one
// machine, which is all a regression check needs; they are not throughput
// figures for a real deployment.
//
// Deferred: the plan's scan-backlog half -- a queue full of fake scan jobs,
// asserting push p50 is unchanged -- needs the scan queue from S-003 and is
// built there, not here.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/blob"
	blobmem "github.com/steveokay/trove/internal/blob/memory"
	"github.com/steveokay/trove/internal/meta"
	metamem "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

const (
	benchSubject = "carol"
	benchRepo    = "team-a/api"

	benchKiB = 1 << 10
	benchMiB = 1 << 20
)

// benchStack is the fixture the benchmarks push through: the same router,
// guard and handlers newStack builds for the tests, trimmed to the one subject
// and one hosted repository a push needs. It is built here rather than shared
// with newStack because that helper takes a *testing.T.
type benchStack struct {
	handler http.Handler
	metaDB  *metamem.Store
	blobs   *blobmem.Store
}

// benchNewStack returns a fresh registry over empty in-memory stores.
//
// Nothing is closed on the way out: both stores are maps, so a discarded stack
// is reclaimed by the collector and holds no descriptor. That matters because
// the blob benchmarks build one stack per iteration -- registering b.N
// cleanups would itself be the leak.
func benchNewStack(b *testing.B) benchStack {
	b.Helper()

	ctx := context.Background()
	metaDB := metamem.New()
	blobs := blobmem.New(blobmem.Options{})

	if err := metaDB.CreateSubject(ctx, meta.Subject{ID: "u-carol", Kind: meta.User, Name: benchSubject}); err != nil {
		b.Fatalf("CreateSubject: %v", err)
	}
	if _, err := metaDB.CreateRepository(ctx, meta.Repository{Name: benchRepo, Type: meta.Hosted}); err != nil {
		b.Fatalf("CreateRepository: %v", err)
	}
	if err := metaDB.CreateRole(ctx, meta.Role{Name: "publisher", Verbs: []string{"repo:read", "repo:write"}}); err != nil {
		b.Fatalf("CreateRole: %v", err)
	}
	if err := metaDB.CreateBinding(ctx, meta.Binding{
		ID: "b-carol", PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-carol",
		Role: "publisher", Scope: "team-a/*",
	}); err != nil {
		b.Fatalf("CreateBinding: %v", err)
	}

	now := func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) }
	router := server.NewRouter(&server.Guard{
		Subjects: metaDB,
		Bindings: metaDB,
		Errors:   server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&registry.Blobs{Store: blobs, Meta: metaDB, Bindings: metaDB, Now: now}).Register(router)
	(&registry.Manifests{Meta: metaDB, Now: now}).Register(router)

	return benchStack{handler: router, metaDB: metaDB, blobs: blobs}
}

// benchRequest builds an authenticated request over body, which is never
// copied: the blob benchmarks hand it a sub-slice of one payload buffer.
func benchRequest(method, target string, body []byte, headers ...string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("X-Test-Subject", benchSubject)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return req
}

// benchSend runs one request and requires the status the push flow promises.
func benchSend(b *testing.B, s benchStack, req *http.Request, want int) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	if rec.Code != want {
		b.Fatalf("%s %s: %d %s, want %d", req.Method, req.URL, rec.Code, rec.Body, want)
	}
	return rec
}

// benchPayload returns size bytes of deterministic filler. Deterministic
// because a benchmark that hashes different content each run is not comparing
// like with like, and because nothing here may depend on a seed.
func benchPayload(size int) []byte {
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(i * 7)
	}
	return p
}

// benchVary stamps the iteration number into the head of the payload, so every
// iteration pushes a digest the stores have not seen. Without it the second
// iteration would store a blob that is already there and measure a
// short-circuit instead of a push.
func benchVary(payload []byte, i int) blob.Digest {
	binary.LittleEndian.PutUint64(payload[:8], uint64(i))
	return blob.FromBytes(blob.SHA256, payload)
}

// BenchmarkMonolithicBlobPush1MiB times the single-request upload -- POST with
// ?digest=, body and commit in one round trip -- which is the shape a small
// layer takes.
func BenchmarkMonolithicBlobPush1MiB(b *testing.B) {
	benchMonolithicPush(b, benchMiB)
}

// BenchmarkMonolithicBlobPush100MiB is the same push at a realistic base-image
// layer size. It is skipped under -short so an ordinary test run does not pay
// for it; the bench CI job runs it explicitly.
func BenchmarkMonolithicBlobPush100MiB(b *testing.B) {
	if testing.Short() {
		b.Skip("100 MiB push: too slow for -short; the bench job runs it")
	}
	benchMonolithicPush(b, 100*benchMiB)
}

func benchMonolithicPush(b *testing.B, size int) {
	payload := benchPayload(size)
	target := "/v2/" + benchRepo + "/blobs/uploads/?digest="

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Hashing the payload and rebuilding the stack are setup, not push
		// cost. The stack is rebuilt rather than reused so the in-memory blob
		// store does not accumulate size*b.N bytes across the run.
		b.StopTimer()
		digest := benchVary(payload, i)
		s := benchNewStack(b)
		req := benchRequest(http.MethodPost, target+digest.String(), payload)
		b.StartTimer()

		benchSend(b, s, req, http.StatusCreated)
	}
}

// BenchmarkChunkedBlobPush times the flow docker actually uses for a layer it
// streams: POST to open a session, PATCH per chunk, PUT to commit. Four chunks
// of a 1 MiB layer -- enough to pay the per-chunk session round trip several
// times without the payload dominating.
func BenchmarkChunkedBlobPush(b *testing.B) {
	const chunks = 4
	payload := benchPayload(benchMiB)
	chunkSize := len(payload) / chunks
	start := "/v2/" + benchRepo + "/blobs/uploads/"

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		digest := benchVary(payload, i)
		s := benchNewStack(b)
		b.StartTimer()

		opened := benchSend(b, s, benchRequest(http.MethodPost, start, nil), http.StatusAccepted)
		location := opened.Header().Get("Location")

		for c := 0; c < chunks; c++ {
			from := c * chunkSize
			to := from + chunkSize
			if c == chunks-1 {
				to = len(payload)
			}
			// The first chunk goes without a Content-Range, as a client that
			// does not know the length yet sends it; the rest carry one.
			var headers []string
			if c > 0 {
				headers = []string{"Content-Range", fmt.Sprintf("%d-%d", from, to-1)}
			}
			benchSend(b, s, benchRequest(http.MethodPatch, location, payload[from:to], headers...),
				http.StatusAccepted)
		}

		benchSend(b, s, benchRequest(http.MethodPut, location+"?digest="+digest.String(), nil),
			http.StatusCreated)
	}
}

const benchConfigBlob = `{"architecture":"amd64","os":"linux"}`

// benchImageManifest is a valid OCI image manifest over the seeded blobs. The
// annotation varies per iteration so every push carries a digest the store has
// not seen, which is what a real push does -- the same tag repointed at new
// content.
func benchImageManifest(config, layerDg blob.Digest, layerSize int, annotation string) string {
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,`+
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},`+
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}],`+
		`"annotations":{"org.opencontainers.image.revision":%q}}`,
		artifact.MediaTypeOCIManifest, config, len(benchConfigBlob), layerDg, layerSize, annotation)
}

// BenchmarkManifestPut times the request that ends a push: the manifest PUT,
// which parses the payload, verifies every referenced blob exists, writes the
// manifest and its refs, then repoints the tag.
//
// One tag, repointed every iteration. That is the realistic path -- `docker
// push repo:latest` in a pipeline pushes new content under a tag that already
// exists -- and there is no repoint short-circuit to dodge: PutTag overwrites
// unconditionally, so a fresh tag per iteration would cost the same and only
// grow the tag table without bound.
//
// The payload rotates through a fixed pool rather than being unique per
// iteration, for the same reason: PutManifest overwrites too, so a repeat
// digest skips no work, and a bounded store reaches a steady state whose
// per-push cost does not drift with b.N. Unbounded growth would time map
// resizing, and would make the number depend on how long the harness happened
// to run.
func BenchmarkManifestPut(b *testing.B) {
	const distinct = 256

	s := benchNewStack(b)
	ctx := context.Background()

	layerBytes := benchPayload(64 * benchKiB)
	configDg := blob.FromBytes(blob.SHA256, []byte(benchConfigBlob))
	layerDg := blob.FromBytes(blob.SHA256, layerBytes)
	for _, seed := range []meta.Blob{
		{Digest: meta.Digest(configDg), Size: int64(len(benchConfigBlob))},
		{Digest: meta.Digest(layerDg), Size: int64(len(layerBytes))},
	} {
		if err := s.metaDB.PutBlob(ctx, seed); err != nil {
			b.Fatalf("PutBlob: %v", err)
		}
	}

	// Built up front, so the timed region holds nothing but the request.
	bodies := make([][]byte, distinct)
	for i := range bodies {
		bodies[i] = []byte(benchImageManifest(configDg, layerDg, len(layerBytes), fmt.Sprintf("r%d", i)))
	}
	target := "/v2/" + benchRepo + "/manifests/latest"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := benchRequest(http.MethodPut, target, bodies[i%distinct], "Content-Type", artifact.MediaTypeOCIManifest)
		benchSend(b, s, req, http.StatusCreated)
	}
}
