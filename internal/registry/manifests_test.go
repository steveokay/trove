package registry_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/authz/verbtest"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

// Fixture blob content the manifests below reference.
const configBlob = `{"architecture":"amd64"}`

func configBlobDigest() blob.Digest { return blob.FromBytes(blob.SHA256, []byte(configBlob)) }

// seedImageBlobs records the config and layer blobs the image manifest
// references, straight into the store: manifest validation reads rows, not
// bytes.
func seedImageBlobs(t *testing.T, s stack) {
	t.Helper()
	ctx := context.Background()
	for content, digest := range map[string]blob.Digest{
		configBlob: configBlobDigest(),
		layer:      layerDigest(),
	} {
		if err := s.metaDB.PutBlob(ctx, meta.Blob{
			Digest: meta.Digest(digest), Size: int64(len(content)), CreatedAt: fixedTime,
		}); err != nil {
			t.Fatalf("PutBlob: %v", err)
		}
	}
}

// imageManifest is a valid OCI image manifest over the seeded blobs. The
// variadic extra fields let a test graft on a subject or artifactType.
func imageManifest(extra ...string) string {
	fields := append([]string{
		`"schemaVersion": 2`,
		fmt.Sprintf(`"mediaType": %q`, artifact.MediaTypeOCIManifest),
		fmt.Sprintf(`"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": %d}`,
			configBlobDigest(), len(configBlob)),
		fmt.Sprintf(`"layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": %q, "size": %d}]`,
			layerDigest(), len(layer)),
	}, extra...)
	return "{" + strings.Join(fields, ", ") + "}"
}

func manifestDigest(payload string) string {
	return blob.FromBytes(blob.SHA256, []byte(payload)).String()
}

// putManifest pushes a payload under the given reference and requires 201.
func putManifest(t *testing.T, s stack, as, reference, mediaType, payload string) string {
	t.Helper()
	rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/"+reference, as, payload, "Content-Type", mediaType)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT %s: %d %s", reference, rec.Code, rec.Body)
	}
	return rec.Header().Get("Docker-Content-Digest")
}

func TestManifestPushPullRoundTrip(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	payload := imageManifest()
	digest := manifestDigest(payload)

	rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/v1", "carol", payload,
		"Content-Type", artifact.MediaTypeOCIManifest)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Location") != "/v2/team-a/api/manifests/"+digest ||
		rec.Header().Get("Docker-Content-Digest") != digest {
		t.Fatalf("PUT headers: %v", rec.Header())
	}
	if rec.Header().Get("OCI-Subject") != "" {
		t.Fatalf("OCI-Subject set on a manifest without a subject")
	}

	// Pulled by tag: the exact bytes, under the stored media type, because the
	// client re-hashes what it receives.
	get := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "rita", "")
	if get.Code != http.StatusOK || get.Body.String() != payload {
		t.Fatalf("GET by tag: %d, body %q", get.Code, get.Body)
	}
	if ct := get.Header().Get("Content-Type"); ct != artifact.MediaTypeOCIManifest {
		t.Errorf("Content-Type = %q", ct)
	}
	if get.Header().Get("Docker-Content-Digest") != digest ||
		get.Header().Get("Content-Length") != fmt.Sprint(len(payload)) {
		t.Errorf("GET headers: %v", get.Header())
	}

	head := s.do(t, http.MethodHead, "/v2/team-a/api/manifests/"+digest, "rita", "")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d, body %q", head.Code, head.Body)
	}
	if head.Header().Get("Docker-Content-Digest") != digest {
		t.Errorf("HEAD headers: %v", head.Header())
	}

	if again := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "rita", ""); again.Body.String() != payload {
		t.Fatalf("GET by digest lost bytes: %q", again.Body)
	}

	// A re-push of the same content is idempotent.
	if rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/v1", "carol", payload,
		"Content-Type", artifact.MediaTypeOCIManifest); rec.Code != http.StatusCreated {
		t.Fatalf("re-PUT: %d %s", rec.Code, rec.Body)
	}
}

func TestManifestTagRepoint(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	first := imageManifest()
	second := imageManifest(`"annotations": {"v": "2"}`)

	putManifest(t, s, "carol", "latest", artifact.MediaTypeOCIManifest, first)
	putManifest(t, s, "carol", "latest", artifact.MediaTypeOCIManifest, second)

	get := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/latest", "carol", "")
	if get.Body.String() != second {
		t.Fatalf("tag still serves the old manifest: %q", get.Body)
	}
	// The first manifest is still pullable by digest: repointing a tag
	// abandons nothing.
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+manifestDigest(first), "carol", ""); rec.Code != http.StatusOK {
		t.Fatalf("first manifest gone after repoint: %d", rec.Code)
	}
}

func TestManifestPutByDigest(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	payload := imageManifest()
	digest := manifestDigest(payload)

	rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/"+digest, "carol", payload,
		"Content-Type", artifact.MediaTypeOCIManifest)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT by digest: %d %s", rec.Code, rec.Body)
	}
	// No tag was created: the manifest is reachable by digest alone.
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "carol", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET by digest: %d", rec.Code)
	}

	wrong := blob.FromBytes(blob.SHA256, []byte("something else")).String()
	rec = s.do(t, http.MethodPut, "/v2/team-a/api/manifests/"+wrong, "carol", payload,
		"Content-Type", artifact.MediaTypeOCIManifest)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), registry.CodeDigestInvalid) {
		t.Fatalf("mismatched digest: %d %s, want DIGEST_INVALID", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+wrong, "carol", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("refused push stored something: %d", rec.Code)
	}
}

// The media-type matrix of the R-002 test plan: every supported type pushes
// and pulls, and the subject field lands where the referrers API will need it.
func TestManifestMediaTypeMatrix(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	ctx := context.Background()

	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "base", artifact.MediaTypeOCIManifest, image)

	docker := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": %q, "size": %d},
		"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": %q, "size": %d}]}`,
		artifact.MediaTypeDockerManifest, configBlobDigest(), len(configBlob), layerDigest(), len(layer))
	dockerDg := putManifest(t, s, "carol", "docker", artifact.MediaTypeDockerManifest, docker)

	index := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"manifests": [{"mediaType": %q, "digest": %q, "size": %d, "platform": {"os": "linux", "architecture": "amd64"}}]}`,
		artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, imageDg, len(image))
	putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, index)

	list := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"manifests": [{"mediaType": %q, "digest": %q, "size": %d}]}`,
		artifact.MediaTypeDockerList, artifact.MediaTypeDockerManifest, dockerDg, len(docker))
	putManifest(t, s, "carol", "multi-docker", artifact.MediaTypeDockerList, list)

	// A helm chart is an ordinary OCI manifest with a helm config type; the
	// artifactType column is what search and the UI will label it by.
	helm := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"config": {"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": %q, "size": %d},
		"layers": [{"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": %q, "size": %d}]}`,
		artifact.MediaTypeOCIManifest, configBlobDigest(), len(configBlob), layerDigest(), len(layer))
	helmDg := putManifest(t, s, "carol", "chart", artifact.MediaTypeOCIManifest, helm)
	record, err := s.metaDB.GetManifest(ctx, "team-a/api", meta.Digest(helmDg))
	if err != nil || record.ArtifactType != "application/vnd.cncf.helm.config.v1+json" {
		t.Fatalf("helm ArtifactType = %q (%v)", record.ArtifactType, err)
	}

	// An SBOM attached to the image: the subject is recorded, echoed in the
	// OCI-Subject header, and listable through the store's referrers query.
	sbom := imageManifest(
		`"artifactType": "application/spdx+json"`,
		fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
			artifact.MediaTypeOCIManifest, imageDg, len(image)))
	rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/"+manifestDigest(sbom), "carol", sbom,
		"Content-Type", artifact.MediaTypeOCIManifest)
	if rec.Code != http.StatusCreated || rec.Header().Get("OCI-Subject") != imageDg {
		t.Fatalf("SBOM push: %d, OCI-Subject %q", rec.Code, rec.Header().Get("OCI-Subject"))
	}
	referrers, err := s.metaDB.ListReferrers(ctx, "team-a/api", meta.Digest(imageDg), "application/spdx+json")
	if err != nil || len(referrers) != 1 {
		t.Fatalf("ListReferrers: %v, %d rows", err, len(referrers))
	}

	// A subject that does not exist yet is accepted (distribution-spec v1.1):
	// attachments may arrive before the thing they attach to.
	ghost := blob.FromBytes(blob.SHA256, []byte("not pushed yet")).String()
	early := imageManifest(fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": 1}`,
		artifact.MediaTypeOCIManifest, ghost))
	rec = s.do(t, http.MethodPut, "/v2/team-a/api/manifests/"+manifestDigest(early), "carol", early,
		"Content-Type", artifact.MediaTypeOCIManifest)
	if rec.Code != http.StatusCreated || rec.Header().Get("OCI-Subject") != ghost {
		t.Fatalf("early attachment: %d, OCI-Subject %q", rec.Code, rec.Header().Get("OCI-Subject"))
	}
}

func TestManifestPutRejections(t *testing.T) {
	t.Parallel()

	missing := blob.FromBytes(blob.SHA256, []byte("never uploaded")).String()

	tests := []struct {
		name       string
		reference  string
		mediaType  string
		payload    string
		wantStatus int
		wantCode   string
		wantIn     string
	}{
		{
			name:      "missing layer",
			reference: "v1", mediaType: artifact.MediaTypeOCIManifest,
			payload: fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
				"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": %d},
				"layers": [{"mediaType": "application/octet-stream", "digest": %q, "size": 9}]}`,
				artifact.MediaTypeOCIManifest, configBlobDigest(), len(configBlob), missing),
			wantStatus: http.StatusNotFound, wantCode: registry.CodeManifestBlobUnknown, wantIn: missing,
		},
		{
			name:      "missing index child",
			reference: "v1", mediaType: artifact.MediaTypeOCIIndex,
			payload: fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
				"manifests": [{"mediaType": %q, "digest": %q, "size": 9}]}`,
				artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, missing),
			wantStatus: http.StatusNotFound, wantCode: registry.CodeManifestBlobUnknown, wantIn: missing,
		},
		{
			name:      "descriptor size that contradicts the blob",
			reference: "v1", mediaType: artifact.MediaTypeOCIManifest,
			payload: fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
				"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": %d},
				"layers": []}`, artifact.MediaTypeOCIManifest, configBlobDigest(), len(configBlob)+5),
			wantStatus: http.StatusBadRequest, wantCode: registry.CodeManifestInvalid, wantIn: "size",
		},
		{
			name:      "malformed JSON",
			reference: "v1", mediaType: artifact.MediaTypeOCIManifest,
			payload:    `{"schemaVersion": 2,`,
			wantStatus: http.StatusBadRequest, wantCode: registry.CodeManifestInvalid,
		},
		{
			name:      "media type mismatch",
			reference: "v1", mediaType: artifact.MediaTypeOCIIndex,
			payload:    imageManifest(),
			wantStatus: http.StatusBadRequest, wantCode: registry.CodeManifestInvalid, wantIn: "does not match",
		},
		{
			name:      "illegal tag",
			reference: ".hidden", mediaType: artifact.MediaTypeOCIManifest,
			payload:    imageManifest(),
			wantStatus: http.StatusBadRequest, wantCode: registry.CodeManifestInvalid, wantIn: "tag",
		},
		{
			name:      "unparseable digest reference",
			reference: "sha256:junk", mediaType: artifact.MediaTypeOCIManifest,
			payload:    imageManifest(),
			wantStatus: http.StatusBadRequest, wantCode: registry.CodeDigestInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			seedImageBlobs(t, s)
			rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/"+tt.reference, "carol", tt.payload,
				"Content-Type", tt.mediaType)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.wantCode) {
				t.Errorf("body %s lacks code %s", rec.Body, tt.wantCode)
			}
			if tt.wantIn != "" && !strings.Contains(rec.Body.String(), tt.wantIn) {
				t.Errorf("body %s lacks %q", rec.Body, tt.wantIn)
			}
			// Nothing was stored under any name the push used.
			if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+tt.reference, "carol", ""); rec.Code == http.StatusOK {
				t.Errorf("refused push left a readable manifest")
			}
		})
	}
}

// The size cap: what does not fit is refused before it is parsed, and the
// limit is the configured one, not the default.
func TestManifestPayloadCap(t *testing.T) {
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
	(&registry.Manifests{Meta: s.metaDB, MaxBytes: 64, Now: func() time.Time { return fixedTime }}).Register(router)
	capped := stack{handler: router, metaDB: s.metaDB, blobs: s.blobs}

	rec := capped.do(t, http.MethodPut, "/v2/team-a/api/manifests/v1", "carol", strings.Repeat("x", 65),
		"Content-Type", artifact.MediaTypeOCIManifest)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), registry.CodeManifestInvalid) ||
		!strings.Contains(rec.Body.String(), "64") {
		t.Fatalf("oversized push: %d %s", rec.Code, rec.Body)
	}
}

func TestManifestReadUnknown(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	ghost := blob.FromBytes(blob.SHA256, []byte("ghost")).String()

	for _, reference := range []string{"missing-tag", ghost, "!!!not-a-tag!!!"} {
		rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+reference, "rita", "")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), registry.CodeManifestUnknown) {
			t.Errorf("GET %q: %d %s, want MANIFEST_UNKNOWN", reference, rec.Code, rec.Body)
		}
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/sha256:short", "rita", ""); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), registry.CodeDigestInvalid) {
		t.Errorf("GET bad digest: %d %s, want DIGEST_INVALID", rec.Code, rec.Body)
	}
}

// Proxy repositories refuse manifest writes and deletes by type (ADR 0005);
// permission has nothing to do with it, so carol's write grant changes
// nothing.
func TestManifestWritesRefusedOnProxy(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	for _, tt := range []struct{ method, target, body string }{
		{http.MethodPut, "/v2/team-a/mirror/manifests/v1", imageManifest()},
		{http.MethodDelete, "/v2/team-a/mirror/manifests/" + manifestDigest(imageManifest()), ""},
	} {
		rec := s.do(t, tt.method, tt.target, "mona", tt.body, "Content-Type", artifact.MediaTypeOCIManifest)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), registry.CodeDenied) {
			t.Errorf("%s on proxy: %d %s, want DENIED", tt.method, rec.Code, rec.Body)
		}
	}
}

// Hidden and absent answer byte-identically on the manifest routes (ADR 0003):
// carol has no grant on secret/*, and secret/absent does not exist.
func TestManifestHiddenAndAbsentAreIdentical(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	ghost := blob.FromBytes(blob.SHA256, []byte("ghost")).String()

	hidden := s.do(t, http.MethodGet, "/v2/secret/vault/manifests/"+ghost, "carol", "")
	absent := s.do(t, http.MethodGet, "/v2/secret/absent/manifests/"+ghost, "carol", "")
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("hidden: %d", hidden.Code)
	}
	if hidden.Body.String() != absent.Body.String() {
		t.Errorf("bodies differ: %q vs %q", hidden.Body, absent.Body)
	}
	if fmt.Sprint(hidden.Header()) != fmt.Sprint(absent.Header()) {
		t.Errorf("headers differ: %v vs %v", hidden.Header(), absent.Header())
	}
}

// The ADR 0011 cascade: deleting the image takes its SBOM and the signature
// on the SBOM with it, transitively, tags included.
func TestManifestDeleteCascadesReferrers(t *testing.T) {
	t.Parallel()
	verbtest.Positive(t, authz.ManifestDelete)

	s := newStack(t)
	seedImageBlobs(t, s)

	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)

	sbom := imageManifest(
		`"artifactType": "application/spdx+json"`,
		fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
			artifact.MediaTypeOCIManifest, imageDg, len(image)))
	sbomDg := putManifest(t, s, "carol", manifestDigest(sbom), artifact.MediaTypeOCIManifest, sbom)

	sig := imageManifest(
		`"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json"`,
		fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
			artifact.MediaTypeOCIManifest, sbomDg, len(sbom)))
	sigDg := putManifest(t, s, "carol", manifestDigest(sig), artifact.MediaTypeOCIManifest, sig)

	rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+imageDg, "mona", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("DELETE: %d %s", rec.Code, rec.Body)
	}

	for name, digest := range map[string]string{"image": imageDg, "sbom": sbomDg, "signature": sigDg} {
		if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "mona", ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s survived the cascade: %d", name, rec.Code)
		}
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "mona", ""); rec.Code != http.StatusNotFound {
		t.Errorf("tag survived the cascade: %d", rec.Code)
	}
}

// manifest:delete is its own verb: repo:write does not imply it (ADR 0002),
// a reader is refused, and anonymous gets the challenge.
func TestManifestDeleteRequiresItsVerb(t *testing.T) {
	t.Parallel()
	verbtest.Negative(t, authz.ManifestDelete)

	s := newStack(t)
	seedImageBlobs(t, s)
	digest := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, imageManifest())

	for _, subject := range []string{"carol", "rita"} {
		rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+digest, subject, "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), registry.CodeDenied) {
			t.Errorf("%s delete: %d %s, want DENIED", subject, rec.Code, rec.Body)
		}
	}
	if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+digest, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous delete: %d, want 401", rec.Code)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "carol", ""); rec.Code != http.StatusOK {
		t.Errorf("manifest gone after refused deletes: %d", rec.Code)
	}
}

func TestManifestDeleteByTagUnsupported(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, imageManifest())

	rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/v1", "mona", "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), registry.CodeUnsupported) {
		t.Fatalf("delete by tag: %d %s, want UNSUPPORTED", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/v1", "mona", ""); rec.Code != http.StatusOK {
		t.Errorf("manifest gone after refused delete: %d", rec.Code)
	}
}

func TestManifestDeleteUnknown(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	ghost := blob.FromBytes(blob.SHA256, []byte("ghost")).String()
	rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+ghost, "mona", "")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), registry.CodeManifestUnknown) {
		t.Fatalf("delete unknown: %d %s, want MANIFEST_UNKNOWN", rec.Code, rec.Body)
	}
}

// Q10: a child a live index still lists cannot be deleted; the refusal names
// the index. Deleting the index releases the child.
func TestIndexChildDeleteRefused(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "base", artifact.MediaTypeOCIManifest, image)
	index := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"manifests": [{"mediaType": %q, "digest": %q, "size": %d}]}`,
		artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, imageDg, len(image))
	indexDg := putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, index)

	rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+imageDg, "mona", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("child delete: %d %s, want 403", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, registry.CodeDenied) || !strings.Contains(body, indexDg) ||
		!strings.Contains(body, "delete the index first") {
		t.Fatalf("refusal does not name the index: %s", body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+imageDg, "mona", ""); rec.Code != http.StatusOK {
		t.Fatalf("child gone after refused delete: %d", rec.Code)
	}

	if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+indexDg, "mona", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("index delete: %d %s", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+imageDg, "mona", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("released child delete: %d %s", rec.Code, rec.Body)
	}
}

// The ADR 0011 corner: a referrer that is also a child of a live index blocks
// the whole cascade, and nothing is deleted.
func TestCascadeBlockedByIndexedReferrer(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)
	sbom := imageManifest(
		`"artifactType": "application/spdx+json"`,
		fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
			artifact.MediaTypeOCIManifest, imageDg, len(image)))
	sbomDg := putManifest(t, s, "carol", manifestDigest(sbom), artifact.MediaTypeOCIManifest, sbom)
	index := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"manifests": [{"mediaType": %q, "digest": %q, "size": %d}]}`,
		artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, sbomDg, len(sbom))
	indexDg := putManifest(t, s, "carol", "holds-sbom", artifact.MediaTypeOCIIndex, index)

	rec := s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+imageDg, "mona", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), indexDg) {
		t.Fatalf("cascade with indexed referrer: %d %s, want 403 naming %s", rec.Code, rec.Body, indexDg)
	}
	for name, digest := range map[string]string{"image": imageDg, "sbom": sbomDg} {
		if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "mona", ""); rec.Code != http.StatusOK {
			t.Errorf("%s deleted by a refused cascade: %d", name, rec.Code)
		}
	}
}

// A stored payload that no longer hashes to its digest is served as a 500,
// never as content: drift is the server's problem, not the client's manifest
// (ADR 0007).
func TestManifestDriftIsAServerError(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	digest := blob.FromBytes(blob.SHA256, []byte("what was pushed")).String()
	if err := s.metaDB.PutManifest(context.Background(), meta.Manifest{
		Repository: "team-a/api", Digest: meta.Digest(digest),
		MediaType: artifact.MediaTypeOCIManifest,
		Payload:   []byte("what the row holds now"), Size: 22, CreatedAt: fixedTime,
	}, nil); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+digest, "carol", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("drifted manifest served: %d %s", rec.Code, rec.Body)
	}
	var envelope struct {
		Errors []struct{ Code string } `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil ||
		len(envelope.Errors) != 1 || envelope.Errors[0].Code != registry.CodeUnknown {
		t.Fatalf("drift answer not in the spec envelope: %s", rec.Body)
	}
}
