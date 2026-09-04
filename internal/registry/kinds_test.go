package registry_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/meta"
)

// R-007 end to end: the payload shapes `helm push` and `oras attach` really
// send, pushed through the real handlers, and classified from the rows that
// came back out. The binary-driven versions of these round trips (helm, oras,
// cosign against a live `trove serve`) belong to R-009's harness; what is
// proven here is that the stored record carries what a classifier needs.
func TestKindsRoundTripThroughTheRegistry(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	ctx := context.Background()

	// `helm push` sends an image manifest whose config type is the chart's.
	chart := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"config": {"mediaType": %q, "digest": %q, "size": %d},
		"layers": [{"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": %q, "size": %d}]}`,
		artifact.MediaTypeOCIManifest, artifact.MediaTypeHelmConfig, configBlobDigest(), len(configBlob),
		layerDigest(), len(layer))
	chartDigest := putManifest(t, s, "carol", "0.1.0", artifact.MediaTypeOCIManifest, chart)

	// An ordinary image, so the chart's label is a distinction rather than a
	// default everything shares.
	image := imageManifest()
	imageDigest := putManifest(t, s, "carol", "v1", artifact.MediaTypeOCIManifest, image)

	// `oras attach --artifact-type application/spdx+json`, and cosign's
	// signature, both attaching to the image by subject.
	attach := func(artifactType, subject string, subjectSize int) string {
		payload := imageManifest(
			fmt.Sprintf(`"artifactType": %q`, artifactType),
			fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
				artifact.MediaTypeOCIManifest, subject, subjectSize))
		return putManifest(t, s, "carol", manifestDigest(payload), artifact.MediaTypeOCIManifest, payload)
	}
	sbomDigest := attach(artifact.ArtifactTypeSPDX, imageDigest, len(image))
	signatureDigest := attach(artifact.ArtifactTypeCosignSignature, imageDigest, len(image))

	// A multi-arch index over the image.
	index := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"manifests": [{"mediaType": %q, "digest": %q, "size": %d}]}`,
		artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, imageDigest, len(image))
	indexDigest := putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, index)

	tests := []struct {
		what   string
		digest string
		want   artifact.Kind
	}{
		{"helm chart", chartDigest, artifact.KindHelmChart},
		{"image", imageDigest, artifact.KindImage},
		{"SBOM", sbomDigest, artifact.KindSBOM},
		{"signature", signatureDigest, artifact.KindSignature},
		{"index", indexDigest, artifact.KindIndex},
	}
	for _, tt := range tests {
		record, err := s.metaDB.GetManifest(ctx, "team-a/api", meta.Digest(tt.digest))
		if err != nil {
			t.Fatalf("GetManifest(%s): %v", tt.what, err)
		}
		if got := artifact.KindOfStored(record.MediaType, record.ArtifactType); got != tt.want {
			t.Errorf("%s stored as media %q artifact %q classifies as %q, want %q",
				tt.what, record.MediaType, record.ArtifactType, got, tt.want)
		}
	}

	// The gating input (ADR 0013): an `unsigned: block` policy asks whether a
	// subject carries a signature-kinded referrer, and it must find exactly
	// the signature among the attachments rather than counting the SBOM.
	referrers, err := s.metaDB.ListReferrers(ctx, "team-a/api", meta.Digest(imageDigest), "")
	if err != nil {
		t.Fatalf("ListReferrers: %v", err)
	}
	signatures := 0
	for _, referrer := range referrers {
		if artifact.KindOfStored(referrer.MediaType, referrer.ArtifactType).IsSignature() {
			signatures++
		}
	}
	if len(referrers) != 2 || signatures != 1 {
		t.Errorf("%d referrers, %d of them signatures; want 2 and exactly 1", len(referrers), signatures)
	}

	// The chart is still an ordinary artifact on every other path: it pulls
	// back byte for byte, because labeling changes nothing about storage.
	rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/0.1.0", "rita", "")
	if rec.Code != http.StatusOK || rec.Body.String() != chart {
		t.Fatalf("chart pull: %d, body %q", rec.Code, rec.Body)
	}
}
