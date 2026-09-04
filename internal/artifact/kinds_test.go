package artifact_test

import (
	"fmt"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
)

// The kind-detection matrix, driven through the real parser over the payload
// shapes the ecosystems actually publish: what a manifest is labelled is
// decided from what a client pushed, not from a hand-built struct.
func TestKindOfParsedPayloads(t *testing.T) {
	t.Parallel()

	// One helper per shape, so each case reads as the artifact it describes.
	image := func(configType string) string {
		return fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
			"config": {"mediaType": %q, "digest": %q, "size": 7},
			"layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": %q, "size": 4}]}`,
			artifact.MediaTypeOCIManifest, configType, configDigest, layerDigest)
	}
	attached := func(artifactType string) string {
		return fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q, "artifactType": %q,
			"config": {"mediaType": %q, "digest": %q, "size": 2},
			"layers": [],
			"subject": {"mediaType": %q, "digest": %q, "size": 100}}`,
			artifact.MediaTypeOCIManifest, artifactType, artifact.MediaTypeEmptyConfig,
			configDigest, artifact.MediaTypeOCIManifest, subjectDigest)
	}

	tests := []struct {
		name        string
		contentType string
		payload     string
		want        artifact.Kind
	}{
		{
			name: "OCI image", contentType: artifact.MediaTypeOCIManifest,
			payload: image(artifact.MediaTypeOCIImageConfig), want: artifact.KindImage,
		},
		{
			name: "Docker image", contentType: artifact.MediaTypeDockerManifest,
			payload: fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
				"config": {"mediaType": %q, "digest": %q, "size": 7}, "layers": []}`,
				artifact.MediaTypeDockerManifest, artifact.MediaTypeDockerImageConfig, configDigest),
			want: artifact.KindImage,
		},
		{
			name: "Helm chart", contentType: artifact.MediaTypeOCIManifest,
			payload: image(artifact.MediaTypeHelmConfig), want: artifact.KindHelmChart,
		},
		{
			name: "multi-arch index", contentType: artifact.MediaTypeOCIIndex,
			payload: fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
				"manifests": [{"mediaType": %q, "digest": %q, "size": 100}]}`,
				artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, childDigest),
			want: artifact.KindIndex,
		},
		{
			name: "Docker manifest list", contentType: artifact.MediaTypeDockerList,
			payload: fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
				"manifests": [{"mediaType": %q, "digest": %q, "size": 100}]}`,
				artifact.MediaTypeDockerList, artifact.MediaTypeDockerManifest, childDigest),
			want: artifact.KindIndex,
		},
		{
			name: "SPDX SBOM", contentType: artifact.MediaTypeOCIManifest,
			payload: attached(artifact.ArtifactTypeSPDX), want: artifact.KindSBOM,
		},
		{
			name: "CycloneDX SBOM", contentType: artifact.MediaTypeOCIManifest,
			payload: attached(artifact.ArtifactTypeCycloneDX), want: artifact.KindSBOM,
		},
		{
			name: "CycloneDX XML spelling", contentType: artifact.MediaTypeOCIManifest,
			payload: attached("application/vnd.cyclonedx+xml"), want: artifact.KindSBOM,
		},
		{
			name: "cosign signature", contentType: artifact.MediaTypeOCIManifest,
			payload: attached(artifact.ArtifactTypeCosignSignature), want: artifact.KindSignature,
		},
		{
			name: "sigstore bundle carries a signature", contentType: artifact.MediaTypeOCIManifest,
			payload: attached(artifact.ArtifactTypeCosignBundle), want: artifact.KindSignature,
		},
		{
			name: "in-toto attestation", contentType: artifact.MediaTypeOCIManifest,
			payload: attached(artifact.ArtifactTypeInTotoAttestation), want: artifact.KindAttestation,
		},
		{
			name: "SLSA provenance", contentType: artifact.MediaTypeOCIManifest,
			payload: attached("application/vnd.slsa.provenance+json"), want: artifact.KindAttestation,
		},
		{
			// The point of the label: an ecosystem trove has never heard of is
			// stored and served like any other, and simply says so.
			name: "an artifact type nobody has invented yet", contentType: artifact.MediaTypeOCIManifest,
			payload: attached("application/vnd.example.future+json"), want: artifact.KindUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := artifact.Parse(tt.contentType, []byte(tt.payload))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := m.Kind(); got != tt.want {
				t.Errorf("Kind() = %q, want %q", got, tt.want)
			}
			// A stored record keeps only the media type and the artifact type
			// (ADR 0006), and must label identically: search and the UI read
			// the row, never the payload.
			if got := artifact.KindOfStored(m.MediaType, m.ArtifactType); got != tt.want {
				t.Errorf("KindOfStored(%q, %q) = %q, want %q", m.MediaType, m.ArtifactType, got, tt.want)
			}
		})
	}
}

// A media-type parameter does not change what a type is: cosign's bundle
// carries `;version=`, and matching the whole string would miss every future
// version of it.
func TestKindOfIgnoresMediaTypeParameters(t *testing.T) {
	t.Parallel()

	for _, artifactType := range []string{
		artifact.ArtifactTypeCosignBundle,
		"application/vnd.dev.cosign.simplesigning.v1+json; charset=utf-8",
		"  application/vnd.dev.cosign.simplesigning.v1+json  ",
	} {
		if got := artifact.KindOfStored(artifact.MediaTypeOCIManifest, artifactType); got != artifact.KindSignature {
			t.Errorf("KindOfStored(%q) = %q, want signature", artifactType, got)
		}
	}
}

// Gating asks about meaning, not media-type strings (ADR 0013): an
// `unsigned: block` policy counts signature-kinded referrers and nothing else.
func TestKindIsSignature(t *testing.T) {
	t.Parallel()

	if !artifact.KindSignature.IsSignature() {
		t.Error("a signature is not a signature")
	}
	for _, kind := range []artifact.Kind{
		artifact.KindImage, artifact.KindIndex, artifact.KindHelmChart,
		artifact.KindSBOM, artifact.KindAttestation, artifact.KindUnknown,
	} {
		if kind.IsSignature() {
			t.Errorf("%q counts as a signature: an unsigned image would pass an unsigned:block policy", kind)
		}
	}
}

// Classification never refuses: every kind, known or not, comes back from the
// parser as a storable manifest. A registry that only accepted types it
// recognised would stop being a registry.
func TestKindNeverGatesStorage(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q, "artifactType": "application/vnd.nobody.knows+json",
		"config": {"mediaType": %q, "digest": %q, "size": 2}, "layers": []}`,
		artifact.MediaTypeOCIManifest, artifact.MediaTypeEmptyConfig, configDigest)

	m, err := artifact.Parse(artifact.MediaTypeOCIManifest, []byte(payload))
	if err != nil {
		t.Fatalf("an unrecognised artifact type was refused: %v", err)
	}
	if m.Kind() != artifact.KindUnknown {
		t.Errorf("Kind() = %q, want unknown", m.Kind())
	}
	if m.ArtifactType != "application/vnd.nobody.knows+json" {
		t.Errorf("ArtifactType = %q, want it stored verbatim", m.ArtifactType)
	}
}

// An index's kind does not depend on what it indexes, and an empty-config
// artifact with no artifactType at all is unknown rather than an image.
func TestKindOfEdgeShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mediaType    string
		artifactType string
		configType   string
		want         artifact.Kind
	}{
		{artifact.MediaTypeOCIIndex, artifact.ArtifactTypeSPDX, "", artifact.KindIndex},
		{artifact.MediaTypeOCIManifest, "", artifact.MediaTypeEmptyConfig, artifact.KindUnknown},
		{artifact.MediaTypeOCIManifest, "", "", artifact.KindUnknown},
		{artifact.MediaTypeOCIManifest, "", artifact.MediaTypeHelmConfig, artifact.KindHelmChart},
		{artifact.MediaTypeOCIManifest, artifact.MediaTypeHelmConfig, "", artifact.KindHelmChart},
	}
	for _, tt := range tests {
		if got := artifact.KindOf(tt.mediaType, tt.artifactType, tt.configType); got != tt.want {
			t.Errorf("KindOf(%q, %q, %q) = %q, want %q",
				tt.mediaType, tt.artifactType, tt.configType, got, tt.want)
		}
	}
}
