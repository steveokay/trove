package artifact_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
)

// Digest literals long enough to satisfy the strict parser.
var (
	configDigest  = "sha256:" + strings.Repeat("aa", 32)
	layerDigest   = "sha256:" + strings.Repeat("bb", 32)
	childDigest   = "sha256:" + strings.Repeat("cc", 32)
	subjectDigest = "sha256:" + strings.Repeat("dd", 32)
	sha512Digest  = "sha512:" + strings.Repeat("ee", 64)
)

func ociManifest() string {
	return fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": 7},
		"layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": %q, "size": 42}]
	}`, artifact.MediaTypeOCIManifest, configDigest, layerDigest)
}

func TestParseOCIImageManifest(t *testing.T) {
	t.Parallel()

	m, err := artifact.Parse(artifact.MediaTypeOCIManifest, []byte(ociManifest()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.MediaType != artifact.MediaTypeOCIManifest {
		t.Errorf("MediaType = %q", m.MediaType)
	}
	if m.Config == nil || string(m.Config.Digest) != configDigest || m.Config.Size != 7 {
		t.Errorf("Config = %+v", m.Config)
	}
	if len(m.Layers) != 1 || string(m.Layers[0].Digest) != layerDigest || m.Layers[0].Size != 42 {
		t.Errorf("Layers = %+v", m.Layers)
	}
	// With no artifactType of its own, the referrers-API value is the config
	// media type (distribution-spec v1.1).
	if m.ArtifactType != "application/vnd.oci.image.config.v1+json" {
		t.Errorf("ArtifactType = %q", m.ArtifactType)
	}
	if m.Subject != nil {
		t.Errorf("Subject = %+v, want nil", m.Subject)
	}
	if len(m.Children) != 0 {
		t.Errorf("Children = %+v", m.Children)
	}
	if m.IsIndex() {
		t.Error("IsIndex() = true for an image manifest")
	}
}

func TestParseOCIArtifactWithSubject(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"artifactType": "application/spdx+json",
		"config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": %q, "size": 2},
		"layers": [],
		"subject": {"mediaType": %q, "digest": %q, "size": 314}
	}`, artifact.MediaTypeOCIManifest, configDigest, artifact.MediaTypeOCIManifest, subjectDigest)

	m, err := artifact.Parse(artifact.MediaTypeOCIManifest, []byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.ArtifactType != "application/spdx+json" {
		t.Errorf("ArtifactType = %q: the explicit field beats the config media type", m.ArtifactType)
	}
	if m.Subject == nil || string(m.Subject.Digest) != subjectDigest {
		t.Errorf("Subject = %+v", m.Subject)
	}
	if len(m.Layers) != 0 {
		t.Errorf("Layers = %+v: an artifact may have none", m.Layers)
	}
}

func TestParseOCIIndex(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"artifactType": "application/vnd.example+type",
		"manifests": [
			{"mediaType": %q, "digest": %q, "size": 100, "platform": {"os": "linux", "architecture": "amd64"}}
		],
		"subject": {"mediaType": %q, "digest": %q, "size": 314}
	}`, artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, childDigest,
		artifact.MediaTypeOCIManifest, subjectDigest)

	m, err := artifact.Parse(artifact.MediaTypeOCIIndex, []byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.IsIndex() {
		t.Error("IsIndex() = false for an index")
	}
	if len(m.Children) != 1 || string(m.Children[0].Digest) != childDigest {
		t.Errorf("Children = %+v", m.Children)
	}
	if m.Config != nil || len(m.Layers) != 0 {
		t.Errorf("index parsed with config %+v layers %+v", m.Config, m.Layers)
	}
	if m.ArtifactType != "application/vnd.example+type" {
		t.Errorf("ArtifactType = %q", m.ArtifactType)
	}
	if m.Subject == nil || string(m.Subject.Digest) != subjectDigest {
		t.Errorf("Subject = %+v", m.Subject)
	}
}

func TestParseDockerManifest(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": %q, "size": 7},
		"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": %q, "size": 42}],
		"subject": {"mediaType": %q, "digest": %q, "size": 1}
	}`, artifact.MediaTypeDockerManifest, configDigest, layerDigest, artifact.MediaTypeDockerManifest, subjectDigest)

	m, err := artifact.Parse(artifact.MediaTypeDockerManifest, []byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.ArtifactType != "application/vnd.docker.container.image.v1+json" {
		t.Errorf("ArtifactType = %q", m.ArtifactType)
	}
	// subject is not part of the Docker schema: whatever a client put there is
	// not an attachment and must not create one.
	if m.Subject != nil {
		t.Errorf("Subject = %+v on a Docker manifest", m.Subject)
	}
}

func TestParseDockerList(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"manifests": [{"mediaType": %q, "digest": %q, "size": 100}]
	}`, artifact.MediaTypeDockerList, artifact.MediaTypeDockerManifest, childDigest)

	m, err := artifact.Parse(artifact.MediaTypeDockerList, []byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.IsIndex() || len(m.Children) != 1 {
		t.Errorf("Children = %+v, IsIndex = %v", m.Children, m.IsIndex())
	}
	if m.ArtifactType != "" {
		t.Errorf("ArtifactType = %q on a Docker list", m.ArtifactType)
	}
}

func TestParseForeignLayerIsExternal(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": %q, "size": 7},
		"layers": [
			{"mediaType": "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip", "digest": %q, "size": 42,
			 "urls": ["https://example.com/layer.tar.gz"]},
			{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": %q, "size": 7}
		]
	}`, artifact.MediaTypeDockerManifest, configDigest, layerDigest, childDigest)

	m, err := artifact.Parse(artifact.MediaTypeDockerManifest, []byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.Layers[0].External {
		t.Error("layer with urls not marked External")
	}
	if m.Layers[1].External {
		t.Error("ordinary layer marked External")
	}
}

func TestParseContentTypeHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		payload     string
		wantType    string
		wantErr     string
	}{
		{
			name:        "parameters on the content type are ignored",
			contentType: artifact.MediaTypeOCIManifest + "; charset=utf-8",
			payload:     ociManifest(),
			wantType:    artifact.MediaTypeOCIManifest,
		},
		{
			name:        "payload media type stands in for a missing content type",
			contentType: "",
			payload:     ociManifest(),
			wantType:    artifact.MediaTypeOCIManifest,
		},
		{
			name:        "content type stands in for a missing payload media type",
			contentType: artifact.MediaTypeOCIManifest,
			payload: fmt.Sprintf(`{"schemaVersion": 2,
				"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": 7},
				"layers": []}`, configDigest),
			wantType: artifact.MediaTypeOCIManifest,
		},
		{
			name:        "mismatch is refused",
			contentType: artifact.MediaTypeOCIIndex,
			payload:     ociManifest(),
			wantErr:     "does not match",
		},
		{
			name:        "no media type anywhere is refused",
			contentType: "",
			payload:     `{"schemaVersion": 2}`,
			wantErr:     "no media type",
		},
		{
			name:        "unsupported type is refused",
			contentType: "application/vnd.docker.distribution.manifest.v1+json",
			payload:     `{"schemaVersion": 1}`,
			wantErr:     "unsupported",
		},
		{
			name:        "unparseable content type is refused",
			contentType: ";;",
			payload:     ociManifest(),
			wantErr:     "Content-Type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := artifact.Parse(tt.contentType, []byte(tt.payload))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
				}
				if !errors.Is(err, artifact.ErrInvalid) {
					t.Errorf("error %v is not artifact.ErrInvalid", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if m.MediaType != tt.wantType {
				t.Errorf("MediaType = %q, want %q", m.MediaType, tt.wantType)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()

	manifest := func(body string) string {
		return fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q, %s}`, artifact.MediaTypeOCIManifest, body)
	}
	config := fmt.Sprintf(`"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": 7}`, configDigest)

	tests := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "malformed JSON",
			payload: `{"schemaVersion": 2,`,
			wantErr: "malformed",
		},
		{
			name:    "wrong schema version",
			payload: manifest(`"schemaVersion": 1, ` + config + `, "layers": []`),
			wantErr: "schemaVersion",
		},
		{
			name:    "missing config",
			payload: manifest(`"layers": []`),
			wantErr: "config",
		},
		{
			name: "bad layer digest",
			payload: manifest(config + `, "layers": [
				{"mediaType": "application/octet-stream", "digest": "sha256:short", "size": 1}]`),
			wantErr: "digest",
		},
		{
			name: "unknown digest algorithm",
			payload: manifest(config + `, "layers": [
				{"mediaType": "application/octet-stream", "digest": "md5:` + strings.Repeat("ab", 16) + `", "size": 1}]`),
			wantErr: "digest",
		},
		{
			name: "missing descriptor size",
			payload: manifest(config + `, "layers": [
				{"mediaType": "application/octet-stream", "digest": "` + layerDigest + `"}]`),
			wantErr: "size",
		},
		{
			name: "negative descriptor size",
			payload: manifest(config + `, "layers": [
				{"mediaType": "application/octet-stream", "digest": "` + layerDigest + `", "size": -1}]`),
			wantErr: "size",
		},
		{
			name:    "artifactType that is not a media type",
			payload: manifest(`"artifactType": "not-a-media-type", ` + config + `, "layers": []`),
			wantErr: "artifactType",
		},
		{
			name: "bad subject digest",
			payload: manifest(config + `, "layers": [],
				"subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "junk", "size": 1}`),
			wantErr: "digest",
		},
		{
			name:    "JSON that is not an object",
			payload: fmt.Sprintf(`["schemaVersion", 2, %q]`, artifact.MediaTypeOCIManifest),
			wantErr: "malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := artifact.Parse(artifact.MediaTypeOCIManifest, []byte(tt.payload))
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", tt.wantErr)
			}
			if !errors.Is(err, artifact.ErrInvalid) {
				t.Errorf("error %v is not artifact.ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseSHA512DescriptorsAreAccepted(t *testing.T) {
	t.Parallel()

	payload := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": %q,
		"config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": %q, "size": 7},
		"layers": []
	}`, artifact.MediaTypeOCIManifest, sha512Digest)

	m, err := artifact.Parse(artifact.MediaTypeOCIManifest, []byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if string(m.Config.Digest) != sha512Digest {
		t.Errorf("Config.Digest = %q", m.Config.Digest)
	}
}

func TestSupportedAndIndexClassification(t *testing.T) {
	t.Parallel()

	for _, mt := range []string{
		artifact.MediaTypeOCIManifest, artifact.MediaTypeOCIIndex,
		artifact.MediaTypeDockerManifest, artifact.MediaTypeDockerList,
	} {
		if !artifact.IsSupported(mt) {
			t.Errorf("IsSupported(%q) = false", mt)
		}
	}
	if artifact.IsSupported("application/vnd.docker.distribution.manifest.v1+json") {
		t.Error("schema 1 reported as supported")
	}
	if !artifact.IsIndex(artifact.MediaTypeOCIIndex) || !artifact.IsIndex(artifact.MediaTypeDockerList) {
		t.Error("index types not classified as indexes")
	}
	if artifact.IsIndex(artifact.MediaTypeOCIManifest) || artifact.IsIndex(artifact.MediaTypeDockerManifest) {
		t.Error("manifest types classified as indexes")
	}
}
