package artifact

import "strings"

// Kind labels what a manifest holds, for the surfaces that present artifacts
// to people — the UI's icons and filters, search facets — and as the input
// gating reads when a policy asks whether a subject carries a signature
// (ADR 0013: presence, not verification, in v1).
//
// Classification is labeling and nothing more. No storage path, no permission,
// and no validation branches on a Kind: an artifact type this package has
// never heard of is stored, served, and referred to exactly like one it knows,
// and simply carries KindUnknown. That is deliberate — a registry that only
// accepted artifact types it recognised would stop being a registry the first
// time somebody invented a media type.
type Kind string

// The kinds trove labels. The set grows as ecosystems appear; nothing outside
// it is refused.
const (
	// KindImage is a runnable container image.
	KindImage Kind = "image"
	// KindIndex is a multi-manifest index: multi-arch images, and artifact
	// indexes.
	KindIndex Kind = "index"
	// KindHelmChart is a Helm chart packaged as an OCI artifact.
	KindHelmChart Kind = "helm-chart"
	// KindSBOM is a software bill of materials, SPDX or CycloneDX.
	KindSBOM Kind = "sbom"
	// KindSignature is a signature over another artifact. Its presence is what
	// an `unsigned: block` policy checks (ADR 0013).
	KindSignature Kind = "signature"
	// KindAttestation is an in-toto attestation: provenance, SLSA, and the
	// scan results trove attaches to what it scans.
	KindAttestation Kind = "attestation"
	// KindUnknown is an artifact whose type this package does not recognise.
	// It is a label, never a refusal.
	KindUnknown Kind = "unknown"
)

// Config media types that identify what an image manifest actually carries.
const (
	// MediaTypeHelmConfig is the Helm chart config type.
	MediaTypeHelmConfig = "application/vnd.cncf.helm.config.v1+json"
	// MediaTypeOCIImageConfig is the OCI image config type.
	MediaTypeOCIImageConfig = "application/vnd.oci.image.config.v1+json"
	// MediaTypeDockerImageConfig is the Docker image config type.
	MediaTypeDockerImageConfig = "application/vnd.docker.container.image.v1+json"
	// MediaTypeEmptyConfig is the OCI v1.1 empty descriptor, used by artifacts
	// that carry their meaning in artifactType instead of a config blob.
	MediaTypeEmptyConfig = "application/vnd.oci.empty.v1+json"
)

// Artifact types trove recognises. Each ecosystem publishes its own; these are
// the ones with a v1 behaviour attached (gating input, or a UI affordance).
const (
	// ArtifactTypeSPDX is an SPDX SBOM.
	ArtifactTypeSPDX = "application/spdx+json"
	// ArtifactTypeCycloneDX is a CycloneDX SBOM.
	ArtifactTypeCycloneDX = "application/vnd.cyclonedx+json"
	// ArtifactTypeCosignSignature is a cosign simple-signing signature.
	ArtifactTypeCosignSignature = "application/vnd.dev.cosign.simplesigning.v1+json"
	// ArtifactTypeInTotoAttestation is an in-toto attestation statement.
	ArtifactTypeInTotoAttestation = "application/vnd.in-toto+json"
	// ArtifactTypeCosignBundle is a cosign/sigstore bundle, which carries the
	// signature alongside its verification material.
	ArtifactTypeCosignBundle = "application/vnd.dev.sigstore.bundle+json;version=0.1"
)

// artifactTypeKinds maps an exact artifact type to what it holds. Prefix and
// suffix rules below catch the versioned spellings these ecosystems also use.
var artifactTypeKinds = map[string]Kind{
	ArtifactTypeSPDX:              KindSBOM,
	ArtifactTypeCycloneDX:         KindSBOM,
	ArtifactTypeCosignSignature:   KindSignature,
	ArtifactTypeInTotoAttestation: KindAttestation,
}

// KindOf labels a manifest from what the parser already extracted: its media
// type, its artifact type, and its config's media type.
//
// The order matters. An index is an index whatever it indexes. Otherwise the
// artifactType wins, because it is the field the spec added for exactly this
// question; the config media type answers only when there is no artifactType,
// which is the shape every image and every Helm chart has.
func KindOf(mediaType, artifactType, configMediaType string) Kind {
	if IsIndex(mediaType) {
		return KindIndex
	}
	if kind := kindOfArtifactType(artifactType); kind != KindUnknown {
		return kind
	}
	// The artifactType is checked as a config type too, because that is what
	// a stored record holds: the parser folds the config media type into
	// ArtifactType when a manifest declares no artifactType of its own
	// (distribution-spec v1.1), so a stored image and a stored chart are
	// recognisable from that one field.
	if kind := kindOfConfigType(artifactType); kind != KindUnknown {
		return kind
	}
	if kind := kindOfConfigType(configMediaType); kind != KindUnknown {
		return kind
	}
	// An artifact manifest with an empty config and an unrecognised
	// artifactType: real, storable, and unlabelled.
	return KindUnknown
}

// KindOfStored labels a manifest from the two fields the metadata store keeps
// (ADR 0006). It is what search, the UI, and gating call: the payload is not
// re-parsed to answer a question the stored columns already settle.
func KindOfStored(mediaType, artifactType string) Kind {
	return KindOf(mediaType, artifactType, "")
}

// kindOfConfigType classifies the media type of a manifest's config blob,
// which is what says whether an image manifest holds an image or a chart.
func kindOfConfigType(configMediaType string) Kind {
	switch configMediaType {
	case MediaTypeHelmConfig:
		return KindHelmChart
	case MediaTypeOCIImageConfig, MediaTypeDockerImageConfig:
		return KindImage
	default:
		return KindUnknown
	}
}

// kindOfArtifactType classifies an artifact type, tolerating the versioned and
// vendor-suffixed spellings these ecosystems publish -- cosign bundles carry a
// `;version=` parameter, and CycloneDX ships `+json` and `+xml` alike.
func kindOfArtifactType(artifactType string) Kind {
	if artifactType == "" {
		return KindUnknown
	}
	// A media-type parameter (`;version=0.1`) does not change what the type
	// is, so it is trimmed before matching rather than enumerated.
	base := strings.TrimSpace(artifactType)
	if semicolon := strings.IndexByte(base, ';'); semicolon >= 0 {
		base = strings.TrimSpace(base[:semicolon])
	}
	if kind, ok := artifactTypeKinds[base]; ok {
		return kind
	}
	switch {
	case strings.HasPrefix(base, "application/vnd.cyclonedx"):
		return KindSBOM
	case strings.HasPrefix(base, "application/spdx"):
		return KindSBOM
	case strings.HasPrefix(base, "application/vnd.dev.cosign"),
		strings.HasPrefix(base, "application/vnd.dev.sigstore"):
		// Sigstore bundles carry the signature with its verification
		// material; for presence-checking they are a signature (ADR 0013).
		return KindSignature
	case strings.HasPrefix(base, "application/vnd.in-toto"),
		strings.HasPrefix(base, "application/vnd.slsa"):
		return KindAttestation
	}
	return KindUnknown
}

// Kind labels a parsed manifest. It is the same classification KindOf makes,
// reading the fields the parse already produced.
func (m Manifest) Kind() Kind {
	configMediaType := ""
	if m.Config != nil {
		configMediaType = m.Config.MediaType
	}
	return KindOf(m.MediaType, m.ArtifactType, configMediaType)
}

// IsSignature reports whether the kind is one an `unsigned: block` policy
// counts as a signature (ADR 0013). It exists so gating asks a question about
// meaning rather than matching media-type strings of its own, which is how the
// two would eventually disagree about what a signature is.
func (k Kind) IsSignature() bool { return k == KindSignature }
