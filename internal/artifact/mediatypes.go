package artifact

// The manifest media types trove accepts on push. The set is closed: a media
// type outside it is not a manifest, and the parser refuses it before any
// content is inspected. Docker schema 1 is deliberately absent — it is
// deprecated by the spec and by Docker itself.
const (
	// MediaTypeOCIManifest is an OCI image manifest (image-spec v1).
	MediaTypeOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	// MediaTypeOCIIndex is an OCI image index (multi-arch or artifact index).
	MediaTypeOCIIndex = "application/vnd.oci.image.index.v1+json"
	// MediaTypeDockerManifest is a Docker v2 schema 2 image manifest.
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	// MediaTypeDockerList is a Docker v2 manifest list (multi-arch).
	MediaTypeDockerList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// IsSupported reports whether the media type is a manifest trove accepts.
func IsSupported(mediaType string) bool {
	switch mediaType {
	case MediaTypeOCIManifest, MediaTypeOCIIndex, MediaTypeDockerManifest, MediaTypeDockerList:
		return true
	default:
		return false
	}
}

// IsIndex reports whether the media type is a multi-manifest index: an OCI
// index or a Docker manifest list. Everything else supported is a single
// image or artifact manifest.
func IsIndex(mediaType string) bool {
	return mediaType == MediaTypeOCIIndex || mediaType == MediaTypeDockerList
}

// isOCI reports whether the media type is from the OCI family. Only OCI
// manifests carry the v1.1 subject and artifactType fields; on the Docker
// types those fields are not part of the schema and are ignored.
func isOCI(mediaType string) bool {
	return mediaType == MediaTypeOCIManifest || mediaType == MediaTypeOCIIndex
}
