package artifact

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"strings"

	"github.com/steveokay/trove/internal/blob"
)

// ErrInvalid reports a payload that is not a manifest this registry accepts.
// Callers assert with errors.Is and map it to the spec's MANIFEST_INVALID.
var ErrInvalid = errors.New("invalid manifest")

// InvalidError carries the reason a payload was refused, phrased for the
// client that pushed it.
type InvalidError struct{ Reason string }

func (e *InvalidError) Error() string { return e.Reason }

// Is makes errors.Is(err, ErrInvalid) true for this typed error.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

func invalid(format string, args ...any) error {
	return &InvalidError{Reason: fmt.Sprintf(format, args...)}
}

// Descriptor is one content reference as a manifest states it.
type Descriptor struct {
	MediaType string
	Digest    blob.Digest
	Size      int64
	// External marks content the manifest locates outside the registry (a
	// foreign layer with urls). Its presence here is not validated and it is
	// not recorded as a reference edge: the registry neither stores nor
	// garbage-collects it.
	External bool
}

// Manifest is a parsed, validated push payload. Exactly one of the two shapes
// is populated: an image or artifact manifest carries Config and Layers, an
// index carries Children.
type Manifest struct {
	// MediaType is the effective manifest media type, one of the constants in
	// this package.
	MediaType string
	// ArtifactType is the referrers-API value: the artifactType field when
	// present, else the config media type for image manifests, else empty.
	ArtifactType string
	// Subject is the manifest this one attaches to, when the OCI v1.1 subject
	// field is present.
	Subject *Descriptor
	// Config is the config blob of an image or artifact manifest.
	Config *Descriptor
	// Layers are the layer blobs of an image or artifact manifest. An OCI
	// artifact may legitimately have none.
	Layers []Descriptor
	// Children are the manifests an index lists.
	Children []Descriptor
}

// IsIndex reports whether the parsed manifest is a multi-manifest index.
func (m Manifest) IsIndex() bool { return IsIndex(m.MediaType) }

// The wire shapes cover OCI image-spec v1.1 and Docker v2 schema 2 alike;
// fields a given type does not define simply stay zero.
type wireDescriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      *int64   `json:"size"`
	URLs      []string `json:"urls"`
}

type wireManifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	MediaType     string           `json:"mediaType"`
	ArtifactType  string           `json:"artifactType"`
	Config        *wireDescriptor  `json:"config"`
	Layers        []wireDescriptor `json:"layers"`
	Manifests     []wireDescriptor `json:"manifests"`
	Subject       *wireDescriptor  `json:"subject"`
}

// Parse validates a pushed manifest payload against the declared Content-Type
// and returns its parsed form. Every refusal satisfies errors.Is(err,
// ErrInvalid); the registry maps that to MANIFEST_INVALID.
//
// The media type is settled first — from the Content-Type header, the
// payload's mediaType field, or both in agreement — because nothing else about
// the payload can be judged before knowing what it claims to be.
func Parse(contentType string, payload []byte) (Manifest, error) {
	declared := ""
	if contentType != "" {
		parsed, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			return Manifest{}, invalid("unparseable Content-Type %q", contentType)
		}
		declared = parsed
	}

	var wire wireManifest
	if err := json.Unmarshal(payload, &wire); err != nil {
		return Manifest{}, invalid("malformed manifest JSON: %v", err)
	}

	mediaType := declared
	switch {
	case declared == "" && wire.MediaType == "":
		return Manifest{}, invalid("no media type: set Content-Type or the manifest's mediaType field")
	case declared == "":
		mediaType = wire.MediaType
	case wire.MediaType != "" && wire.MediaType != declared:
		return Manifest{}, invalid("manifest mediaType %q does not match Content-Type %q", wire.MediaType, declared)
	}
	if !IsSupported(mediaType) {
		return Manifest{}, invalid("unsupported manifest media type %q", mediaType)
	}
	if wire.SchemaVersion != 2 {
		return Manifest{}, invalid("schemaVersion must be 2, got %d", wire.SchemaVersion)
	}
	if wire.ArtifactType != "" && !strings.Contains(wire.ArtifactType, "/") {
		return Manifest{}, invalid("artifactType %q is not a media type", wire.ArtifactType)
	}

	m := Manifest{MediaType: mediaType}

	if IsIndex(mediaType) {
		children, err := descriptors("manifests", wire.Manifests)
		if err != nil {
			return Manifest{}, err
		}
		m.Children = children
		if isOCI(mediaType) {
			m.ArtifactType = wire.ArtifactType
		}
	} else {
		if wire.Config == nil {
			return Manifest{}, invalid("manifest has no config descriptor")
		}
		config, err := descriptor("config", *wire.Config)
		if err != nil {
			return Manifest{}, err
		}
		m.Config = &config
		layers, err := descriptors("layers", wire.Layers)
		if err != nil {
			return Manifest{}, err
		}
		m.Layers = layers
		// The referrers-API value: the explicit field wins, the config media
		// type stands in (distribution-spec v1.1). The Docker type has no
		// artifactType field, so for it this is always the config type.
		m.ArtifactType = wire.ArtifactType
		if !isOCI(mediaType) || m.ArtifactType == "" {
			m.ArtifactType = config.MediaType
		}
	}

	// subject is an OCI v1.1 field. On a Docker manifest it is not part of
	// the schema: honoring it there would create attachments no Docker client
	// asked for.
	if wire.Subject != nil && isOCI(mediaType) {
		subject, err := descriptor("subject", *wire.Subject)
		if err != nil {
			return Manifest{}, err
		}
		m.Subject = &subject
	}
	return m, nil
}

func descriptor(field string, wire wireDescriptor) (Descriptor, error) {
	digest, err := blob.ParseDigest(wire.Digest)
	if err != nil {
		return Descriptor{}, invalid("%s digest: %v", field, err)
	}
	if wire.Size == nil {
		return Descriptor{}, invalid("%s descriptor %s has no size", field, digest)
	}
	if *wire.Size < 0 {
		return Descriptor{}, invalid("%s descriptor %s has negative size %d", field, digest, *wire.Size)
	}
	return Descriptor{
		MediaType: wire.MediaType,
		Digest:    digest,
		Size:      *wire.Size,
		External:  len(wire.URLs) > 0,
	}, nil
}

func descriptors(field string, wires []wireDescriptor) ([]Descriptor, error) {
	out := make([]Descriptor, 0, len(wires))
	for i, w := range wires {
		d, err := descriptor(fmt.Sprintf("%s[%d]", field, i), w)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
