package registry_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/artifact"
	"github.com/steveokay/trove/internal/registry"
)

// The R-006 delete-order matrix. Index PUT already records child edges and the
// Q10 refusal already names the referencing index (both landed with R-002);
// what is proven here is the *ordering* those rules imply once more than one
// index, or more than one level of index, is in play — which member of a
// multi-arch graph may be deleted when, and what the registry answers when the
// order is wrong.
//
// Every case below is driven through the real handlers over the real stores,
// so a refusal that did not actually protect the child would show up as a
// missing manifest on the next request rather than as a passing assertion.

// indexChild is one entry of an index's manifests list. platform is raw JSON
// so a test can state exactly the object it expects to get back: the registry
// never interprets it, and never rewrites it.
type indexChild struct {
	mediaType string
	digest    string
	size      int
	platform  string
}

// indexOf renders an index payload of the given media type. It is deliberately
// string-built rather than marshalled, so the bytes a test pushes are the bytes
// it can compare against on the way out.
func indexOf(mediaType string, children ...indexChild) string {
	entries := make([]string, 0, len(children))
	for _, child := range children {
		entry := fmt.Sprintf(`{"mediaType": %q, "digest": %q, "size": %d`,
			child.mediaType, child.digest, child.size)
		if child.platform != "" {
			entry += `, "platform": ` + child.platform
		}
		entries = append(entries, entry+"}")
	}
	return fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q, "manifests": [%s]}`,
		mediaType, strings.Join(entries, ", "))
}

// indexDockerManifest is a Docker v2 schema 2 image manifest over the seeded
// blobs, so the Docker manifest-list cases have a child of their own kind.
func indexDockerManifest() string {
	return fmt.Sprintf(`{"schemaVersion": 2, "mediaType": %q,
		"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": %q, "size": %d},
		"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": %q, "size": %d}]}`,
		artifact.MediaTypeDockerManifest, configBlobDigest(), len(configBlob), layerDigest(), len(layer))
}

// indexDelete deletes as mona, the only fixture subject holding
// manifest:delete.
func indexDelete(t *testing.T, s stack, digest string) *httptest.ResponseRecorder {
	t.Helper()
	return s.do(t, http.MethodDelete, "/v2/team-a/api/manifests/"+digest, "mona", "")
}

func indexGet(t *testing.T, s stack, reference string) *httptest.ResponseRecorder {
	t.Helper()
	return s.do(t, http.MethodGet, "/v2/team-a/api/manifests/"+reference, "mona", "")
}

// indexRequireReleased requires the digest to be deletable now, which is the
// only observable proof that every edge holding it is gone.
func indexRequireReleased(t *testing.T, s stack, what, digest string) {
	t.Helper()
	if rec := indexDelete(t, s, digest); rec.Code != http.StatusAccepted {
		t.Fatalf("%s not released: %d %s", what, rec.Code, rec.Body)
	}
	if rec := indexGet(t, s, digest); rec.Code != http.StatusNotFound {
		t.Fatalf("%s readable after delete: %d", what, rec.Code)
	}
}

// indexRequireRefused requires the Q10 refusal: 403 DENIED, naming every index
// in names and none of the ones in gone, with the child still readable
// afterwards. A refusal that named a already-deleted index would send an
// operator to delete something that no longer exists.
func indexRequireRefused(t *testing.T, s stack, child string, names, gone []string) {
	t.Helper()
	rec := indexDelete(t, s, child)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete of indexed child %s: %d %s, want 403", child, rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, registry.CodeDenied) || !strings.Contains(body, "delete the index first") {
		t.Fatalf("refusal is not the Q10 shape: %s", body)
	}
	for _, name := range names {
		if !strings.Contains(body, name) {
			t.Errorf("refusal does not name index %s: %s", name, body)
		}
	}
	for _, name := range gone {
		if strings.Contains(body, name) {
			t.Errorf("refusal names deleted index %s: %s", name, body)
		}
	}
	if rec := indexGet(t, s, child); rec.Code != http.StatusOK {
		t.Fatalf("child %s gone after a refused delete: %d", child, rec.Code)
	}
}

// Two indexes over one child -- the ordinary shape when the same image is
// listed by both a release index and a nightly one. The child is pinned while
// either lives, the refusal names both, and the second refusal names only the
// survivor.
func TestIndexTwoParentsShareOneChild(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	leaf := imageManifest()
	leafDg := putManifest(t, s, "carol", "leaf", artifact.MediaTypeOCIManifest, leaf)

	// The two indexes differ only in the platform they claim for the same
	// child, which is enough to make them distinct manifests.
	amd := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIManifest, digest: leafDg, size: len(leaf),
		platform: `{"os": "linux", "architecture": "amd64"}`,
	})
	arm := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIManifest, digest: leafDg, size: len(leaf),
		platform: `{"os": "linux", "architecture": "arm64"}`,
	})
	amdDg := putManifest(t, s, "carol", "amd", artifact.MediaTypeOCIIndex, amd)
	armDg := putManifest(t, s, "carol", "arm", artifact.MediaTypeOCIIndex, arm)
	if amdDg == armDg {
		t.Fatalf("the two indexes collapsed to one digest %s", amdDg)
	}

	indexRequireRefused(t, s, leafDg, []string{amdDg, armDg}, nil)

	// One parent gone is not enough: the other still pins the child, and says
	// so without mentioning the index that is already deleted.
	indexRequireReleased(t, s, "index amd", amdDg)
	indexRequireRefused(t, s, leafDg, []string{armDg}, []string{amdDg})

	indexRequireReleased(t, s, "index arm", armDg)
	indexRequireReleased(t, s, "leaf", leafDg)
}

// An index whose child is itself an index. The OCI type allows it, and the
// deletion order it forces is outer, inner, leaf -- nothing else works at any
// step.
func TestIndexNestedDeleteOrder(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	leaf := imageManifest()
	leafDg := putManifest(t, s, "carol", "leaf", artifact.MediaTypeOCIManifest, leaf)

	inner := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIManifest, digest: leafDg, size: len(leaf),
		platform: `{"os": "linux", "architecture": "amd64"}`,
	})
	innerDg := putManifest(t, s, "carol", "inner", artifact.MediaTypeOCIIndex, inner)

	outer := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIIndex, digest: innerDg, size: len(inner),
	})
	outerDg := putManifest(t, s, "carol", "outer", artifact.MediaTypeOCIIndex, outer)

	// Bottom-up is refused at both levels: the inner index is Q10-protected by
	// the outer one exactly as an image is by an index.
	indexRequireRefused(t, s, leafDg, []string{innerDg}, nil)
	indexRequireRefused(t, s, innerDg, []string{outerDg}, nil)

	// Top-down works, one level at a time -- and only one level: with the outer
	// index gone the leaf is still pinned by the inner one.
	indexRequireReleased(t, s, "outer index", outerDg)
	indexRequireRefused(t, s, leafDg, []string{innerDg}, []string{outerDg})

	indexRequireReleased(t, s, "inner index", innerDg)
	indexRequireReleased(t, s, "leaf", leafDg)
}

// A Docker manifest list pins its children exactly as an OCI index does: the
// rule is about the child edge, not about which of the two wire formats
// recorded it.
func TestIndexDockerListGetsTheSameRefusal(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	child := indexDockerManifest()
	childDg := putManifest(t, s, "carol", "docker", artifact.MediaTypeDockerManifest, child)

	list := indexOf(artifact.MediaTypeDockerList, indexChild{
		mediaType: artifact.MediaTypeDockerManifest, digest: childDg, size: len(child),
		platform: `{"os": "linux", "architecture": "amd64"}`,
	})
	listDg := putManifest(t, s, "carol", "multi-docker", artifact.MediaTypeDockerList, list)

	indexRequireRefused(t, s, childDg, []string{listDg}, nil)
	indexRequireReleased(t, s, "manifest list", listDg)
	indexRequireReleased(t, s, "list child", childDg)
}

// Index deletion releases its children rather than taking them: each becomes an
// ordinary manifest, individually deletable, and the tags follow the manifests
// they actually point at -- the index's tag dies with the index, a tag on a
// child does not.
func TestIndexDeleteReleasesChildren(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	// Two distinct children: one tagged, one pushed by digest only.
	tagged := imageManifest(`"annotations": {"org.opencontainers.image.title": "tagged"}`)
	taggedDg := putManifest(t, s, "carol", "leaf-a", artifact.MediaTypeOCIManifest, tagged)
	untagged := imageManifest(`"annotations": {"org.opencontainers.image.title": "untagged"}`)
	untaggedDg := putManifest(t, s, "carol", manifestDigest(untagged), artifact.MediaTypeOCIManifest, untagged)

	multi := indexOf(artifact.MediaTypeOCIIndex,
		indexChild{mediaType: artifact.MediaTypeOCIManifest, digest: taggedDg, size: len(tagged),
			platform: `{"os": "linux", "architecture": "amd64"}`},
		indexChild{mediaType: artifact.MediaTypeOCIManifest, digest: untaggedDg, size: len(untagged),
			platform: `{"os": "linux", "architecture": "arm64"}`},
	)
	multiDg := putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, multi)

	// Both children are pinned while the index lives.
	indexRequireRefused(t, s, taggedDg, []string{multiDg}, nil)
	indexRequireRefused(t, s, untaggedDg, []string{multiDg}, nil)

	indexRequireReleased(t, s, "index", multiDg)

	// The index's own tag went with it; the tag on a child did not, and still
	// serves that child's bytes.
	if rec := indexGet(t, s, "multi"); rec.Code != http.StatusNotFound {
		t.Errorf("the index tag survived its manifest: %d", rec.Code)
	}
	rec := indexGet(t, s, "leaf-a")
	if rec.Code != http.StatusOK || rec.Body.String() != tagged {
		t.Fatalf("tag on a released child: %d, body %q", rec.Code, rec.Body)
	}

	// Released children are ordinary manifests again: each deletable on its
	// own, in either order.
	indexRequireReleased(t, s, "untagged child", untaggedDg)
	indexRequireReleased(t, s, "tagged child", taggedDg)
}

// Platform selection is the client's job: we serve the index. A rich platform
// object -- every field the image-spec defines -- comes back byte-identical,
// because the payload is stored and served verbatim and is never re-marshalled
// through a struct that would drop the fields it does not model.
func TestIndexPlatformRoundTrip(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	oci := imageManifest()
	ociDg := putManifest(t, s, "carol", "leaf-oci", artifact.MediaTypeOCIManifest, oci)
	docker := indexDockerManifest()
	dockerDg := putManifest(t, s, "carol", "leaf-docker", artifact.MediaTypeDockerManifest, docker)

	rich := `{"architecture": "arm64", "os": "windows", "os.version": "10.0.17763.1234", ` +
		`"os.features": ["win32k"], "variant": "v8", "features": ["sse4"]}`

	for _, tt := range []struct{ name, mediaType, childType, child, childDg string }{
		{"oci index", artifact.MediaTypeOCIIndex, artifact.MediaTypeOCIManifest, oci, ociDg},
		{"docker manifest list", artifact.MediaTypeDockerList, artifact.MediaTypeDockerManifest, docker, dockerDg},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload := indexOf(tt.mediaType, indexChild{
				mediaType: tt.childType, digest: tt.childDg, size: len(tt.child), platform: rich,
			})
			tag := strings.ReplaceAll(tt.name, " ", "-")
			digest := putManifest(t, s, "carol", tag, tt.mediaType, payload)

			for _, reference := range []string{tag, digest} {
				got := indexGet(t, s, reference)
				if got.Code != http.StatusOK {
					t.Fatalf("GET %s: %d %s", reference, got.Code, got.Body)
				}
				if got.Body.String() != payload {
					t.Fatalf("GET %s rewrote the index:\n got %s\nwant %s", reference, got.Body, payload)
				}
				if ct := got.Header().Get("Content-Type"); ct != tt.mediaType {
					t.Errorf("GET %s Content-Type = %q", reference, ct)
				}
				if got.Header().Get("Docker-Content-Digest") != digest ||
					got.Header().Get("Content-Length") != fmt.Sprint(len(payload)) {
					t.Errorf("GET %s headers: %v", reference, got.Header())
				}
			}

			// The child reached through the index, as a client does it: read
			// the index, then fetch the digest it lists. The direct read of the
			// same digest is the identical answer.
			var served struct {
				Manifests []struct {
					Digest   string          `json:"digest"`
					Platform json.RawMessage `json:"platform"`
				} `json:"manifests"`
			}
			if err := json.Unmarshal(indexGet(t, s, tag).Body.Bytes(), &served); err != nil {
				t.Fatalf("unmarshal served index: %v", err)
			}
			if len(served.Manifests) != 1 || served.Manifests[0].Digest != tt.childDg {
				t.Fatalf("served index lists %+v", served.Manifests)
			}
			var gotPlatform, wantPlatform map[string]any
			if err := json.Unmarshal(served.Manifests[0].Platform, &gotPlatform); err != nil {
				t.Fatalf("unmarshal served platform: %v", err)
			}
			if err := json.Unmarshal([]byte(rich), &wantPlatform); err != nil {
				t.Fatalf("unmarshal wanted platform: %v", err)
			}
			if !reflect.DeepEqual(gotPlatform, wantPlatform) {
				t.Errorf("platform = %v, want %v", gotPlatform, wantPlatform)
			}

			through := indexGet(t, s, served.Manifests[0].Digest)
			if through.Code != http.StatusOK || through.Body.String() != tt.child {
				t.Fatalf("child through the index: %d, body %q", through.Code, through.Body)
			}
		})
	}
}

// The delete-order case the cascade must get right: the *subject* is the
// index child, so the member Q10 refuses is the last one a deepest-first walk
// would reach. Nothing may be deleted -- not the signature, not the SBOM --
// because the refusal has to be decided before the walk starts (ADR 0011:
// Q10 takes precedence and the cascade fails closed).
//
// This is the case the store's own Q10 check cannot cover: it would fire only
// after the referrers above the subject had already been deleted, leaving an
// operator who was told "delete the index first" with an image whose
// attestations are gone.
func TestIndexedSubjectFailsCascadeClosed(t *testing.T) {
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

	sig := imageManifest(
		`"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json"`,
		fmt.Sprintf(`"subject": {"mediaType": %q, "digest": %q, "size": %d}`,
			artifact.MediaTypeOCIManifest, sbomDg, len(sbom)))
	sigDg := putManifest(t, s, "carol", manifestDigest(sig), artifact.MediaTypeOCIManifest, sig)

	multi := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIManifest, digest: imageDg, size: len(image),
		platform: `{"os": "linux", "architecture": "amd64"}`,
	})
	multiDg := putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, multi)

	indexRequireRefused(t, s, imageDg, []string{multiDg}, nil)

	// The whole tree survived, and so did the subject's tag.
	for what, digest := range map[string]string{"sbom": sbomDg, "signature": sigDg, "v1 tag": "v1"} {
		if rec := indexGet(t, s, digest); rec.Code != http.StatusOK {
			t.Errorf("%s deleted by a refused cascade: %d", what, rec.Code)
		}
	}

	// Deleting the index first is what the refusal told the operator to do, and
	// it is enough: the cascade then takes the whole tree.
	indexRequireReleased(t, s, "index", multiDg)
	if rec := indexDelete(t, s, imageDg); rec.Code != http.StatusAccepted {
		t.Fatalf("cascade after the index went: %d %s", rec.Code, rec.Body)
	}
	for what, digest := range map[string]string{"image": imageDg, "sbom": sbomDg, "signature": sigDg, "v1 tag": "v1"} {
		if rec := indexGet(t, s, digest); rec.Code != http.StatusNotFound {
			t.Errorf("%s survived the cascade: %d", what, rec.Code)
		}
	}
}

// Deleting an index and pushing it again restores the pin: the edges are
// recreated by the second PUT, so the child is refused exactly as it was
// before. A stale edge table would show up here as a child that stayed
// deletable, or one that was never released in the first place.
func TestIndexRepushAfterDeleteRecreatesEdges(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)

	leaf := imageManifest()
	leafDg := putManifest(t, s, "carol", "leaf", artifact.MediaTypeOCIManifest, leaf)
	payload := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIManifest, digest: leafDg, size: len(leaf),
		platform: `{"os": "linux", "architecture": "amd64"}`,
	})

	first := putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, payload)
	indexRequireRefused(t, s, leafDg, []string{first}, nil)
	indexRequireReleased(t, s, "index", first)

	// Re-push of the identical payload: same digest, tag back, pin back.
	second := putManifest(t, s, "carol", "multi", artifact.MediaTypeOCIIndex, payload)
	if second != first {
		t.Fatalf("re-pushed index digest = %s, want %s", second, first)
	}
	rec := indexGet(t, s, "multi")
	if rec.Code != http.StatusOK || rec.Body.String() != payload {
		t.Fatalf("re-pushed index by tag: %d, body %q", rec.Code, rec.Body)
	}
	indexRequireRefused(t, s, leafDg, []string{second}, nil)

	indexRequireReleased(t, s, "re-pushed index", second)
	indexRequireReleased(t, s, "leaf", leafDg)
}

// A child descriptor whose size contradicts the stored child manifest is
// refused the same way a lying blob descriptor is (the R-006 reconcile closed
// the parity gap): clients trust descriptor sizes, so the registry must not
// serve an index that misstates one.
func TestIndexChildDescriptorSizeMismatch(t *testing.T) {
	t.Parallel()

	s := newStack(t)
	seedImageBlobs(t, s)
	image := imageManifest()
	imageDg := putManifest(t, s, "carol", "base", artifact.MediaTypeOCIManifest, image)

	payload := indexOf(artifact.MediaTypeOCIIndex, indexChild{
		mediaType: artifact.MediaTypeOCIManifest, digest: imageDg, size: len(image) + 7,
	})
	rec := s.do(t, http.MethodPut, "/v2/team-a/api/manifests/lying", "carol", payload,
		"Content-Type", artifact.MediaTypeOCIIndex)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), registry.CodeManifestInvalid) {
		t.Fatalf("lying child size: %d %s, want MANIFEST_INVALID", rec.Code, rec.Body)
	}
	if rec := s.do(t, http.MethodGet, "/v2/team-a/api/manifests/lying", "carol", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("refused index left a readable tag: %d", rec.Code)
	}
}
