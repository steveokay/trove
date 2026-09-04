package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The harness sanity test the R-009 plan asks for.
//
// It proves the harness itself before any upstream suite runs: a red
// conformance job should mean the registry is wrong, and this is what makes
// that inference sound. It also happens to be a complete push and pull over
// real HTTP against a real `trove serve` -- the first in the project, since
// every earlier suite drove handlers in process.
func TestHarnessPushesAndPullsOverRealHTTP(t *testing.T) {
	registry := Start(t, Build(t))
	registry.CreateRepository(t, "conformance")

	const (
		repository = "conformance/harness"
		tag        = "v1"
	)
	layer := []byte("a layer, pushed over a socket for once")
	config := []byte(`{"architecture":"amd64","os":"linux"}`)

	layerDigest := pushBlob(t, registry, repository, layer)
	configDigest := pushBlob(t, registry, repository, config)

	manifest := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},`+
		`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`,
		configDigest, len(config), layerDigest, len(layer))

	resp := registry.Do(t, http.MethodPut, "/v2/"+repository+"/manifests/"+tag, []byte(manifest),
		"Content-Type", "application/vnd.oci.image.manifest.v1+json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("manifest push: %s\n%s\nserver: %s", resp.Status, readBody(resp), registry.Logs())
	}
	manifestDigest := resp.Header.Get("Docker-Content-Digest")
	_ = resp.Body.Close()
	if manifestDigest == "" {
		t.Fatal("the manifest push returned no Docker-Content-Digest")
	}

	// Pull it back by tag: the bytes a client re-hashes must be the bytes it
	// pushed.
	pulled := registry.Do(t, http.MethodGet, "/v2/"+repository+"/manifests/"+tag, nil)
	defer func() { _ = pulled.Body.Close() }()
	if pulled.StatusCode != http.StatusOK {
		t.Fatalf("manifest pull: %s\n%s", pulled.Status, readBody(pulled))
	}
	body, err := io.ReadAll(pulled.Body)
	if err != nil {
		t.Fatalf("reading the manifest: %v", err)
	}
	if string(body) != manifest {
		t.Errorf("pulled manifest differs from what was pushed:\ngot  %s\nwant %s", body, manifest)
	}
	if got := pulled.Header.Get("Docker-Content-Digest"); got != manifestDigest {
		t.Errorf("Docker-Content-Digest = %q on pull, %q on push", got, manifestDigest)
	}

	// The tag listing sees it, which is the content-discovery surface the
	// conformance suite exercises next.
	tags := registry.Do(t, http.MethodGet, "/v2/"+repository+"/tags/list", nil)
	defer func() { _ = tags.Body.Close() }()
	var listing struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(tags.Body).Decode(&listing); err != nil {
		t.Fatalf("decoding the tag list: %v", err)
	}
	if listing.Name != repository || len(listing.Tags) != 1 || listing.Tags[0] != tag {
		t.Errorf("tag list = %+v, want %s holding %s alone", listing, repository, tag)
	}

	// And the blob is served back verbatim.
	blob := registry.Do(t, http.MethodGet, "/v2/"+repository+"/blobs/"+layerDigest, nil)
	defer func() { _ = blob.Body.Close() }()
	pulledLayer, err := io.ReadAll(blob.Body)
	if err != nil {
		t.Fatalf("reading the blob: %v", err)
	}
	if string(pulledLayer) != string(layer) {
		t.Errorf("pulled layer differs from what was pushed")
	}
}

// The bootstrap sequence the harness depends on: a password printed exactly
// once, useless until rotated, and an administrator that can act afterwards.
// If any of this changes, the harness must change with it -- and this says so
// in one place rather than through an inscrutable conformance failure.
func TestHarnessBootstrapContract(t *testing.T) {
	registry := Start(t, Build(t))

	if registry.Password == "" {
		t.Fatal("no admin password captured")
	}
	// The credential never reaches the log stream, only stdout (Z-014).
	for _, line := range scanLines(registry.Logs()) {
		if strings.Contains(line, registry.Password) {
			t.Fatal("the admin password appears in the log stream")
		}
	}
	// Rotation happened: the registry accepts the rotated password on a
	// route the must-rotate gate would otherwise refuse.
	resp := registry.Do(t, http.MethodGet, "/api/v1/repositories", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing repositories as the rotated admin: %s\n%s", resp.Status, readBody(resp))
	}
}

// pushBlob does a monolithic upload and returns the digest, which is the
// shortest real push there is.
func pushBlob(t *testing.T, registry *Registry, repository string, content []byte) string {
	t.Helper()

	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	resp := registry.Do(t, http.MethodPost,
		"/v2/"+repository+"/blobs/uploads/?digest="+digest, content,
		"Content-Type", "application/octet-stream")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("blob push: %s\n%s\nserver: %s", resp.Status, readBody(resp), registry.Logs())
	}
	return digest
}
