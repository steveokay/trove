package proxy_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxy/clienttest"
)

// The upstream client is tested against a real registry, not only against the
// fake: half of what this client has to get right is what a distribution
// implementation actually does -- which headers come back on a HEAD, what a
// 404 looks like, whether an ETag is offered, how a manifest is content
// negotiated. A fake that passes a suite written from the same misunderstanding
// as the client proves nothing.
//
// The container is shared by the package; each case pushes the fixture again,
// which is idempotent for blobs and resets the tag for the one case that moves
// it.

const registryImage = "registry:2.8.3"

var (
	registryOnce     sync.Once
	registryEndpoint string
	registryErr      error
)

// containerEndpoint starts the shared registry on first use.
func containerEndpoint(ctx context.Context) (string, error) {
	registryOnce.Do(func() {
		container, err := testcontainers.Run(ctx, registryImage,
			testcontainers.WithExposedPorts("5000/tcp"),
			testcontainers.WithWaitStrategy(
				wait.ForHTTP("/v2/").WithPort("5000/tcp").WithStartupTimeout(2*time.Minute)),
		)
		if err != nil {
			registryErr = fmt.Errorf("start %s: %w", registryImage, err)
			return
		}
		registryEndpoint, registryErr = container.PortEndpoint(ctx, "5000/tcp", "http")
	})
	return registryEndpoint, registryErr
}

// requireRegistry returns the shared registry's URL, skipping when Docker is
// not available at all and failing when CI expected it to be.
func requireRegistry(t *testing.T) string {
	t.Helper()

	endpoint, err := containerEndpoint(context.Background())
	if err != nil {
		if _, set := os.LookupEnv("CI"); set {
			t.Fatalf("registry container unavailable in CI: %v", err)
		}
		t.Skipf("registry container unavailable: %v", err)
	}
	return endpoint
}

func TestRegistryContainerStarts(t *testing.T) {
	endpoint := requireRegistry(t)

	resp, err := http.Get(endpoint + "/v2/")
	if err != nil {
		t.Fatalf("GET /v2/: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v2/ = %d, want 200", resp.StatusCode)
	}
}

// TestClientContractAgainstRegistry2 is the acceptance criterion for C-002:
// the same suite the fake passes, green against a real distribution registry.
func TestClientContractAgainstRegistry2(t *testing.T) {
	endpoint := requireRegistry(t)

	clienttest.Run(t, func(t *testing.T, seed clienttest.Fixture) clienttest.Target {
		seedRegistry(t, endpoint, seed)

		recorder := &recordingTransport{}
		client := mustClient(t, proxy.Options{
			Upstream:  endpoint,
			Transport: recorder,
			Now:       fixedNow,
		})
		return clienttest.Target{
			Client: client,
			Retag: func(t *testing.T, to clienttest.Content) {
				pushManifest(t, endpoint, seed.Repository, seed.Tag, to)
			},
			Requests: recorder.snapshot,
		}
	})
}

// seedRegistry pushes the fixture and points the tag at the first manifest.
// Every push is idempotent, so a case that moved the tag leaves nothing behind
// for the next one.
func seedRegistry(t *testing.T, endpoint string, seed clienttest.Fixture) {
	t.Helper()

	for _, content := range seed.Blobs {
		pushBlob(t, endpoint, seed.Repository, content)
	}
	for _, manifest := range []clienttest.Content{seed.Manifest, seed.Next} {
		pushManifest(t, endpoint, seed.Repository, manifest.Digest.String(), manifest)
	}
	pushManifest(t, endpoint, seed.Repository, seed.Tag, seed.Manifest)
}

// pushBlob uploads one blob with the two-step monolithic upload.
func pushBlob(t *testing.T, endpoint, repository string, content clienttest.Content) {
	t.Helper()

	ctx := context.Background()
	start, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/v2/%s/blobs/uploads/", endpoint, repository), nil)
	if err != nil {
		t.Fatalf("build upload request: %v", err)
	}
	started, err := http.DefaultClient.Do(start)
	if err != nil {
		t.Fatalf("start upload: %v", err)
	}
	location := started.Header.Get("Location")
	drainResponse(t, started)
	if started.StatusCode != http.StatusAccepted || location == "" {
		t.Fatalf("start upload = %d, location %q", started.StatusCode, location)
	}

	target, err := started.Request.URL.Parse(location)
	if err != nil {
		t.Fatalf("resolve upload location: %v", err)
	}
	query := target.Query()
	query.Set("digest", content.Digest.String())
	target.RawQuery = query.Encode()

	put, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), bytes.NewReader(content.Bytes))
	if err != nil {
		t.Fatalf("build commit request: %v", err)
	}
	put.Header.Set("Content-Type", "application/octet-stream")
	committed, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatalf("commit upload: %v", err)
	}
	status := committed.StatusCode
	drainResponse(t, committed)
	if status != http.StatusCreated {
		t.Fatalf("commit upload = %d, want 201", status)
	}
}

// pushManifest puts a manifest under a reference.
func pushManifest(t *testing.T, endpoint, repository, reference string, content clienttest.Content) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
		fmt.Sprintf("%s/v2/%s/manifests/%s", endpoint, repository, reference),
		bytes.NewReader(content.Bytes))
	if err != nil {
		t.Fatalf("build manifest request: %v", err)
	}
	req.Header.Set("Content-Type", content.MediaType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push manifest: %v", err)
	}
	status := resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	drainResponse(t, resp)
	if status != http.StatusCreated {
		t.Fatalf("push manifest %s = %d: %s", reference, status, body)
	}
}

func drainResponse(t *testing.T, resp *http.Response) {
	t.Helper()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close response: %v", err)
	}
}
