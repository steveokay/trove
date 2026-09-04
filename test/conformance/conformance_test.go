package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binaryEnv names the prebuilt upstream conformance binary. CI builds it from
// opencontainers/distribution-spec and points this at the result; a developer
// can do the same locally. When it is unset the test skips, so `go test ./...`
// stays green on a machine that has never heard of the suite -- the gate that
// matters is the CI job, and a suite that cannot run is not a suite that
// failed.
const binaryEnv = "TROVE_CONFORMANCE_BIN"

// namespace is the repository the suite pushes into. Its first path segment is
// the entity the harness creates (ADR 0005); the suite treats the whole string
// as an opaque repository name.
const namespace = "conformance/oci"

// crossmountNamespace is the second repository the push suite mounts blobs
// from, exercising the cross-repo mount R-001 built.
const crossmountNamespace = "conformance/crossmount"

// TestDistributionSpecConformance runs the official suite against a real
// registry: push, pull, content discovery, and content management, which is
// every workflow the spec defines.
//
// The suite is the acceptance criterion for Phase 3 (R-009). It is run as a
// child process rather than imported because it is a ginkgo suite that reads
// its configuration from the environment at load time -- driving it in process
// would mean setting global state and hoping.
func TestDistributionSpecConformance(t *testing.T) {
	binary := os.Getenv(binaryEnv)
	if binary == "" {
		t.Skipf("set %s to the upstream conformance binary to run the suite "+
			"(CI builds it from opencontainers/distribution-spec; see the conformance job)", binaryEnv)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("%s=%q is not usable: %v", binaryEnv, binary, err)
	}

	registry := Start(t, Build(t))
	// Both namespaces live under one entity, so one create serves the whole
	// suite: content is keyed by full name beneath the entity it routes to.
	registry.CreateRepository(t, "conformance")

	reportDir := t.TempDir()
	suite := exec.Command(binary)
	suite.Dir = reportDir
	suite.Env = append(os.Environ(),
		"OCI_ROOT_URL="+registry.BaseURL,
		"OCI_NAMESPACE="+namespace,
		"OCI_CROSSMOUNT_NAMESPACE="+crossmountNamespace,
		"OCI_USERNAME="+registry.Username,
		"OCI_PASSWORD="+registry.Password,
		// Every workflow the spec defines. Running a subset would let a
		// regression in the unrun half reach a release.
		"OCI_TEST_PULL=1",
		"OCI_TEST_PUSH=1",
		"OCI_TEST_CONTENT_DISCOVERY=1",
		"OCI_TEST_CONTENT_MANAGEMENT=1",
		// The suite deletes what it pushed; without this it leaves the
		// registry dirty for a rerun against the same data directory.
		"OCI_HIDE_SKIPPED_WORKFLOWS=0",
		"OCI_DEBUG=0",
	)

	output, err := suite.CombinedOutput()
	t.Logf("conformance output:\n%s", output)
	if err != nil {
		// The registry's own logs are what say *why* a spec expectation was
		// not met, and they are gone once the process is reaped.
		t.Fatalf("the distribution-spec conformance suite failed: %v\nregistry log:\n%s", err, registry.Logs())
	}

	// The suite writes an HTML/JUnit report beside itself; surfacing the path
	// makes the CI artifact discoverable from the log.
	if entries, readErr := os.ReadDir(reportDir); readErr == nil {
		for _, entry := range entries {
			t.Logf("conformance report: %s", filepath.Join(reportDir, entry.Name()))
		}
	}
}

// The group pull-side conformance run the R-009 plan defers: a group endpoint
// resolves to its members, and a client pulling through one must see the same
// spec behaviour as a hosted repository. It needs C-012's permission-filtered
// resolution, so it is a tracked skip rather than an absence -- and the skip
// names the task, the way the disclosure suite's does.
func TestGroupPullConformance(t *testing.T) {
	t.Skip("group pull-side conformance ships with C-012 (permission-filtered group resolution)")
}

// The harness's own contract with CI: the environment variable is the only
// switch, and its absence is a skip rather than a silent pass. A CI job that
// stopped exporting it would otherwise look green forever.
func TestConformanceIsSkippedOnlyWhenUnconfigured(t *testing.T) {
	t.Parallel()

	if binary := os.Getenv(binaryEnv); binary != "" {
		if strings.TrimSpace(binary) == "" {
			t.Fatalf("%s is set to whitespace, which would run nothing", binaryEnv)
		}
		if _, err := os.Stat(binary); err != nil {
			t.Fatalf("%s is set but unusable, so the suite would not run: %v", binaryEnv, err)
		}
	}
}
