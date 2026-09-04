// Package conformance runs the OCI distribution-spec conformance suite
// against a real `trove serve` (R-009).
//
// The suite itself is an upstream test binary that speaks plain HTTP to a
// registry root. What it cannot do is stand one up: trove prints its admin
// password exactly once, forces a rotation before that account can do
// anything, and has no repositories until somebody creates one. That sequence
// is this package's job, and it is exercised by a sanity test of its own, so a
// red conformance run means the registry is wrong rather than the harness.
package conformance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTimeout bounds how long a spawned registry may take to listen. It is
// generous because a first boot creates a database, runs every migration, and
// generates two keypairs.
const startTimeout = 90 * time.Second

// adminPassword matches the credential line `trove serve` prints once on a
// first boot. The format is the bootstrap's (Z-014); a change to it breaks
// this harness loudly rather than silently authenticating as nobody.
var adminPassword = regexp.MustCompile(`password:\s+(\S+)`)

// Registry is a running `trove serve` with an administrator whose password
// has been rotated into usability.
type Registry struct {
	// BaseURL is the registry root, e.g. http://127.0.0.1:53219.
	BaseURL string
	// Username and Password authenticate as the bootstrapped administrator,
	// which holds every verb (Z-014) -- the conformance suite pushes, pulls,
	// and deletes, so it needs all of them.
	Username string
	Password string

	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
	client *http.Client
}

// syncBuffer collects a child process's output while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Build compiles the trove binary under test and returns its path. It builds
// from source rather than trusting one on PATH: the suite must exercise this
// commit, not whatever was installed.
func Build(t *testing.T) string {
	t.Helper()

	root := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "trove")
	if isWindows() {
		binary += ".exe"
	}

	build := exec.Command("go", "build", "-o", binary, "./cmd/trove")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building trove: %v\n%s", err, output)
	}
	return binary
}

// Start spawns a registry on a free port with a fresh data directory, waits
// for it to listen, and rotates the bootstrap password so the administrator
// can act. The registry is stopped when the test ends.
func Start(t *testing.T, binary string) *Registry {
	t.Helper()

	port := freePort(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	registry := &Registry{
		BaseURL:  "http://" + address,
		Username: "admin",
		stdout:   &syncBuffer{},
		stderr:   &syncBuffer{},
		client:   &http.Client{Timeout: 30 * time.Second},
	}

	// The binary is one this harness just built from this repository, and the
	// arguments are literals plus test-owned temporary paths -- nothing here
	// crosses a trust boundary.
	registry.cmd = exec.Command(binary, //nolint:gosec // see above
		"serve",
		"-data-dir", t.TempDir(),
		"-server.address", address,
		"-log.format", "json",
	)
	registry.cmd.Stdout = registry.stdout
	registry.cmd.Stderr = registry.stderr
	if err := registry.cmd.Start(); err != nil {
		t.Fatalf("starting trove: %v", err)
	}
	t.Cleanup(func() { registry.stop(t) })

	registry.waitReady(t)
	registry.rotatePassword(t)
	return registry
}

// waitReady blocks until the registry answers, failing with the child's own
// logs when it does not -- a registry that refused to start has already said
// why, and repeating the reason beats reporting a timeout.
func (r *Registry) waitReady(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(startTimeout)
	for time.Now().Before(deadline) {
		if r.cmd.ProcessState != nil && r.cmd.ProcessState.Exited() {
			t.Fatalf("trove exited before listening:\nstdout: %s\nstderr: %s", r.stdout, r.stderr)
		}
		// The /v2/ root answers 401 unauthenticated (Z-004), which is proof
		// enough that the route table is up.
		resp, err := r.client.Get(r.BaseURL + "/v2/")
		if err == nil {
			_ = resp.Body.Close()
			r.readAdminPassword(t)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("trove did not listen within %s:\nstdout: %s\nstderr: %s", startTimeout, r.stdout, r.stderr)
}

// readAdminPassword lifts the one-time credential out of the child's stdout.
func (r *Registry) readAdminPassword(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if match := adminPassword.FindStringSubmatch(r.stdout.String()); match != nil {
			r.Password = match[1]
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no admin credentials printed on first boot:\nstdout: %s", r.stdout)
}

// rotatePassword replaces the bootstrap password, which is the only thing that
// account may do until it does (Z-014's must-rotate gate).
func (r *Registry) rotatePassword(t *testing.T) {
	t.Helper()

	rotated := r.Password + "-rotated-for-conformance"
	body, err := json.Marshal(map[string]string{
		"current_password": r.Password,
		"new_password":     rotated,
	})
	if err != nil {
		t.Fatalf("encoding the rotation request: %v", err)
	}

	resp := r.request(t, http.MethodPost, "/api/v1/auth/password", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("rotating the bootstrap password: %s\n%s", resp.Status, readBody(resp))
	}
	r.Password = rotated
}

// CreateRepository creates a hosted repository entity, which is what gives the
// conformance suite a namespace to push into (C-016).
func (r *Registry) CreateRepository(t *testing.T, name string) {
	t.Helper()

	body, err := json.Marshal(map[string]string{"name": name, "type": "hosted"})
	if err != nil {
		t.Fatalf("encoding the create request: %v", err)
	}
	resp := r.request(t, http.MethodPost, "/api/v1/repositories", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating the repository %q: %s\n%s", name, resp.Status, readBody(resp))
	}
}

// Do sends an authenticated request to the registry, for tests that drive it
// directly rather than through the conformance binary.
func (r *Registry) Do(t *testing.T, method, path string, body []byte, headers ...string) *http.Response {
	t.Helper()

	resp := r.request(t, method, path, body, headers...)
	return resp
}

func (r *Registry) request(t *testing.T, method, path string, body []byte, headers ...string) *http.Response {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, r.BaseURL+path, reader)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, path, err)
	}
	req.SetBasicAuth(r.Username, r.Password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// Logs returns what the registry has written, for a failure that needs the
// server's side of the story.
func (r *Registry) Logs() string { return r.stderr.String() }

// stop ends the process and reports a crash, which would otherwise look like a
// suite failure with no explanation.
func (r *Registry) stop(t *testing.T) {
	t.Helper()

	if r.cmd == nil || r.cmd.Process == nil {
		return
	}
	// SIGINT is the graceful path everywhere it exists; Windows has no such
	// signal for another process, so the kill is the shutdown there.
	if err := interrupt(r.cmd); err != nil {
		_ = r.cmd.Process.Kill()
	}
	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = r.cmd.Process.Kill()
		<-done
		t.Errorf("trove did not shut down within 30s:\n%s", r.stderr)
	}
}

func readBody(resp *http.Response) string {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return "(unreadable body: " + err.Error() + ")"
	}
	return string(body)
}

// freePort asks the operating system for an unused port. The listener is
// closed before the registry binds it, so there is a race in principle; in a
// test process on a loopback interface it has never mattered, and the
// alternative is a fixed port that collides with a parallel run for certain.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not TCP", listener.Addr())
	}
	return addr.Port
}

// repositoryRoot walks up to the module root, so the harness works whatever
// directory the test was invoked from.
func repositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

// scanLines is a small helper for tests that assert on the child's log stream.
func scanLines(s string) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
