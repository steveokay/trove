// Package offline proves what a fresh install does not do: reach the network.
//
// §0.6 says the only outbound calls trove makes are to upstreams the operator
// explicitly configured, and Q7 ships five proxy presets *disabled* so that a
// default install has none. Those are claims about a boot, not about a
// function, so this is a test that boots the real `trove serve` -- the same
// entry point the binary calls -- and watches for a connection.
//
// It lives in the top-level test tree because it swaps process-wide state
// (http.DefaultTransport) and must therefore own its package's parallelism.
// Inside internal/cli it would race the parallel serve tests already there.
package offline_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/cli"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlite"
	"github.com/steveokay/trove/internal/repo"
)

// TestAFreshInstallTalksToNobody boots a default deployment and asserts that
// nothing reached out and nothing was created to reach out *with*.
//
// Deliberately not parallel: it replaces http.DefaultTransport for the duration
// and restores it afterwards.
func TestAFreshInstallTalksToNobody(t *testing.T) {
	watcher := &networkWatcher{}
	restore := http.DefaultTransport
	http.DefaultTransport = watcher
	t.Cleanup(func() { http.DefaultTransport = restore })

	dataDir := t.TempDir()
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- cli.Run(ctx, cli.Env{Stdout: io.Discard, Stderr: logs}, []string{
			"serve",
			"-data-dir", dataDir,
			"-server.address", "127.0.0.1:0",
			"-log.format", "json",
		})
	}()

	waitForServing(t, logs, done)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v, want nil on cancellation", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not shut down")
	}

	// The direct claim: a boot that bootstraps an admin, runs migrations,
	// mints keys, and serves did not send a single HTTP request.
	if attempts := watcher.attempts(); len(attempts) > 0 {
		t.Errorf("a fresh install made %d outbound request(s): %v", len(attempts), attempts)
	}

	// And the reason it stays true: no repository exists, so there is no
	// upstream to reach even once something starts pulling. This is Q7's
	// "presets ship disabled" as a property of the deployment rather than of
	// a flag -- a preset that was instantiated at boot would show up here as a
	// proxy entity nobody asked for.
	store, err := sqlite.Open(context.Background(), sqlite.Options{Path: filepath.Join(dataDir, "trove.db")})
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	defer func() { _ = store.Close() }()

	page, err := store.ListRepositories(context.Background(), meta.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(page.Repositories) != 0 {
		names := make([]string, 0, len(page.Repositories))
		for _, r := range page.Repositories {
			names = append(names, fmt.Sprintf("%s(%s)", r.Name, r.Type))
		}
		t.Errorf("a fresh install created %d repositor(ies): %v", len(names), names)
	}
}

// TestEveryPresetIsAbsentFromAFreshInstall states the same thing the other way
// round, and is the one that would fail if somebody wired the preset list into
// the bootstrap: every shipped preset's name is available, because nothing
// claimed it.
func TestEveryPresetIsAbsentFromAFreshInstall(t *testing.T) {
	dataDir := t.TempDir()
	logs := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- cli.Run(ctx, cli.Env{Stdout: io.Discard, Stderr: logs}, []string{
			"serve", "-data-dir", dataDir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v", err)
	}

	store, err := sqlite.Open(context.Background(), sqlite.Options{Path: filepath.Join(dataDir, "trove.db")})
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	defer func() { _ = store.Close() }()

	presets := repo.Presets()
	if len(presets) == 0 {
		t.Fatal("no presets shipped; this test would pass vacuously")
	}
	for _, preset := range presets {
		_, err := store.GetRepository(context.Background(), preset.Name)
		if !errors.Is(err, meta.ErrNotFound) {
			t.Errorf("preset %q exists after a fresh boot (err = %v); presets ship disabled (Q7)", preset.Name, err)
		}
	}
}

// TestTheWatcherWouldNoticeARequest is the harness's self-test, and the reason
// the assertion above is worth anything. A negative test that cannot fail is
// indistinguishable from one that passes, so this proves the swap is effective
// by making exactly the kind of call the boot must not make.
func TestTheWatcherWouldNoticeARequest(t *testing.T) {
	watcher := &networkWatcher{}
	restore := http.DefaultTransport
	http.DefaultTransport = watcher
	t.Cleanup(func() { http.DefaultTransport = restore })

	// DefaultClient uses DefaultTransport: the path any casual "just fetch it"
	// call in the boot path would take. Nothing leaves the machine -- the
	// watcher refuses before a connection is opened.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry-1.docker.io/v2/", nil)
	if err != nil {
		t.Fatalf("building the probe request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the watcher let a request through")
	}

	attempts := watcher.attempts()
	if len(attempts) != 1 {
		t.Fatalf("watcher recorded %v, want exactly one attempt", attempts)
	}
	if !strings.Contains(attempts[0], "registry-1.docker.io") {
		t.Errorf("watcher recorded %q, which does not name the host asked for", attempts[0])
	}
}

// networkWatcher is an http.RoundTripper that records what it was asked to
// fetch and refuses to fetch it. Refusing matters as much as recording: if
// something in the boot path did reach out, the test should fail on the
// recording rather than on whatever the remote happened to answer.
type networkWatcher struct {
	mu   sync.Mutex
	seen []string
}

func (w *networkWatcher) RoundTrip(r *http.Request) (*http.Response, error) {
	w.mu.Lock()
	w.seen = append(w.seen, r.Method+" "+r.URL.Redacted())
	w.mu.Unlock()
	return nil, fmt.Errorf("outbound request refused by the offline test: %s", r.URL.Redacted())
}

func (w *networkWatcher) attempts() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.seen...)
}

// assert the watcher is a transport at compile time, so a signature change
// fails here rather than silently leaving the swap ineffective.
var _ http.RoundTripper = (*networkWatcher)(nil)

// syncBuffer is an io.Writer safe to read while the server goroutine logs into
// it.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
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

// waitForServing blocks until serve reports that it is listening.
func waitForServing(t *testing.T, logs *syncBuffer, exited <-chan error) {
	t.Helper()

	deadline := time.After(30 * time.Second)
	for {
		if strings.Contains(logs.String(), `"msg":"serving"`) {
			return
		}
		select {
		case err := <-exited:
			t.Fatalf("serve exited before listening: %v (log: %s)", err, logs.String())
		case <-deadline:
			t.Fatalf("serve did not start within 30s (log: %s)", logs.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
}
