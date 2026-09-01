package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/config"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg, err := config.Load(config.Options{
		Args:      []string{"-data-dir", t.TempDir(), "-server.address", "127.0.0.1:0"},
		LookupEnv: func(string) (string, bool) { return "", false },
		ReadFile:  func(string) ([]byte, error) { return nil, fs.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("loading test config: %v", err)
	}
	return cfg
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// start runs a server in the background and waits for it to bind, returning
// its base URL and a stop function that reports the run's error.
func start(t *testing.T, cfg *config.Config, log *slog.Logger, h http.Handler) (string, func() error) {
	t.Helper()

	srv := New(cfg, log, h)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	select {
	case <-srv.Ready():
	case err := <-done:
		cancel()
		t.Fatalf("server exited before binding: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("server did not bind within 10s")
	}

	url := "http://" + srv.Addr().String()
	return url, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			return errors.New("server did not stop within 10s")
		}
	}
}

func TestServerServesAndStopsCleanly(t *testing.T) {
	t.Parallel()

	url, stop := start(t, testConfig(t), discardLogger(), http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "hello")
		}))

	resp, err := http.Get(url + "/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
	if resp.Header.Get(RequestIDHeader) == "" {
		t.Error("response carries no request id header")
	}
	if err := stop(); err != nil {
		t.Errorf("Run returned %v, want nil on clean shutdown", err)
	}
}

// The acceptance criterion for F-004: a request already in flight when
// shutdown begins must finish, not be cut off.
func TestInFlightRequestSurvivesShutdown(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})

	url, stop := start(t, testConfig(t), discardLogger(), http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			fmt.Fprint(w, "finished")
		}))

	type result struct {
		body string
		err  error
	}
	results := make(chan result, 1)
	go func() {
		resp, err := http.Get(url + "/slow")
		if err != nil {
			results <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		results <- result{body: string(body), err: err}
	}()

	<-started // the handler is running

	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()

	// Shutdown is now under way. Let the handler finish and check that its
	// response still reached the client.
	time.Sleep(50 * time.Millisecond)
	close(release)

	got := <-results
	if got.err != nil {
		t.Fatalf("in-flight request failed during shutdown: %v", got.err)
	}
	if got.body != "finished" {
		t.Errorf("body = %q, want finished", got.body)
	}
	if err := <-stopped; err != nil {
		t.Errorf("Run returned %v, want nil", err)
	}
}

func TestShutdownClosesConnectionsPastGracePeriod(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)
	cfg.Server.ShutdownGrace = config.Duration(20 * time.Millisecond)

	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))

	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	url, stop := start(t, cfg, log, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			close(started)
			<-release
			fmt.Fprint(w, "too late")
		}))

	go func() {
		resp, err := http.Get(url + "/slow")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started

	if err := stop(); err != nil {
		t.Errorf("Run returned %v, want nil even when the grace period expires", err)
	}
	if !strings.Contains(logs.String(), "grace period expired") {
		t.Errorf("expected a warning about the expired grace period, got:\n%s", logs.String())
	}
}

func TestRunFailsWhenDataDirIsLocked(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)

	held, err := AcquireDataDirLock(cfg.DataDir)
	if err != nil {
		t.Fatalf("acquiring the lock: %v", err)
	}
	defer func() { _ = held.Release() }()

	srv := New(cfg, discardLogger(), http.NotFoundHandler())
	err = srv.Run(context.Background())

	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Run error = %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), LockFileName) {
		t.Errorf("error = %v, want it to name the lock file", err)
	}
}

func TestRunFailsOnUnusableAddress(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)

	// Occupy an address so the bind is guaranteed to conflict.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	cfg.Server.Address = ln.Addr().String()

	srv := New(cfg, discardLogger(), http.NotFoundHandler())
	if err := srv.Run(context.Background()); err == nil {
		t.Fatal("Run succeeded on an address already in use, want an error")
	} else if !strings.Contains(err.Error(), "listening on") {
		t.Errorf("error = %v, want it to mention listening", err)
	}
}

func TestRunReleasesLockOnExit(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)
	_, stop := start(t, cfg, discardLogger(), http.NotFoundHandler())
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// The directory must be claimable again once the server has stopped.
	lock, err := AcquireDataDirLock(cfg.DataDir)
	if err != nil {
		t.Fatalf("data directory still locked after shutdown: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Errorf("Release: %v", err)
	}
}
