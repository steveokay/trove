package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is an io.Writer safe to read while a server goroutine logs into
// it. A plain bytes.Buffer would be a data race.
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

// newServeEnv returns an Env whose stderr can be read while serve is running.
func newServeEnv() (Env, *syncBuffer) {
	logs := &syncBuffer{}
	return Env{Stdout: &syncBuffer{}, Stderr: logs}, logs
}

// waitForServing blocks until the serve command reports that it is listening.
func waitForServing(t *testing.T, logs *syncBuffer, exited <-chan error) {
	t.Helper()

	deadline := time.After(15 * time.Second)
	for {
		if strings.Contains(logs.String(), `"msg":"serving"`) {
			return
		}
		select {
		case err := <-exited:
			t.Fatalf("serve exited before listening: %v (log: %s)", err, logs.String())
		case <-deadline:
			t.Fatalf("serve did not start within 15s (log: %s)", logs.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestServeStartsAndStopsOnContextCancellation(t *testing.T) {
	t.Parallel()

	env, logs := newServeEnv()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve",
			"-data-dir", t.TempDir(),
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
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return within 10s of cancellation")
	}

	out := logs.String()
	for _, want := range []string{`"msg":"serving"`, `"msg":"shutting down"`, `"msg":"stopped"`, `"version"`} {
		if !strings.Contains(out, want) {
			t.Errorf("logs missing %s:\n%s", want, out)
		}
	}

	// Every line must be structured: this is what a log shipper consumes.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Errorf("log line is not JSON: %q", line)
		}
	}
}

func TestServeRejectsBadConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "invalid value",
			args: []string{"serve", "-log.level", "chatty"},
			want: "log.level",
		},
		{
			name: "unknown flag",
			args: []string{"serve", "-not-a-setting"},
			want: "parsing flags",
		},
		{
			name: "missing config file",
			args: []string{"serve", "-config", "/definitely/not/here.yaml"},
			want: "here.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env, _, _ := newEnv()
			err := Run(context.Background(), env, tt.args)

			if err == nil {
				t.Fatal("serve succeeded, want a configuration error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestServeFailsWhenDataDirIsAlreadyServed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	env, logs := newServeEnv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first := make(chan error, 1)
	go func() {
		first <- Run(ctx, env, []string{"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0"})
	}()

	waitForServing(t, logs, first)

	second, _ := newServeEnv()
	err := Run(context.Background(), second, []string{"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0"})
	if err == nil {
		t.Fatal("second serve started against a locked data directory, want an error")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Errorf("error = %v, want it to explain the lock", err)
	}

	cancel()
	if err := <-first; err != nil {
		t.Errorf("first serve returned %v, want nil", err)
	}
}

func TestPlaceholderHandlerRefusesExplicitly(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	placeholderHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 rather than a misleading 404", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON (%q): %v", rec.Body.String(), err)
	}
	if body["path"] != "/v2/" {
		t.Errorf("body = %v, want it to echo the path", body)
	}
}
