package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/meta/memory"
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

// newServeEnv returns an Env whose streams can be read while serve is
// running: stdout for the one-time bootstrap credentials, stderr for logs.
func newServeEnv() (Env, *syncBuffer) {
	env, _, logs := newServeStreams()
	return env, logs
}

func newServeStreams() (Env, *syncBuffer, *syncBuffer) {
	stdout, logs := &syncBuffer{}, &syncBuffer{}
	return Env{Stdout: stdout, Stderr: logs}, stdout, logs
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
		{
			name: "unusable postgres DSN",
			args: []string{"serve", "-database.driver", "postgres", "-database.dsn", "://not-a-dsn"},
			want: "open metadata store",
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

// An unreadable existing keyfile is fatal: with credential digests keyed by
// it in the database, starting over with a fresh key would orphan them all
// while looking like a successful boot (ADR 0016).
func TestServeRefusesACorruptKeyfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "secrets.key"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	env, _ := newServeEnv()
	err := Run(context.Background(), env, []string{"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "secrets keyfile") {
		t.Fatalf("Run = %v, want a refusal naming the keyfile", err)
	}
}

// The assembled table is a security artifact: every route guarded, none
// public, and exactly one door through the rotation gate. Walking it here
// means adding a route to serve without thinking about these properties fails
// a test rather than shipping.
func TestAssembledRouteTable(t *testing.T) {
	t.Parallel()

	store := memory.New()
	t.Cleanup(func() { _ = store.Close() })
	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	router := buildRouter(store, login, nil, nil)
	if err := router.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var exempt []string
	for _, route := range router.Routes() {
		if route.Public() {
			t.Errorf("%s %s is public; serve registers no public routes yet", route.Method, route.Pattern)
		}
		if route.Permission.RotationExempt {
			exempt = append(exempt, route.Method+" "+route.Pattern)
		}
	}
	if len(exempt) != 1 || exempt[0] != "POST /api/v1/auth/password" {
		t.Errorf("rotation-exempt routes = %v, want exactly the rotation endpoint", exempt)
	}
}

// servingAddress digs the listener's resolved address out of the JSON logs.
func servingAddress(t *testing.T, logs *syncBuffer) string {
	t.Helper()

	for _, line := range strings.Split(logs.String(), "\n") {
		var record struct {
			Msg     string `json:"msg"`
			Address string `json:"address"`
		}
		if json.Unmarshal([]byte(line), &record) == nil && record.Msg == "serving" {
			return record.Address
		}
	}
	t.Fatal("no serving line in the logs")
	return ""
}

// The Z-014 acceptance path against a real process boundary: first boot
// prints credentials once, the printed password opens only the rotation door,
// rotating opens the rest, and a restart prints nothing.
func TestServeBootstrapsAndForcesRotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	env, stdout, logs := newServeStreams()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs, done)

	// The credentials went to stdout, once, and never to the log stream.
	credentials := regexp.MustCompile(`password: ([A-Za-z0-9_-]{32})`).FindStringSubmatch(stdout.String())
	if credentials == nil {
		t.Fatalf("stdout has no bootstrap password:\n%s", stdout.String())
	}
	password := credentials[1]
	if strings.Contains(logs.String(), password) {
		t.Fatal("the bootstrap password leaked into the log stream")
	}

	base := "http://" + servingAddress(t, logs)
	call := func(method, path, password, body string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.SetBasicAuth("admin", password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		read := new(strings.Builder)
		_, _ = io.Copy(read, resp.Body)
		return resp, read.String()
	}

	// The printed password reaches nothing but the rotation endpoint.
	if resp, body := call(http.MethodGet, "/api/v1/auth/explain?verb=gc:run", password, ""); resp.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, "rotation-required") {
		t.Fatalf("explain before rotation: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(http.MethodPost, "/api/v1/auth/password", password,
		`{"current_password":"`+password+`","new_password":"correct horse battery"}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("rotation: %d %s", resp.StatusCode, body)
	}
	resp, body := call(http.MethodGet, "/api/v1/auth/explain?verb=gc:run", "correct horse battery", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"allowed":true`) {
		t.Fatalf("explain after rotation: %d %s", resp.StatusCode, body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve returned %v", err)
	}

	// The first boot also generated the secrets keyfile (Q21) and said so.
	if _, err := os.Stat(filepath.Join(dir, "keys", "secrets.key")); err != nil {
		t.Errorf("secrets keyfile after first boot: %v", err)
	}
	if !strings.Contains(logs.String(), "generated a new secrets keyfile") {
		t.Error("first boot did not log the keyfile generation")
	}

	// A restart prints no credentials and generates no second key: the store
	// remembers its admin and the keyfile is loaded, not replaced.
	env2, stdout2, logs2 := newServeStreams()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() {
		done2 <- Run(ctx2, env2, []string{
			"serve", "-data-dir", dir, "-server.address", "127.0.0.1:0", "-log.format", "json",
		})
	}()
	waitForServing(t, logs2, done2)
	if strings.Contains(stdout2.String(), "password:") {
		t.Fatalf("second boot printed credentials:\n%s", stdout2.String())
	}
	if strings.Contains(logs2.String(), "generated a new secrets keyfile") {
		t.Fatal("second boot generated a fresh key over the existing one")
	}
	cancel2()
	if err := <-done2; err != nil {
		t.Fatalf("second serve returned %v", err)
	}
}
