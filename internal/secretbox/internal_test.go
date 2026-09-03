package secretbox

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// failingReader stands in for an entropy source that has stopped working.
type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

var errNoEntropy = errors.New("entropy source is unavailable")

// Losing the entropy source must fail the operation, not silently produce a
// weak key: a key derived from short reads is a key an attacker can guess.
func TestGenerateKeyReportsAnEntropyFailure(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		source io.Reader
	}{
		{"read error", failingReader{err: errNoEntropy}},
		{"short read", bytes.NewReader(make([]byte, KeySize-1))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := generateKey(tt.source)
			if err == nil {
				t.Fatal("generateKey succeeded without entropy")
			}
			if key.ID() != "" {
				t.Errorf("generateKey returned key %s alongside its error", key.ID())
			}
		})
	}
}

// Sealing with a nonce we are not sure is random is worse than refusing: GCM
// loses its guarantees the moment a nonce repeats under one key.
func TestSealRefusesWithoutANonce(t *testing.T) {
	t.Parallel()

	key, err := NewKey(bytes.Repeat([]byte{3}, KeySize))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	ring, err := newKeyring(failingReader{err: errNoEntropy}, key)
	if err != nil {
		t.Fatalf("newKeyring: %v", err)
	}

	sealed, err := ring.Seal([]byte("token"), ProxyCredential("repo-1"))
	if !errors.Is(err, errNoEntropy) {
		t.Fatalf("Seal = %v, want the entropy failure", err)
	}
	if sealed != "" {
		t.Errorf("Seal returned %q alongside its error", sealed)
	}
}

// A keyring built without an explicit source still seals with real entropy,
// which is what keeps a zero value or a hand-rolled construction from being
// quietly deterministic.
func TestSourceDefaultsToSystemEntropy(t *testing.T) {
	t.Parallel()

	var nilRing *Keyring
	if nilRing.source() == nil {
		t.Error("a nil keyring has no entropy source")
	}
	if (&Keyring{}).source() == nil {
		t.Error("a zero keyring has no entropy source")
	}
}

func TestInsecureMode(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		mode fs.FileMode
		want bool
	}{
		{"owner read-write", 0o600, false},
		{"owner read only", 0o400, false},
		{"owner all", 0o700, false},
		{"group read", 0o640, true},
		{"world read", 0o604, true},
		{"world write", 0o602, true},
		{"everything", 0o666, true},
		{"with the directory bit set", fs.ModeDir | 0o700, false},
		{"a directory anyone can enter", fs.ModeDir | 0o755, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := insecureMode(tt.mode); got != tt.want {
				t.Errorf("insecureMode(%v) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestDefaultLoadConfigSkipsTheCheckOnlyOnWindows(t *testing.T) {
	t.Parallel()

	// Windows synthesises mode bits from a read-only attribute, so enforcing
	// them there would reject every keyfile. Linux CI is the gate (Q25).
	if got, want := defaultLoadConfig().skipPermissionCheck, runtime.GOOS == "windows"; got != want {
		t.Errorf("skipPermissionCheck = %v on %s, want %v", got, runtime.GOOS, want)
	}
}

// The permission refusal itself must hold on every platform, so it is exercised
// with the check forced on rather than only where the default enables it.
func TestLoadRefusesAWidelyReadableKeyfile(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "secrets.key")
	if err := os.WriteFile(path, []byte(key.Encode()+"\n"), 0o644); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	enforce := func(c *loadConfig) { c.skipPermissionCheck = false }
	ring, err := load(nil, path, enforce)
	if !errors.Is(err, ErrInsecureKeyfile) {
		t.Fatalf("load = %v, want ErrInsecureKeyfile", err)
	}
	if ring != nil {
		t.Error("load returned a keyring for an insecure keyfile")
	}

	var insecure *InsecureKeyfileError
	if !errors.As(err, &insecure) {
		t.Fatalf("error is %T, want *InsecureKeyfileError", err)
	}
	if !insecureMode(insecure.Mode) {
		t.Errorf("InsecureKeyfileError reports mode %v, which is not insecure", insecure.Mode)
	}

	// Same file, permission check waived: the operator's escape hatch.
	if _, err := load(nil, path, AllowInsecurePermissions()); err != nil {
		t.Errorf("load with AllowInsecurePermissions = %v, want nil", err)
	}
}

// annotate must not lose an error whose shape it did not expect.
func TestAnnotateWrapsAForeignError(t *testing.T) {
	t.Parallel()

	err := annotate("/keys/secrets.key", errNoEntropy)
	var keyfileErr *KeyfileError
	if !errors.As(err, &keyfileErr) {
		t.Fatalf("annotate returned %T, want *KeyfileError", err)
	}
	if keyfileErr.Path != "/keys/secrets.key" {
		t.Errorf("Path = %q", keyfileErr.Path)
	}
	if !errors.Is(err, errNoEntropy) {
		t.Error("annotate dropped the cause")
	}
}

// A rename that cannot land must be reported, and must not leave the temporary
// file behind for a backup to collect.
func TestWriteReportsAFailedRename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.key")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write occupant: %v", err)
	}

	key, err := NewKey(bytes.Repeat([]byte{4}, KeySize))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	ring, err := NewKeyring(key)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	if err := ring.Write(path); err == nil {
		t.Fatal("Write over a non-empty directory succeeded, want an error")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries after a failed write, want 1", len(entries))
	}
}

// A closed file is the cheapest stand-in for a full disk or a read-only mount:
// the write must surface rather than be swallowed by the close.
func TestWriteAndCloseReportsAWriteFailure(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp(t.TempDir(), "closed-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := writeAndClose(file, "content"); !errors.Is(err, os.ErrClosed) {
		t.Errorf("writeAndClose = %v, want os.ErrClosed", err)
	}
}
