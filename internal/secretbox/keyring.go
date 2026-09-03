package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// MaxKeyfileSize bounds how much of a keyfile is read. A keyfile holds a
// handful of 44-character lines; anything larger is a misconfiguration — a
// database or a certificate pointed at the wrong setting — and reading it into
// memory would be the second mistake.
const MaxKeyfileSize = 64 << 10

// keyfileMode is what a keyfile must be created with and, on a platform that
// enforces mode bits, what it must still have when it is read.
const keyfileMode fs.FileMode = 0o600

// keyDirMode is used for directories created on the way to a keyfile.
const keyDirMode fs.FileMode = 0o700

// Keyring is an ordered set of keys: the first seals, all of them open.
//
// That ordering is the whole of the rotation story (ADR 0016). Prepending a
// new key changes what fresh values are sealed with while every value sealed
// by a retired key keeps opening, so re-encryption is a background pass rather
// than a maintenance window.
//
// A Keyring is immutable once built and safe for concurrent use. Rotate
// returns a new one rather than mutating this one.
type Keyring struct {
	entries []entry
	byID    map[string]int
	random  io.Reader
}

// entry pairs a key with the AEAD built from it. Building the cipher once at
// construction keeps the per-value path allocation-light and, more usefully,
// means a key that cannot produce a cipher is rejected at startup rather than
// on the first push.
type entry struct {
	key  Key
	aead cipher.AEAD
}

// NewKeyring builds a keyring from key material already in memory — for a
// test, or for an operator injecting a key from their platform rather than a
// file. The first key is the active one.
func NewKeyring(keys ...Key) (*Keyring, error) { return newKeyring(rand.Reader, keys...) }

// newKeyring is the injectable form; random supplies nonces.
func newKeyring(random io.Reader, keys ...Key) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("build keyring: %w", ErrNoKey)
	}
	r := &Keyring{
		entries: make([]entry, 0, len(keys)),
		byID:    make(map[string]int, len(keys)),
		random:  random,
	}
	for _, k := range keys {
		if k.id == "" {
			return nil, &InvalidKeyError{Reason: "key was not built by NewKey, GenerateKey, or DecodeKey"}
		}
		if _, duplicate := r.byID[k.id]; duplicate {
			return nil, &InvalidKeyError{Reason: fmt.Sprintf("key %s appears more than once", k.id)}
		}
		block, err := aes.NewCipher(k.material[:])
		if err != nil {
			return nil, fmt.Errorf("build cipher for key %s: %w", k.id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("build aead for key %s: %w", k.id, err)
		}
		r.byID[k.id] = len(r.entries)
		r.entries = append(r.entries, entry{key: k, aead: aead})
	}
	return r, nil
}

// ParseKeyring reads keyfile content: one standard-base64 key per line, first
// line active. Blank lines and lines beginning with '#' are ignored, so an
// operator mid-rotation can label which line is retired without inventing a
// second file format.
func ParseKeyring(data []byte) (*Keyring, error) { return parseKeyring(rand.Reader, data) }

func parseKeyring(random io.Reader, data []byte) (*Keyring, error) {
	var keys []Key
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := DecodeKey(line)
		if err != nil {
			return nil, &KeyfileError{Line: i + 1, Err: err}
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		// An empty keyfile is not an invitation to generate one: values
		// already in the database were sealed with something (ADR 0016).
		return nil, &KeyfileError{Err: ErrNoKey}
	}
	kr, err := newKeyring(random, keys...)
	if err != nil {
		return nil, &KeyfileError{Err: err}
	}
	return kr, nil
}

// LoadOption adjusts how Load reads a keyfile.
type LoadOption func(*loadConfig)

type loadConfig struct {
	skipPermissionCheck bool
}

func defaultLoadConfig() loadConfig {
	// Windows carries no POSIX mode bits — os.Stat synthesises them from the
	// read-only attribute — so the check would reject every keyfile there.
	// Linux CI remains the authoritative gate (Q25).
	return loadConfig{skipPermissionCheck: runtime.GOOS == "windows"}
}

// AllowInsecurePermissions accepts a keyfile that accounts other than its
// owner can read. It exists for operators mounting a key from a platform that
// dictates the mode — a Kubernetes secret volume is 0644 — where the
// protection is the mount, not the bits.
func AllowInsecurePermissions() LoadOption {
	return func(c *loadConfig) { c.skipPermissionCheck = true }
}

// Load reads and parses the keyfile at path.
//
// A missing or unreadable keyfile is returned as an error and never as an
// empty keyring: with encrypted values in the database the caller must fail
// loudly rather than start with a fresh key (ADR 0016). errors.Is reaches
// fs.ErrNotExist, ErrNoKey, ErrInvalidKey, and ErrInsecureKeyfile through the
// KeyfileError wrapper.
func Load(path string, opts ...LoadOption) (*Keyring, error) { return load(rand.Reader, path, opts...) }

func load(random io.Reader, path string, opts ...LoadOption) (*Keyring, error) {
	cfg := defaultLoadConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	defer func() { _ = file.Close() }()

	// Stat the open handle rather than the path: checking the permissions of
	// one file and then reading another is exactly the race the check exists
	// to prevent.
	info, err := file.Stat()
	if err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	if !cfg.skipPermissionCheck && insecureMode(info.Mode()) {
		return nil, &KeyfileError{Path: path, Err: &InsecureKeyfileError{Mode: info.Mode()}}
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxKeyfileSize+1))
	if err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	if len(data) > MaxKeyfileSize {
		return nil, &KeyfileError{Path: path, Err: &InvalidKeyError{
			Reason: fmt.Sprintf("keyfile is larger than %d bytes; is this the right path?", MaxKeyfileSize),
		}}
	}

	kr, err := parseKeyring(random, data)
	if err != nil {
		return nil, annotate(path, err)
	}
	return kr, nil
}

// insecureMode reports whether a mode lets anyone but the owner at the file.
func insecureMode(mode fs.FileMode) bool { return mode.Perm()&0o077 != 0 }

// annotate attaches the path to a parse error raised before the path was
// known, so one message carries both the file and the line.
func annotate(path string, err error) error {
	var keyfileErr *KeyfileError
	if errors.As(err, &keyfileErr) {
		keyfileErr.Path = path
		return err
	}
	return &KeyfileError{Path: path, Err: err}
}

// Create generates a keyfile at path holding one fresh key, creating parent
// directories as needed, and returns the keyring it holds.
//
// It refuses to overwrite an existing file. Re-keying over one would leave
// every stored value unopenable while looking like a successful first run,
// which is the failure ADR 0016 is most concerned to prevent.
func Create(path string) (*Keyring, error) {
	if err := os.MkdirAll(filepath.Dir(path), keyDirMode); err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	kr, err := NewKeyring(key)
	if err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyfileMode)
	if err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	if err := writeAndClose(file, kr.Encode()); err != nil {
		return nil, &KeyfileError{Path: path, Err: err}
	}
	return kr, nil
}

// Write replaces the keyfile at path with this keyring's keys, active first.
// Rotation calls it after prepending a new key.
//
// The write goes to a temporary file in the same directory and is renamed into
// place, because a keyfile truncated by a crash mid-write is unrecoverable
// data loss: every secret in the database becomes noise.
func (r *Keyring) Write(path string) error {
	if r == nil || len(r.entries) == 0 {
		return &KeyfileError{Path: path, Err: ErrNoKey}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, keyDirMode); err != nil {
		return &KeyfileError{Path: path, Err: err}
	}
	// os.CreateTemp creates with mode 0600, which is exactly what a keyfile
	// must be; there is no window in which the new file is world-readable.
	temp, err := os.CreateTemp(dir, ".secrets-*.key")
	if err != nil {
		return &KeyfileError{Path: path, Err: err}
	}
	tempPath := temp.Name()
	if err := writeAndClose(temp, r.Encode()); err != nil {
		_ = os.Remove(tempPath)
		return &KeyfileError{Path: path, Err: err}
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return &KeyfileError{Path: path, Err: err}
	}
	return nil
}

// writeAndClose flushes content to disk before returning, and closes the file
// whatever happens. A keyfile that is only in the page cache when the machine
// loses power is a keyfile that never existed, and every secret in the
// database becomes noise.
func writeAndClose(file *os.File, content string) error {
	err := writeAndSync(file, content)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func writeAndSync(file *os.File, content string) error {
	if _, err := file.WriteString(content); err != nil {
		return err
	}
	return file.Sync()
}

// Encode renders the keyring in keyfile format, active key first.
func (r *Keyring) Encode() string {
	var b strings.Builder
	for _, k := range r.Keys() {
		b.WriteString(k.Encode())
		b.WriteByte('\n')
	}
	return b.String()
}

// Keys returns the keys in order, active first. The slice is a copy.
func (r *Keyring) Keys() []Key {
	if r == nil {
		return nil
	}
	keys := make([]Key, 0, len(r.entries))
	for _, e := range r.entries {
		keys = append(keys, e.key)
	}
	return keys
}

// ActiveKeyID returns the identifier of the key Seal uses, or the empty string
// for a keyring with no keys. Config dumps and support bundles render it (as
// "<redacted:key-id>") in place of anything they must not print.
func (r *Keyring) ActiveKeyID() string {
	if r == nil || len(r.entries) == 0 {
		return ""
	}
	return r.entries[0].key.ID()
}

// KeyIDs returns every identifier the keyring can open values under, active
// first.
func (r *Keyring) KeyIDs() []string {
	keys := r.Keys()
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID())
	}
	return ids
}

// Rotate returns a keyring with key active and every existing key retained for
// decryption. The receiver is unchanged.
//
// This is step one of the two-step rotation in ADR 0016: write the result,
// re-encrypt every stored value, confirm nothing still names the retired key,
// and only then remove its line.
func (r *Keyring) Rotate(key Key) (*Keyring, error) {
	keys := append([]Key{key}, r.Keys()...)
	return newKeyring(r.source(), keys...)
}

// source is the nonce source, defaulting to the system entropy pool so that a
// keyring built by any route — including a zero value — never silently seals
// with predictable nonces.
func (r *Keyring) source() io.Reader {
	if r == nil || r.random == nil {
		return rand.Reader
	}
	return r.random
}

// String describes the keyring without exposing any key material.
func (r *Keyring) String() string {
	if r == nil {
		return "secretbox.Keyring(empty)"
	}
	return fmt.Sprintf("secretbox.Keyring(active=%s, keys=%d)", r.ActiveKeyID(), len(r.entries))
}
