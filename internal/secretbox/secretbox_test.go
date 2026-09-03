package secretbox_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/secretbox"
)

// A pinned value for the wire format. It was produced by AES-256-GCM under a
// key of 32 bytes of 0x07 with the nonce 01..0c, and it is checked in because
// the format is a contract with the database: values sealed by today's build
// must still open under next year's, and nothing else in the test suite would
// notice a change to the nonce placement, the encoding, or the associated
// data.
const (
	goldenValue     = "v1:4bb06f8e:AQIDBAUGBwgJCgsMzgyb6hiPg0HISm118Mlwai32prE3VbOJ2mXSfnEE"
	goldenPlaintext = "upstream-token"
	goldenKeyByte   = 7
	goldenKeyID     = "4bb06f8e"
)

// fixedKey builds a key from a repeated byte, so a test can name the key it
// means and get the same identifier every run.
func fixedKey(t *testing.T, b byte) secretbox.Key {
	t.Helper()

	key, err := secretbox.NewKey(bytes.Repeat([]byte{b}, secretbox.KeySize))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return key
}

func keyring(t *testing.T, bytesOfKeys ...byte) *secretbox.Keyring {
	t.Helper()

	keys := make([]secretbox.Key, 0, len(bytesOfKeys))
	for _, b := range bytesOfKeys {
		keys = append(keys, fixedKey(t, b))
	}
	ring, err := secretbox.NewKeyring(keys...)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return ring
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	for _, tt := range []struct {
		name      string
		plaintext []byte
		context   secretbox.Context
	}{
		{"empty", []byte{}, secretbox.ProxyCredential("repo-1")},
		{"nil", nil, secretbox.ProxyCredential("repo-1")},
		{"short", []byte("hunter2"), secretbox.WebhookSecret("wh-9")},
		{"binary with nul bytes", []byte{0, 1, 2, 0, 255, 0}, secretbox.Context("column:row")},
		{"unicode", []byte("pässwörd·🔐"), secretbox.Context("column:row")},
		{"kilobyte", bytes.Repeat([]byte("a"), 1024), secretbox.Context("column:row")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sealed, err := ring.Seal(tt.plaintext, tt.context)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if strings.Contains(sealed, string(tt.plaintext)) && len(tt.plaintext) > 0 {
				t.Fatalf("sealed value contains the plaintext")
			}

			opened, err := ring.Open(sealed, tt.context)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened, tt.plaintext) {
				t.Errorf("Open returned %q, want %q", opened, tt.plaintext)
			}
		})
	}
}

// The wire format is a contract: it is stored in a database column and read
// back by a later build, and rotation depends on being able to read the key-id
// without the key.
func TestSealedValueShape(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	sealed, err := ring.Seal([]byte("secret"), secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	parts := strings.Split(sealed, ":")
	if len(parts) != 3 {
		t.Fatalf("sealed value has %d colon-separated fields, want 3", len(parts))
	}
	if parts[0] != secretbox.Version {
		t.Errorf("version = %q, want %q", parts[0], secretbox.Version)
	}
	if parts[1] != ring.ActiveKeyID() {
		t.Errorf("key id = %q, want the active key %q", parts[1], ring.ActiveKeyID())
	}
	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("payload is not standard base64: %v", err)
	}
	// 12-byte nonce + 6 bytes of plaintext + 16-byte GCM tag.
	if want := 12 + 6 + 16; len(payload) != want {
		t.Errorf("payload is %d bytes, want %d (nonce, ciphertext, tag)", len(payload), want)
	}

	id, err := secretbox.KeyIDOf(sealed)
	if err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if id != ring.ActiveKeyID() {
		t.Errorf("KeyIDOf = %q, want %q", id, ring.ActiveKeyID())
	}
}

// The format is a contract with every row already in the database, so a value
// sealed by an older build must still open here, byte for byte.
func TestGoldenValueStillOpens(t *testing.T) {
	t.Parallel()

	ring := keyring(t, goldenKeyByte)
	if got := ring.ActiveKeyID(); got != goldenKeyID {
		t.Fatalf("key id derivation changed: %q, want %q", got, goldenKeyID)
	}

	opened, err := ring.Open(goldenValue, secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Open of the pinned value: %v", err)
	}
	if string(opened) != goldenPlaintext {
		t.Errorf("Open = %q, want %q", opened, goldenPlaintext)
	}

	// Same bytes, different binding: the associated data really is part of
	// what is authenticated, not decoration.
	if _, err := ring.Open(goldenValue, secretbox.ProxyCredential("repo-2")); !errors.Is(err, secretbox.ErrAuthentication) {
		t.Errorf("Open under another context = %v, want ErrAuthentication", err)
	}
}

// A fresh nonce per value is what keeps two rows holding the same credential
// from looking alike on disk.
func TestSealIsNonDeterministic(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	ctx := secretbox.ProxyCredential("repo-1")

	first, err := ring.Seal([]byte("same"), ctx)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := ring.Seal([]byte("same"), ctx)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if first == second {
		t.Fatal("two seals of the same plaintext are identical; the nonce is not random")
	}
	for _, sealed := range []string{first, second} {
		opened, err := ring.Open(sealed, ctx)
		if err != nil || string(opened) != "same" {
			t.Fatalf("Open(%q) = %q, %v", sealed, opened, err)
		}
	}
}

// The adversarial case ADR 0016 names: a ciphertext lifted out of one row and
// pasted into another must fail rather than decrypt into the wrong context.
func TestCiphertextDoesNotMoveBetweenContexts(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	sealed, err := ring.Seal([]byte("upstream-token"), secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, tt := range []struct {
		name string
		ctx  secretbox.Context
	}{
		{"another row of the same column", secretbox.ProxyCredential("repo-2")},
		{"another column of the same row", secretbox.WebhookSecret("repo-1")},
		{"the context with a trailing space", secretbox.Context("proxy-credential:repo-1 ")},
		{"a prefix of the context", secretbox.Context("proxy-credential:repo-")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opened, err := ring.Open(sealed, tt.ctx)
			if !errors.Is(err, secretbox.ErrAuthentication) {
				t.Fatalf("Open = %v, want ErrAuthentication", err)
			}
			if opened != nil {
				t.Errorf("Open returned %d bytes alongside its error", len(opened))
			}
		})
	}
}

func TestOpenRejectsTamperedValues(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	ctx := secretbox.ProxyCredential("repo-1")
	sealed, err := ring.Seal([]byte("upstream-token"), ctx)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.SplitN(sealed, ":", 3)[2])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	// One flipped bit anywhere in the value -- nonce, ciphertext, or tag --
	// must be caught. Flipping every byte in turn is cheap and leaves no gap
	// for a region the tag does not actually cover.
	for offset := 0; offset < len(payload); offset++ {
		tampered := bytes.Clone(payload)
		tampered[offset] ^= 0x01
		value := fmt.Sprintf("%s:%s:%s", secretbox.Version, ring.ActiveKeyID(),
			base64.StdEncoding.EncodeToString(tampered))

		if _, err := ring.Open(value, ctx); !errors.Is(err, secretbox.ErrAuthentication) {
			t.Fatalf("flipping byte %d gave %v, want ErrAuthentication", offset, err)
		}
	}
}

func TestOpenRejectsUnparseableValues(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	id := ring.ActiveKeyID()
	payload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 28))

	for _, tt := range []struct {
		name  string
		value string
		want  error
	}{
		{"empty", "", secretbox.ErrMalformed},
		{"no separators", "just-a-string", secretbox.ErrMalformed},
		{"one separator", "v1:" + id, secretbox.ErrMalformed},
		{"four fields", "v1:" + id + ":" + payload + ":extra", secretbox.ErrMalformed},
		{"unknown version", "v2:" + id + ":" + payload, secretbox.ErrUnsupportedVersion},
		{"empty version", ":" + id + ":" + payload, secretbox.ErrUnsupportedVersion},
		{"uppercase key id", "v1:" + strings.ToUpper(id) + ":" + payload, secretbox.ErrMalformed},
		{"short key id", "v1:abc:" + payload, secretbox.ErrMalformed},
		{"non-hex key id", "v1:zzzzzzzz:" + payload, secretbox.ErrMalformed},
		{"empty key id", "v1::" + payload, secretbox.ErrMalformed},
		{"payload is not base64", "v1:" + id + ":not base64!", secretbox.ErrMalformed},
		// Go's base64 decoder skips CR and LF, so without a canonicality
		// check one payload would have unboundedly many spellings.
		{"newline inside the payload", "v1:" + id + ":" + payload[:4] + "\n" + payload[4:], secretbox.ErrMalformed},
		{"carriage return inside the payload", "v1:" + id + ":" + payload[:4] + "\r" + payload[4:], secretbox.ErrMalformed},
		{"non-zero padding bits", "v1:" + id + ":AB==", secretbox.ErrMalformed},
		{"empty payload", "v1:" + id + ":", secretbox.ErrMalformed},
		{"payload shorter than a nonce", "v1:" + id + ":" + base64.StdEncoding.EncodeToString([]byte("short")), secretbox.ErrMalformed},
		{"nonce but no tag", "v1:" + id + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 12)), secretbox.ErrMalformed},
		{"unknown key", "v1:0123abcd:" + payload, secretbox.ErrUnknownKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opened, err := ring.Open(tt.value, secretbox.ProxyCredential("repo-1"))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Open(%q) = %v, want %v", tt.value, err, tt.want)
			}
			if opened != nil {
				t.Errorf("Open returned %d bytes alongside its error", len(opened))
			}
			// An error must not carry the value it failed on: these end up in
			// logs, and a malformed secret is still a secret.
			if tt.value != "" && strings.Contains(err.Error(), tt.value) {
				t.Errorf("error message %q quotes the rejected value", err)
			}
		})
	}
}

// A value sealed by one deployment's key must not open with another's, and the
// failure must say which key is missing rather than looking like corruption.
func TestOpenWithAForeignKeyringReportsUnknownKey(t *testing.T) {
	t.Parallel()

	mine := keyring(t, 1)
	theirs := keyring(t, 2)
	sealed, err := mine.Seal([]byte("token"), secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	_, err = theirs.Open(sealed, secretbox.ProxyCredential("repo-1"))
	if !errors.Is(err, secretbox.ErrUnknownKey) {
		t.Fatalf("Open = %v, want ErrUnknownKey", err)
	}
	var unknown *secretbox.UnknownKeyError
	if !errors.As(err, &unknown) {
		t.Fatalf("Open error is %T, want *UnknownKeyError", err)
	}
	if unknown.KeyID != mine.ActiveKeyID() {
		t.Errorf("UnknownKeyError names %q, want %q", unknown.KeyID, mine.ActiveKeyID())
	}
}

// Rotation, end to end: values sealed by the retired key keep opening while
// everything new is sealed by the incoming one.
func TestRotationKeepsRetiredKeysReadable(t *testing.T) {
	t.Parallel()

	ctx := secretbox.ProxyCredential("repo-1")
	old := keyring(t, 1)
	oldValue, err := old.Seal([]byte("before"), ctx)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rotated, err := old.Rotate(fixedKey(t, 2))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.ActiveKeyID() == old.ActiveKeyID() {
		t.Fatal("Rotate did not change the active key")
	}
	if got := old.ActiveKeyID(); got != fixedKey(t, 1).ID() {
		t.Errorf("Rotate mutated the receiver: active key is now %q", got)
	}
	if want := []string{fixedKey(t, 2).ID(), fixedKey(t, 1).ID()}; !equalStrings(rotated.KeyIDs(), want) {
		t.Errorf("KeyIDs = %v, want %v", rotated.KeyIDs(), want)
	}

	opened, err := rotated.Open(oldValue, ctx)
	if err != nil || string(opened) != "before" {
		t.Fatalf("Open of a value sealed by the retired key = %q, %v", opened, err)
	}

	newValue, err := rotated.Seal([]byte("after"), ctx)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if id, _ := secretbox.KeyIDOf(newValue); id != rotated.ActiveKeyID() {
		t.Errorf("new value sealed under %q, want the active key %q", id, rotated.ActiveKeyID())
	}

	// The re-encryption pass finds the old rows by asking, never by decrypting.
	for _, tt := range []struct {
		name  string
		value string
		want  bool
	}{
		{"sealed by the retired key", oldValue, true},
		{"sealed by the active key", newValue, false},
	} {
		got, err := rotated.NeedsReseal(tt.value)
		if err != nil {
			t.Fatalf("NeedsReseal(%s): %v", tt.name, err)
		}
		if got != tt.want {
			t.Errorf("NeedsReseal(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
	if _, err := rotated.NeedsReseal("garbage"); !errors.Is(err, secretbox.ErrMalformed) {
		t.Errorf("NeedsReseal(garbage) = %v, want ErrMalformed", err)
	}

	// A key already in the ring cannot be rotated in: it would make the
	// key-id lookup ambiguous.
	if _, err := rotated.Rotate(fixedKey(t, 1)); !errors.Is(err, secretbox.ErrInvalidKey) {
		t.Errorf("Rotate with a key already held = %v, want ErrInvalidKey", err)
	}
}

func TestContextIsRequired(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	sealed, err := ring.Seal([]byte("token"), secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, tt := range []struct {
		name string
		ctx  secretbox.Context
	}{
		{"empty", ""},
		{"proxy credential with no repository", secretbox.ProxyCredential("")},
		{"webhook secret with no subscription", secretbox.WebhookSecret("")},
		{"too long", secretbox.Context(strings.Repeat("a", secretbox.MaxContextLength+1))},
		{"control character", secretbox.Context("column:\x00row")},
		{"newline", secretbox.Context("column:row\n")},
		{"non-ascii", secretbox.Context("column:rö")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.ctx.Validate(); !errors.Is(err, secretbox.ErrInvalidContext) {
				t.Errorf("Validate = %v, want ErrInvalidContext", err)
			}
			if _, err := ring.Seal([]byte("token"), tt.ctx); !errors.Is(err, secretbox.ErrInvalidContext) {
				t.Errorf("Seal = %v, want ErrInvalidContext", err)
			}
			if _, err := ring.Open(sealed, tt.ctx); !errors.Is(err, secretbox.ErrInvalidContext) {
				t.Errorf("Open = %v, want ErrInvalidContext", err)
			}
		})
	}
}

func TestContextConstructors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		ctx  secretbox.Context
		want string
	}{
		{"proxy credential", secretbox.ProxyCredential("repo-1"), "proxy-credential:repo-1"},
		{"webhook secret", secretbox.WebhookSecret("wh-9"), "webhook-secret:wh-9"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.ctx.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if err := tt.ctx.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestKeyIDIsStableAndEightHex(t *testing.T) {
	t.Parallel()

	// SHA-256 over 32 zero bytes, truncated. Pinned so that a change to the
	// derivation shows up here rather than as unopenable rows in production.
	zero, err := secretbox.NewKey(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if got := zero.ID(); got != "66687aad" {
		t.Errorf("ID() = %q, want %q", got, "66687aad")
	}

	again, err := secretbox.NewKey(make([]byte, secretbox.KeySize))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if again.ID() != zero.ID() {
		t.Errorf("the same material produced ids %q and %q", zero.ID(), again.ID())
	}
	if other := fixedKey(t, 1); other.ID() == zero.ID() {
		t.Errorf("different material produced the same id %q", other.ID())
	}

	for _, id := range []string{zero.ID(), fixedKey(t, 1).ID()} {
		if len(id) != secretbox.KeyIDLength {
			t.Errorf("id %q is %d characters, want %d", id, len(id), secretbox.KeyIDLength)
		}
		for _, c := range id {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("id %q is not lowercase hex", id)
				break
			}
		}
	}
}

func TestGenerateKeyProducesDistinctUsableKeys(t *testing.T) {
	t.Parallel()

	first, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	second, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if first.ID() == second.ID() {
		t.Fatal("two generated keys share an id")
	}
	if first.Encode() == second.Encode() {
		t.Fatal("two generated keys share their material")
	}

	ring, err := secretbox.NewKeyring(first)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	sealed, err := ring.Seal([]byte("token"), secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if opened, err := ring.Open(sealed, secretbox.ProxyCredential("repo-1")); err != nil || string(opened) != "token" {
		t.Fatalf("Open = %q, %v", opened, err)
	}
}

func TestNewKeyRejectsWrongLength(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one short", secretbox.KeySize - 1},
		{"one long", secretbox.KeySize + 1},
		{"aes-128", 16},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := secretbox.NewKey(make([]byte, tt.size)); !errors.Is(err, secretbox.ErrInvalidKey) {
				t.Errorf("NewKey(%d bytes) = %v, want ErrInvalidKey", tt.size, err)
			}
		})
	}
}

// Formatting a key, or anything holding one, must not print its material: the
// most common way a secret escapes is a debug log line.
func TestKeyFormattingHidesMaterial(t *testing.T) {
	t.Parallel()

	key := fixedKey(t, 9)
	holder := struct{ Key secretbox.Key }{Key: key}
	raw := string(bytes.Repeat([]byte{9}, secretbox.KeySize))

	rendered := []string{key.String()}
	// The formats go through a variable so that this stays a test of what fmt
	// prints rather than something a linter rewrites into a String() call.
	for _, format := range []string{"%v", "%s", "%q"} {
		rendered = append(rendered, fmt.Sprintf(format, key), fmt.Sprintf(format, holder))
	}
	for _, out := range rendered {
		if strings.Contains(out, key.Encode()) {
			t.Errorf("rendering %q exposes the encoded key material", out)
		}
		if strings.Contains(out, raw) {
			t.Errorf("rendering %q exposes raw key material", out)
		}
		if !strings.Contains(out, key.ID()) {
			t.Errorf("rendering %q does not name the key", out)
		}
	}

	ring := keyring(t, 9, 8)
	if got, want := ring.String(), "secretbox.Keyring(active="+key.ID()+", keys=2)"; got != want {
		t.Errorf("Keyring.String() = %q, want %q", got, want)
	}
	if strings.Contains(ring.String(), key.Encode()) {
		t.Error("Keyring.String() exposes key material")
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()

	ring := keyring(t, 1)
	sealed, err := ring.Seal([]byte("token"), secretbox.ProxyCredential("repo-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, tt := range []struct {
		name  string
		value string
		want  string
	}{
		{"a sealed value", sealed, "<redacted:" + ring.ActiveKeyID() + ">"},
		{"an unsealed value", "plaintext", "<redacted>"},
		{"empty", "", "<redacted>"},
		{"a future version", "v2:0123abcd:AAAA", "<redacted>"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := secretbox.Redact(tt.value)
			if got != tt.want {
				t.Errorf("Redact = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewKeyringRejects(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		keys []secretbox.Key
		want error
	}{
		{"no keys", nil, secretbox.ErrNoKey},
		{"a zero key", []secretbox.Key{{}}, secretbox.ErrInvalidKey},
		{"a zero key behind a good one", []secretbox.Key{fixedKey(t, 1), {}}, secretbox.ErrInvalidKey},
		{"the same key twice", []secretbox.Key{fixedKey(t, 1), fixedKey(t, 1)}, secretbox.ErrInvalidKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring, err := secretbox.NewKeyring(tt.keys...)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewKeyring = %v, want %v", err, tt.want)
			}
			if ring != nil {
				t.Error("NewKeyring returned a keyring alongside its error")
			}
		})
	}
}

// A keyring that was never built must fail closed rather than panic: it is
// what a caller holds after ignoring an error from Load.
func TestNilKeyringFailsClosed(t *testing.T) {
	t.Parallel()

	var ring *secretbox.Keyring
	ctx := secretbox.ProxyCredential("repo-1")

	if _, err := ring.Seal([]byte("token"), ctx); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("Seal = %v, want ErrNoKey", err)
	}
	if _, err := ring.Open("v1:0123abcd:"+base64.StdEncoding.EncodeToString(make([]byte, 28)), ctx); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("Open = %v, want ErrNoKey", err)
	}
	if got := ring.ActiveKeyID(); got != "" {
		t.Errorf("ActiveKeyID = %q, want empty", got)
	}
	if got := ring.KeyIDs(); len(got) != 0 {
		t.Errorf("KeyIDs = %v, want empty", got)
	}
	if got := ring.Keys(); got != nil {
		t.Errorf("Keys = %v, want nil", got)
	}
	if got := ring.Encode(); got != "" {
		t.Errorf("Encode = %q, want empty", got)
	}
	if got := ring.String(); got != "secretbox.Keyring(empty)" {
		t.Errorf("String = %q", got)
	}
	if err := ring.Write(filepath.Join(t.TempDir(), "secrets.key")); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("Write = %v, want ErrNoKey", err)
	}

	// Rotating onto nothing still yields a usable keyring, which is what makes
	// a first rotation on a fresh deployment work.
	rotated, err := ring.Rotate(fixedKey(t, 1))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.ActiveKeyID() != fixedKey(t, 1).ID() {
		t.Errorf("Rotate produced active key %q", rotated.ActiveKeyID())
	}
}

func TestParseKeyring(t *testing.T) {
	t.Parallel()

	active, retired := fixedKey(t, 1), fixedKey(t, 2)

	t.Run("orders keys by line, active first", func(t *testing.T) {
		t.Parallel()

		ring, err := secretbox.ParseKeyring([]byte(active.Encode() + "\n" + retired.Encode() + "\n"))
		if err != nil {
			t.Fatalf("ParseKeyring: %v", err)
		}
		if want := []string{active.ID(), retired.ID()}; !equalStrings(ring.KeyIDs(), want) {
			t.Errorf("KeyIDs = %v, want %v", ring.KeyIDs(), want)
		}
	})

	t.Run("ignores blank lines, comments, and carriage returns", func(t *testing.T) {
		t.Parallel()

		content := "# active since 2026-09-03\r\n" + active.Encode() + "\r\n" +
			"\n   \n" + "# retired, remove once re-encryption reports zero\n" +
			"  " + retired.Encode() + "  \n\n"
		ring, err := secretbox.ParseKeyring([]byte(content))
		if err != nil {
			t.Fatalf("ParseKeyring: %v", err)
		}
		if want := []string{active.ID(), retired.ID()}; !equalStrings(ring.KeyIDs(), want) {
			t.Errorf("KeyIDs = %v, want %v", ring.KeyIDs(), want)
		}
	})

	t.Run("round-trips through Encode", func(t *testing.T) {
		t.Parallel()

		source, err := secretbox.NewKeyring(active, retired)
		if err != nil {
			t.Fatalf("NewKeyring: %v", err)
		}
		ring, err := secretbox.ParseKeyring([]byte(source.Encode()))
		if err != nil {
			t.Fatalf("ParseKeyring: %v", err)
		}
		if !equalStrings(ring.KeyIDs(), source.KeyIDs()) {
			t.Errorf("KeyIDs = %v, want %v", ring.KeyIDs(), source.KeyIDs())
		}
	})

	for _, tt := range []struct {
		name    string
		content string
		want    error
		line    int
	}{
		{"empty file", "", secretbox.ErrNoKey, 0},
		{"only whitespace", "\n\n   \n", secretbox.ErrNoKey, 0},
		{"only comments", "# nothing here\n# really\n", secretbox.ErrNoKey, 0},
		{"not base64", active.Encode() + "\nnot base64!\n", secretbox.ErrInvalidKey, 2},
		{"key too short", base64.StdEncoding.EncodeToString(make([]byte, 16)) + "\n", secretbox.ErrInvalidKey, 1},
		{"key too long", base64.StdEncoding.EncodeToString(make([]byte, 64)) + "\n", secretbox.ErrInvalidKey, 1},
		{"hex instead of base64", strings.Repeat("ab", 32) + "\n", secretbox.ErrInvalidKey, 1},
		{"duplicate key", active.Encode() + "\n" + active.Encode() + "\n", secretbox.ErrInvalidKey, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring, err := secretbox.ParseKeyring([]byte(tt.content))
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseKeyring = %v, want %v", err, tt.want)
			}
			if ring != nil {
				t.Error("ParseKeyring returned a keyring alongside its error")
			}
			var keyfileErr *secretbox.KeyfileError
			if !errors.As(err, &keyfileErr) {
				t.Fatalf("error is %T, want *KeyfileError", err)
			}
			if keyfileErr.Line != tt.line {
				t.Errorf("KeyfileError.Line = %d, want %d", keyfileErr.Line, tt.line)
			}
			// The rejected line may itself be key material.
			if strings.Contains(err.Error(), active.Encode()) {
				t.Errorf("error message %q quotes key material", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("reads a keyfile written by Create", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "keys", "secrets.key")
		created, err := secretbox.Create(path)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		loaded, err := secretbox.Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if loaded.ActiveKeyID() != created.ActiveKeyID() {
			t.Errorf("loaded active key %q, want %q", loaded.ActiveKeyID(), created.ActiveKeyID())
		}

		// The round trip that matters: a value sealed before a restart opens
		// after one.
		ctx := secretbox.WebhookSecret("wh-1")
		sealed, err := created.Seal([]byte("signing"), ctx)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if opened, err := loaded.Open(sealed, ctx); err != nil || string(opened) != "signing" {
			t.Fatalf("Open after reload = %q, %v", opened, err)
		}
	})

	t.Run("a missing keyfile is an error, never an empty keyring", func(t *testing.T) {
		t.Parallel()

		ring, err := secretbox.Load(filepath.Join(t.TempDir(), "absent.key"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Load = %v, want fs.ErrNotExist", err)
		}
		if ring != nil {
			t.Error("Load returned a keyring for a missing file")
		}
	})

	t.Run("an unreadable file is an error", func(t *testing.T) {
		t.Parallel()

		// A directory opens but does not read, on every platform trove
		// targets, which exercises the read failure without a permission trick.
		if _, err := secretbox.Load(t.TempDir()); err == nil {
			t.Fatal("Load of a directory succeeded, want an error")
		}
	})

	t.Run("an empty keyfile is ErrNoKey and names the path", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "secrets.key")
		writeKeyfile(t, path, "")

		_, err := secretbox.Load(path)
		if !errors.Is(err, secretbox.ErrNoKey) {
			t.Fatalf("Load = %v, want ErrNoKey", err)
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name the keyfile", err)
		}
	})

	t.Run("a bad line names the path and the line", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "secrets.key")
		writeKeyfile(t, path, "# comment\nnot base64!\n")

		err := errorFromLoad(t, path)
		var keyfileErr *secretbox.KeyfileError
		if !errors.As(err, &keyfileErr) {
			t.Fatalf("error is %T, want *KeyfileError", err)
		}
		if keyfileErr.Path != path || keyfileErr.Line != 2 {
			t.Errorf("KeyfileError = {Path: %q, Line: %d}, want {%q, 2}", keyfileErr.Path, keyfileErr.Line, path)
		}
	})

	t.Run("an oversized file is rejected before it is parsed", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "secrets.key")
		writeKeyfile(t, path, strings.Repeat("a", secretbox.MaxKeyfileSize+1))

		if err := errorFromLoad(t, path); !errors.Is(err, secretbox.ErrInvalidKey) {
			t.Errorf("Load = %v, want ErrInvalidKey", err)
		}
	})

	t.Run("a keyfile others can read is refused", func(t *testing.T) {
		t.Parallel()

		if runtime.GOOS == "windows" {
			t.Skip("POSIX mode bits are not enforced on Windows (Q25)")
		}
		path := filepath.Join(t.TempDir(), "secrets.key")
		key, err := secretbox.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		writeKeyfile(t, path, key.Encode()+"\n")
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		if err := errorFromLoad(t, path); !errors.Is(err, secretbox.ErrInsecureKeyfile) {
			t.Errorf("Load = %v, want ErrInsecureKeyfile", err)
		}
		// The operator who mounted the key from a platform that dictates the
		// mode has a way through.
		if _, err := secretbox.Load(path, secretbox.AllowInsecurePermissions()); err != nil {
			t.Errorf("Load with AllowInsecurePermissions = %v, want nil", err)
		}
	})
}

func TestCreate(t *testing.T) {
	t.Parallel()

	t.Run("creates parents and one key", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "nested", "keys", "secrets.key")
		ring, err := secretbox.Create(path)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if len(ring.KeyIDs()) != 1 {
			t.Errorf("Create made %d keys, want 1", len(ring.KeyIDs()))
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("keyfile mode is %#o, want 0600", info.Mode().Perm())
		}
	})

	t.Run("refuses to overwrite", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "secrets.key")
		first, err := secretbox.Create(path)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		second, err := secretbox.Create(path)
		if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("second Create = %v, want fs.ErrExist", err)
		}
		if second != nil {
			t.Error("second Create returned a keyring")
		}

		// The point of refusing: the original key is still there.
		loaded, err := secretbox.Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if loaded.ActiveKeyID() != first.ActiveKeyID() {
			t.Errorf("active key is now %q, want %q", loaded.ActiveKeyID(), first.ActiveKeyID())
		}
	})

	t.Run("reports a path it cannot create", func(t *testing.T) {
		t.Parallel()

		// A file where a directory must go: the same shape as a data dir
		// pointed at something that is not one.
		dir := t.TempDir()
		blocker := filepath.Join(dir, "keys")
		if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write blocker: %v", err)
		}

		if _, err := secretbox.Create(filepath.Join(blocker, "secrets.key")); err == nil {
			t.Fatal("Create through a file succeeded, want an error")
		}
	})
}

// The rotation write path: the new keyfile must replace the old atomically and
// still hold every key needed to read what is already stored.
func TestWritePersistsRotation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keys", "secrets.key")
	ctx := secretbox.ProxyCredential("repo-1")

	old, err := secretbox.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sealed, err := old.Seal([]byte("before"), ctx)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	fresh, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rotated, err := old.Rotate(fresh)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := rotated.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reloaded, err := secretbox.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !equalStrings(reloaded.KeyIDs(), rotated.KeyIDs()) {
		t.Errorf("KeyIDs = %v, want %v", reloaded.KeyIDs(), rotated.KeyIDs())
	}
	if opened, err := reloaded.Open(sealed, ctx); err != nil || string(opened) != "before" {
		t.Fatalf("Open of a pre-rotation value = %q, %v", opened, err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("rotated keyfile mode is %#o, want 0600", info.Mode().Perm())
		}
	}

	// The temporary file must not be left behind for a backup to pick up.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("key directory holds %d entries after a rotation, want 1", len(entries))
	}
}

func TestWriteReportsAnUnusableDestination(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	blocker := filepath.Join(dir, "keys")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	ring := keyring(t, 1)
	if err := ring.Write(filepath.Join(blocker, "secrets.key")); err == nil {
		t.Fatal("Write through a file succeeded, want an error")
	}
}

func TestErrorMessages(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"keyfile with path and line", &secretbox.KeyfileError{Path: "/k", Line: 3, Err: secretbox.ErrNoKey}, "keyfile /k line 3: no secrets key available"},
		{"keyfile with path", &secretbox.KeyfileError{Path: "/k", Err: secretbox.ErrNoKey}, "keyfile /k: no secrets key available"},
		{"keyfile with line", &secretbox.KeyfileError{Line: 3, Err: secretbox.ErrNoKey}, "keyfile line 3: no secrets key available"},
		{"keyfile bare", &secretbox.KeyfileError{Err: secretbox.ErrNoKey}, "keyfile: no secrets key available"},
		{"invalid key", &secretbox.InvalidKeyError{Reason: "why"}, "invalid secrets key: why"},
		{"insecure keyfile", &secretbox.InsecureKeyfileError{Mode: 0o644}, "permissions are 0644, want 0600: a key any other account can read is not a secret"},
		{"unknown key", &secretbox.UnknownKeyError{KeyID: "0123abcd"}, "no key 0123abcd in the keyring: it may have been retired before every value was re-encrypted"},
		{"malformed", &secretbox.MalformedError{Reason: "why"}, "malformed sealed value: why"},
		{"authentication", &secretbox.AuthenticationError{KeyID: "0123abcd"}, "value sealed with key 0123abcd did not authenticate"},
		{"invalid context", &secretbox.InvalidContextError{Reason: "why"}, "invalid associated-data context: why"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Each typed error must answer to its sentinel and to nothing else, because
// callers branch on exactly that (§11).
func TestTypedErrorsMatchOnlyTheirSentinel(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		secretbox.ErrNoKey, secretbox.ErrInvalidKey, secretbox.ErrInsecureKeyfile,
		secretbox.ErrUnknownKey, secretbox.ErrMalformed, secretbox.ErrUnsupportedVersion,
		secretbox.ErrAuthentication, secretbox.ErrInvalidContext,
	}
	for _, tt := range []struct {
		err  error
		want error
	}{
		{&secretbox.InvalidKeyError{}, secretbox.ErrInvalidKey},
		{&secretbox.InsecureKeyfileError{}, secretbox.ErrInsecureKeyfile},
		{&secretbox.UnknownKeyError{}, secretbox.ErrUnknownKey},
		{&secretbox.MalformedError{}, secretbox.ErrMalformed},
		{&secretbox.AuthenticationError{}, secretbox.ErrAuthentication},
		{&secretbox.InvalidContextError{}, secretbox.ErrInvalidContext},
	} {
		t.Run(fmt.Sprintf("%T", tt.err), func(t *testing.T) {
			t.Parallel()

			for _, sentinel := range sentinels {
				got := errors.Is(tt.err, sentinel)
				if want := sentinel == tt.want; got != want {
					t.Errorf("errors.Is(%T, %v) = %v, want %v", tt.err, sentinel, got, want)
				}
			}
		})
	}
}

func errorFromLoad(t *testing.T, path string) error {
	t.Helper()

	ring, err := secretbox.Load(path)
	if err == nil {
		t.Fatalf("Load(%q) succeeded, want an error", path)
	}
	if ring != nil {
		t.Error("Load returned a keyring alongside its error")
	}
	return err
}

func writeKeyfile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
