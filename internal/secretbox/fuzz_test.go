package secretbox_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/steveokay/trove/internal/secretbox"
)

// FuzzOpen drives the wire-format parser with arbitrary stored values.
//
// Two claims are under test. Nothing that reaches Open may panic: these strings
// come out of a database column that an operator, a migration, or a restored
// backup can put anything into. And nothing Open did not produce may open: a
// value the keyring accepts is a value the keyring sealed, which is the whole
// point of authenticating the ciphertext rather than merely decrypting it.
func FuzzOpen(f *testing.F) {
	key, err := secretbox.NewKey(bytes.Repeat([]byte{7}, secretbox.KeySize))
	if err != nil {
		f.Fatalf("NewKey: %v", err)
	}
	ring, err := secretbox.NewKeyring(key)
	if err != nil {
		f.Fatalf("NewKeyring: %v", err)
	}

	// The one value that must open is a fixed one rather than a fresh Seal:
	// the fuzzing engine re-runs this setup in each worker process, and a
	// randomly nonced value would differ between the corpus and the worker.
	sealed, plaintext, ctx := goldenValue, goldenPlaintext, secretbox.ProxyCredential("repo-1")

	id := ring.ActiveKeyID()
	for _, seed := range []string{
		sealed,
		"",
		":",
		"::",
		"v1",
		"v1:" + id,
		"v1:" + id + ":",
		"v1:" + id + ":" + base64.StdEncoding.EncodeToString(make([]byte, 28)),
		"v1:" + id + ":====",
		"v1:00000000:" + base64.StdEncoding.EncodeToString(make([]byte, 28)),
		"v2:" + id + ":AAAA",
		// Non-canonical spellings of the pinned value: base64 decoding skips
		// CR and LF, so these decode to the same payload and must still be
		// refused.
		sealed[:20] + "\n" + sealed[20:],
		sealed[:20] + "\r\n" + sealed[20:],
		"v1:" + id + ":" + string([]byte{0xff, 0xfe}),
		plaintext,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		// Redact feeds config dumps, support bundles, and log lines, so its
		// output must be one of exactly two shapes whatever it is handed. Any
		// third shape is ciphertext escaping into a file an operator shares.
		redacted := secretbox.Redact(value)
		if id, err := secretbox.KeyIDOf(value); err == nil {
			if want := "<redacted:" + id + ">"; redacted != want {
				t.Errorf("Redact(%q) = %q, want %q", value, redacted, want)
			}
		} else if redacted != "<redacted>" {
			t.Errorf("Redact(%q) = %q, want <redacted>", value, redacted)
		}

		opened, err := ring.Open(value, ctx)
		if err != nil {
			if opened != nil {
				t.Errorf("Open(%q) returned %d bytes alongside its error", value, len(opened))
			}
			return
		}
		if value != sealed {
			t.Errorf("Open accepted %q, which it never sealed", value)
		}
		if string(opened) != plaintext {
			t.Errorf("Open(%q) = %q, want %q", value, opened, plaintext)
		}
	})
}

// FuzzParseKeyring drives the keyfile parser. A keyfile is operator-edited
// text, so it arrives malformed in ways nothing in the codebase produces; the
// parser must reject rather than fail, and must never build a keyring with no
// usable key in it.
func FuzzParseKeyring(f *testing.F) {
	key, err := secretbox.NewKey(bytes.Repeat([]byte{7}, secretbox.KeySize))
	if err != nil {
		f.Fatalf("NewKey: %v", err)
	}
	for _, seed := range []string{
		"",
		"\n",
		"#\n",
		key.Encode(),
		key.Encode() + "\n" + key.Encode(),
		key.Encode() + "\r\n# retired\n",
		"AAAA",
		"not base64!",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, content string) {
		ring, err := secretbox.ParseKeyring([]byte(content))
		if err != nil {
			if ring != nil {
				t.Errorf("ParseKeyring returned a keyring alongside its error")
			}
			return
		}
		if ring.ActiveKeyID() == "" {
			t.Errorf("ParseKeyring built a keyring with no active key from %q", content)
		}
		if len(ring.KeyIDs()) != len(ring.Keys()) {
			t.Error("KeyIDs and Keys disagree on how many keys there are")
		}
	})
}
