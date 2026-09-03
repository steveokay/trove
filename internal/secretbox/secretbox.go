package secretbox

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Version is the format tag every sealed value carries. It exists so that a
// future algorithm change is a data migration driven by what is stored rather
// than a guess about what the bytes mean (ADR 0016).
const Version = "v1"

// MaxContextLength bounds associated data. Contexts are short identifiers
// built from a column name and a row id; anything longer is a caller passing
// the wrong value.
const MaxContextLength = 255

// Context is the associated data binding a sealed value to where it lives.
//
// It is the reason a ciphertext lifted out of one row and pasted into another
// fails to open instead of decrypting into the wrong repository's upstream
// credential. Every Seal and Open requires one; there is no default, because a
// shared default binds everything to the same thing, which is the same as
// binding nothing.
type Context string

// ProxyCredential names the context for a proxy repository's upstream
// credential (ADR 0016, C-003). The repository id must be non-empty.
func ProxyCredential(repoID string) Context { return Context("proxy-credential:" + repoID) }

// WebhookSecret names the context for a webhook subscription's signing secret
// (ADR 0012, E-002). The subscription id must be non-empty.
func WebhookSecret(subscriptionID string) Context {
	return Context("webhook-secret:" + subscriptionID)
}

// Validate reports whether the context can bind a value to a specific row.
func (c Context) Validate() error {
	switch {
	case c == "":
		return &InvalidContextError{
			Reason: "must not be empty: a value bound to nothing can be moved anywhere",
		}
	case len(c) > MaxContextLength:
		return &InvalidContextError{
			Reason: fmt.Sprintf("must be at most %d bytes, got %d", MaxContextLength, len(c)),
		}
	case strings.HasSuffix(string(c), ":"):
		// Catches ProxyCredential("") and its relatives, which would bind
		// every row of a table to one identical context.
		return &InvalidContextError{
			Reason: "must not end with ':': the identifier after the separator is missing",
		}
	}
	for i := 0; i < len(c); i++ {
		if c[i] < 0x20 || c[i] > 0x7e {
			return &InvalidContextError{Reason: "must be printable ASCII"}
		}
	}
	return nil
}

// String renders the context. It is not secret: it names a column and a row.
func (c Context) String() string { return string(c) }

// Seal encrypts plaintext under the active key, bound to ctx, and returns the
// value to store: "v1:<key-id>:<base64(nonce ‖ ciphertext)>".
//
// The nonce is fresh for every call, so sealing the same plaintext twice
// produces different values and an observer cannot tell that two rows hold the
// same credential.
func (r *Keyring) Seal(plaintext []byte, ctx Context) (string, error) {
	if err := ctx.Validate(); err != nil {
		return "", err
	}
	if r == nil || len(r.entries) == 0 {
		return "", fmt.Errorf("seal: %w", ErrNoKey)
	}
	active := r.entries[0]

	nonce := make([]byte, active.aead.NonceSize(), active.aead.NonceSize()+len(plaintext)+active.aead.Overhead())
	if _, err := io.ReadFull(r.source(), nonce); err != nil {
		// Sealing with a nonce we are not sure is random is worse than
		// refusing: GCM nonce reuse loses the key's authentication guarantee.
		return "", fmt.Errorf("seal: read nonce: %w", err)
	}
	sealed := active.aead.Seal(nonce, nonce, plaintext, []byte(ctx))

	return Version + ":" + active.key.ID() + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a stored value that was sealed under ctx, using whichever key
// in the keyring produced it. Retired keys open values they sealed, which is
// what makes rotation a background pass rather than a maintenance window.
//
// Tampering, a wrong context, and a ciphertext copied from another row all
// return ErrAuthentication and are not distinguished, deliberately.
func (r *Keyring) Open(value string, ctx Context) ([]byte, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	id, payload, err := parseSealed(value)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("open: %w", ErrNoKey)
	}
	index, ok := r.byID[id]
	if !ok {
		return nil, &UnknownKeyError{KeyID: id}
	}
	e := r.entries[index]

	if len(payload) < e.aead.NonceSize()+e.aead.Overhead() {
		return nil, &MalformedError{Reason: "payload is shorter than a nonce and an authentication tag"}
	}
	nonce, ciphertext := payload[:e.aead.NonceSize()], payload[e.aead.NonceSize():]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, []byte(ctx))
	if err != nil {
		return nil, &AuthenticationError{KeyID: id}
	}
	return plaintext, nil
}

// NeedsReseal reports whether a stored value was sealed with a key other than
// the active one. "trove admin rotate-secrets" uses it to find the rows to
// re-encrypt and to prove the count reached zero before the operator removes
// the retired keyfile line (ADR 0016).
func (r *Keyring) NeedsReseal(value string) (bool, error) {
	id, err := KeyIDOf(value)
	if err != nil {
		return false, err
	}
	return id != r.ActiveKeyID(), nil
}

// KeyIDOf returns the identifier of the key a stored value was sealed with,
// without needing that key. Rotation and support bundles use it to report on
// values they cannot and must not decrypt.
func KeyIDOf(value string) (string, error) {
	id, _, err := parseSealed(value)
	return id, err
}

// Redact renders a stored value the way a config dump, a support bundle, or a
// log line must: "<redacted:key-id>", or "<redacted>" when the value is not
// one of ours. It never returns any part of the ciphertext, because a
// ciphertext plus a leaked keyfile is a plaintext.
func Redact(value string) string {
	id, err := KeyIDOf(value)
	if err != nil {
		return "<redacted>"
	}
	return "<redacted:" + id + ">"
}

// parseSealed splits a stored value into its key identifier and payload. It
// validates the shape before anything is decoded or looked up, and its errors
// never echo the value: a value that failed to parse is still one somebody
// stored as a secret.
func parseSealed(value string) (string, []byte, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return "", nil, &MalformedError{Reason: "want " + Version + ":<key-id>:<base64>"}
	}
	if parts[0] != Version {
		return "", nil, fmt.Errorf("%w: this build reads %s", ErrUnsupportedVersion, Version)
	}
	if !isKeyID(parts[1]) {
		return "", nil, &MalformedError{
			Reason: fmt.Sprintf("key id must be %d lowercase hex characters", KeyIDLength),
		}
	}
	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, &MalformedError{Reason: "payload must be standard base64"}
	}
	// Go's base64 decoder skips CR and LF and tolerates non-zero padding bits,
	// so several strings decode to one payload. Re-encoding and comparing
	// pins the format to a single representation: one sealed value, one
	// spelling, which is what anything downstream comparing or deduplicating
	// stored values has to be able to assume.
	if base64.StdEncoding.EncodeToString(payload) != parts[2] {
		return "", nil, &MalformedError{Reason: "payload must be canonical standard base64"}
	}
	return parts[1], payload, nil
}
