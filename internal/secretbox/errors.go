package secretbox

import (
	"errors"
	"fmt"
	"io/fs"
)

// Sentinel errors. Callers assert with errors.Is; no caller may match on
// message text (§11).
//
// They are kept separate because they demand different responses. A key
// problem is an operator problem and, per ADR 0016, a fatal one at startup:
// serving on with encrypted rows we cannot read would silently re-key the
// deployment. A malformed or unauthenticated value is a data problem: refuse
// that one row, keep running, and say nothing about why.
var (
	// ErrNoKey reports that there is no key to encrypt or decrypt with: an
	// empty or absent keyfile, or a keyring that was never built. With
	// encrypted values present this is fatal at startup and never a reason to
	// generate a fresh key (ADR 0016).
	ErrNoKey = errors.New("no secrets key available")

	// ErrInvalidKey reports key material this package will not accept —
	// the wrong length, undecodable, or repeated within one keyring.
	ErrInvalidKey = errors.New("invalid secrets key")

	// ErrInsecureKeyfile reports a keyfile that some account other than its
	// owner can read. Operators mounting a secret from a platform that
	// insists on wider bits opt out with AllowInsecurePermissions.
	ErrInsecureKeyfile = errors.New("keyfile is readable beyond its owner")

	// ErrUnknownKey reports a sealed value naming a key this keyring does not
	// hold — usually a retired keyfile line removed before every value using
	// it had been re-encrypted.
	ErrUnknownKey = errors.New("unknown key id")

	// ErrMalformed reports a stored value that is not in the wire format at
	// all: truncated, mis-encoded, or never produced by Seal.
	ErrMalformed = errors.New("malformed sealed value")

	// ErrUnsupportedVersion reports a sealed value in a format this build does
	// not implement, which is what the version prefix exists to make
	// detectable rather than mysterious.
	ErrUnsupportedVersion = errors.New("unsupported sealed value version")

	// ErrAuthentication reports that a value did not authenticate under the
	// key and context it was opened with. Tampering, a ciphertext copied from
	// another row, and the wrong context are indistinguishable on purpose.
	ErrAuthentication = errors.New("authentication failed")

	// ErrInvalidContext reports associated data that cannot bind a value to
	// anything useful.
	ErrInvalidContext = errors.New("invalid associated-data context")
)

// InvalidKeyError explains why key material was rejected. The reason never
// quotes the material, because the most likely cause of a rejection is that
// somebody pasted a real key somewhere it would end up in a log.
type InvalidKeyError struct {
	Reason string
}

func (e *InvalidKeyError) Error() string { return "invalid secrets key: " + e.Reason }

// Is makes errors.Is(err, ErrInvalidKey) true for this typed error.
func (e *InvalidKeyError) Is(target error) bool { return target == ErrInvalidKey }

// KeyfileError locates a problem in a keyfile so the operator can fix the
// right line. Line is zero when the problem is with the file as a whole.
type KeyfileError struct {
	Path string
	Line int
	Err  error
}

func (e *KeyfileError) Error() string {
	where := "keyfile"
	if e.Path != "" {
		where = fmt.Sprintf("keyfile %s", e.Path)
	}
	if e.Line > 0 {
		return fmt.Sprintf("%s line %d: %v", where, e.Line, e.Err)
	}
	return fmt.Sprintf("%s: %v", where, e.Err)
}

// Unwrap exposes the underlying cause, so errors.Is reaches ErrNoKey,
// ErrInvalidKey, or fs.ErrNotExist through this wrapper.
func (e *KeyfileError) Unwrap() error { return e.Err }

// InsecureKeyfileError names the permission bits that were found. Reporting
// the mode is what turns "trove will not start" into a one-line fix.
type InsecureKeyfileError struct {
	Mode fs.FileMode
}

func (e *InsecureKeyfileError) Error() string {
	return fmt.Sprintf("permissions are %#o, want 0600: a key any other account can read is not a secret", e.Mode.Perm())
}

// Is makes errors.Is(err, ErrInsecureKeyfile) true for this typed error.
func (e *InsecureKeyfileError) Is(target error) bool { return target == ErrInsecureKeyfile }

// UnknownKeyError names the key a value asked for. The identifier is public —
// it is stored beside every value — so naming it costs nothing and tells the
// operator exactly which retired keyfile line to restore.
type UnknownKeyError struct {
	KeyID string
}

func (e *UnknownKeyError) Error() string {
	return fmt.Sprintf("no key %s in the keyring: it may have been retired before every value was re-encrypted", e.KeyID)
}

// Is makes errors.Is(err, ErrUnknownKey) true for this typed error.
func (e *UnknownKeyError) Is(target error) bool { return target == ErrUnknownKey }

// MalformedError says how a stored value failed to parse. The reason is a
// fixed phrase and never echoes the value: a malformed value is still a value
// somebody stored as a secret.
type MalformedError struct {
	Reason string
}

func (e *MalformedError) Error() string { return "malformed sealed value: " + e.Reason }

// Is makes errors.Is(err, ErrMalformed) true for this typed error.
func (e *MalformedError) Is(target error) bool { return target == ErrMalformed }

// AuthenticationError names the key that rejected a value and nothing else.
// What the value was, what it was bound to, and which of tampering, a wrong
// context, or a copied row caused it are the attacker's questions.
type AuthenticationError struct {
	KeyID string
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("value sealed with key %s did not authenticate", e.KeyID)
}

// Is makes errors.Is(err, ErrAuthentication) true for this typed error.
func (e *AuthenticationError) Is(target error) bool { return target == ErrAuthentication }

// InvalidContextError explains why associated data was rejected.
type InvalidContextError struct {
	Reason string
}

func (e *InvalidContextError) Error() string {
	return "invalid associated-data context: " + e.Reason
}

// Is makes errors.Is(err, ErrInvalidContext) true for this typed error.
func (e *InvalidContextError) Is(target error) bool { return target == ErrInvalidContext }
