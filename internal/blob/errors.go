package blob

import (
	"errors"
	"fmt"
)

// Sentinel errors every driver must return for these conditions. Callers assert
// with errors.Is; no caller may match on message text (§11). The registry layer
// maps them to spec error codes: ErrNotFound to BLOB_UNKNOWN, the two digest
// errors to DIGEST_INVALID.
var (
	// ErrNotFound reports that no blob or upload session exists for the given
	// identifier.
	ErrNotFound = errors.New("not found")

	// ErrInvalidDigest reports that a digest string is not one this package
	// will accept. It is returned before any path or key is built.
	ErrInvalidDigest = errors.New("invalid digest")

	// ErrDigestMismatch reports that content did not hash to the digest it was
	// stored or requested under. On write nothing is kept; on read the blob is
	// quarantined and the reader fails short of its last byte.
	ErrDigestMismatch = errors.New("digest mismatch")

	// ErrInvalid reports an argument the driver cannot act on, such as an
	// upload session with no identifier.
	ErrInvalid = errors.New("invalid argument")

	// ErrNoRedirect reports that a driver cannot hand out a URL for a client
	// to fetch directly, either because it has no such notion or because the
	// mode is switched off. Callers fall back to streaming the blob.
	ErrNoRedirect = errors.New("redirects are not available")
)

// NotFoundError names what was missing while satisfying errors.Is(ErrNotFound).
type NotFoundError struct {
	Kind string
	ID   string
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s %q not found", e.Kind, e.ID) }

// Is makes errors.Is(err, ErrNotFound) true for this typed error.
func (e *NotFoundError) Is(target error) bool { return target == ErrNotFound }

// NotFound builds a NotFoundError.
func NotFound(kind, id string) error { return &NotFoundError{Kind: kind, ID: id} }

// InvalidDigestError carries the string that was rejected and why. The reason
// is for the operator; the caller matches on ErrInvalidDigest.
type InvalidDigestError struct {
	Digest string
	Reason string
}

func (e *InvalidDigestError) Error() string {
	return fmt.Sprintf("invalid digest %q: %s", e.Digest, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidDigest) true for this typed error.
func (e *InvalidDigestError) Is(target error) bool { return target == ErrInvalidDigest }

// InvalidDigest builds an InvalidDigestError.
func InvalidDigest(digest, reason string) error {
	return &InvalidDigestError{Digest: digest, Reason: reason}
}

// MismatchError names both digests. Logging what arrived alongside what was
// asked for is what turns "a pull failed" into "this upstream served us the
// wrong bytes".
type MismatchError struct {
	Expected Digest
	Actual   Digest
	// Size is how many bytes were hashed, which distinguishes a truncated
	// stream from corrupt content of the right length.
	Size int64
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("digest mismatch: expected %s, got %s over %d bytes",
		e.Expected, e.Actual, e.Size)
}

// Is makes errors.Is(err, ErrDigestMismatch) true for this typed error.
func (e *MismatchError) Is(target error) bool { return target == ErrDigestMismatch }

// Mismatch builds a MismatchError.
func Mismatch(expected, actual Digest, size int64) error {
	return &MismatchError{Expected: expected, Actual: actual, Size: size}
}

// InvalidError explains why an argument could not be used.
type InvalidError struct {
	Field  string
	Reason string
}

func (e *InvalidError) Error() string { return fmt.Sprintf("invalid %s: %s", e.Field, e.Reason) }

// Is makes errors.Is(err, ErrInvalid) true for this typed error.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Invalid builds an InvalidError.
func Invalid(field, reason string) error { return &InvalidError{Field: field, Reason: reason} }
