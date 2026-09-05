package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/secretbox"
)

// This file is the whole of C-003's read path: the one place a stored upstream
// credential turns back into a username and a password, and the one place the
// sealed payload's shape is written down.
//
// Three rules hold, and the code is arranged so that breaking one is awkward
// rather than merely discouraged:
//
//   - The plaintext exists only inside Basic's return, for the duration of one
//     upstream request. Nothing here retains it, caches it, or hands it to a
//     logger.
//   - No error names it. Every failure names the repository, because that is
//     what an operator has to act on, and says what kind of failure it was.
//     The value, the username, and the ciphertext appear in no message.
//   - A missing credential is a failure, never a downgrade to anonymous. See
//     ErrCredentialUnavailable.

// ErrCredentialUnavailable reports that a proxy repository's configured
// upstream credential could not be produced: none is stored, the keyring
// cannot open it, or the stored value is not one of ours.
//
// It is deliberately not one of the Client sentinels at the top of client.go.
// Those classify what an *upstream* did; this is our own configuration or key
// material failing, and folding it into ErrUnauthorized would tell an operator
// their password was rejected when in fact it was never read. The client wraps
// it in AuthError on the way out, so a caller of Client still sees exactly one
// of the closed sentinel set.
var ErrCredentialUnavailable = errors.New("upstream credential unavailable")

// CredentialError says which repository's credential could not be produced and
// why, and nothing else.
//
// The Reason is a fixed phrase chosen from a handful, never derived from the
// stored value: a message that echoed any part of a credential would put it in
// the log line of every failed pull, which is the most-read place in the
// system.
type CredentialError struct {
	// Repository is the proxy entity whose credential was wanted.
	Repository string
	// Reason is what went wrong, in operator terms.
	Reason string
	// Err is the underlying failure, so errors.Is reaches meta.ErrNotFound for
	// an unset credential and secretbox.ErrAuthentication, ErrUnknownKey, or
	// ErrMalformed for a value the keyring would not open.
	Err error
}

func (e *CredentialError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("upstream credential for repository %q: %s: %v", e.Repository, e.Reason, e.Err)
	}
	return fmt.Sprintf("upstream credential for repository %q: %s", e.Repository, e.Reason)
}

// Unwrap exposes the underlying failure so a caller can tell "nobody set one"
// from "the retired key was removed too early".
func (e *CredentialError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrCredentialUnavailable) true for this typed error.
func (e *CredentialError) Is(target error) bool { return target == ErrCredentialUnavailable }

// Opener is the part of *secretbox.Keyring this package needs: it decrypts, it
// never encrypts. Declaring the consumer's half (§11) is what keeps the read
// path unable to seal a new value even by mistake.
type Opener interface {
	Open(value string, ctx secretbox.Context) ([]byte, error)
}

// Sealer is the writing half, used by the admin API when an operator sets a
// credential. It lives here rather than in the server package so that the
// sealed payload's shape is defined once, in the same file that reads it --
// a format written down in two places is a format that drifts.
type Sealer interface {
	Seal(plaintext []byte, ctx secretbox.Context) (string, error)
}

// CredentialReader is the slice of the metadata store this package reads
// through, declared by the consumer (§11).
//
// It is one method wide, and that is the point: StoredCredentials holds an
// interface that can fetch a sealed credential and do nothing else at all.
type CredentialReader interface {
	GetProxyCredential(ctx context.Context, repository string) (meta.ProxyCredential, error)
}

// credentialPayload is what goes inside the sealed blob.
//
// JSON rather than a packed encoding because the payload has to survive a
// rotation pass that re-seals values it does not interpret, and because the
// field names make an added third field (a registry token type, say) a
// backwards-compatible change rather than an offset everybody has to agree on.
// It costs a few bytes inside a ciphertext nobody parses without the key.
//
// Both fields travel together and neither is stored in the clear. Putting the
// username in its own column would look harmless and would hand half of every
// credential to every read path, backup, and replica -- and when the password
// is a registry token, the username is the half that names who it belongs to.
type credentialPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SealCredential encrypts a username and password for one proxy repository,
// returning the value to store in meta.ProxyCredential.Sealed.
//
// The associated data is secretbox.ProxyCredential(repository), which is what
// makes a stolen row useless anywhere else: a ciphertext moved into another
// repository's row fails to open rather than decrypting into the wrong
// upstream (ADR 0016).
func SealCredential(keys Sealer, repository, username, password string) (string, error) {
	if keys == nil {
		return "", &CredentialError{
			Repository: repository,
			Reason:     "no keyring is configured, so nothing can be encrypted",
			Err:        secretbox.ErrNoKey,
		}
	}
	plaintext, err := json.Marshal(credentialPayload{Username: username, Password: password})
	if err != nil {
		// Unreachable: two strings always marshal. It is reported rather than
		// ignored because the alternative is storing an empty credential.
		return "", &CredentialError{Repository: repository, Reason: "the credential could not be encoded", Err: err}
	}
	sealed, err := keys.Seal(plaintext, secretbox.ProxyCredential(repository))
	if err != nil {
		return "", &CredentialError{Repository: repository, Reason: "the keyring could not seal it", Err: err}
	}
	return sealed, nil
}

// StoredCredentials is the Credentials implementation backed by the metadata
// store: it reads the sealed row and opens it with the keyring, once per
// request that needs it.
//
// There is no caching. A credential is read on the request that uses it, so
// rotating or revoking one takes effect on the next upstream call rather than
// on the next process restart -- the same reason authorization reads live
// bindings instead of trusting a token's scopes (§5).
type StoredCredentials struct {
	// Repository is the proxy entity whose credential this is. It is both the
	// row key and half the associated data, so the two cannot disagree.
	Repository string
	// Store supplies the sealed value.
	Store CredentialReader
	// Keys opens it.
	Keys Opener
}

// assert the frozen interface is satisfied at compile time.
var _ Credentials = StoredCredentials{}

// Basic returns the username and password for the upstream.
//
// Every failure is an error and none is an empty pair. Silently proceeding
// anonymously when a credential cannot be read turns a retired keyfile line or
// a revoked row into a 404 from the upstream, and the operator then debugs the
// wrong system entirely -- which is what the Credentials interface warns about
// in client.go.
func (c StoredCredentials) Basic(ctx context.Context) (string, string, error) {
	if c.Store == nil || c.Keys == nil {
		return "", "", &CredentialError{
			Repository: c.Repository,
			Reason:     "the credential source is not configured",
		}
	}

	cred, err := c.Store.GetProxyCredential(ctx, c.Repository)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return "", "", &CredentialError{
			Repository: c.Repository,
			Reason:     "none is stored, and a proxy configured to authenticate must not fall back to anonymous",
			Err:        err,
		}
	case err != nil:
		return "", "", &CredentialError{Repository: c.Repository, Reason: "it could not be read", Err: err}
	}

	// The context is built from this struct's repository rather than from the
	// row's, so a row that somehow arrived from elsewhere fails to open here
	// instead of authenticating against the wrong upstream.
	plaintext, err := c.Keys.Open(cred.Sealed, secretbox.ProxyCredential(c.Repository))
	if err != nil {
		return "", "", &CredentialError{Repository: c.Repository, Reason: "the keyring could not open it", Err: err}
	}

	var payload credentialPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		// The error is dropped rather than wrapped: an unmarshal failure
		// quotes the input it choked on, and the input here is a decrypted
		// credential.
		return "", "", &CredentialError{
			Repository: c.Repository,
			Reason:     "the decrypted value is not a credential pair",
		}
	}
	return payload.Username, payload.Password, nil
}
