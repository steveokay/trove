package authn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/meta"
)

// ErrBadCredentials reports a login that presented a username and password
// that do not belong together. It is deliberately the only answer for a wrong
// password, an unknown user, and an empty attempt: anything finer is an
// account-enumeration oracle.
var ErrBadCredentials = errors.New("bad credentials")

// RateLimitedError reports a login attempt refused before evaluation, with a
// truthful wait (Z-002: the limiter's arithmetic is exact so Retry-After can
// be honest).
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited: retry after %s", e.RetryAfter)
}

// CredentialSource is the slice of the store a password login needs: the
// verifier to check, and the same row again to upgrade its cost after a
// successful check.
type CredentialSource interface {
	GetUserCredential(ctx context.Context, subject string) (meta.UserCredential, error)
	PutUserCredential(ctx context.Context, cred meta.UserCredential) error
}

// PasswordLogin authenticates username/password pairs against stored
// verifiers, with rate limiting and cost upgrades. It is what basic auth
// (Z-014), the token endpoint (Z-004), and the UI login (Z-020) all call, so
// there is one place attempts are limited and one place hashes rise.
type PasswordLogin struct {
	store   CredentialSource
	limiter *AttemptLimiter
	hasher  Hasher
	// decoy is a real verifier for a random value nobody knows. An attempt
	// against a user that does not exist burns the same Argon2id work as one
	// against a user that does, so response time does not say which usernames
	// are real.
	decoy string
}

// NewPasswordLogin builds a login path. The limiter may be nil, which means
// no limiting -- acceptable only where something upstream already limits.
func NewPasswordLogin(store CredentialSource, limiter *AttemptLimiter, hasher Hasher) (*PasswordLogin, error) {
	decoySecret, err := generatePassword()
	if err != nil {
		return nil, err
	}
	decoy, err := hasher.Hash(decoySecret)
	if err != nil {
		return nil, fmt.Errorf("prepare the decoy verifier: %w", err)
	}
	return &PasswordLogin{store: store, limiter: limiter, hasher: hasher, decoy: decoy}, nil
}

// Authenticate checks one attempt. A nil return means the password is the
// subject's; the caller still resolves the subject (disabled is its answer).
//
// source is the network address the attempt came from, and may be empty when
// the caller could not determine one -- that limits by account alone rather
// than opting out (Z-002).
func (l *PasswordLogin) Authenticate(ctx context.Context, username, password, source string) error {
	if l.limiter != nil {
		if ok, wait := l.limiter.Allow(Attempt{Account: username, Address: source}); !ok {
			return &RateLimitedError{RetryAfter: wait}
		}
	}
	if username == "" || password == "" {
		// Counted against the limiter above: an empty attempt is still an
		// attempt, or hammering with blank passwords would be free.
		return ErrBadCredentials
	}

	cred, err := l.store.GetUserCredential(ctx, username)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		// Burn the same work a real user costs, then say what a wrong
		// password says.
		_ = Verify(l.decoy, password)
		return ErrBadCredentials
	case err != nil:
		return fmt.Errorf("read credential: %w", err)
	}

	if err := Verify(cred.Hash, password); err != nil {
		if errors.Is(err, ErrPasswordMismatch) {
			return ErrBadCredentials
		}
		// A corrupt row is a server problem, never "wrong password".
		return err
	}

	l.upgrade(ctx, cred, password)
	return nil
}

// upgrade re-hashes at the current cost after a successful verify -- the one
// moment the plaintext is in hand. It is best-effort: a login must not fail
// because the write-back of a better hash did, or a store that has gone
// read-only turns every login into an outage. The old hash stays valid either
// way, so nothing is lost but the upgrade itself.
func (l *PasswordLogin) upgrade(ctx context.Context, cred meta.UserCredential, password string) {
	needs, err := NeedsRehash(cred.Hash, l.hasher.Params)
	if err != nil || !needs {
		return
	}
	hash, err := l.hasher.Hash(password)
	if err != nil {
		return
	}
	cred.Hash = hash
	_ = l.store.PutUserCredential(ctx, cred)
}
