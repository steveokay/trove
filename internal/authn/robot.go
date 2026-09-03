package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/secretbox"
)

// RobotNamePrefix marks robot subjects apart from users in every username
// field (ADR 0004): "robot$ci" cannot be mistaken for a person, and the
// authentication path dispatches on it without a database read.
const RobotNamePrefix = "robot$"

// robotSecretPrefix begins every robot secret.
const robotSecretPrefix = "trove_r_"

// DefaultRobotTTL is how long a robot secret lives when its creator does not
// say (ADR 0004): long enough for quarterly rotation to be a calendar entry,
// short enough that a forgotten robot dies on its own.
const DefaultRobotTTL = 90 * 24 * time.Hour

// RobotStore is the slice of the store robot authentication needs.
type RobotStore interface {
	GetSubject(ctx context.Context, name string) (meta.Subject, error)
	PutRobotCredential(ctx context.Context, cred meta.RobotCredential) error
	GetRobotCredential(ctx context.Context, subject string, now time.Time) (meta.RobotCredential, error)
}

// RobotSecrets mints and verifies robot account secrets (Z-003b, ADR 0004).
//
// A secret has the form trove_r_<robot-id>_<random> and is stored only as a
// keyed digest (secretbox.MAC), so a database copy yields nothing usable and
// the secret itself is shown exactly once, at minting. One secret is active
// per robot: minting again is rotation, revocation deletes the digest, and
// either way the next use fails regardless of what was handed out earlier.
type RobotSecrets struct {
	store   RobotStore
	ring    *secretbox.Keyring
	limiter *AttemptLimiter
	now     func() time.Time
}

// NewRobotSecrets builds the robot credential path. The limiter may be nil,
// which means no limiting; the clock nil, which means time.Now.
func NewRobotSecrets(store RobotStore, ring *secretbox.Keyring, limiter *AttemptLimiter, now func() time.Time) *RobotSecrets {
	if now == nil {
		now = time.Now
	}
	return &RobotSecrets{store: store, ring: ring, limiter: limiter, now: now}
}

// Mint issues a fresh secret for the robot, replacing any previous one, and
// returns it for its single showing. A zero expiresAt means the default TTL;
// expiry is mandatory and may not already have passed.
func (r *RobotSecrets) Mint(ctx context.Context, robotName string, expiresAt time.Time) (string, error) {
	subject, err := r.store.GetSubject(ctx, robotName)
	if err != nil {
		return "", fmt.Errorf("resolve robot %q: %w", robotName, err)
	}
	if subject.Kind != meta.Robot {
		return "", fmt.Errorf("subject %q is a %s: only robots hold robot secrets", robotName, subject.Kind)
	}

	now := r.now()
	if expiresAt.IsZero() {
		expiresAt = now.Add(DefaultRobotTTL)
	}
	if !expiresAt.After(now) {
		return "", fmt.Errorf("expiry %s is not in the future", expiresAt)
	}

	random, err := generatePassword()
	if err != nil {
		return "", err
	}
	secret := robotSecretPrefix + subject.ID + "_" + random
	digest, err := r.ring.MAC([]byte(secret), secretbox.RobotSecret(subject.ID))
	if err != nil {
		return "", fmt.Errorf("digest the robot secret: %w", err)
	}
	if err := r.store.PutRobotCredential(ctx, meta.RobotCredential{
		Subject: robotName, SecretHash: digest, ExpiresAt: expiresAt, RotatedAt: now,
	}); err != nil {
		return "", fmt.Errorf("store the robot credential: %w", err)
	}
	return secret, nil
}

// Verify checks a presented secret. Everything that is not a live, matching
// secret for this robot -- unknown robot, a user's name, expiry, revocation,
// another robot's secret, garbage -- is ErrBadCredentials, indistinguishably:
// the caller resolves the subject afterwards, exactly like a password login.
func (r *RobotSecrets) Verify(ctx context.Context, robotName, presented, source string) error {
	if r.limiter != nil {
		if ok, wait := r.limiter.Allow(Attempt{Account: robotName, Address: source}); !ok {
			return &RateLimitedError{RetryAfter: wait}
		}
	}
	if !strings.HasPrefix(presented, robotSecretPrefix) {
		return ErrBadCredentials
	}

	subject, err := r.store.GetSubject(ctx, robotName)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return ErrBadCredentials
	case err != nil:
		return fmt.Errorf("resolve robot %q: %w", robotName, err)
	case subject.Kind != meta.Robot:
		return ErrBadCredentials
	}

	// Expired and absent are the same answer from the store, on purpose: an
	// authentication path should not reveal which robots used to exist.
	cred, err := r.store.GetRobotCredential(ctx, robotName, r.now())
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return ErrBadCredentials
	case err != nil:
		return fmt.Errorf("read robot credential: %w", err)
	}

	// The digest is bound to the robot's id, so a secret lifted from one
	// robot's row cannot authenticate another (secretbox context binding).
	if !r.ring.VerifyMAC([]byte(presented), secretbox.RobotSecret(subject.ID), cred.SecretHash) {
		return ErrBadCredentials
	}
	return nil
}
