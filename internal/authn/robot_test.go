package authn_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/secretbox"
)

func robotRing(t *testing.T) *secretbox.Keyring {
	t.Helper()
	key, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring, err := secretbox.NewKeyring(key)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return ring
}

// robotFixture is a store with the robot "robot$ci" and the user "alice".
func robotFixture(t *testing.T) *memory.Store {
	t.Helper()
	ctx := context.Background()
	store := newBootStore(t)
	for _, subject := range []meta.Subject{
		{ID: "r-ci", Kind: meta.Robot, Name: "robot$ci"},
		{ID: "r-cd", Kind: meta.Robot, Name: "robot$cd"},
		{ID: "u-alice", Kind: meta.User, Name: "alice"},
	} {
		if err := store.CreateSubject(ctx, subject); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
	}
	return store
}

var robotSecretShape = regexp.MustCompile(`^trove_r_r-ci_[A-Za-z0-9_-]{32}$`)

func TestRobotSecretLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store := robotFixture(t)
	robots := authn.NewRobotSecrets(store, robotRing(t), nil, func() time.Time { return now })

	secret, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// The secret embeds the robot's id and enough randomness to be a
	// credential; it is shown exactly once, so the store must hold only a
	// digest of it.
	if !robotSecretShape.MatchString(secret) {
		t.Fatalf("secret %q does not match the ADR 0004 form", secret)
	}
	cred, err := store.GetRobotCredential(ctx, "robot$ci", now)
	if err != nil {
		t.Fatalf("GetRobotCredential: %v", err)
	}
	if strings.Contains(string(cred.SecretHash), secret[len("trove_r_r-ci_"):]) {
		t.Fatal("the stored digest contains the secret")
	}

	if err := robots.Verify(ctx, "robot$ci", secret, ""); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	tests := []struct {
		name      string
		robot     string
		presented string
	}{
		{"wrong secret", "robot$ci", "trove_r_r-ci_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"not a robot secret at all", "robot$ci", "sesame"},
		{"unknown robot", "robot$ghost", secret},
		{"a user's name", "alice", secret},
		// The digest is bound to the robot's id: one robot's secret presented
		// as another is a replay, not a login.
		{"another robot's secret", "robot$cd", secret},
		{"empty secret", "robot$ci", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := robots.Verify(ctx, tt.robot, tt.presented, ""); !errors.Is(err, authn.ErrBadCredentials) {
				t.Errorf("Verify = %v, want ErrBadCredentials", err)
			}
		})
	}
}

// Revocation is the store deletion, and it wins over any outstanding secret:
// the next use fails, not the next mint (ADR 0004).
func TestRobotRevocationWinsImmediately(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store := robotFixture(t)
	robots := authn.NewRobotSecrets(store, robotRing(t), nil, func() time.Time { return now })

	secret, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := store.DeleteRobotCredential(ctx, "robot$ci"); err != nil {
		t.Fatalf("DeleteRobotCredential: %v", err)
	}
	if err := robots.Verify(ctx, "robot$ci", secret, ""); !errors.Is(err, authn.ErrBadCredentials) {
		t.Fatalf("Verify after revocation = %v, want ErrBadCredentials", err)
	}
}

// One active secret per robot: minting again is rotation, and the old secret
// dies at that moment.
func TestRobotRemintReplacesTheSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store := robotFixture(t)
	robots := authn.NewRobotSecrets(store, robotRing(t), nil, func() time.Time { return now })

	first, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	second, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint (again): %v", err)
	}
	if first == second {
		t.Fatal("two mints produced the same secret")
	}
	if err := robots.Verify(ctx, "robot$ci", first, ""); !errors.Is(err, authn.ErrBadCredentials) {
		t.Errorf("the replaced secret still verifies: %v", err)
	}
	if err := robots.Verify(ctx, "robot$ci", second, ""); err != nil {
		t.Errorf("the active secret does not verify: %v", err)
	}
}

// Expiry is mandatory and enforced on read: a robot with no stated expiry
// gets the 90-day default, and past it the answer is indistinguishable from
// no robot at all.
func TestRobotExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	start := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	now := start
	store := robotFixture(t)
	robots := authn.NewRobotSecrets(store, robotRing(t), nil, func() time.Time { return now })

	secret, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	now = start.Add(authn.DefaultRobotTTL - time.Hour)
	if err := robots.Verify(ctx, "robot$ci", secret, ""); err != nil {
		t.Fatalf("Verify an hour before expiry: %v", err)
	}
	now = start.Add(authn.DefaultRobotTTL + time.Hour)
	if err := robots.Verify(ctx, "robot$ci", secret, ""); !errors.Is(err, authn.ErrBadCredentials) {
		t.Fatalf("Verify past expiry = %v, want ErrBadCredentials", err)
	}

	// An explicit expiry is honoured, and one already in the past is a
	// caller error, not a credential that dies at birth.
	if _, err := robots.Mint(ctx, "robot$ci", start.Add(-time.Minute)); err == nil {
		t.Fatal("Mint accepted an expiry in the past")
	}
	short, err := robots.Mint(ctx, "robot$ci", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Mint with explicit expiry: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := robots.Verify(ctx, "robot$ci", short, ""); !errors.Is(err, authn.ErrBadCredentials) {
		t.Fatalf("Verify past explicit expiry = %v", err)
	}
}

func TestRobotMintRefusals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := robotFixture(t)
	robots := authn.NewRobotSecrets(store, robotRing(t), nil, bootClock)

	if _, err := robots.Mint(ctx, "alice", time.Time{}); err == nil {
		t.Error("Mint accepted a user: only robots hold robot secrets")
	}
	if _, err := robots.Mint(ctx, "robot$ghost", time.Time{}); err == nil {
		t.Error("Mint accepted a robot that does not exist")
	}
}

func TestRobotVerifyIsRateLimited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store := robotFixture(t)
	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 2, Refill: 10 * time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 100, Refill: time.Second, MaxKeys: 16},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	robots := authn.NewRobotSecrets(store, robotRing(t), limiter, func() time.Time { return now })

	secret, err := robots.Mint(ctx, "robot$ci", time.Time{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for range 2 {
		_ = robots.Verify(ctx, "robot$ci", "trove_r_r-ci_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "203.0.113.7")
	}
	var limited *authn.RateLimitedError
	if err := robots.Verify(ctx, "robot$ci", secret, "203.0.113.7"); !errors.As(err, &limited) {
		t.Fatalf("Verify = %v, want a rate-limited error", err)
	}
}

// brokenRobotStore fails the selected calls, so each failure is proven to
// surface as a failure rather than as a wrong secret.
type brokenRobotStore struct {
	*memory.Store
	failGetSubject bool
	failPut        bool
}

func (b *brokenRobotStore) GetRobotCredential(context.Context, string, time.Time) (meta.RobotCredential, error) {
	return meta.RobotCredential{}, errors.New("disk on fire")
}

func (b *brokenRobotStore) GetSubject(ctx context.Context, name string) (meta.Subject, error) {
	if b.failGetSubject {
		return meta.Subject{}, errors.New("disk on fire")
	}
	return b.Store.GetSubject(ctx, name)
}

func (b *brokenRobotStore) PutRobotCredential(ctx context.Context, cred meta.RobotCredential) error {
	if b.failPut {
		return errors.New("disk on fire")
	}
	return b.Store.PutRobotCredential(ctx, cred)
}

func TestRobotStoreFailuresSurface(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := robotFixture(t)

	t.Run("credential read during verify", func(t *testing.T) {
		t.Parallel()
		robots := authn.NewRobotSecrets(&brokenRobotStore{Store: store}, robotRing(t), nil, bootClock)
		err := robots.Verify(ctx, "robot$ci", "trove_r_r-ci_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
		if err == nil || errors.Is(err, authn.ErrBadCredentials) {
			t.Fatalf("Verify = %v, want a plain failure distinct from bad credentials", err)
		}
	})

	t.Run("subject read during verify", func(t *testing.T) {
		t.Parallel()
		robots := authn.NewRobotSecrets(&brokenRobotStore{Store: store, failGetSubject: true}, robotRing(t), nil, bootClock)
		err := robots.Verify(ctx, "robot$ci", "trove_r_r-ci_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
		if err == nil || errors.Is(err, authn.ErrBadCredentials) {
			t.Fatalf("Verify = %v, want a plain failure", err)
		}
	})

	t.Run("credential write during mint", func(t *testing.T) {
		t.Parallel()
		robots := authn.NewRobotSecrets(&brokenRobotStore{Store: store, failPut: true}, robotRing(t), nil, bootClock)
		if _, err := robots.Mint(ctx, "robot$ci", time.Time{}); err == nil {
			t.Fatal("Mint succeeded without storing the digest")
		}
	})

	t.Run("a keyring with no keys cannot mint", func(t *testing.T) {
		t.Parallel()
		robots := authn.NewRobotSecrets(store, nil, nil, bootClock)
		if _, err := robots.Mint(ctx, "robot$ci", time.Time{}); err == nil {
			t.Fatal("Mint succeeded with no key to digest under")
		}
	})
}
