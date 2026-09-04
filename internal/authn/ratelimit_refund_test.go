package authn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
)

// A refund unspends one attempt, and never banks credit: a key that owed
// nothing still owes nothing afterwards, so refunding in a loop cannot buy a
// burst larger than the configured one.
func TestLimiterRefund(t *testing.T) {
	t.Parallel()

	c := newClock()
	limiter := newTestLimiter(t, testLimit(), c) // burst 3

	for i := range 3 {
		if ok, _ := limiter.Allow("k"); !ok {
			t.Fatalf("attempt %d refused inside the burst", i)
		}
	}
	if ok, _ := limiter.Allow("k"); ok {
		t.Fatal("the fourth attempt was allowed")
	}

	limiter.Refund("k")
	if ok, wait := limiter.Allow("k"); !ok {
		t.Fatalf("a refunded attempt was not restored (wait %s)", wait)
	}
	if ok, _ := limiter.Allow("k"); ok {
		t.Fatal("one refund restored more than one attempt")
	}

	// Refunds cannot accumulate into a bigger burst: ten of them on an
	// already-idle key still leave exactly the configured burst.
	for range 10 {
		limiter.Refund("k")
	}
	allowed := 0
	for range 10 {
		if ok, _ := limiter.Allow("k"); ok {
			allowed++
		}
	}
	if allowed > 3 {
		t.Errorf("refunds banked credit: %d attempts allowed, want at most the burst of 3", allowed)
	}

	// Refunding a key nobody has spent is a no-op rather than a credit.
	limiter.Refund("never-seen")
	if keys := limiter.Keys(); keys != 1 {
		t.Errorf("refunding an unknown key created state: %d keys", keys)
	}
}

// The rule the conformance run forced (R-009): a client authenticating
// correctly is not guessing, so its budget comes back and a long push is not
// cut off partway. Wrong guesses stay charged, which is where the limiter's
// teeth are.
func TestPasswordLoginRefundsSuccesses(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := loginFixture(t, authn.NewHasher())

	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 3, Refill: 10 * time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 5, Refill: time.Second, MaxKeys: 16},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	// Far more successful authentications than either burst: a real push
	// mints a token per operation, and the clock never moves here, so any
	// charging at all would refuse one of these.
	for i := range 50 {
		if err := login.Authenticate(ctx, "alice", "sesame", "203.0.113.7"); err != nil {
			t.Fatalf("successful login %d was refused: %v", i, err)
		}
	}

	// The brute-force arithmetic is untouched: wrong guesses still exhaust
	// the account burst, at exactly the configured count.
	guesses := 0
	for {
		err := login.Authenticate(ctx, "alice", "wrong", "203.0.113.7")
		var limited *authn.RateLimitedError
		if errors.As(err, &limited) {
			break
		}
		if !errors.Is(err, authn.ErrBadCredentials) {
			t.Fatalf("guess %d = %v, want bad credentials", guesses, err)
		}
		guesses++
		if guesses > 10 {
			t.Fatal("wrong passwords are no longer rate limited")
		}
	}
	if guesses != 3 {
		t.Errorf("%d wrong guesses allowed, want the configured burst of 3", guesses)
	}
}

// A correct password for a subject that does not exist cannot be refunded into
// free enumeration: the unknown-user path never reaches the refund, so probing
// for valid usernames stays as expensive as guessing passwords.
func TestPasswordLoginDoesNotRefundUnknownUsers(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := loginFixture(t, authn.NewHasher())

	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 100, Refill: time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 3, Refill: 10 * time.Second, MaxKeys: 16},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	// Each probe names a different account, so only the address dimension
	// holds them back -- which it must, or username enumeration is free.
	probes := 0
	for {
		err := login.Authenticate(ctx, "ghost-"+string(rune('a'+probes)), "whatever", "198.51.100.9")
		var limited *authn.RateLimitedError
		if errors.As(err, &limited) {
			break
		}
		probes++
		if probes > 10 {
			t.Fatal("enumeration across accounts is not limited by address")
		}
	}
	if probes != 3 {
		t.Errorf("%d enumeration probes allowed, want the configured address burst of 3", probes)
	}
}
