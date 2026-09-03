package authn_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
)

// clock is the injected time source. No test here sleeps: a rate limiter is
// entirely about elapsed time, so a suite that waits for real seconds is both
// slow and flaky, and one that cannot advance time cannot test a cooldown at
// all (CLAUDE.md §7, §9).
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testLimit() authn.LimiterConfig {
	return authn.LimiterConfig{Burst: 3, Refill: 10 * time.Second, MaxKeys: 16}
}

func newTestLimiter(t *testing.T, cfg authn.LimiterConfig, c *clock) *authn.Limiter {
	t.Helper()

	limiter, err := authn.NewLimiter(cfg, c.Now)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	return limiter
}

// The shape of the thing: a burst, then refusal, then the allowance coming
// back with time. The last part is the one that matters -- a limiter that
// throttles but never forgives is an account lockout, and account lockout is a
// denial of service an attacker can trigger on anyone whose username they know.
func TestLimiterBurstThenCooldown(t *testing.T) {
	t.Parallel()

	c := newClock()
	limiter := newTestLimiter(t, testLimit(), c)

	for i := range testLimit().Burst {
		if ok, _ := limiter.Allow("alice"); !ok {
			t.Fatalf("attempt %d was refused inside the burst", i+1)
		}
	}

	ok, retry := limiter.Allow("alice")
	if ok {
		t.Fatal("the attempt after the burst was allowed")
	}
	if retry != 10*time.Second {
		t.Errorf("retry after = %s, want the full refill interval", retry)
	}

	// Not yet.
	c.advance(9 * time.Second)
	if ok, retry := limiter.Allow("alice"); ok {
		t.Error("an attempt was allowed before the allowance had come back")
	} else if retry != time.Second {
		t.Errorf("retry after = %s, want 1s", retry)
	}

	// Now. This is "legitimate login after cooldown succeeds".
	c.advance(time.Second)
	if ok, _ := limiter.Allow("alice"); !ok {
		t.Error("the attempt after the cooldown was refused")
	}
	// And only one attempt was earned back.
	if ok, _ := limiter.Allow("alice"); ok {
		t.Error("the cooldown returned more than the one attempt it had earned")
	}
}

// Refill is continuous, not stepped. Two half-intervals must earn as much as
// one whole one, or an attacker who paces themselves just under the interval
// would be throttled forever while a real user would be too.
func TestLimiterRefillsProportionally(t *testing.T) {
	t.Parallel()

	c := newClock()
	limiter := newTestLimiter(t, testLimit(), c)
	drain(t, limiter, "alice", testLimit().Burst)

	c.advance(5 * time.Second)
	if ok, _ := limiter.Allow("alice"); ok {
		t.Fatal("half an interval bought a whole attempt")
	}
	c.advance(5 * time.Second)
	if ok, _ := limiter.Allow("alice"); !ok {
		t.Error("two half-intervals did not add up to one attempt")
	}
}

// An idle key does not accumulate an unbounded allowance. Without the cap, an
// account untouched for a month would arrive with thousands of free guesses,
// which is precisely the situation an attacker waits for.
func TestLimiterAllowanceIsCapped(t *testing.T) {
	t.Parallel()

	c := newClock()
	limiter := newTestLimiter(t, testLimit(), c)
	drain(t, limiter, "alice", testLimit().Burst)

	c.advance(30 * 24 * time.Hour)
	drain(t, limiter, "alice", testLimit().Burst)
	if ok, _ := limiter.Allow("alice"); ok {
		t.Error("a month of idling bought more than one burst")
	}
}

// One key's exhaustion is not another's.
func TestLimiterKeysAreIndependent(t *testing.T) {
	t.Parallel()

	c := newClock()
	limiter := newTestLimiter(t, testLimit(), c)
	drain(t, limiter, "alice", testLimit().Burst)

	if ok, _ := limiter.Allow("alice"); ok {
		t.Fatal("alice is not throttled")
	}
	if ok, _ := limiter.Allow("bob"); !ok {
		t.Error("bob was throttled by alice's attempts")
	}
}

// Peek answers the same question as Allow without spending anything, which is
// what lets the two-dimensional limiter decide before it commits.
func TestLimiterPeekSpendsNothing(t *testing.T) {
	t.Parallel()

	c := newClock()
	limiter := newTestLimiter(t, testLimit(), c)

	for range 10 {
		if ok, _ := limiter.Peek("alice"); !ok {
			t.Fatal("peeking used up the allowance")
		}
	}
	drain(t, limiter, "alice", testLimit().Burst)

	ok, retry := limiter.Peek("alice")
	if ok {
		t.Error("Peek says an exhausted key may proceed")
	}
	if retry != 10*time.Second {
		t.Errorf("Peek retry after = %s, want the full interval", retry)
	}
}

// Keys arrive from the network: an address per attempt, a username per guess.
// The map has to be bounded or the limiter is itself a way to exhaust memory
// without presenting a single credential.
func TestLimiterBoundsItsMemory(t *testing.T) {
	t.Parallel()

	c := newClock()
	cfg := testLimit()
	cfg.MaxKeys = 8
	limiter := newTestLimiter(t, cfg, c)

	for i := range 500 {
		if ok, _ := limiter.Allow(fmt.Sprintf("10.0.0.%d", i)); !ok {
			// Eviction must never turn into a refusal: an attacker spraying
			// addresses would otherwise lock out everyone arriving after them.
			t.Fatalf("a new key was refused after %d others", i)
		}
	}
	if got := limiter.Keys(); got > cfg.MaxKeys {
		t.Errorf("holding %d keys, want at most %d", got, cfg.MaxKeys)
	}
}

// Eviction drops the buckets that record nothing before the ones that do. A
// throttled key is the only kind whose absence changes an answer, so it must
// outlive the idle keys sprayed to displace it -- otherwise the memory bound
// becomes the way around the limiter.
func TestEvictionKeepsTheThrottledKey(t *testing.T) {
	t.Parallel()

	c := newClock()
	cfg := testLimit()
	cfg.MaxKeys = 8
	limiter := newTestLimiter(t, cfg, c)

	drain(t, limiter, "attacker", cfg.Burst)
	if ok, _ := limiter.Peek("attacker"); ok {
		t.Fatal("the attacker is not throttled to begin with")
	}

	// Every one of these touches a key once, leaving a nearly full bucket --
	// the cheap kind to drop.
	for i := range 200 {
		if ok, _ := limiter.Allow(fmt.Sprintf("noise-%d", i)); !ok {
			t.Fatalf("noise key %d was refused", i)
		}
	}

	if ok, _ := limiter.Peek("attacker"); ok {
		t.Error("the throttled key was evicted by traffic that was not throttled")
	}
}

// A key that owes nothing is free to drop: recreating it produces exactly the
// state that was thrown away. Once traffic has aged out, the whole map should
// clear rather than the limiter carrying yesterday's addresses forever.
func TestEvictionDropsSettledKeys(t *testing.T) {
	t.Parallel()

	c := newClock()
	cfg := testLimit()
	cfg.MaxKeys = 8
	limiter := newTestLimiter(t, cfg, c)

	for i := range cfg.MaxKeys {
		if ok, _ := limiter.Allow(fmt.Sprintf("10.0.0.%d", i)); !ok {
			t.Fatalf("key %d was refused", i)
		}
	}

	// Long enough that every bucket has settled its debt.
	c.advance(time.Hour)
	if ok, _ := limiter.Allow("10.0.1.1"); !ok {
		t.Fatal("a new key was refused")
	}
	if got := limiter.Keys(); got != 1 {
		t.Errorf("holding %d keys, want only the new one: settled keys were kept", got)
	}
}

func TestLimiterConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  authn.LimiterConfig
	}{
		{name: "zero", cfg: authn.LimiterConfig{}},
		{name: "no burst", cfg: authn.LimiterConfig{Burst: 0, Refill: time.Second, MaxKeys: 1}},
		{name: "negative burst", cfg: authn.LimiterConfig{Burst: -1, Refill: time.Second, MaxKeys: 1}},
		{name: "no refill", cfg: authn.LimiterConfig{Burst: 1, MaxKeys: 1}},
		{name: "negative refill", cfg: authn.LimiterConfig{Burst: 1, Refill: -time.Second, MaxKeys: 1}},
		{name: "unbounded memory", cfg: authn.LimiterConfig{Burst: 1, Refill: time.Second}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.cfg.Validate(); !errors.Is(err, authn.ErrInvalidLimit) {
				t.Errorf("Validate = %v, want ErrInvalidLimit", err)
			}
			if _, err := authn.NewLimiter(tt.cfg, nil); !errors.Is(err, authn.ErrInvalidLimit) {
				t.Errorf("NewLimiter = %v, want ErrInvalidLimit", err)
			}
		})
	}

	// Both defaults have to be usable, since they are what a deployment that
	// configures nothing gets.
	for name, cfg := range map[string]authn.LimiterConfig{
		"account": authn.DefaultAccountLimit,
		"address": authn.DefaultAddressLimit,
	} {
		if err := cfg.Validate(); err != nil {
			t.Errorf("the default %s limit does not validate: %v", name, err)
		}
	}
}

// A nil clock means time.Now rather than a nil dereference on the first
// attempt, which would be a crash in the login path.
func TestLimiterDefaultsToTheWallClock(t *testing.T) {
	t.Parallel()

	limiter, err := authn.NewLimiter(testLimit(), nil)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	if ok, _ := limiter.Allow("alice"); !ok {
		t.Error("the first attempt was refused")
	}
}

// Concurrent attempts on one key must not hand out more than the burst. The
// single-key limiter takes one lock for the check and the spend together, so
// this is exact rather than approximate -- and it is what the race detector
// runs over in CI.
func TestLimiterIsExactUnderConcurrency(t *testing.T) {
	t.Parallel()

	c := newClock()
	cfg := testLimit()
	cfg.Burst = 50
	limiter := newTestLimiter(t, cfg, c)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for range 200 {
		wg.Go(func() {
			if ok, _ := limiter.Allow("alice"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if allowed != cfg.Burst {
		t.Errorf("%d attempts were allowed, want exactly the burst of %d", allowed, cfg.Burst)
	}
}

// Both dimensions apply, and each catches what the other cannot: one account
// hammered from everywhere, and one host spraying one guess at every account.
func TestAttemptLimiterAppliesBothDimensions(t *testing.T) {
	t.Parallel()

	c := newClock()
	account := authn.LimiterConfig{Burst: 3, Refill: 10 * time.Second, MaxKeys: 16}
	address := authn.LimiterConfig{Burst: 5, Refill: 10 * time.Second, MaxKeys: 16}
	limiter, err := authn.NewAttemptLimiter(account, address, c.Now)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}

	// One account guessed from three different hosts: the account limit is
	// what stops it, since no single address has done much.
	for i := range account.Burst {
		attempt := authn.Attempt{Account: "alice", Address: fmt.Sprintf("10.0.0.%d", i)}
		if ok, _ := limiter.Allow(attempt); !ok {
			t.Fatalf("attempt %d was refused inside the account burst", i+1)
		}
	}
	if ok, retry := limiter.Allow(authn.Attempt{Account: "alice", Address: "10.0.0.99"}); ok {
		t.Error("a fresh address bypassed the account limit")
	} else if retry <= 0 {
		t.Error("a refusal came with no retry-after")
	}

	// A different account from a fresh address is unaffected.
	if ok, _ := limiter.Allow(authn.Attempt{Account: "bob", Address: "10.0.0.99"}); !ok {
		t.Error("bob was throttled by attempts against alice")
	}

	// One host spraying distinct accounts: the address limit is what stops
	// it, since no single account has been tried more than once.
	c2 := newClock()
	sprayer, err := authn.NewAttemptLimiter(account, address, c2.Now)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	for i := range address.Burst {
		attempt := authn.Attempt{Account: fmt.Sprintf("user-%d", i), Address: "10.0.0.1"}
		if ok, _ := sprayer.Allow(attempt); !ok {
			t.Fatalf("attempt %d was refused inside the address burst", i+1)
		}
	}
	if ok, _ := sprayer.Allow(authn.Attempt{Account: "user-999", Address: "10.0.0.1"}); ok {
		t.Error("a fresh account bypassed the address limit")
	}
}

// A refusal by one dimension must not spend the other. Otherwise an attacker
// hammering one account would drain the address allowance of everyone behind
// the same NAT -- the limiter becoming the outage it exists to prevent.
func TestAttemptLimiterDoesNotSpendOnRefusal(t *testing.T) {
	t.Parallel()

	c := newClock()
	account := authn.LimiterConfig{Burst: 2, Refill: 10 * time.Second, MaxKeys: 16}
	address := authn.LimiterConfig{Burst: 100, Refill: 10 * time.Second, MaxKeys: 16}
	limiter, err := authn.NewAttemptLimiter(account, address, c.Now)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}

	office := "203.0.113.7"
	for range account.Burst {
		if ok, _ := limiter.Allow(authn.Attempt{Account: "alice", Address: office}); !ok {
			t.Fatal("an attempt inside the account burst was refused")
		}
	}
	// Alice is throttled; keep hammering her account from the office address.
	for range 500 {
		if ok, _ := limiter.Allow(authn.Attempt{Account: "alice", Address: office}); ok {
			t.Fatal("a throttled account was allowed through")
		}
	}

	// Her colleagues, on the same address, must be unaffected: only two
	// attempts were ever spent from it.
	for i := range address.Burst - account.Burst {
		attempt := authn.Attempt{Account: fmt.Sprintf("colleague-%d", i), Address: office}
		if ok, _ := limiter.Allow(attempt); !ok {
			t.Fatalf("colleague %d was locked out by the attack on alice", i)
		}
	}
}

// An attempt that names nobody is still limited by where it came from, and an
// attempt with no address is still limited by which account it targets. An
// empty dimension must not become the way to opt out of the other one.
func TestAttemptLimiterHandlesMissingDimensions(t *testing.T) {
	t.Parallel()

	c := newClock()
	cfg := authn.LimiterConfig{Burst: 2, Refill: 10 * time.Second, MaxKeys: 16}
	limiter, err := authn.NewAttemptLimiter(cfg, cfg, c.Now)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}

	// No account named: the address limit still applies.
	for range cfg.Burst {
		if ok, _ := limiter.Allow(authn.Attempt{Address: "10.0.0.1"}); !ok {
			t.Fatal("an anonymous attempt inside the burst was refused")
		}
	}
	if ok, _ := limiter.Allow(authn.Attempt{Address: "10.0.0.1"}); ok {
		t.Error("omitting the account bypassed the address limit")
	}

	// No address known: the account limit still applies.
	for range cfg.Burst {
		if ok, _ := limiter.Allow(authn.Attempt{Account: "alice"}); !ok {
			t.Fatal("an attempt with no address inside the burst was refused")
		}
	}
	if ok, _ := limiter.Allow(authn.Attempt{Account: "alice"}); ok {
		t.Error("omitting the address bypassed the account limit")
	}

	// An attempt with neither is limited by nothing here; the caller has no
	// key to limit it by, and inventing one would throttle unrelated traffic
	// together.
	if ok, _ := limiter.Allow(authn.Attempt{}); !ok {
		t.Error("an attempt with no dimensions at all was refused")
	}
}

func TestNewAttemptLimiterRefusesBadConfigurations(t *testing.T) {
	t.Parallel()

	good := testLimit()
	bad := authn.LimiterConfig{}

	if _, err := authn.NewAttemptLimiter(bad, good, nil); !errors.Is(err, authn.ErrInvalidLimit) {
		t.Errorf("a bad account limit = %v, want ErrInvalidLimit", err)
	}
	if _, err := authn.NewAttemptLimiter(good, bad, nil); !errors.Is(err, authn.ErrInvalidLimit) {
		t.Errorf("a bad address limit = %v, want ErrInvalidLimit", err)
	}
}

// drain spends a key's whole allowance, failing if any of it is refused.
func drain(t *testing.T, limiter *authn.Limiter, key string, attempts int) {
	t.Helper()

	for i := range attempts {
		if ok, _ := limiter.Allow(key); !ok {
			t.Fatalf("attempt %d of %d was refused while draining %q", i+1, attempts, key)
		}
	}
}
