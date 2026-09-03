package authn

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Rate limiting on the authentication endpoints (ADR 0004, CLAUDE.md §11).
//
// A password hash costs about a tenth of a second by design, which stops an
// attacker with the database. It does nothing about an attacker with the
// network: they can guess as fast as the server will answer, and they are
// happy to spend our CPU doing it. The limiter is what makes online guessing
// expensive in wall-clock time rather than in our memory bandwidth.
//
// Two dimensions, because each catches what the other misses. Per account
// stops one password being guessed from a botnet. Per source address stops one
// host spraying one guess across every account -- which is the attack that
// per-account limits are blind to, since no single account sees more than one
// attempt.
//
// In-process and single-node, which is what ADR 0018 chose for v1 (Q5). A
// second replica would have its own buckets and the effective rate would be
// per replica; that is the seam a shared limiter would fill, and it is why
// this is a type behind a small interface-shaped surface rather than a package
// of free functions.

// LimiterConfig is a token bucket's shape: how many attempts may happen at
// once, and how quickly the allowance comes back.
type LimiterConfig struct {
	// Burst is the number of attempts allowed before throttling begins. It has
	// to absorb ordinary human error -- a few typos, a stale saved password,
	// a CI job with an old token -- or the limiter becomes the outage.
	Burst int
	// Refill is how long one attempt takes to come back. Burst 10 with a 10s
	// refill means a sustained six attempts a minute after the burst is spent.
	Refill time.Duration
	// MaxKeys bounds memory. Keys arrive from the network -- an address per
	// attempt, a username per guess -- so an unbounded map is a memory
	// exhaustion attack that needs no credentials at all.
	MaxKeys int
}

// Defaults for the two dimensions. The address bucket is the looser of the two
// because an office, a CI cluster, or a Kubernetes node all appear as one
// address with many legitimate users behind it, while an account is one person
// or one robot and has no such excuse.
var (
	// DefaultAccountLimit throttles attempts against a single account.
	DefaultAccountLimit = LimiterConfig{Burst: 10, Refill: 10 * time.Second, MaxKeys: 4096}
	// DefaultAddressLimit throttles attempts from a single source address.
	DefaultAddressLimit = LimiterConfig{Burst: 60, Refill: 2 * time.Second, MaxKeys: 4096}
)

// ErrInvalidLimit reports a limiter configuration that cannot work.
var ErrInvalidLimit = errors.New("invalid rate limit")

// Validate reports whether the configuration describes a working bucket.
func (c LimiterConfig) Validate() error {
	switch {
	case c.Burst <= 0:
		return fmt.Errorf("%w: burst must be positive, got %d", ErrInvalidLimit, c.Burst)
	case c.Refill <= 0:
		return fmt.Errorf("%w: refill must be positive, got %s", ErrInvalidLimit, c.Refill)
	case c.MaxKeys <= 0:
		return fmt.Errorf("%w: max keys must be positive, got %d", ErrInvalidLimit, c.MaxKeys)
	}
	return nil
}

// Limiter is a token bucket per key.
//
// Every attempt spends a token, whether it succeeds or fails. Refunding
// successes is the obvious refinement and the wrong one: an attacker who knows
// one valid password would get an unlimited allowance to guess the rest, and
// the burst is generous enough that no honest client notices.
type Limiter struct {
	cfg   LimiterConfig
	clock func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket is one key's allowance, held as the single instant at which that
// allowance would be fully restored.
//
// One timestamp rather than a token count, because a count has to be credited
// for elapsed time and that means fractional tokens: with floats, "nine
// seconds into a ten-second refill" answers 999.999999ms instead of one
// second, and the error accumulates over a long-lived bucket. Here every
// answer is exact integer time arithmetic, which is also what lets a
// Retry-After header be true rather than approximately true.
//
// The encoding is the standard generic cell rate algorithm: restoredAt runs
// ahead of now by the debt the key has accrued, one refill interval per
// attempt, and an attempt is refused while that debt exceeds what the burst
// tolerates.
type bucket struct {
	restoredAt time.Time
}

// NewLimiter returns a limiter, or an error if the configuration cannot work.
// The clock is injected; nil means time.Now.
func NewLimiter(cfg LimiterConfig, clock func() time.Time) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{cfg: cfg, clock: clock, buckets: make(map[string]*bucket)}, nil
}

// tolerance is how far ahead of now a key's debt may run before attempts are
// refused: one interval short of the whole burst, so the burst is exactly
// Burst attempts and the one after it is not.
func (l *Limiter) tolerance() time.Duration {
	return time.Duration(l.cfg.Burst-1) * l.cfg.Refill
}

// Allow spends one attempt for key, reporting whether it may proceed and, when
// it may not, how long until it could.
//
// The wait is exact rather than rounded up to the whole refill interval, so a
// caller can put it in a Retry-After header and be telling the truth.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	b := l.bucket(key, now)
	if wait := l.wait(b, now); wait > 0 {
		return false, wait
	}

	// An idle key starts owing from now, not from whenever it was last seen;
	// that is what caps an untouched account at one burst instead of letting a
	// month of silence buy thousands of guesses.
	if b.restoredAt.Before(now) {
		b.restoredAt = now
	}
	b.restoredAt = b.restoredAt.Add(l.cfg.Refill)
	return true, 0
}

// Peek reports whether an attempt would be allowed without spending anything.
// It exists so a caller checking several dimensions can decide before
// committing to any of them.
func (l *Limiter) Peek(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	wait := l.wait(l.bucket(key, now), now)
	return wait <= 0, max(wait, 0)
}

// Keys reports how many buckets are held. It is the number a memory metric
// would publish, and what the eviction test asserts on.
func (l *Limiter) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// wait is how long until the key may attempt again; zero or less means now.
func (l *Limiter) wait(b *bucket, now time.Time) time.Duration {
	return b.restoredAt.Add(-l.tolerance()).Sub(now)
}

// bucket returns key's state, creating it owing nothing. The caller holds the
// lock.
func (l *Limiter) bucket(key string, now time.Time) *bucket {
	b, known := l.buckets[key]
	if !known {
		l.evict(now)
		b = &bucket{restoredAt: now}
		l.buckets[key] = b
	}
	return b
}

// evict makes room when the map is at its bound. The caller holds the lock.
//
// It drops the keys that owe the least. A key with no outstanding debt records
// nothing that recreating it would not reproduce, so dropping one costs no
// enforcement at all; beyond those, the least indebted key is the one whose
// loss grants the least. Note what this is not: it is not least-recently-used.
// The most valuable bucket to keep belongs to the attacker who exhausted their
// allowance and went quiet, which is precisely the bucket an LRU policy would
// throw away first -- and spraying keys to displace it would then be the way
// around the limiter.
//
// Eviction is never a refusal to admit new keys. Refusing them would let
// somebody spraying addresses lock out everyone who arrived afterwards.
func (l *Limiter) evict(now time.Time) {
	if len(l.buckets) < l.cfg.MaxKeys {
		return
	}

	for key, b := range l.buckets {
		if !b.restoredAt.After(now) {
			delete(l.buckets, key)
		}
	}

	for len(l.buckets) >= l.cfg.MaxKeys {
		var (
			poorest string
			least   time.Time
		)
		for key, b := range l.buckets {
			if least.IsZero() || b.restoredAt.Before(least) {
				poorest, least = key, b.restoredAt
			}
		}
		delete(l.buckets, poorest)
	}
}

// Attempt is one authentication attempt's rate-limiting identity: which
// account it targets and where it came from.
//
// Either may be empty. An empty account is an attempt that named nobody -- a
// malformed header, an anonymous token request -- and is limited by address
// alone; an empty address is a caller that could not determine one, which
// must not become a way to opt out of the account limit.
type Attempt struct {
	Account string
	Address string
}

// AttemptLimiter applies both dimensions to one attempt.
type AttemptLimiter struct {
	account *Limiter
	address *Limiter
}

// NewAttemptLimiter returns a limiter over both dimensions.
func NewAttemptLimiter(account, address LimiterConfig, clock func() time.Time) (*AttemptLimiter, error) {
	byAccount, err := NewLimiter(account, clock)
	if err != nil {
		return nil, fmt.Errorf("account limit: %w", err)
	}
	byAddress, err := NewLimiter(address, clock)
	if err != nil {
		return nil, fmt.Errorf("address limit: %w", err)
	}
	return &AttemptLimiter{account: byAccount, address: byAddress}, nil
}

// Allow reports whether an attempt may proceed, and how long until it could.
//
// Both dimensions are checked before either is spent, so an attempt refused by
// one does not also drain the other. Without that, an attacker hammering one
// account would burn down the address allowance of every user behind the same
// NAT -- turning a limiter into the denial of service it exists to prevent.
//
// The check and the spend are not one atomic step across both dimensions, so
// simultaneous attempts can overshoot a burst by the number of them in flight.
// That is the right trade here: the alternative is one lock over both buckets
// on every login, and an attacker who gains a handful of extra guesses out of
// a race has gained nothing that matters against a rate measured in seconds.
func (l *AttemptLimiter) Allow(a Attempt) (bool, time.Duration) {
	wait := time.Duration(0)
	for _, check := range []struct {
		limiter *Limiter
		key     string
	}{
		{l.account, a.Account},
		{l.address, a.Address},
	} {
		if check.key == "" {
			continue
		}
		if ok, retry := check.limiter.Peek(check.key); !ok {
			wait = max(wait, retry)
		}
	}
	if wait > 0 {
		return false, wait
	}

	if a.Account != "" {
		_, _ = l.account.Allow(a.Account)
	}
	if a.Address != "" {
		_, _ = l.address.Allow(a.Address)
	}
	return true, 0
}
