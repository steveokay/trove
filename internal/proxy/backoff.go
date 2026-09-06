package proxy

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/steveokay/trove/internal/reponame"
)

// Rate-limit backoff (C-009).
//
// Avoiding Docker Hub throttling is a primary reason operators deploy a
// pull-through cache (§4), so being throttled *by* Docker Hub is the one
// failure this subsystem must not make worse. A 429 that is retried
// immediately, by every pull, from every node in a cluster, is how a rate limit
// becomes an outage that outlasts the window that caused it.
//
// The rule is therefore: when an upstream says stop, stop -- for as long as it
// asked, jittered so a fleet does not resume in lockstep, and capped so a
// six-hour Retry-After does not turn a proxy into a brick. While stopped the
// proxy behaves exactly as it does when the upstream is unreachable (ADR 0008),
// which is a behaviour C-008 already built: cached content is served stale,
// uncached content fails cleanly, and `strict` fails both.
//
// The client itself neither sleeps nor retries (C-002). It reports what the
// upstream said; this decides what to do about it.

// Backoff defaults. Base is deliberately small and Max deliberately modest: the
// point is to stop hammering, not to stop trying. One probe every few minutes
// costs an upstream nothing and is what lets a proxy recover on its own.
const (
	// DefaultBackoffBase is the first delay after a 429 that carried no
	// Retry-After.
	DefaultBackoffBase = time.Second

	// DefaultBackoffMax bounds every delay, including one the upstream asked
	// for. An upstream that demands six hours is either wrong or is telling us
	// something an operator needs to see rather than sleep through, and a proxy
	// that goes quiet for six hours is indistinguishable from a broken one.
	DefaultBackoffMax = 5 * time.Minute
)

// Backoff tracks, per upstream, when it may be called again.
//
// State is keyed by the proxy *entity* -- the first path segment of a content
// name -- because that is the unit an upstream quota belongs to: one entity has
// one upstream and one credential (ADR 0005), and a 429 for
// `dockerhub/library/nginx` is a 429 for everything under `dockerhub`. Keying
// by content name would let a hundred repository paths each discover the same
// throttling separately, which is exactly the storm this exists to prevent.
//
// It is safe for concurrent use.
type Backoff struct {
	base   time.Duration
	max    time.Duration
	jitter func(time.Duration) time.Duration

	mu     sync.Mutex
	states map[string]backoffState
}

// backoffState is one upstream's standing with us.
type backoffState struct {
	// failures is how many refusals in a row, which is what the exponential
	// climbs on.
	failures int
	// until is when the upstream may be called again.
	until time.Time
}

// BackoffOptions configures a Backoff.
type BackoffOptions struct {
	// Base is the first delay for a refusal that named no deadline of its own.
	// Zero means DefaultBackoffBase.
	Base time.Duration

	// Max bounds every delay. Zero means DefaultBackoffMax.
	Max time.Duration

	// Jitter spreads a delay so that a fleet throttled together does not
	// resume together. Nil means full jitter -- a uniform draw from [0, d) --
	// which is the shape that de-synchronises fastest.
	//
	// It is injectable because a schedule with randomness in it is otherwise
	// untestable, and because an operator's fleet of one gains nothing from
	// jitter at all.
	Jitter func(time.Duration) time.Duration
}

// NewBackoff builds a Backoff.
func NewBackoff(opts BackoffOptions) *Backoff {
	b := &Backoff{
		base:   opts.Base,
		max:    opts.Max,
		jitter: opts.Jitter,
		states: make(map[string]backoffState),
	}
	if b.base <= 0 {
		b.base = DefaultBackoffBase
	}
	if b.max <= 0 {
		b.max = DefaultBackoffMax
	}
	if b.jitter == nil {
		b.jitter = fullJitter
	}
	return b
}

// fullJitter draws uniformly from [0, d). It is the default because a fleet
// that all backs off for exactly the same computed delay resumes in lockstep
// and re-creates the storm it was backing off from.
// The randomness is scheduling noise and nothing depends on it being
// unguessable: knowing when a proxy will retry its upstream reveals nothing and
// controls nothing, and a cryptographic source here would be false precision
// bought with a syscall on a path that runs on every refusal.
func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d))) //nolint:gosec // jitter is scheduling noise, not a secret
}

// Ready reports whether an upstream may be called, and when it may be if not.
//
// An upstream nothing is known about is ready, which is the only safe default:
// a cache that refused to talk to an upstream it had never met would never
// fill.
func (b *Backoff) Ready(entity string, now time.Time) (bool, time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	state, known := b.states[entity]
	if !known || !now.Before(state.until) {
		return true, time.Time{}
	}
	return false, state.until
}

// Penalize records a refusal and returns when the upstream may be called again.
//
// The delay is the longest of what the upstream asked for and a jittered
// exponential on consecutive failures, then capped. Honouring the upstream's
// own number is the point -- it is the only party that knows when its window
// rolls over -- and the exponential is what covers a 429 that named nothing.
func (b *Backoff) Penalize(entity string, now time.Time, retryAfter time.Duration) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()

	state := b.states[entity]
	state.failures++

	// The exponential climbs on consecutive failures and is capped before the
	// jitter, so the draw is always from a bounded window.
	exponential := b.base << min(state.failures-1, 32)
	if exponential > b.max || exponential <= 0 {
		exponential = b.max
	}

	delay := b.jitter(exponential)
	if retryAfter > delay {
		delay = retryAfter
	}
	if delay > b.max {
		delay = b.max
	}
	if delay < 0 {
		delay = 0
	}

	state.until = now.Add(delay)
	b.states[entity] = state
	return state.until
}

// Succeed clears an upstream's standing. Recovery is immediate and total: a
// registry that answered is not one we should still be avoiding, and carrying
// the failure count forward would make the next unrelated 429 start halfway up
// the curve.
func (b *Backoff) Succeed(entity string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.states, entity)
}

// UpstreamBackoff is one upstream's backoff state, for the operator.
//
// It is what E-005 turns into gauges. This package deliberately registers no
// metrics of its own: the registry, the exposure mode, and the rule that a
// repository name may only be a label behind `metrics.per_repo` are E-005's and
// E-006's, and a collector written here would have to pre-empt all three.
type UpstreamBackoff struct {
	// Entity is the proxy repository the state belongs to.
	Entity string
	// Failures is how many consecutive refusals it has given us.
	Failures int
	// Until is when it may be called again.
	Until time.Time
	// Active reports whether the deadline is still in the future.
	Active bool
}

// Snapshot reports every upstream currently being backed off, ordered by
// entity so a scrape is stable.
func (b *Backoff) Snapshot(now time.Time) []UpstreamBackoff {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]UpstreamBackoff, 0, len(b.states))
	for entity, state := range b.states {
		out = append(out, UpstreamBackoff{
			Entity:   entity,
			Failures: state.failures,
			Until:    state.until,
			Active:   now.Before(state.until),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entity < out[j].Entity })
	return out
}

// upstreamEntity is the backoff key for a target: the entity its content name
// belongs to.
func upstreamEntity(t Target) string { return reponame.Prefix(t.Repository) }

// upstreamReady reports nil when the target's upstream may be called, and a
// rate-limited error when it may not.
//
// The error is the same one the upstream's own 429 produces, on purpose: a
// caller must not have to distinguish "they are throttling us" from "we are
// still serving the throttling they did a minute ago", because the answer to
// both is the same -- serve what is cached, fail what is not (ADR 0008), and
// C-008 already classifies it.
func (f *Filler) upstreamReady(t Target, now time.Time) error {
	ready, until := f.backoff.Ready(upstreamEntity(t), now)
	if ready {
		return nil
	}
	return &RateLimitedError{
		RetryAfter:    until.Sub(now),
		HasRetryAfter: true,
		Path:          fmt.Sprintf("%s (backing off until %s)", t.Upstream, until.UTC().Format(time.RFC3339)),
	}
}

// recordUpstream updates an upstream's standing from the result of a call to
// it.
//
// Only throttling backs off. An unreachable upstream is retried on the next
// pull, because a dial that fails costs nobody anything and a proxy that
// stopped trying would keep failing for the length of a window after the
// network came back -- the opposite of what degraded mode is for. Throttling is
// different in kind: the request itself is the harm.
func (f *Filler) recordUpstream(ctx context.Context, t Target, now time.Time, err error) {
	entity := upstreamEntity(t)
	if err == nil {
		f.backoff.Succeed(entity)
		return
	}

	cause, degraded := Classify(err)
	if !degraded || cause != CauseRateLimited {
		return
	}

	retryAfter := time.Duration(0)
	var limited *RateLimitedError
	if errors.As(err, &limited) && limited.HasRetryAfter {
		retryAfter = limited.RetryAfter
	}

	until := f.backoff.Penalize(entity, now, retryAfter)
	f.log.WarnContext(ctx, "upstream is throttling us, backing off",
		"repository", t.Repository, "upstream", t.Remote, "until", until)
}
