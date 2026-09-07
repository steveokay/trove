package cache

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Scheduler defaults. Eviction is a background reclaim, so the timer is short
// enough that a cache does not sit over budget for long and long enough that a
// quiet deployment is not querying usage all day.
const (
	// DefaultSweepInterval is how often the budget sweep runs unprompted.
	DefaultSweepInterval = 5 * time.Minute

	// DefaultOrphanEvery is how many budget sweeps pass between orphan passes.
	// The orphan pass walks the whole cache store, which is much more
	// expensive than a usage query, and what it reclaims is bytes nobody can
	// serve -- worth collecting hourly, not every five minutes.
	DefaultOrphanEvery = 12
)

// Flusher writes out pending observations before a sweep reads them.
// *TouchBatcher satisfies it.
type Flusher interface {
	Flush(ctx context.Context) error
}

// Scheduler runs the sweeps: on a timer, and on demand when something fills
// the cache (Q11's breach trigger).
//
// Triggers coalesce. A hundred fills arriving during one sweep leave exactly
// one sweep pending afterwards, because what a trigger means is "the cache
// grew" and a sweep that has not started yet will see all of that growth
// anyway. Without the coalescing, a busy proxy would queue a sweep per fill
// and spend its budget query on every layer of every image.
//
// The sweeps run one at a time, in this goroutine, deliberately: two
// concurrent sweeps would rank the same LRU page twice and race each other to
// delete it, and the loser's failures would be indistinguishable from a broken
// store.
type Scheduler struct {
	evictor     *Evictor
	touches     Flusher
	interval    time.Duration
	orphanEvery int
	now         func() time.Time
	log         *slog.Logger

	ticks    <-chan time.Time
	stopTick func()
	triggers chan struct{}
}

// SchedulerOptions configures a Scheduler. Only Evictor is required.
type SchedulerOptions struct {
	// Evictor performs the sweeps.
	Evictor *Evictor

	// Touches, when set, is flushed before every budget sweep so the LRU ranks
	// on the accesses that have happened rather than on the ones that have
	// been written. Nil means the sweep reads whatever the store holds.
	Touches Flusher

	// Interval is how often the budget sweep runs. Zero means
	// DefaultSweepInterval.
	Interval time.Duration

	// OrphanEvery is how many budget sweeps pass between orphan passes. Zero
	// means DefaultOrphanEvery; a negative value switches the orphan pass off,
	// which is for a deployment that would rather run it from the CLI.
	OrphanEvery int

	// Now is the clock the sweep durations are measured with. Nil means
	// time.Now. It is injected for the reason every clock here is (§7): a test
	// that asserts on a log line should not have to assert on a real duration.
	Now func() time.Time

	// Log receives sweep outcomes. Nil means slog.Default.
	Log *slog.Logger

	// Ticks replaces the internal timer so a test can drive the schedule.
	// Production leaves it nil and gets a ticker at Interval.
	Ticks <-chan time.Time
}

// NewScheduler builds a Scheduler. It does not start: Run does, and the caller
// owns the goroutine so that shutdown is the caller's to sequence.
func NewScheduler(opts SchedulerOptions) (*Scheduler, error) {
	if opts.Evictor == nil {
		return nil, errInvalid("an evictor is required")
	}

	s := &Scheduler{
		evictor:     opts.Evictor,
		touches:     opts.Touches,
		interval:    opts.Interval,
		orphanEvery: opts.OrphanEvery,
		now:         opts.Now,
		log:         opts.Log,

		ticks:    opts.Ticks,
		stopTick: func() {},
		// Depth one is the coalescing: a trigger that finds the slot taken has
		// nothing to add, because the sweep it would have asked for has not
		// run yet.
		triggers: make(chan struct{}, 1),
	}
	if s.interval <= 0 {
		s.interval = DefaultSweepInterval
	}
	if s.orphanEvery == 0 {
		s.orphanEvery = DefaultOrphanEvery
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// Trigger asks for a sweep. It never blocks and it is safe to call from a
// request path: the caller is a fill that has already succeeded, and eviction
// runs after it rather than in front of it.
func (s *Scheduler) Trigger() {
	select {
	case s.triggers <- struct{}{}:
	default:
	}
}

// Run sweeps until the context is cancelled, then returns its error. It is a
// blocking call: the caller starts it in a goroutine and cancels the context
// to stop it.
//
// A sweep that fails does not stop the loop. The failure is logged and the
// next tick tries again, because the reason a sweep fails -- a metadata store
// that is not answering -- is one that resolves without this goroutine's help,
// and a cache that stopped evicting the moment its store hiccuped would fill
// up silently.
func (s *Scheduler) Run(ctx context.Context) error {
	if s.ticks == nil {
		ticker := time.NewTicker(s.interval)
		s.ticks = ticker.C
		s.stopTick = ticker.Stop
	}
	defer s.stopTick()

	// A sweep counter rather than a second timer: the orphan pass is expensive
	// in proportion to the cache, and pinning it to a multiple of the sweep
	// means one schedule to reason about instead of two that drift.
	var sweeps int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ticks:
		case <-s.triggers:
		}

		s.sweep(ctx)
		sweeps++
		if s.orphanEvery > 0 && sweeps%s.orphanEvery == 0 {
			s.sweepOrphans(ctx)
		}
	}
}

// sweep runs one budget sweep, flushing pending touches first.
func (s *Scheduler) sweep(ctx context.Context) {
	if s.touches != nil {
		if err := s.touches.Flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
			// The sweep still runs. Ranking on slightly stale access times
			// costs a refill; not sweeping costs the budget.
			s.log.WarnContext(ctx, "could not flush cache accesses before sweeping", "error", err)
		}
	}

	started := s.now()
	result, err := s.evictor.Sweep(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.ErrorContext(ctx, "cache sweep failed", "error", err)
		}
		return
	}
	s.evictor.logSweep(ctx, result, s.now().Sub(started))
}

// sweepOrphans runs one orphan pass.
func (s *Scheduler) sweepOrphans(ctx context.Context) {
	result, err := s.evictor.SweepOrphans(ctx)
	switch {
	case err != nil && errors.Is(err, context.Canceled):
	case err != nil:
		s.log.ErrorContext(ctx, "cache orphan pass failed", "error", err)
	case result.Reclaimed > 0 || result.Failed > 0:
		s.log.InfoContext(ctx, "cache orphan pass reclaimed unclaimed bytes",
			"scanned", result.Scanned, "reclaimed", result.Reclaimed,
			"bytes", result.Bytes, "failed", result.Failed)
	default:
		s.log.DebugContext(ctx, "cache orphan pass found nothing", "scanned", result.Scanned)
	}
}
