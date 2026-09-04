package event

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultQueueDepth is how many events may await one consumer before the bus
// starts dropping them for that consumer.
//
// It is a bound rather than a promise. A consumer is meant to be fast -- a
// metrics increment, an outbox insert -- and a queue this deep absorbs a burst
// while one of those completes. A consumer that falls permanently behind is a
// consumer that is doing too much, and dropping is how an operator finds out:
// the count is logged and exported (E-005) rather than buried in latency.
const DefaultQueueDepth = 1024

// Handler receives one event. It runs on the subscriber's own goroutine, so it
// may take as long as it needs without delaying the publisher or any other
// consumer -- but everything queued behind it waits, and a queue that fills
// drops.
//
// A handler that panics is recovered, logged, counted, and the subscription
// carries on with the next event (ADR 0012). One consumer's bug must not take
// the registry down or silence the others.
type Handler func(ctx context.Context, e Event)

// Subscription registers one consumer with the bus.
type Subscription struct {
	// Name identifies the consumer in logs and in the drop and panic counts.
	// Required: a nameless consumer is one an operator cannot act on.
	Name string

	// Types selects what the consumer receives. Empty means every type, which
	// is what the outbox and the metrics collector want; anything narrower
	// says so explicitly.
	Types []Type

	// Handle is called once per matching event. Required.
	Handle Handler

	// QueueDepth bounds the events awaiting this consumer. Zero means
	// DefaultQueueDepth.
	QueueDepth int
}

// Bus fans events out to in-process consumers.
//
// Two properties are the whole design, and both exist because a registry must
// not be brought down by something watching it:
//
//   - Publish never blocks. It hands the event to each interested consumer's
//     queue without waiting; an event that does not fit is dropped and counted.
//     A push that waited on a metrics collector would be a push whose latency
//     is somebody else's code.
//   - A consumer is isolated. It runs on its own goroutine behind its own
//     queue, so a slow one delays only itself, and a panicking one is recovered
//     without touching the publisher or the other consumers.
//
// What the bus deliberately does *not* provide is durability. Its queues die
// with the process, which is why the outbox writes to the metadata store and
// why webhook delivery reads from there rather than from here (ADR 0012).
//
// The clock and the id source are injected, so the events a test observes are
// the ones it chose (§9).
type Bus struct {
	now   func() time.Time
	ids   *IDSource
	log   *slog.Logger
	depth int

	mu          sync.RWMutex
	subscribers []*subscriber
	closed      bool

	// The counters live on the bus, not only on the subscribers, so they
	// survive a consumer being removed and the bus being closed: a shutdown
	// that reset the drop count would hide exactly the incident an operator is
	// trying to read afterwards.
	//
	// published counts what was accepted and refused what was not. They are
	// separate because they mean different things: the first is load, the
	// second is a bug in an emitter.
	published atomic.Int64
	refused   atomic.Int64
	dropped   atomic.Int64
	panicked  atomic.Int64
}

// Options configure a Bus. Every field has a working default.
type Options struct {
	// Now supplies the time an event is stamped with. Nil means time.Now.
	Now func() time.Time

	// IDs mints event ids. Nil means a source over crypto/rand.
	IDs *IDSource

	// Log receives drop counts, consumer panics, and refused events. Nil
	// falls back to the default logger.
	Log *slog.Logger

	// QueueDepth is the default bound for a subscription that does not set
	// its own. Zero means DefaultQueueDepth.
	QueueDepth int
}

// New returns a running bus. The caller must Close it: an unclosed bus leaks a
// goroutine per subscriber and loses whatever they had queued.
func New(opts Options) *Bus {
	b := &Bus{
		now:   opts.Now,
		ids:   opts.IDs,
		log:   opts.Log,
		depth: opts.QueueDepth,
	}
	if b.now == nil {
		b.now = time.Now
	}
	if b.ids == nil {
		b.ids = NewIDSource(nil)
	}
	if b.log == nil {
		b.log = slog.Default()
	}
	if b.depth <= 0 {
		b.depth = DefaultQueueDepth
	}
	return b
}

// subscriber is one registered consumer and the goroutine that serves it.
type subscriber struct {
	bus   *Bus
	name  string
	types map[Type]bool
	// all short-circuits the type check for a consumer that wants everything,
	// which is the common case and the one on the publisher's path.
	all    bool
	handle Handler
	log    *slog.Logger

	queue chan delivery
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once

	// dropped is this consumer's running total and reported is how much of it
	// has been logged. Keeping both means the log says how many were lost
	// since the last line without the counter itself ever going backwards.
	dropped  atomic.Int64
	reported atomic.Int64
}

// delivery is one queued event together with the context it was published
// under. The context travels with the event so a handler keeps the request's
// values -- its logger, its request id -- without keeping its cancellation:
// see Publish.
type delivery struct {
	ctx   context.Context
	event Event
}

// Subscribe registers a consumer and returns the function that removes it.
//
// The returned function waits for the consumer's queue to drain, so an event
// already accepted for it is still delivered. Calling it twice is safe.
func (b *Bus) Subscribe(s Subscription) (func(), error) {
	switch {
	case s.Name == "":
		return nil, fmt.Errorf("%w: a subscription needs a name", ErrInvalidEvent)
	case s.Handle == nil:
		return nil, fmt.Errorf("%w: subscription %q has no handler", ErrInvalidEvent, s.Name)
	}
	for _, t := range s.Types {
		if !t.Valid() {
			return nil, fmt.Errorf("%w: subscription %q wants unknown type %q",
				ErrInvalidEvent, s.Name, t)
		}
	}

	depth := s.QueueDepth
	if depth <= 0 {
		depth = b.depth
	}
	sub := &subscriber{
		bus:    b,
		name:   s.Name,
		types:  make(map[Type]bool, len(s.Types)),
		all:    len(s.Types) == 0,
		handle: s.Handle,
		log:    b.log.With("consumer", s.Name),
		queue:  make(chan delivery, depth),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	for _, t := range s.Types {
		sub.types[t] = true
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: the bus is closed", ErrInvalidEvent)
	}
	b.subscribers = append(b.subscribers, sub)
	b.mu.Unlock()

	go sub.run()
	return func() { b.unsubscribe(sub) }, nil
}

// unsubscribe removes a consumer and waits for its queue to drain.
func (b *Bus) unsubscribe(sub *subscriber) {
	b.mu.Lock()
	for i, existing := range b.subscribers {
		if existing == sub {
			b.subscribers = append(b.subscribers[:i], b.subscribers[i+1:]...)
			break
		}
	}
	b.mu.Unlock()

	sub.shutdown()
	<-sub.done
}

// Publish hands an event to every interested consumer. It never blocks and it
// never fails: its caller is a request that has already succeeded, and an
// observation is never worth the thing observed.
//
// The event's id and timestamp are filled in here if the caller left them
// unset, from the injected id source and clock. An emitter therefore says what
// happened and the bus says when and in what order, which is what keeps
// ordering a property of the bus rather than of whoever called it.
//
// An event that does not validate is refused, counted, and logged at error
// level: it is an emitter bug, not an operational condition, and shipping a
// malformed body to a subscriber would turn it into somebody else's.
//
// ctx is the caller's -- a request, usually. Handlers receive it with its
// cancellation detached: a handler outlives the request that triggered it, so
// the request returning must not cancel an outbox insert, while the request's
// logger and identifiers still travel with the event.
func (b *Bus) Publish(ctx context.Context, e Event) {
	if e.At.IsZero() {
		e.At = b.now()
	}
	if e.ID == "" {
		e.ID = b.ids.New(e.At)
	}
	if err := e.Validate(); err != nil {
		b.refused.Add(1)
		b.log.Error("refused to publish a malformed event", "type", e.Type, "error", err)
		return
	}

	item := delivery{ctx: context.WithoutCancel(ctx), event: e}

	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		// A closed bus is not an error at the call site: shutdown races with
		// in-flight requests by construction, and the alternative is every
		// emitter checking first.
		b.refused.Add(1)
		return
	}
	b.published.Add(1)
	for _, sub := range b.subscribers {
		if !sub.wants(e.Type) {
			continue
		}
		select {
		case sub.queue <- item:
		default:
			// Counted rather than logged here: one line per dropped event
			// would flood exactly when the process is already struggling. The
			// consumer's goroutine reports the total once it is moving again.
			sub.dropped.Add(1)
			b.dropped.Add(1)
		}
	}
}

// wants reports whether the consumer subscribed to a type.
func (s *subscriber) wants(t Type) bool { return s.all || s.types[t] }

// run serves the consumer until it is stopped, then drains what is already
// queued. Everything accepted before shutdown is delivered: the queue is a
// buffer, not a place events go to be forgotten.
func (s *subscriber) run() {
	defer close(s.done)

	for {
		select {
		case item := <-s.queue:
			s.deliver(item)
		case <-s.stop:
			for {
				select {
				case item := <-s.queue:
					s.deliver(item)
				default:
					s.reportDrops()
					return
				}
			}
		}
	}
}

// deliver invokes the handler with the panic recovered.
//
// The recovery is the isolation ADR 0012 asks for: a consumer that panics is
// one consumer with a bug, and the alternative -- an unrecovered panic on a
// goroutine -- takes the whole registry down with it, which turns any
// subscriber into a denial of service against the thing it was watching.
func (s *subscriber) deliver(item delivery) {
	defer func() {
		if r := recover(); r != nil {
			s.bus.panicked.Add(1)
			s.log.Error("a consumer panicked and was isolated",
				"event_id", item.event.ID, "type", item.event.Type, "panic", r)
		}
	}()

	s.reportDrops()
	s.handle(item.ctx, item.event)
}

// reportDrops logs whatever has been dropped since it last said so. It runs on
// the consumer's goroutine, so the line appears once the consumer is moving
// again rather than once per drop while it is not.
func (s *subscriber) reportDrops() {
	total := s.dropped.Load()
	if unreported := total - s.reported.Swap(total); unreported > 0 {
		// The depth is a configured bound, so this is an operator's number: it
		// says the queue is too small for the event rate, or the consumer too
		// slow for it, and by how much.
		s.log.Warn("dropped events: the consumer's queue was full",
			"count", unreported, "queue_depth", cap(s.queue))
	}
}

// shutdown signals the goroutine to drain and exit. It is idempotent.
func (s *subscriber) shutdown() { s.once.Do(func() { close(s.stop) }) }

// Close stops the bus and waits for every consumer to finish what it has
// already been handed. Publish is a no-op afterwards.
//
// A ctx that expires first abandons the wait and returns its error: shutdown
// does not hang on a consumer that has stopped making progress. The consumers
// are still asked to stop, so the process is not left with a live bus.
func (b *Bus) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	subscribers := b.subscribers
	b.subscribers = nil
	b.mu.Unlock()

	for _, sub := range subscribers {
		sub.shutdown()
	}
	for _, sub := range subscribers {
		select {
		case <-sub.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Stats is what the bus knows about itself, for metrics (E-005) and for tests.
type Stats struct {
	// Published is how many events were accepted for fan-out.
	Published int64
	// Refused is how many were rejected before fan-out: malformed, or
	// published after Close.
	Refused int64
	// Dropped is how many deliveries were discarded because a consumer's
	// queue was full. One event dropped by two consumers counts twice.
	Dropped int64
	// Panicked is how many handler invocations panicked and were isolated.
	Panicked int64
}

// Stats returns a snapshot of the bus's counters.
func (b *Bus) Stats() Stats {
	return Stats{
		Published: b.published.Load(),
		Refused:   b.refused.Load(),
		Dropped:   b.dropped.Load(),
		Panicked:  b.panicked.Load(),
	}
}
