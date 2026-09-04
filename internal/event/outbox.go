package event

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/steveokay/trove/internal/meta"
)

// OutboxStore is the slice of the metadata store the outbox writes through,
// declared by the consumer (§11).
//
// It is one method wide, and that method is the transaction seam rather than an
// append: the rule the outbox exists to keep is that an event row exists if and
// only if the change it announces committed, and only a transaction can say
// that. Nothing reachable from here can read a manifest, a tag, or a binding.
type OutboxStore interface {
	WithinTx(ctx context.Context, fn func(tx meta.Tx) error) error
}

// Outbox writes published events to the metadata store, where webhook delivery
// picks them up (E-002, E-003).
//
// It is a bus consumer, which is what makes it non-blocking without owning a
// queue of its own: the bus already gives every consumer a buffer, a goroutine,
// a drop count, and panic isolation, and a second queue in front of this one
// would only add a second place for events to be lost.
//
// One event, one transaction. That is more transactions than a batching writer
// would use, and it is the right trade here: pull statistics may be batched
// because a lost count is unreconstructable but also uninteresting, while a
// lost event is a webhook that never fires and a delivery guarantee that was
// never true. When an emitter has a transaction of its own -- a manifest write
// that must commit with its `artifact.pushed` -- it calls WithinTx directly and
// does not go through the bus at all; this path is for the events that have no
// transaction to join.
//
// A write the store refuses is logged and counted, not retried. A retry queue
// in front of a store that is failing grows without bound for exactly as long
// as the store stays broken, which is when memory is worth least; the bus's
// queue is the buffer, and past it the loss is visible rather than silent.
type Outbox struct {
	store        OutboxStore
	log          *slog.Logger
	persistPulls bool

	written atomic.Int64
	skipped atomic.Int64
	failed  atomic.Int64
}

// OutboxOptions configure an Outbox. Only Store is required.
type OutboxOptions struct {
	// Store receives the events. Required.
	Store OutboxStore

	// PersistPulls records artifact.pulled events as well.
	//
	// It is off by default and it is the operator's call (`events.persist_pulls`,
	// ADR 0012). A pull is the highest-volume thing a registry does, and a row
	// per pull would make the outbox the largest table in the database within a
	// day. Pulls still reach the bus either way -- metrics and pull statistics
	// are built from them -- so turning this off costs webhook subscribers the
	// type and costs nothing else.
	PersistPulls bool

	// Log receives write failures and skips. Nil falls back to the default
	// logger.
	Log *slog.Logger
}

// NewOutbox returns an outbox writing through store. It returns an error rather
// than defaulting the store: an outbox with nowhere to write would silently
// turn at-least-once delivery into none.
func NewOutbox(opts OutboxOptions) (*Outbox, error) {
	if opts.Store == nil {
		return nil, errors.New("event: an outbox needs a metadata store")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Outbox{store: opts.Store, log: log, persistPulls: opts.PersistPulls}, nil
}

// Subscription is the registration to hand to Bus.Subscribe.
//
// It takes every type. The artifact.pulled filter is applied in Handle rather
// than by subscribing to a narrower set, so the decision has one home and the
// skip is counted: an operator asking "why is there no pull in the outbox"
// gets an answer from the counter rather than from reading the wiring.
func (o *Outbox) Subscription() Subscription {
	return Subscription{Name: "outbox", Handle: o.Handle}
}

// Handle writes one event. It is the bus Handler, so it runs on the outbox's
// own goroutine and its latency is nobody's request.
func (o *Outbox) Handle(ctx context.Context, e Event) {
	if e.Type == ArtifactPulled && !o.persistPulls {
		o.skipped.Add(1)
		return
	}

	row, err := e.Record()
	if err != nil {
		// The bus refuses malformed events, so reaching this means an event
		// whose payload cannot be encoded at all -- a channel or a NaN in a
		// payload struct. It is an emitter bug and is reported as one.
		o.failed.Add(1)
		o.log.Error("dropped an event that could not be encoded",
			"event_id", e.ID, "type", e.Type, "error", err)
		return
	}

	if err := o.store.WithinTx(ctx, func(tx meta.Tx) error {
		return tx.AppendEvent(ctx, row)
	}); err != nil {
		if errors.Is(err, meta.ErrConflict) {
			// The id is the idempotency key, so a duplicate means this event
			// is already durable. Nothing was lost and nothing needs doing.
			o.skipped.Add(1)
			return
		}
		o.failed.Add(1)
		o.log.Error("dropped an event the store refused",
			"event_id", e.ID, "type", e.Type, "error", err)
		return
	}
	o.written.Add(1)
}

// OutboxStats is what the outbox knows about itself, for metrics (E-005) and
// for tests.
type OutboxStats struct {
	// Written is how many events reached the store.
	Written int64
	// Skipped is how many were deliberately not written: pulls with
	// persist_pulls off, and events already durable under the same id.
	Skipped int64
	// Failed is how many were lost -- a store that refused the write, or a
	// payload that would not encode. Any of these is worth an alert: it is a
	// webhook that will never fire.
	Failed int64
}

// Stats returns a snapshot of the outbox's counters.
func (o *Outbox) Stats() OutboxStats {
	return OutboxStats{
		Written: o.written.Load(),
		Skipped: o.skipped.Load(),
		Failed:  o.failed.Load(),
	}
}
