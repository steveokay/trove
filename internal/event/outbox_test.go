package event

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
)

// failingStore is a metadata store whose transactions do not commit.
type failingStore struct{ err error }

func (f failingStore) WithinTx(context.Context, func(meta.Tx) error) error { return f.err }

// abortingStore runs the caller's function and then fails the transaction,
// which is what a commit failure looks like from the outbox's side.
type abortingStore struct {
	inner OutboxStore
	err   error
}

func (a abortingStore) WithinTx(ctx context.Context, fn func(meta.Tx) error) error {
	if err := a.inner.WithinTx(ctx, func(tx meta.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return a.err
	}); err != nil {
		return err
	}
	return nil
}

func newMemoryStore(t *testing.T) *memory.Store {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

func mustOutbox(t *testing.T, opts OutboxOptions) *Outbox {
	t.Helper()

	if opts.Log == nil {
		opts.Log = quiet()
	}
	outbox, err := NewOutbox(opts)
	if err != nil {
		t.Fatalf("NewOutbox: %v", err)
	}
	return outbox
}

func storedEvents(t *testing.T, store meta.Store) []meta.Event {
	t.Helper()

	page, err := store.ListEvents(context.Background(), meta.ListOptions{
		Visibility: meta.Unrestricted(),
	})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	return page.Events
}

// An outbox with nowhere to write would turn at-least-once delivery into none,
// silently, so it refuses to be built.
func TestNewOutboxNeedsAStore(t *testing.T) {
	t.Parallel()

	if _, err := NewOutbox(OutboxOptions{}); err == nil {
		t.Error("NewOutbox with no store returned no error")
	}

	// Everything else has a working default: nothing in production has to
	// remember to pass a logger, and nothing silently gets a nil one.
	outbox, err := NewOutbox(OutboxOptions{Store: newMemoryStore(t)})
	if err != nil {
		t.Fatalf("NewOutbox: %v", err)
	}
	if outbox.log == nil {
		t.Error("the outbox has no logger")
	}
}

// The event reaches the store whole: the row carries the envelope's columns and
// the payload byte for byte, which is what delivery re-sends.
func TestOutboxWritesThroughTheBus(t *testing.T) {
	t.Parallel()

	store := newMemoryStore(t)
	outbox := mustOutbox(t, OutboxOptions{Store: store})

	bus := testBus(t, quiet())
	done := newCollector(8)
	mustSubscribe(t, bus, Subscription{
		Name: "outbox",
		Handle: func(ctx context.Context, e Event) {
			outbox.Handle(ctx, e)
			done.handle(ctx, e)
		},
	})

	bus.Publish(context.Background(), pushed("team-a/api"))
	done.await(t, 1)

	rows := storedEvents(t, store)
	if len(rows) != 1 {
		t.Fatalf("stored %d events, want 1", len(rows))
	}
	row := rows[0]
	switch {
	case row.Type != string(ArtifactPushed):
		t.Errorf("type = %q, want %q", row.Type, ArtifactPushed)
	case row.Repository != "team-a/api":
		t.Errorf("repository = %q, want team-a/api", row.Repository)
	case row.Actor != "alice":
		t.Errorf("actor = %q, want alice", row.Actor)
	case len(row.ID) != IDLength:
		t.Errorf("id = %q, want the bus's ULID", row.ID)
	}

	// And the row decodes back into the event that was published.
	restored, err := FromRecord(row)
	if err != nil {
		t.Fatalf("FromRecord: %v", err)
	}
	if restored.Payload.EventType() != ArtifactPushed {
		t.Errorf("payload = %T, want an ArtifactPushedPayload", restored.Payload)
	}
	if stats := outbox.Stats(); stats.Written != 1 || stats.Failed != 0 {
		t.Errorf("stats = %+v, want one written", stats)
	}
}

// Subscription is what the wiring registers, and it takes every type: the pull
// filter lives in Handle so the decision has one home and the skip is counted.
func TestOutboxSubscriptionTakesEveryType(t *testing.T) {
	t.Parallel()

	sub := mustOutbox(t, OutboxOptions{Store: newMemoryStore(t)}).Subscription()
	if sub.Name == "" || sub.Handle == nil {
		t.Fatalf("subscription = %+v, want a named handler", sub)
	}
	if len(sub.Types) != 0 {
		t.Errorf("types = %v, want every type", sub.Types)
	}
}

// A pull is the highest-volume thing a registry does. It reaches the bus either
// way -- metrics and pull statistics are built from it -- but it is not written
// to the outbox unless the operator says so (events.persist_pulls, ADR 0012).
func TestPullsArePersistedOnlyWhenTheOperatorAsks(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		persist bool
		want    int
	}{
		{"off by default", false, 1},
		{"on when configured", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newMemoryStore(t)
			outbox := mustOutbox(t, OutboxOptions{Store: store, PersistPulls: tc.persist})

			at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)
			ids := NewIDSource(zeroReader{})
			for _, e := range []Event{pushed("team-a/api"), pulled("team-a/api")} {
				e.At = at
				e.ID = ids.New(at)
				outbox.Handle(context.Background(), e)
			}

			rows := storedEvents(t, store)
			if len(rows) != tc.want {
				t.Fatalf("stored %d events, want %d: %+v", len(rows), tc.want, rows)
			}
			if !tc.persist {
				if rows[0].Type != string(ArtifactPushed) {
					t.Errorf("stored %q, want only the push", rows[0].Type)
				}
				if stats := outbox.Stats(); stats.Skipped != 1 {
					t.Errorf("stats = %+v, want the pull counted as skipped", stats)
				}
			}
		})
	}
}

// The id is the idempotency key, so a repeat means the event is already
// durable. Nothing was lost, so nothing is reported as lost.
func TestOutboxTreatsADuplicateAsAlreadyDurable(t *testing.T) {
	t.Parallel()

	store := newMemoryStore(t)
	outbox := mustOutbox(t, OutboxOptions{Store: store})

	e := pushed("team-a/api")
	e.ID = "01K4EXAMPLE0DUPLICATE000AA"
	e.At = time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	outbox.Handle(context.Background(), e)
	outbox.Handle(context.Background(), e)

	if rows := storedEvents(t, store); len(rows) != 1 {
		t.Errorf("stored %d events, want the duplicate collapsed", len(rows))
	}
	stats := outbox.Stats()
	if stats.Written != 1 || stats.Skipped != 1 || stats.Failed != 0 {
		t.Errorf("stats = %+v, want one written and one skipped", stats)
	}
}

// A store that refuses the write loses the event. That is the honest outcome --
// a retry queue in front of a broken store grows without bound for as long as
// it stays broken -- so it is counted and logged rather than hidden.
func TestOutboxReportsAStoreThatRefusesTheWrite(t *testing.T) {
	t.Parallel()

	log := &recorder{}
	outbox := mustOutbox(t, OutboxOptions{
		Store: failingStore{err: errors.New("the database is gone")},
		Log:   slog.New(log),
	})

	e := pushed("team-a/api")
	e.ID = "01K4EXAMPLE0LOST00000000AA"
	e.At = time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)
	outbox.Handle(context.Background(), e)

	if stats := outbox.Stats(); stats.Failed != 1 || stats.Written != 0 {
		t.Errorf("stats = %+v, want one failure", stats)
	}
	if !log.contains("dropped an event the store refused") {
		t.Errorf("the loss was not reported: %v", log.lines)
	}
}

// The rule ADR 0012 exists for: the row is written inside a transaction, so a
// transaction that does not commit leaves no event. An outbox that wrote
// outside one would announce changes that never happened.
func TestOutboxWritesInsideTheTransaction(t *testing.T) {
	t.Parallel()

	store := newMemoryStore(t)
	outbox := mustOutbox(t, OutboxOptions{
		Store: abortingStore{inner: store, err: errors.New("the change failed")},
	})

	e := pushed("team-a/api")
	e.ID = "01K4EXAMPLE0ROLLEDBACK00AA"
	e.At = time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)
	outbox.Handle(context.Background(), e)

	if rows := storedEvents(t, store); len(rows) != 0 {
		t.Errorf("stored %+v, want nothing from a transaction that failed", rows)
	}
	if stats := outbox.Stats(); stats.Failed != 1 {
		t.Errorf("stats = %+v, want the rollback counted as a failure", stats)
	}
}

// The bus refuses malformed events, so what reaches the outbox broken is a
// valid type carrying a body json cannot render. It is an emitter bug and is
// reported as one rather than written half way.
func TestOutboxReportsAPayloadThatWillNotEncode(t *testing.T) {
	t.Parallel()

	log := &recorder{}
	store := newMemoryStore(t)
	outbox := mustOutbox(t, OutboxOptions{Store: store, Log: slog.New(log)})

	outbox.Handle(context.Background(), Event{
		ID:      "01K4EXAMPLE0UNENCODABLE0AA",
		Type:    ArtifactPushed,
		At:      time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC),
		Payload: unencodablePayload{},
	})

	if rows := storedEvents(t, store); len(rows) != 0 {
		t.Errorf("stored %+v, want nothing", rows)
	}
	if stats := outbox.Stats(); stats.Failed != 1 {
		t.Errorf("stats = %+v, want one failure", stats)
	}
	if !log.contains("dropped an event that could not be encoded") {
		t.Errorf("the encoding failure was not reported: %v", log.lines)
	}
}

// The end-to-end shape the wiring produces: publish an event, and it is in the
// store, permission-filtered like every other listing.
func TestOutboxAndBusTogether(t *testing.T) {
	t.Parallel()

	store := newMemoryStore(t)
	outbox := mustOutbox(t, OutboxOptions{Store: store})
	bus := testBus(t, quiet())

	written := newCollector(16)
	sub := outbox.Subscription()
	handle := sub.Handle
	sub.Handle = func(ctx context.Context, e Event) {
		handle(ctx, e)
		written.handle(ctx, e)
	}
	mustSubscribe(t, bus, sub)

	bus.Publish(context.Background(), pushed("team-a/api"))
	bus.Publish(context.Background(), pushed("team-b/api"))
	written.await(t, 2)

	page, err := store.ListEvents(context.Background(), meta.ListOptions{
		Visibility: meta.VisibleTo(meta.ScopeFilter{Prefix: "team-a/"}),
	})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].Repository != "team-a/api" {
		t.Errorf("a scoped read saw %+v, want only team-a/api", page.Events)
	}

	// The payload survived the round trip through storage untouched.
	var body ArtifactPushedPayload
	if err := json.Unmarshal(page.Events[0].Payload, &body); err != nil {
		t.Fatalf("decode the stored payload: %v", err)
	}
	if body.Repository != "team-a/api" {
		t.Errorf("payload = %+v, want the repository it was published for", body)
	}
}
