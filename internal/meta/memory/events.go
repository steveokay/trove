package memory

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/steveokay/trove/internal/meta"
)

// validEvent rejects an event the outbox could not be read back from. The ID
// and the type are what a receiver deduplicates and routes on, and an event
// with no timestamp cannot be ordered against anything, so all three are
// required rather than defaulted.
func validEvent(e meta.Event) error {
	switch {
	case e.ID == "":
		return meta.Invalid("id", "must not be empty")
	case e.Type == "":
		return meta.Invalid("type", "must not be empty")
	case e.At.IsZero():
		return meta.Invalid("at", "must not be zero")
	default:
		return nil
	}
}

// cloneEvent copies the payload out, so a caller that keeps the slice it handed
// in cannot rewrite a stored event afterwards. The database stores never share
// memory with their callers and the reference implementation must not either,
// or the contract suite would pass here for a reason no real store has.
func cloneEvent(e meta.Event) meta.Event {
	if e.Payload != nil {
		e.Payload = json.RawMessage(append([]byte(nil), e.Payload...))
	}
	return e
}

// tx is the transaction-scoped write surface WithinTx hands out.
//
// It buffers rather than writing through. The store holds one global lock and
// does not model isolation, so the only way to give WithinTx the all-or-nothing
// guarantee its contract promises is to apply nothing until the caller's
// function has returned successfully. Buffering also keeps the lock out of the
// caller's function: a Tx that held the write lock would deadlock the moment
// somebody read the store from inside a transaction.
type tx struct {
	pending []meta.Event
	done    bool
}

// AppendEvent queues one event, to be applied when the transaction commits.
//
// Only the batch is checked for a duplicate id here. The store is checked at
// commit, under the lock, which is the only moment the answer can still be
// true: a check against the store now would be a check somebody else could
// invalidate before the write.
func (t *tx) AppendEvent(_ context.Context, event meta.Event) error {
	if t.done {
		return meta.Invalid("tx", "the transaction has already finished")
	}
	if err := validEvent(event); err != nil {
		return err
	}

	for _, queued := range t.pending {
		if queued.ID == event.ID {
			return meta.Conflict("event", event.ID)
		}
	}
	t.pending = append(t.pending, cloneEvent(event))
	return nil
}

// WithinTx runs fn and applies its writes only if it returns nil.
//
// The store's lock is taken only to apply the batch, never while fn runs: a
// transaction that held it would deadlock the moment somebody read the store
// from inside one.
func (s *Store) WithinTx(ctx context.Context, fn func(meta.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	open := s.checkOpen()
	s.mu.RUnlock()
	if open != nil {
		return open
	}

	pending := &tx{}
	err := fn(pending)
	// Marked finished either way: a Tx retained past this point must not be
	// able to add to a batch that has already been decided.
	pending.done = true
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, event := range pending.pending {
		if _, taken := s.events[event.ID]; taken {
			// Nothing has been applied yet, so returning here leaves the
			// store exactly as the transaction found it.
			return meta.Conflict("event", event.ID)
		}
	}
	for _, event := range pending.pending {
		s.events[event.ID] = event
	}
	return nil
}

// ListEvents returns a permission-filtered page of events, oldest first.
func (s *Store) ListEvents(ctx context.Context, opts meta.ListOptions) (meta.EventPage, error) {
	if err := ctx.Err(); err != nil {
		return meta.EventPage{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.EventPage{}, err
	}

	ids := make([]string, 0, len(s.events))
	for id, event := range s.events {
		// Filtering happens here, while building the result set -- never
		// after (ADR 0003). A system event has no repository to check, so a
		// restricted view does not see it at all.
		if !visibleEvent(opts.Visibility, event) || id <= opts.Cursor {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)

	limit := opts.EffectiveLimit()
	page := meta.EventPage{}
	for i, id := range ids {
		if i == limit {
			page.NextCursor = ids[i-1]
			break
		}
		page.Events = append(page.Events, cloneEvent(s.events[id]))
	}
	return page, nil
}

// visibleEvent applies the ADR 0003 rule the SQL engines apply in their WHERE
// clause, so all three stores answer the same question.
func visibleEvent(v meta.Visibility, event meta.Event) bool {
	if event.Repository == "" {
		return v.IsUnrestricted()
	}
	return v.Allows(event.Repository)
}
