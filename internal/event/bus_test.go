package event

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// quiet is the logger a test uses when it does not care what was logged. The
// bus logs drops and panics at warn and error, and a suite that printed them
// would look like it was failing.
func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// recorder captures log lines so a test can assert that an operator was told
// about something, not merely that a counter moved.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, record slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	line := record.Message
	record.Attrs(func(a slog.Attr) bool {
		line += " " + a.Key + "=" + a.Value.String()
		return true
	})
	r.lines = append(r.lines, line)
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

func (r *recorder) contains(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, line := range r.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// testBus returns a bus with a fixed clock and deterministic ids, closed by the
// test. Nothing here depends on wall-clock time (§9).
func testBus(t *testing.T, log *slog.Logger) *Bus {
	t.Helper()

	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)
	bus := New(Options{
		Now: func() time.Time { return at },
		IDs: NewIDSource(zeroReader{fill: 0x11}),
		Log: log,
	})
	t.Cleanup(func() {
		if err := bus.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return bus
}

// collector is a consumer that records what it received.
type collector struct {
	mu     sync.Mutex
	events []Event
	got    chan struct{}
}

func newCollector(capacity int) *collector {
	return &collector{got: make(chan struct{}, capacity)}
}

func (c *collector) handle(_ context.Context, e Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
	c.got <- struct{}{}
}

// await blocks until n events have arrived, failing rather than hanging if they
// do not. It is a signal, not a sleep: the suite has no timing assumptions.
func (c *collector) await(t *testing.T, n int) {
	t.Helper()

	for i := 0; i < n; i++ {
		select {
		case <-c.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("waited for %d events, got %d", n, i)
		}
	}
}

func (c *collector) seen() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]Event(nil), c.events...)
}

func pushed(repo string) Event {
	return Event{
		Type:       ArtifactPushed,
		Repository: repo,
		Resource:   "sha256:aa",
		Actor:      "alice",
		Payload:    ArtifactPushedPayload{Repository: repo, Digest: "sha256:aa"},
	}
}

func pulled(repo string) Event {
	return Event{
		Type:       ArtifactPulled,
		Repository: repo,
		Resource:   "latest",
		Payload:    ArtifactPulledPayload{Repository: repo, Reference: "latest"},
	}
}

func mustSubscribe(t *testing.T, bus *Bus, s Subscription) func() {
	t.Helper()

	cancel, err := bus.Subscribe(s)
	if err != nil {
		t.Fatalf("Subscribe(%q): %v", s.Name, err)
	}
	return cancel
}

// Every consumer subscribed to a type receives it, and one subscribed to a
// narrower set receives only what it asked for.
func TestPublishFansOutByType(t *testing.T) {
	t.Parallel()

	bus := testBus(t, quiet())
	all := newCollector(8)
	pushesOnly := newCollector(8)

	mustSubscribe(t, bus, Subscription{Name: "all", Handle: all.handle})
	mustSubscribe(t, bus, Subscription{
		Name: "pushes", Types: []Type{ArtifactPushed}, Handle: pushesOnly.handle,
	})

	bus.Publish(context.Background(), pushed("team-a/api"))
	bus.Publish(context.Background(), pulled("team-a/api"))

	all.await(t, 2)
	pushesOnly.await(t, 1)

	if got := all.seen(); len(got) != 2 {
		t.Errorf("the unfiltered consumer saw %d events, want 2", len(got))
	}
	got := pushesOnly.seen()
	if len(got) != 1 || got[0].Type != ArtifactPushed {
		t.Errorf("the filtered consumer saw %+v, want one artifact.pushed", got)
	}
	if stats := bus.Stats(); stats.Published != 2 || stats.Dropped != 0 {
		t.Errorf("stats = %+v, want two published and nothing dropped", stats)
	}
}

// The bus stamps the id and the timestamp, so ordering is a property of the bus
// rather than of whoever emitted. Both are injected, so a test gets the same
// values every run.
func TestPublishStampsIDAndTime(t *testing.T) {
	t.Parallel()

	bus := testBus(t, quiet())
	seen := newCollector(4)
	mustSubscribe(t, bus, Subscription{Name: "seen", Handle: seen.handle})

	bus.Publish(context.Background(), pushed("team-a/api"))
	bus.Publish(context.Background(), pushed("team-a/api"))
	seen.await(t, 2)

	got := seen.seen()
	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)
	for i, e := range got {
		if len(e.ID) != IDLength {
			t.Errorf("event %d id = %q, want a ULID", i, e.ID)
		}
		if !e.At.Equal(at) {
			t.Errorf("event %d at = %s, want the injected clock's %s", i, e.At, at)
		}
	}
	if got[0].ID >= got[1].ID {
		t.Errorf("ids %q and %q are not increasing within one tick", got[0].ID, got[1].ID)
	}

	// An emitter that already knows the id and the time -- a replay, a
	// migration import -- keeps them.
	fixed := pushed("team-a/api")
	fixed.ID = "01K4EXAMPLE0FIXEDID00000AA"
	fixed.At = at.Add(-time.Hour)
	bus.Publish(context.Background(), fixed)
	seen.await(t, 1)

	last := seen.seen()[2]
	if last.ID != fixed.ID || !last.At.Equal(fixed.At) {
		t.Errorf("the bus overwrote a caller's id or time: %+v", last)
	}
}

// A consumer that is not keeping up loses events; it does not slow the
// publisher down. Push latency is a hard SLO and an observer is never worth it.
func TestASlowConsumerIsDroppedNotWaitedFor(t *testing.T) {
	t.Parallel()

	log := &recorder{}
	bus := testBus(t, slog.New(log))

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	slow := newCollector(32)
	mustSubscribe(t, bus, Subscription{
		Name:       "slow",
		QueueDepth: 1,
		Handle: func(ctx context.Context, e Event) {
			once.Do(func() {
				close(started)
				<-release
			})
			slow.handle(ctx, e)
		},
	})

	fast := newCollector(32)
	mustSubscribe(t, bus, Subscription{Name: "fast", Handle: fast.handle})

	// The first event is picked up and blocks in the handler; the second fills
	// the depth-1 queue; everything after it has nowhere to go.
	bus.Publish(context.Background(), pushed("team-a/api"))
	<-started
	for i := 0; i < 10; i++ {
		bus.Publish(context.Background(), pushed("team-a/api"))
	}

	// The publisher was never blocked, so the consumer that is keeping up has
	// everything already.
	fast.await(t, 11)

	close(release)
	slow.await(t, 2)

	stats := bus.Stats()
	if stats.Dropped == 0 {
		t.Fatalf("stats = %+v, want drops from the slow consumer", stats)
	}
	if stats.Published != 11 {
		t.Errorf("stats = %+v, want 11 published: a drop is not a refusal", stats)
	}
	if len(fast.seen()) != 11 {
		t.Errorf("the consumer that kept up saw %d events, want 11", len(fast.seen()))
	}

	// An operator is told, with the number and the bound that produced it. The
	// line is written by the consumer's goroutine as it takes the next event,
	// so awaiting that event above is what makes this deterministic.
	if !log.contains("dropped events") || !log.contains("queue_depth=1") {
		t.Errorf("the drop was not reported to the operator: %v", log.lines)
	}
}

// A consumer that panics is one consumer with a bug. It must not take the
// registry down, must not silence the other consumers, and must keep receiving
// events itself: the alternative turns any subscriber into a denial of service
// against the thing it is watching.
func TestAPanickingConsumerIsIsolated(t *testing.T) {
	t.Parallel()

	log := &recorder{}
	bus := testBus(t, slog.New(log))

	after := newCollector(8)
	var panics int
	mustSubscribe(t, bus, Subscription{
		Name: "buggy",
		Handle: func(ctx context.Context, e Event) {
			if e.Repository == "boom" {
				panics++
				panic("the consumer dereferenced something")
			}
			after.handle(ctx, e)
		},
	})

	bystander := newCollector(8)
	mustSubscribe(t, bus, Subscription{Name: "bystander", Handle: bystander.handle})

	bus.Publish(context.Background(), pushed("boom"))
	bus.Publish(context.Background(), pushed("team-a/api"))

	// The panicking subscription carried on to the next event.
	after.await(t, 1)
	// And the other consumer saw both, so the panic did not reach it.
	bystander.await(t, 2)

	if stats := bus.Stats(); stats.Panicked != 1 {
		t.Errorf("stats = %+v, want one isolated panic", stats)
	}
	if !log.contains("a consumer panicked and was isolated") {
		t.Errorf("the panic was not reported: %v", log.lines)
	}

	// The bus is still usable, which is the point of isolating rather than
	// tearing the subscription down.
	bus.Publish(context.Background(), pushed("team-a/web"))
	after.await(t, 1)
	if got := len(after.seen()); got != 2 {
		t.Errorf("the recovered consumer saw %d events after its panic, want 2", got)
	}
}

// A handler outlives the request that triggered it, so the request returning
// must not cancel an outbox insert -- while the request's values still travel
// with the event, which is what keeps a log line attributable.
func TestHandlersKeepTheCallersValuesAndLoseItsCancellation(t *testing.T) {
	t.Parallel()

	type key struct{}

	bus := testBus(t, quiet())
	seen := make(chan context.Context, 1)
	mustSubscribe(t, bus, Subscription{
		Name:   "context",
		Handle: func(ctx context.Context, _ Event) { seen <- ctx },
	})

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "request-42"))
	bus.Publish(ctx, pushed("team-a/api"))
	cancel()

	select {
	case handlerCtx := <-seen:
		if got, _ := handlerCtx.Value(key{}).(string); got != "request-42" {
			t.Errorf("handler context value = %q, want the caller's", got)
		}
		if err := handlerCtx.Err(); err != nil {
			t.Errorf("handler context = %v, want the cancellation detached", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}
}

// A malformed event is an emitter bug, not an operational condition. It is
// refused before fan-out so a body nobody can parse never reaches a subscriber.
func TestPublishRefusesMalformedEvents(t *testing.T) {
	t.Parallel()

	log := &recorder{}
	bus := testBus(t, slog.New(log))
	seen := newCollector(4)
	mustSubscribe(t, bus, Subscription{Name: "seen", Handle: seen.handle})

	bus.Publish(context.Background(), Event{Type: "artifact.exploded"})
	bus.Publish(context.Background(), Event{Type: ArtifactPushed})
	bus.Publish(context.Background(), Event{
		Type: ArtifactPushed, Payload: ArtifactPulledPayload{},
	})

	// A well-formed event afterwards proves the bus is still working, and
	// gives the consumer something to have received instead.
	bus.Publish(context.Background(), pushed("team-a/api"))
	seen.await(t, 1)

	if got := seen.seen(); len(got) != 1 || got[0].Type != ArtifactPushed {
		t.Errorf("consumer saw %+v, want only the valid event", got)
	}
	if stats := bus.Stats(); stats.Refused != 3 || stats.Published != 1 {
		t.Errorf("stats = %+v, want three refused and one published", stats)
	}
	if !log.contains("refused to publish a malformed event") {
		t.Errorf("the refusal was not reported: %v", log.lines)
	}
}

// Close delivers what has already been accepted: the queue is a buffer, not a
// place events go to be forgotten. An orderly shutdown loses nothing.
func TestCloseDrainsWhatWasAccepted(t *testing.T) {
	t.Parallel()

	bus := New(Options{
		Now: func() time.Time { return time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC) },
		IDs: NewIDSource(zeroReader{}),
		Log: quiet(),
	})

	seen := newCollector(64)
	block := make(chan struct{})
	var once sync.Once
	mustSubscribe(t, bus, Subscription{
		Name: "slow",
		Handle: func(ctx context.Context, e Event) {
			once.Do(func() { <-block })
			seen.handle(ctx, e)
		},
	})

	for i := 0; i < 20; i++ {
		bus.Publish(context.Background(), pushed("team-a/api"))
	}
	close(block)

	if err := bus.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(seen.seen()); got != 20 {
		t.Errorf("Close delivered %d of 20 accepted events", got)
	}

	// Closing twice is safe, and publishing afterwards is a no-op rather than
	// a panic: shutdown races with in-flight requests by construction.
	if err := bus.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}
	bus.Publish(context.Background(), pushed("team-a/api"))
	if stats := bus.Stats(); stats.Published != 20 || stats.Refused != 1 {
		t.Errorf("stats = %+v, want the post-close publish refused", stats)
	}
}

// Shutdown must not hang on a consumer that has stopped making progress. The
// caller's deadline is what bounds the wait.
func TestCloseGivesUpOnAStuckConsumer(t *testing.T) {
	t.Parallel()

	bus := New(Options{Log: quiet()})
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })

	mustSubscribe(t, bus, Subscription{
		Name:   "stuck",
		Handle: func(context.Context, Event) { <-stuck },
	})
	bus.Publish(context.Background(), pushed("team-a/api"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bus.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Close = %v, want the caller's context error", err)
	}
}

// Unsubscribing stops delivery to that consumer and leaves the others alone.
// It waits for what the consumer already had, and is safe to call twice.
func TestUnsubscribe(t *testing.T) {
	t.Parallel()

	bus := testBus(t, quiet())
	leaving := newCollector(8)
	staying := newCollector(8)

	cancel := mustSubscribe(t, bus, Subscription{Name: "leaving", Handle: leaving.handle})
	mustSubscribe(t, bus, Subscription{Name: "staying", Handle: staying.handle})

	bus.Publish(context.Background(), pushed("team-a/api"))
	leaving.await(t, 1)
	staying.await(t, 1)

	cancel()
	cancel()

	bus.Publish(context.Background(), pushed("team-a/web"))
	staying.await(t, 1)

	if got := len(leaving.seen()); got != 1 {
		t.Errorf("the removed consumer saw %d events, want the one it had", got)
	}
	if got := len(staying.seen()); got != 2 {
		t.Errorf("the remaining consumer saw %d events, want 2", got)
	}
}

func TestSubscribeValidation(t *testing.T) {
	t.Parallel()

	bus := testBus(t, quiet())

	for _, tc := range []struct {
		name string
		sub  Subscription
	}{
		{"no name", Subscription{Handle: func(context.Context, Event) {}}},
		{"no handler", Subscription{Name: "nameless"}},
		{"a type outside the taxonomy", Subscription{
			Name: "wrong", Types: []Type{"artifact.exploded"},
			Handle: func(context.Context, Event) {},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := bus.Subscribe(tc.sub); !errors.Is(err, ErrInvalidEvent) {
				t.Errorf("Subscribe = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// Subscribing to a closed bus must fail rather than register a consumer whose
// goroutine nothing will ever stop.
func TestSubscribeAfterCloseIsRefused(t *testing.T) {
	t.Parallel()

	bus := New(Options{Log: quiet()})
	if err := bus.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := bus.Subscribe(Subscription{Name: "late", Handle: func(context.Context, Event) {}})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("Subscribe on a closed bus = %v, want ErrInvalidEvent", err)
	}
}

// The zero Options must produce a working bus: nothing in production has to
// remember to set a clock, and nothing silently gets a nil one.
func TestOptionDefaults(t *testing.T) {
	t.Parallel()

	bus := New(Options{})
	t.Cleanup(func() {
		if err := bus.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if bus.depth != DefaultQueueDepth {
		t.Errorf("queue depth = %d, want %d", bus.depth, DefaultQueueDepth)
	}

	seen := newCollector(4)
	mustSubscribe(t, bus, Subscription{Name: "seen", Handle: seen.handle})
	bus.Publish(context.Background(), pushed("team-a/api"))
	seen.await(t, 1)

	got := seen.seen()[0]
	if len(got.ID) != IDLength {
		t.Errorf("id = %q, want a ULID from the default source", got.ID)
	}
	if got.At.IsZero() {
		t.Error("the default clock stamped no time")
	}
}
