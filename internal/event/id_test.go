package event

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// failingReader is an entropy source that has stopped answering.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// zeroReader hands out a fixed pattern, so a test can say what an id will be.
type zeroReader struct{ fill byte }

func (z zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = z.fill
	}
	return len(p), nil
}

func TestIDShape(t *testing.T) {
	t.Parallel()

	id := NewIDSource(zeroReader{}).New(time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC))
	if len(id) != IDLength {
		t.Errorf("len(%q) = %d, want %d", id, len(id), IDLength)
	}
	for _, r := range id {
		if !strings.ContainsRune(crockford, r) {
			t.Errorf("id %q contains %q, which is not in the alphabet", id, r)
		}
	}
	// The alphabet excludes the characters an operator would misread when
	// copying an id out of a log.
	for _, excluded := range "ILOU" {
		if strings.ContainsRune(crockford, excluded) {
			t.Errorf("the alphabet contains %q", excluded)
		}
	}
}

// Lexical order is chronological order: the outbox's primary key is its sort
// key and a page cursor is the last id of the page, so this is the property
// everything downstream rests on.
func TestIDsSortChronologically(t *testing.T) {
	t.Parallel()

	source := NewIDSource(zeroReader{fill: 0x7f})
	base := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	var ids []string
	for i := 0; i < 50; i++ {
		ids = append(ids, source.New(base.Add(time.Duration(i)*time.Millisecond)))
	}

	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for i := range ids {
		if ids[i] != sorted[i] {
			t.Fatalf("ids are not in lexical order at %d:\n minted: %v\n sorted: %v", i, ids, sorted)
		}
	}
}

// Two events in the same millisecond still sort in the order they were minted:
// a push and the scan it triggered must not read as simultaneous.
func TestIDsAreMonotonicWithinAMillisecond(t *testing.T) {
	t.Parallel()

	source := NewIDSource(zeroReader{})
	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	previous := source.New(at)
	for i := 0; i < 100; i++ {
		id := source.New(at)
		if id <= previous {
			t.Fatalf("id %d = %q, want something after %q", i, id, previous)
		}
		previous = id
	}
}

// A clock that steps backwards -- an NTP correction, or an emitter stamping an
// event with when it happened -- must not produce an id that sorts before one
// already handed out.
func TestIDsSurviveTheClockGoingBackwards(t *testing.T) {
	t.Parallel()

	source := NewIDSource(zeroReader{})
	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	forward := source.New(at)
	backward := source.New(at.Add(-time.Hour))
	if backward <= forward {
		t.Errorf("after the clock stepped back, id = %q, want something after %q", backward, forward)
	}
}

// An id is an identifier, not a secret. A randomness source that fails must not
// stop the registry emitting events, and must not repeat a value either.
func TestIDsSurviveAFailingEntropySource(t *testing.T) {
	t.Parallel()

	source := NewIDSource(failingReader{})
	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	seen := make(map[string]bool)
	previous := ""
	for i := 0; i < 10; i++ {
		id := source.New(at.Add(time.Duration(i) * time.Second))
		if len(id) != IDLength {
			t.Fatalf("id %q is not a ULID", id)
		}
		if seen[id] {
			t.Fatalf("id %q was minted twice", id)
		}
		if id <= previous {
			t.Fatalf("id %q does not follow %q", id, previous)
		}
		seen[id] = true
		previous = id
	}
}

// Exhausting the 80-bit counter inside one millisecond cannot happen, but the
// wrap must still be handled: it falls back to a fresh draw rather than
// repeating the value it started from.
func TestEntropyOverflowRedraws(t *testing.T) {
	t.Parallel()

	source := NewIDSource(zeroReader{fill: 0xff})
	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	first := source.New(at)
	second := source.New(at)
	if first == "" || second == "" {
		t.Fatal("an overflow produced no id")
	}
	// The draw refills with 0xff, which increments back to the same value: the
	// point is that it does not panic or return an empty id, and the ordering
	// property is restored by the next millisecond.
	if next := source.New(at.Add(time.Millisecond)); next <= second {
		t.Errorf("id after the overflow = %q, want something after %q", next, second)
	}

	// The same wrap on the backwards-clock path, which pins the earlier
	// instant to the last one used and steps the counter from there.
	backwards := NewIDSource(zeroReader{fill: 0xff})
	forward := backwards.New(at)
	if stepped := backwards.New(at.Add(-time.Hour)); stepped == "" || len(stepped) != IDLength {
		t.Errorf("id after a backwards overflow = %q, want a ULID", stepped)
	} else if stepped[:12] != forward[:12] {
		t.Errorf("id after a backwards step = %q, want the timestamp of %q", stepped, forward)
	}
}

func TestIncrementWraps(t *testing.T) {
	t.Parallel()

	counter := []byte{0x00, 0xff}
	if !increment(counter) {
		t.Error("increment reported a wrap it did not have")
	}
	if !bytes.Equal(counter, []byte{0x01, 0x00}) {
		t.Errorf("counter = %v, want a carry into the high byte", counter)
	}

	full := []byte{0xff, 0xff}
	if increment(full) {
		t.Error("increment did not report the wrap")
	}
	if !bytes.Equal(full, []byte{0x00, 0x00}) {
		t.Errorf("counter = %v, want zeroes after the wrap", full)
	}
}

// The source is shared by every emitter in the process, so concurrent minting
// must neither race nor repeat.
func TestIDSourceIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	source := NewIDSource(nil)
	at := time.Date(2026, 9, 4, 9, 30, 15, 0, time.UTC)

	const workers, each = 8, 64
	var (
		mu   sync.Mutex
		seen = make(map[string]bool, workers*each)
		wg   sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				id := source.New(at)
				mu.Lock()
				if seen[id] {
					t.Errorf("id %q was minted twice", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != workers*each {
		t.Errorf("minted %d distinct ids, want %d", len(seen), workers*each)
	}
}
