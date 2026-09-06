package proxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

// The failure classification is exercised end to end through real client errors
// in the external test; this covers the one shape that cannot arrive that way.
// Every failure the client wraps has been through net/http, so it is always a
// net.Error underneath -- but isTimeout is a predicate over an arbitrary error,
// and a predicate whose default answer is untested is a predicate one refactor
// away from answering "true" to everything.
func TestIsTimeoutRequiresEvidence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"a plain error", errors.New("something went wrong"), false},
		{"no error at all", nil, false},
		{"our own header deadline", errHeaderTimeout, true},
		{"a resolver that gave up", &net.DNSError{IsTimeout: true}, true},
		{"a resolver that answered no", &net.DNSError{IsNotFound: true}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isTimeout(tc.err); got != tc.want {
				t.Errorf("isTimeout(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// fullJitter is the default spread. It is exercised through the schedule
// elsewhere; this pins the two properties the schedule depends on -- that the
// draw stays inside the window it was given, and that a window of nothing
// cannot become a delay of something (nor panic, which is what the underlying
// random source does when asked for a value below one).
func TestFullJitterStaysInsideItsWindow(t *testing.T) {
	t.Parallel()

	for _, window := range []time.Duration{0, -time.Second} {
		if got := fullJitter(window); got != 0 {
			t.Errorf("fullJitter(%s) = %s, want 0", window, got)
		}
	}

	for range 64 {
		got := fullJitter(time.Second)
		if got < 0 || got >= time.Second {
			t.Fatalf("fullJitter(1s) = %s, want it drawn from [0s, 1s)", got)
		}
	}
}
