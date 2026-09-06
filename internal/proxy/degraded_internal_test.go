package proxy

import (
	"errors"
	"net"
	"testing"
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
