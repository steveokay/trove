package proxy

import (
	"net/http"
	"testing"
	"time"
)

// clockTime is the fixed instant the Retry-After date arithmetic is measured
// against: the whole reason the clock is injected.
var clockTime = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func TestParseRateLimitHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		value  string
		ok     bool
		count  int64
		window time.Duration
	}{
		{name: "docker hub", value: "100;w=21600", ok: true, count: 100, window: 6 * time.Hour},
		{name: "a bare count", value: "42", ok: true, count: 42},
		{name: "exhausted", value: "0;w=21600", ok: true, count: 0, window: 6 * time.Hour},
		{name: "a list of policies takes the first", value: "10;w=60,1000;w=86400", ok: true, count: 10, window: time.Minute},
		{name: "whitespace", value: "  7 ; w = 30 ", ok: true, count: 7, window: 30 * time.Second},
		{name: "an unknown parameter", value: "7;burst=2;w=30", ok: true, count: 7, window: 30 * time.Second},
		{name: "empty", value: "", ok: false},
		{name: "not a number", value: "lots;w=60", ok: false},
		{name: "a window that is not a number", value: "7;w=soon", ok: true, count: 7},
		{name: "a zero window is no window", value: "7;w=0", ok: true, count: 7},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			count, ok, window := parseRateLimitHeader(tc.value)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (count != tc.count || window != tc.window) {
				t.Errorf("= (%d, %s), want (%d, %s)", count, window, tc.count, tc.window)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value string
		ok    bool
		delay time.Duration
	}{
		{name: "seconds", value: "120", ok: true, delay: 2 * time.Minute},
		{name: "zero", value: "0", ok: true},
		{name: "a negative count is now", value: "-5", ok: true},
		{name: "an http date in the future", value: clockTime.Add(90 * time.Second).Format(http.TimeFormat), ok: true, delay: 90 * time.Second},
		{name: "an http date in the past is now", value: clockTime.Add(-time.Hour).Format(http.TimeFormat), ok: true},
		{name: "empty", value: "", ok: false},
		{name: "nonsense", value: "soon please", ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			delay, ok := parseRetryAfter(tc.value, clockTime)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && delay != tc.delay {
				t.Errorf("delay = %s, want %s", delay, tc.delay)
			}
		})
	}
}

// TestObserveRateLimitIgnoresAResponseWithNothingToSay keeps the gauge honest:
// a response with no rate-limit headers must not overwrite what a previous one
// reported, or the headroom would flicker to zero on every other request.
func TestObserveRateLimitIgnoresAResponseWithNothingToSay(t *testing.T) {
	t.Parallel()

	client, err := New(Options{Upstream: "https://registry.example.com", Now: func() time.Time { return clockTime }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client.observeRateLimit(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Ratelimit-Limit": {"100;w=21600"}, "Ratelimit-Remaining": {"7;w=21600"}},
	})
	client.observeRateLimit(&http.Response{StatusCode: http.StatusOK, Header: http.Header{}})

	state := client.RateLimit()
	if !state.Known || state.Limit != 100 || state.Remaining != 7 {
		t.Errorf("RateLimit() = %+v, want the earlier observation intact", state)
	}
	if state.Until.IsZero() != true {
		t.Errorf("Until = %s, want zero: no 429 has been seen", state.Until)
	}
}
