package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Rate-limit awareness is a reporting job here, not a control job. The client
// records what the upstream said and hands it to whoever asks; C-009 owns the
// backoff, the jitter, and the metrics, because those need a schedule and this
// needs to stay a thing that can be tested without one (§4, ADR 0008).

// observeRateLimit records what a response says about our quota. It is called
// for every response, including error ones: a 429 is exactly when the headers
// matter most.
func (c *RegistryClient) observeRateLimit(resp *http.Response) {
	now := c.now()

	limit, haveLimit, limitWindow := parseRateLimitHeader(resp.Header.Get("RateLimit-Limit"))
	remaining, haveRemaining, remainingWindow := parseRateLimitHeader(resp.Header.Get("RateLimit-Remaining"))
	retryAfter, haveRetryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), now)

	if !haveLimit && !haveRemaining && !haveRetryAfter {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.rate
	state.Observed = now
	if haveLimit {
		state.Known = true
		state.Limit = limit
		if limitWindow > 0 {
			state.Window = limitWindow
		}
	}
	if haveRemaining {
		state.Known = true
		state.Remaining = remaining
		if remainingWindow > 0 {
			state.Window = remainingWindow
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		state.RetryAfter = retryAfter
		state.Until = now.Add(retryAfter)
	}
	c.rate = state
}

// RateLimit reports what the upstream last told us about our quota.
func (c *RegistryClient) RateLimit() RateLimitState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rate
}

// parseRateLimitHeader reads one RateLimit-Limit or RateLimit-Remaining value.
//
// Docker Hub sends "100;w=21600" -- a count and the window it applies to -- and
// may send a comma-separated list of policies, of which the first is the one
// that bites first. A bare integer is also legal. Anything else is ignored
// rather than guessed at: a wrong gauge is worse than an absent one.
func parseRateLimitHeader(value string) (count int64, ok bool, window time.Duration) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, 0
	}
	first, _, _ := strings.Cut(value, ",")

	countPart, rest, _ := strings.Cut(first, ";")
	parsed, err := strconv.ParseInt(strings.TrimSpace(countPart), 10, 64)
	if err != nil {
		return 0, false, 0
	}

	for _, param := range strings.Split(rest, ";") {
		key, val, found := strings.Cut(param, "=")
		if !found || strings.TrimSpace(strings.ToLower(key)) != "w" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err == nil && seconds > 0 {
			window = time.Duration(seconds) * time.Second
		}
	}
	return parsed, true, window
}

// parseRetryAfter reads a Retry-After header in either of its two forms: a
// delay in seconds, or an HTTP-date. The date form is why this needs the
// injected clock -- the delay is the difference between the date and now, and
// a business rule that reads the wall clock is one that cannot be tested.
//
// A date in the past yields zero, not a negative duration: the upstream is
// saying "now", and a negative backoff is a bug waiting to be multiplied by
// something.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if delay := when.Sub(now); delay > 0 {
		return delay, true
	}
	return 0, true
}
