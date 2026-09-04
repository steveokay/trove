package proxy_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/proxy"
)

// The error surface is the frozen part of the contract: C-004 through C-008
// branch on it, and they are written against this table rather than against
// the implementation. Two properties are asserted for every error the package
// produces -- that it maps to exactly the sentinels it should, and that its
// message says enough for an operator to act on.

func TestErrorClassification(t *testing.T) {
	t.Parallel()

	sentinels := []struct {
		name string
		err  error
	}{
		{"not found", proxy.ErrNotFound},
		{"unauthorized", proxy.ErrUnauthorized},
		{"rate limited", proxy.ErrRateLimited},
		{"digest mismatch", proxy.ErrDigestMismatch},
		{"unavailable", proxy.ErrUpstreamUnavailable},
		{"redirect refused", proxy.ErrRedirectRefused},
		{"invalid reference", proxy.ErrInvalidReference},
		{"manifest too large", proxy.ErrManifestTooLarge},
	}

	cases := []struct {
		name  string
		err   error
		match []error
	}{
		{
			name:  "404",
			err:   &proxy.StatusError{Status: 404, Method: "GET", Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrNotFound},
		},
		{
			name:  "410",
			err:   &proxy.StatusError{Status: 410, Method: "GET", Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrNotFound},
		},
		{
			name:  "401",
			err:   &proxy.StatusError{Status: 401, Method: "GET", Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrUnauthorized},
		},
		{
			name:  "403",
			err:   &proxy.StatusError{Status: 403, Method: "GET", Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrUnauthorized},
		},
		{
			name:  "500",
			err:   &proxy.StatusError{Status: 500, Method: "GET", Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrUpstreamUnavailable},
		},
		{
			// The mapping is total on purpose: no caller is ever handed a
			// failure it has no sentinel for.
			name:  "a status nobody planned for",
			err:   &proxy.StatusError{Status: 418, Method: "GET", Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrUpstreamUnavailable},
		},
		{
			name:  "rate limited",
			err:   &proxy.RateLimitedError{RetryAfter: time.Minute, HasRetryAfter: true, Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrRateLimited},
		},
		{
			name:  "rate limited with no delay given",
			err:   &proxy.RateLimitedError{Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrRateLimited},
		},
		{
			name:  "transport",
			err:   &proxy.TransportError{Op: "GET https://r.example.com/v2/", Err: errors.New("dial: no route to host")},
			match: []error{proxy.ErrUpstreamUnavailable},
		},
		{
			name:  "redirect",
			err:   &proxy.RedirectError{From: "https://r.example.com/a", To: "https://evil.example.net/b", Reason: "off the family"},
			match: []error{proxy.ErrRedirectRefused},
		},
		{
			name:  "a refused realm names only where it was sent",
			err:   &proxy.RedirectError{To: "https://evil.example.net/token", Reason: "untrusted"},
			match: []error{proxy.ErrRedirectRefused},
		},
		{
			name:  "reference",
			err:   &proxy.ReferenceError{Kind: "tag", Value: "../x", Reason: "not a tag"},
			match: []error{proxy.ErrInvalidReference},
		},
		{
			name:  "too large",
			err:   &proxy.TooLargeError{Limit: 4 << 20, Path: "/v2/a/manifests/x"},
			match: []error{proxy.ErrManifestTooLarge},
		},
		{
			name:  "authentication",
			err:   &proxy.AuthError{Reason: "token endpoint returned no token"},
			match: []error{proxy.ErrUnauthorized},
		},
		{
			name:  "authentication over an underlying failure",
			err:   &proxy.AuthError{Reason: "credentials could not be read", Err: errors.New("keyfile missing")},
			match: []error{proxy.ErrUnauthorized},
		},
		{
			name:  "digest mismatch is blob's",
			err:   blob.Mismatch(blob.Digest("sha256:"+strings.Repeat("a", 64)), blob.Digest("sha256:"+strings.Repeat("b", 64)), 12),
			match: []error{proxy.ErrDigestMismatch},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wanted := make(map[error]bool, len(tc.match))
			for _, target := range tc.match {
				wanted[target] = true
			}
			for _, sentinel := range sentinels {
				got := errors.Is(tc.err, sentinel.err)
				if got != wanted[sentinel.err] {
					t.Errorf("errors.Is(%v, %s) = %v, want %v", tc.err, sentinel.name, got, wanted[sentinel.err])
				}
			}
			if message := tc.err.Error(); message == "" {
				t.Error("the error has no message")
			}
		})
	}
}

// TestErrorMessagesCarryTheDetail keeps the operator-facing half honest: every
// message names the thing that went wrong, because the sentinel is for the
// code and the message is for the person reading the log.
func TestErrorMessagesCarryTheDetail(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want []string
	}{
		{&proxy.StatusError{Status: 503, Method: "HEAD", Path: "/v2/a/manifests/v1"}, []string{"503", "HEAD", "/v2/a/manifests/v1"}},
		{&proxy.RateLimitedError{RetryAfter: 90 * time.Second, HasRetryAfter: true, Path: "/v2/a"}, []string{"1m30s", "/v2/a"}},
		{&proxy.RateLimitedError{Path: "/v2/a"}, []string{"no retry-after", "/v2/a"}},
		{&proxy.TransportError{Op: "GET /v2/", Err: errors.New("connection refused")}, []string{"GET /v2/", "connection refused"}},
		{&proxy.RedirectError{From: "https://a/x", To: "https://b/y", Reason: "off the family"}, []string{"https://a/x", "https://b/y", "off the family"}},
		{&proxy.RedirectError{To: "https://b/y", Reason: "untrusted"}, []string{"https://b/y", "untrusted"}},
		{&proxy.ReferenceError{Kind: "repository", Value: "../etc", Reason: "traversal"}, []string{"repository", "../etc", "traversal"}},
		{&proxy.TooLargeError{Limit: 1024, Path: "/v2/a"}, []string{"1024", "/v2/a"}},
		{&proxy.AuthError{Reason: "no realm"}, []string{"no realm"}},
		{&proxy.AuthError{Reason: "unreadable", Err: errors.New("keyfile missing")}, []string{"unreadable", "keyfile missing"}},
	}

	for _, tc := range cases {
		message := tc.err.Error()
		for _, want := range tc.want {
			if !strings.Contains(message, want) {
				t.Errorf("%q does not mention %q", message, want)
			}
		}
	}
}

// TestErrorsUnwrapToTheirCause lets a caller reach the detail without matching
// on text (§9).
func TestErrorsUnwrapToTheirCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("keyfile missing")
	if !errors.Is(&proxy.AuthError{Reason: "unreadable", Err: cause}, cause) {
		t.Error("an AuthError does not unwrap to its cause")
	}
	if !errors.Is(&proxy.TransportError{Op: "GET /v2/", Err: cause}, cause) {
		t.Error("a TransportError does not unwrap to its cause")
	}
}

// TestConditionalIsZero is what tells a caller's lease code whether it has
// anything to revalidate with.
func TestConditionalIsZero(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cond proxy.Conditional
		zero bool
	}{
		{proxy.Conditional{}, true},
		{proxy.Conditional{Digest: blob.Digest("sha256:" + strings.Repeat("a", 64))}, false},
		{proxy.Conditional{ETag: `"x"`}, false},
		{proxy.Conditional{Digest: blob.Digest("sha256:" + strings.Repeat("a", 64)), ETag: `"x"`}, false},
	}
	for _, tc := range cases {
		if got := tc.cond.IsZero(); got != tc.zero {
			t.Errorf("Conditional%+v.IsZero() = %v, want %v", tc.cond, got, tc.zero)
		}
	}
}

func TestStaticCredentials(t *testing.T) {
	t.Parallel()

	username, password, err := proxy.StaticCredentials{Username: "robot", Password: "hunter2"}.Basic(t.Context())
	if err != nil || username != "robot" || password != "hunter2" {
		t.Errorf("Basic() = (%q, %q, %v)", username, password, err)
	}
}
