package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

// Registration refuses a route with no verb or an unknown one, so these two
// tables cannot be built through Handle. They are built directly here on
// purpose: Verify is what runs over the assembled table -- at startup, and in
// front of a reviewer -- and a check that only holds because another check
// already ran is a check that stops holding the day the first one moves.
//
// This is also the only test in the package that reaches past the router's own
// API, which is why it lives in its own internal file rather than blurring the
// boundary the rest of the tests respect.
func TestVerifyRefusesATableRegistrationCouldNotProduce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		route Route
		want  error
		named string
	}{
		{
			name:  "no verb and no reason",
			route: Route{Method: "GET", Pattern: "/api/v1/secrets"},
			want:  ErrUnguardedRoute,
			named: "GET /api/v1/secrets",
		},
		{
			name: "a verb outside the vocabulary",
			route: Route{
				Method: "POST", Pattern: "/api/v1/repositories",
				Permission: Permission{Verb: authz.Verb("repo:admin")},
			},
			want:  ErrUnknownRouteVerb,
			named: `verb "repo:admin"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &Router{routes: []Route{tt.route}}
			err := r.Verify()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify = %v, want %v", err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.named) {
				t.Errorf("the failure does not say %q: %v", tt.named, err)
			}
		})
	}
}

// An empty table is not a failure. It is what the router looks like before
// anything registers, and Verify answering "nothing is wrong" there is what
// lets the composition point call it unconditionally.
func TestVerifyAcceptsAnEmptyTable(t *testing.T) {
	t.Parallel()

	if err := (&Router{}).Verify(); err != nil {
		t.Errorf("Verify = %v, want nil", err)
	}
}

// RouteError renders with and without a detail. The message is the whole
// value of the check: it is read in CI output, and a route nobody can locate
// is a failure nobody can fix.
func TestRouteErrorNamesTheRoute(t *testing.T) {
	t.Parallel()

	bare := &RouteError{Method: "GET", Pattern: "/a", Err: ErrUnguardedRoute}
	if got := bare.Error(); got != "GET /a: "+ErrUnguardedRoute.Error() {
		t.Errorf("Error = %q", got)
	}

	detailed := &RouteError{Method: "GET", Pattern: "/a", Detail: "guard it", Err: ErrUnguardedRoute}
	if got := detailed.Error(); !strings.HasSuffix(got, ": guard it") {
		t.Errorf("Error = %q, want the detail at the end", got)
	}
	if !errors.Is(detailed, ErrUnguardedRoute) {
		t.Error("errors.Is cannot see the sentinel through RouteError")
	}
}
