package server

import (
	"errors"
	"fmt"
)

// PublicRoute is one endpoint permitted to be served without an authorization
// check, together with why.
//
// The list of them is frozen in this file. Registration already refuses a
// public route with no reason (see HandlePublic), but a reason a developer
// writes for themselves is not review: the frozen list is what makes adding an
// unguarded endpoint a change somebody else has to read and agree with. There
// are six entries and there should never be many more.
type PublicRoute struct {
	// Method and Pattern must match the registration exactly. A near-miss is a
	// failure rather than a match, because "close enough" is how a second,
	// unapproved path gets served by an approved-looking entry.
	Method  string
	Pattern string
	// Reason is why serving this without a check is acceptable. It must match
	// the reason given at registration, so the two cannot drift into meaning
	// different things.
	Reason string
	// Task is the status.md task that registers the route. Every entry names
	// one: an approval for a route nobody is building is an approval nobody
	// reviewed for a purpose, and this is what a reader checks it against.
	Task string
}

// publicRoutes is the frozen list. Each entry traces to an ADR that says the
// endpoint answers before, or without, authentication:
//
//   - The health endpoints are how a supervisor and a load balancer decide
//     whether to send traffic. Requiring credentials for them would make
//     liveness depend on the database that liveness exists to report on, and
//     keeping /healthz and /readyz distinct is what makes a rolling upgrade
//     safe (§8).
//
//   - The token endpoint is where credentials are exchanged, so it cannot
//     require the thing it issues. It accepts basic auth or none, and answers
//     with the scopes the subject's bindings allow at that moment (ADR 0004).
//     It is rate-limited instead (Z-002).
//
//   - The UI shell and its assets are a JavaScript bundle and a stylesheet.
//     They disclose which features exist, which is public information, and the
//     data they render is fetched through the guarded API like any other
//     client's (ADR 0019, §10). Hash-based routing is what keeps this to two
//     entries rather than a catch-all.
//
//   - The OCI base endpoint /v2/ is the client's authentication probe, and
//     ADR 0004 step 1 decides its behaviour: 401 with the bearer challenge
//     for an unauthenticated request -- that is how docker discovers the
//     token endpoint -- and 200 with an empty body for an authenticated one,
//     which discloses nothing beyond "your credentials are valid". The check
//     lives in the handler because the question is authentication, not a
//     verb; R-008 still owns the error body's spec shape (Z-004).
//
// Nothing else is here.
var publicRoutes = []PublicRoute{
	{
		Method:  "GET",
		Pattern: "/healthz",
		Reason:  "liveness must answer before anything is configured",
		Task:    "E-007",
	},
	{
		Method:  "GET",
		Pattern: "/readyz",
		Reason:  "readiness is a probe, not a client, and reports the dependencies a client would need",
		Task:    "E-007",
	},
	{
		Method:  "GET",
		Pattern: "/token",
		Reason:  "the token endpoint issues credentials, so it cannot require them",
		Task:    "Z-004",
	},
	{
		Method:  "GET",
		Pattern: "/v2/{$}",
		Reason:  "the OCI base endpoint answers only whether the client is authenticated (ADR 0004): 401 with the challenge, or 200 disclosing nothing",
		Task:    "Z-004",
	},
	{
		Method:  "GET",
		Pattern: "/{$}",
		Reason:  "the UI shell is a static bundle; everything it renders is fetched through the guarded API",
		Task:    "U-001",
	},
	{
		Method:  "GET",
		Pattern: "/assets/{path...}",
		Reason:  "built UI assets, embedded and static",
		Task:    "U-001",
	},
}

// PublicRoutes returns the frozen list of routes permitted to be public, as a
// copy. A support bundle or an operator doc can print it; the point of it being
// available at runtime is that "what does this deployment serve unguarded" has
// a single answer that is not a grep.
func PublicRoutes() []PublicRoute {
	out := make([]PublicRoute, len(publicRoutes))
	copy(out, publicRoutes)
	return out
}

// Errors a route table can fail with. Callers assert on these; the offending
// route is named in the message.
var (
	// ErrUnguardedRoute reports a route with neither a verb nor a declared
	// reason for being public.
	ErrUnguardedRoute = errors.New("route is neither guarded nor declared public")
	// ErrUnapprovedPublicRoute reports a public route missing from the frozen
	// list.
	ErrUnapprovedPublicRoute = errors.New("public route is not on the approved list")
	// ErrPublicReasonMismatch reports a public route whose registered reason
	// differs from the approved one.
	ErrPublicReasonMismatch = errors.New("public route's reason differs from the approved one")
	// ErrUnknownRouteVerb reports a route requiring a verb outside the
	// vocabulary.
	ErrUnknownRouteVerb = errors.New("route requires a verb outside the vocabulary")
)

// RouteError names the route a problem was found on.
type RouteError struct {
	Method  string
	Pattern string
	Detail  string
	Err     error
}

func (e *RouteError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s %s: %v", e.Method, e.Pattern, e.Err)
	}
	return fmt.Sprintf("%s %s: %v: %s", e.Method, e.Pattern, e.Err, e.Detail)
}

// Unwrap exposes the sentinel so errors.Is identifies the kind of problem while
// the message identifies the route.
func (e *RouteError) Unwrap() error { return e.Err }

// Verify reports every route that is not demonstrably guarded.
//
// Registration already refuses the obvious mistakes, so this is the second of
// two checks rather than the only one -- and it is the one that runs over the
// assembled table, which is what a reviewer, a CI test, and the router itself
// can all look at. ServeHTTP will not dispatch a table this rejects, so a
// route added without a permission is never served rather than being served
// until somebody notices.
//
// Every problem is reported, not just the first: someone adding three routes
// should see all three, and a check that stops early trains people to fix
// things one CI run at a time.
func (r *Router) Verify() error {
	approved := make(map[string]PublicRoute, len(publicRoutes))
	for _, route := range publicRoutes {
		approved[route.Method+" "+route.Pattern] = route
	}

	var problems []error
	for _, route := range r.Routes() {
		fail := func(err error, detail string) {
			problems = append(problems, &RouteError{
				Method: route.Method, Pattern: route.Pattern, Detail: detail, Err: err,
			})
		}

		switch {
		case route.Public():
			// A public route is approved by pattern, not by prefix: an entry
			// for /assets/{path...} does not approve /assets/../secrets.
			match, ok := approved[route.Method+" "+route.Pattern]
			switch {
			case !ok:
				fail(ErrUnapprovedPublicRoute, "add it to publicRoutes with a reason, or guard it")
			case match.Reason != route.PublicReason:
				fail(ErrPublicReasonMismatch, fmt.Sprintf("approved as %q", match.Reason))
			}
		case route.Permission.Verb == "":
			fail(ErrUnguardedRoute, "give it a Permission, or register it with HandlePublic and a reason")
		case !route.Permission.Verb.Valid():
			fail(ErrUnknownRouteVerb, fmt.Sprintf("verb %q", route.Permission.Verb))
		}
	}

	return errors.Join(problems...)
}
