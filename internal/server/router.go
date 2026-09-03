package server

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

// Route is one registered endpoint and the permission it enforces.
//
// The registry exists so the route table can be inspected: Z-011 walks it and
// fails if anything is registered without a verb or without a written reason
// for being public. A router that only handed patterns to a mux would have
// nothing to walk, and "every route is guarded" would be a claim rather than a
// check.
type Route struct {
	// Method and Pattern are how the route was registered.
	Method  string
	Pattern string
	// Permission is what the route requires. Its Verb is empty only for a
	// public route.
	Permission Permission
	// PublicReason says why an unguarded route is acceptable. It is empty for
	// guarded routes and non-empty for public ones -- one of the two is always
	// true, which is what makes the walk decidable.
	PublicReason string
}

// Public reports whether the route is served without an authorization check.
func (r Route) Public() bool { return r.PublicReason != "" }

// Router registers handlers behind the guard and remembers what it registered.
//
// Registration is the enforcement point. There is no method that takes a
// handler and a pattern alone: Handle demands a Permission, and HandlePublic
// demands a written reason. Forgetting to guard a route is therefore not
// something you can do by omission -- you have to say out loud that the route
// is public, and Z-011's walk makes somebody read it.
type Router struct {
	guard  *Guard
	mux    *http.ServeMux
	routes []Route

	// verified caches the table check the first request triggers. Routes are
	// registered before serving starts -- the mux requires that anyway -- so
	// checking once is checking the table that will actually be served.
	verified  sync.Once
	verifyErr error
}

// NewRouter returns a router that guards every route it registers.
func NewRouter(guard *Guard) *Router {
	return &Router{guard: guard, mux: http.NewServeMux()}
}

// Handle registers a guarded route.
//
// The permission is a required argument rather than an option, so a route
// without one does not compile. That is the whole design: the check cannot be
// forgotten, only refused in writing.
func (r *Router) Handle(method, pattern string, permission Permission, handler http.Handler) {
	if permission.Verb == "" {
		// A zero verb would sail through Decide as an unknown one and deny
		// everything, which looks like a permissions bug rather than the
		// programming error it is.
		panic(fmt.Sprintf("server: route %s %s registered with no verb", method, pattern))
	}
	if !permission.Verb.Valid() {
		panic(fmt.Sprintf("server: route %s %s registered with unknown verb %q",
			method, pattern, permission.Verb))
	}

	r.record(Route{Method: method, Pattern: pattern, Permission: permission})
	r.mux.Handle(method+" "+pattern, r.guard.Require(permission, handler))
}

// HandleFunc registers a guarded route from a handler function.
func (r *Router) HandleFunc(method, pattern string, permission Permission, handler http.HandlerFunc) {
	r.Handle(method, pattern, permission, handler)
}

// HandlePublic registers a route served without an authorization check.
//
// The reason is required and is not decoration: it is what a reviewer reads in
// Z-011's frozen list. The legitimate cases are few -- health checks, the
// token endpoint that issues credentials, and the UI's static assets -- and
// each is a deliberate decision rather than an oversight (ADR 0002).
func (r *Router) HandlePublic(method, pattern, reason string, handler http.Handler) {
	if reason == "" {
		panic(fmt.Sprintf("server: public route %s %s registered without a reason", method, pattern))
	}

	r.record(Route{Method: method, Pattern: pattern, PublicReason: reason})
	r.mux.Handle(method+" "+pattern, handler)
}

// record adds a route to the table, refusing a duplicate registration before
// the mux panics with less context.
func (r *Router) record(route Route) {
	for _, existing := range r.routes {
		if existing.Method == route.Method && existing.Pattern == route.Pattern {
			panic(fmt.Sprintf("server: route %s %s registered twice", route.Method, route.Pattern))
		}
	}
	r.routes = append(r.routes, route)
}

// Routes returns the route table, ordered by pattern and method, as a copy.
// Z-011 walks it; an audit or a support bundle can print it.
func (r *Router) Routes() []Route {
	out := make([]Route, len(r.routes))
	copy(out, r.routes)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// ServeHTTP dispatches to the registered handlers, or to nothing at all.
//
// A table that does not verify serves no requests. That makes Verify a
// property of the router rather than a step somebody remembers: an endpoint
// added without a permission, or made public without approval, takes the
// deployment down loudly instead of being served quietly. The error names
// every offending route, and it is logged on each refusal because the first
// one may be the only thing in the log by the time anyone looks.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.verified.Do(func() { r.verifyErr = r.Verify() })
	if r.verifyErr != nil {
		Logger(req.Context(), nil).Error("refusing to serve an unverified route table",
			"error", r.verifyErr)
		ProblemErrors{}.Internal(w, req)
		return
	}
	r.mux.ServeHTTP(w, req)
}
