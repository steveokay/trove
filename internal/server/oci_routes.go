package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// OCI routes are the distribution API's paths: /v2/<name>/blobs/<digest> and
// friends, where <name> is a repository name spanning any number of path
// segments. http.ServeMux cannot express a multi-segment wildcard in the
// middle of a pattern, so these routes are matched here instead: a suffix
// pattern anchored at the end of the path, with everything between /v2/ and
// the suffix becoming the repository name.
//
// The routes still live in the one route table. Registration demands a
// Permission exactly like Handle, Verify walks them, and ServeHTTP dispatches
// them from the same verified table -- a second dispatcher was the thing the
// mux quarantine exists to prevent, so this one is part of the Router rather
// than beside it.

// ociRoute is one registered distribution route.
type ociRoute struct {
	method string
	// segments is the suffix pattern, split: literals match exactly, and a
	// "{placeholder}" matches any single non-empty segment.
	segments []string
	// trailingSlash marks a suffix that ends in "/", like the upload-start
	// path /v2/<name>/blobs/uploads/.
	trailingSlash bool
	handler       http.Handler
}

// ociKey carries the matched name and placeholders to the handler and to the
// permission's resource extractor, which runs before the handler does.
const ociKey contextKey = 200

type ociMatch struct {
	name   string
	values map[string]string
}

// OCIName returns the repository name an OCI route matched, or empty outside
// one.
func OCIName(r *http.Request) string {
	match, ok := r.Context().Value(ociKey).(*ociMatch)
	if !ok {
		return ""
	}
	return match.name
}

// OCIValue returns a matched placeholder, such as "digest" for a route
// registered with "/blobs/{digest}".
func OCIValue(r *http.Request, key string) string {
	match, ok := r.Context().Value(ociKey).(*ociMatch)
	if !ok {
		return ""
	}
	return match.values[key]
}

// HandleOCI registers a guarded distribution route by its suffix: for
// example ("GET", "/blobs/{digest}", ...) serves GET /v2/<name>/blobs/<digest>
// for every repository name. The recorded pattern spells the name out, so the
// table reads like the API it serves.
func (r *Router) HandleOCI(method, suffix string, permission Permission, handler http.Handler) {
	if permission.Verb == "" {
		panic(fmt.Sprintf("server: OCI route %s %s registered with no verb", method, suffix))
	}
	if !permission.Verb.Valid() {
		panic(fmt.Sprintf("server: OCI route %s %s registered with unknown verb %q", method, suffix, permission.Verb))
	}
	if !strings.HasPrefix(suffix, "/") || len(suffix) < 2 {
		panic(fmt.Sprintf("server: OCI route %s %s: the suffix must start with '/' and name something", method, suffix))
	}
	if permission.Listing {
		// An OCI route is always about the repository in its path; a
		// cross-repository listing route registers through Handle.
		panic(fmt.Sprintf("server: OCI route %s %s registered as Listing", method, suffix))
	}

	trimmed, trailingSlash := strings.CutSuffix(suffix, "/")
	segments := strings.Split(strings.TrimPrefix(trimmed, "/"), "/")
	for _, segment := range segments {
		if segment == "" {
			panic(fmt.Sprintf("server: OCI route %s %s has an empty segment", method, suffix))
		}
		// Parsed at registration so an unknown constraint panics here rather
		// than becoming a route that quietly never matches.
		_, _, _ = cutPlaceholder(segment)
	}

	r.record(Route{Method: method, Pattern: "/v2/{name}" + suffix, Permission: permission})
	r.oci = append(r.oci, ociRoute{
		method:        method,
		segments:      segments,
		trailingSlash: trailingSlash,
		handler:       r.guard.Require(permission, handler),
	})
	// Longer suffixes first, so /blobs/uploads/{id} wins over /blobs/{digest}
	// wherever both could match; registration order breaks ties stably.
	sort.SliceStable(r.oci, func(i, j int) bool {
		return len(r.oci[i].segments) > len(r.oci[j].segments)
	})
}

// matchOCI finds the registered route for a /v2/ path, if any, and returns
// the handler with the match injected into the request.
func (r *Router) matchOCI(req *http.Request) (http.Handler, *http.Request, bool) {
	path, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok || path == "" {
		return nil, nil, false
	}
	path, trailingSlash := strings.CutSuffix(path, "/")
	parts := strings.Split(path, "/")

	for _, route := range r.oci {
		if route.method != req.Method || route.trailingSlash != trailingSlash {
			continue
		}
		// At least one segment must remain for the repository name.
		k := len(route.segments)
		if len(parts) <= k {
			continue
		}
		tail := parts[len(parts)-k:]
		values := map[string]string{}
		matched := true
		for i, pattern := range route.segments {
			if placeholder, constraint, ok := cutPlaceholder(pattern); ok {
				if tail[i] == "" || !constraint(tail[i]) {
					matched = false
					break
				}
				values[placeholder] = tail[i]
				continue
			}
			if pattern != tail[i] {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}

		match := &ociMatch{name: strings.Join(parts[:len(parts)-k], "/"), values: values}
		return route.handler, req.WithContext(context.WithValue(req.Context(), ociKey, match)), true
	}
	return nil, nil, false
}

// cutPlaceholder reads a "{name}" or "{name:kind}" segment, returning the
// value name and the constraint the segment must satisfy.
func cutPlaceholder(segment string) (name string, constraint ociConstraint, ok bool) {
	if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
		return "", nil, false
	}
	inner := segment[1 : len(segment)-1]
	name, kind, constrained := strings.Cut(inner, ":")
	if !constrained {
		return inner, anySegment, true
	}
	check, known := ociConstraints[kind]
	if !known {
		panic(fmt.Sprintf("server: unknown route constraint %q in %q", kind, segment))
	}
	return name, check, true
}

// ociConstraint reports whether a path segment may fill a placeholder.
type ociConstraint func(string) bool

// anySegment accepts anything non-empty, which is what a bare "{name}" means.
func anySegment(string) bool { return true }

// ociConstraints is the closed set of constraints a route may name. It is
// closed on purpose: a route table that accepted arbitrary patterns would be a
// second matcher to disagree with the handlers, and the point of these two is
// that one wire path carries two different permissions.
//
// The distribution spec overloads `/manifests/<reference>` for both a tag and
// a digest, and deleting a tag is `tag:delete` while deleting a manifest is
// `manifest:delete` (ADR 0002 keeps them apart because they destroy different
// things). A route declares exactly one verb, so the two are two routes, and
// the constraint is what tells them apart before the guard decides.
var ociConstraints = map[string]ociConstraint{
	"digest": func(segment string) bool { return strings.Contains(segment, ":") },
	"tag":    func(segment string) bool { return !strings.Contains(segment, ":") },
}
