// Package reponame is the repository-name grammar: what counts as a legal OCI
// repository name, and nothing else.
//
// It is a leaf package with no internal dependencies because two layers that
// must not depend on each other both need it. Authorization validates binding
// scope patterns against it (ADR 0001: a pattern that could not name a legal
// repository is rejected at write time, which is what closes
// traversal-via-binding-pattern), and the registry and repository router
// validate incoming names against it before any lookup (ADR 0005). One grammar
// in one place: a second copy would be a second answer to "is this a legal
// name", and the two would eventually differ on exactly the input that matters.
package reponame

import (
	"fmt"
	"regexp"
	"strings"
)

// MaxLength bounds a repository name. The distribution spec caps it at 255
// characters, and a bound is what keeps a name from becoming a filesystem or
// object-store problem further down.
const MaxLength = 255

// pattern is the distribution-spec grammar, anchored:
//
//	name            := path-component ('/' path-component)*
//	path-component  := alphanumeric (separator alphanumeric)*
//	alphanumeric    := [a-z0-9]+
//	separator       := '.' | '_' | '__' | '-'+
//
// Lowercase only, and every component starts and ends with an alphanumeric --
// which is what makes "..", "//", a leading "/" and a trailing "." impossible
// without a separate check for each.
var pattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*$`)

// ErrInvalid reports a string that is not a legal repository name. Callers
// assert with errors.Is; the grammar is closed, so this is the only answer for
// anything outside it.
var ErrInvalid = fmt.Errorf("invalid repository name")

// InvalidError names what was rejected and why, while satisfying
// errors.Is(err, ErrInvalid).
type InvalidError struct {
	Name   string
	Reason string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("invalid repository name %q: %s", e.Name, e.Reason)
}

// Is makes errors.Is(err, ErrInvalid) true for this typed error.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Invalid builds an InvalidError.
func Invalid(name, reason string) error { return &InvalidError{Name: name, Reason: reason} }

// Validate reports whether name is a legal repository name.
//
// The checks before the pattern exist to give a useful reason rather than to
// add strictness: the pattern alone rejects every one of them.
func Validate(name string) error {
	switch {
	case name == "":
		return Invalid(name, "must not be empty")
	case len(name) > MaxLength:
		return Invalid(name, fmt.Sprintf("must be at most %d characters, got %d", MaxLength, len(name)))
	case strings.ToLower(name) != name:
		return Invalid(name, "must be lowercase: one repository has one name")
	case !pattern.MatchString(name):
		return Invalid(name, "must be path components of [a-z0-9] separated by '.', '_', '__' or '-'")
	}
	return nil
}

// Valid reports whether name is a legal repository name.
func Valid(name string) bool { return Validate(name) == nil }

// Segments splits a name into its path components. The first is the repository
// entity a request routes to and the rest are the remainder (ADR 0005); the
// full name is what bindings and catalogs use.
//
// It is only meaningful for a validated name.
func Segments(name string) []string { return strings.Split(name, "/") }

// Prefix returns the routing prefix of a name: its first path component.
func Prefix(name string) string {
	first, _, found := strings.Cut(name, "/")
	if !found {
		return name
	}
	return first
}
