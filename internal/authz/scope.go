package authz

import (
	"fmt"
	"strings"

	"github.com/steveokay/trove/internal/reponame"
)

// Scope is where a binding applies. It is exactly one of four forms
// (ADR 0001):
//
//	system      global, non-repository permissions: user admin, GC, maintenance
//	*           every repository
//	team-a/api  exactly this repository
//	team-a/*    every repository under this prefix, at any depth
//
// The only wildcard is a single trailing "/*", or a bare "*". Mid-pattern and
// multi-wildcard forms (team-*/api, */prod) are rejected: they reintroduce
// precedence-like reasoning to a model that is deliberately additive, and they
// are hard to fuzz convincingly.
//
// A Scope that exists has been through ParseScope, and matching is pure string
// comparison over validated names -- no filesystem, no regex engine, nothing
// that could interpret a pattern differently from the query filter built from
// the same value.
type Scope string

// SystemScope is the global scope. Verbs that are not about a repository --
// user administration, garbage collection, maintenance mode -- are only ever
// granted here.
//
// The whole "system" prefix is reserved, even though it is a legal repository
// name: "system" is this scope, and "system/*" or "system/api" are refused
// rather than quietly meaning a repository under a directory called system.
// A binding written as admin@system/* by somebody who meant the global scope
// would grant nothing while looking like it granted everything, and a scope
// that can be misread that way has no place in a security grammar. Repository
// creation refuses the same prefix (C-016), so nothing becomes unreachable.
const SystemScope Scope = "system"

// AllRepositories matches every repository. It does not match the system
// scope: an administrator holds both, which is why ADR 0001's admin role is
// bound at "system" and at "*" rather than at one scope meaning everything.
const AllRepositories Scope = "*"

// wildcardSuffix is the only wildcard form.
const wildcardSuffix = "/*"

// ErrInvalidScope reports a scope outside the grammar.
var ErrInvalidScope = fmt.Errorf("invalid scope")

// InvalidScopeError names what was rejected and why, while satisfying
// errors.Is(err, ErrInvalidScope).
type InvalidScopeError struct {
	Scope  string
	Reason string
}

func (e *InvalidScopeError) Error() string {
	return fmt.Sprintf("invalid scope %q: %s", e.Scope, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidScope) true for this typed error.
func (e *InvalidScopeError) Is(target error) bool { return target == ErrInvalidScope }

// InvalidScope builds an InvalidScopeError.
func InvalidScope(scope, reason string) error {
	return &InvalidScopeError{Scope: scope, Reason: reason}
}

// ParseScope validates a scope string.
//
// The grammar is total: every input is either one of the four forms or a typed
// error. Repository parts are validated against the repository-name grammar,
// so a pattern that could not name a legal repository never reaches storage --
// which is what closes traversal through a binding pattern (ADR 0001).
func ParseScope(s string) (Scope, error) {
	switch {
	case s == "":
		return "", InvalidScope(s, "must not be empty")
	case s == string(SystemScope):
		return SystemScope, nil
	case s == string(AllRepositories):
		return AllRepositories, nil
	}

	if prefix, found := strings.CutSuffix(s, wildcardSuffix); found {
		if err := reponame.Validate(prefix); err != nil {
			return "", InvalidScope(s, fmt.Sprintf("%q is not a repository prefix: %v", prefix, err))
		}
		if err := checkNotReserved(s, prefix); err != nil {
			return "", err
		}
		return Scope(s), nil
	}

	// Anything else must name one repository exactly. A leftover "*" here is
	// a mid-pattern wildcard, and the name grammar rejects it along with
	// everything else that is not a legal name.
	if err := reponame.Validate(s); err != nil {
		return "", InvalidScope(s, err.Error())
	}
	if err := checkNotReserved(s, s); err != nil {
		return "", err
	}
	return Scope(s), nil
}

// checkNotReserved refuses a repository scope that starts with the system
// keyword, so "system" always means the global scope and never a directory.
func checkNotReserved(scope, name string) error {
	if reponame.Prefix(name) != string(SystemScope) {
		return nil
	}
	return InvalidScope(scope, `"system" is the global scope: a repository scope cannot start with it`)
}

// Validate reports whether the scope is well formed. Methods call it rather
// than trusting the type: a Scope can be produced by conversion as well as by
// parsing, and one that never went through the parser must not match anything.
func (s Scope) Validate() error {
	_, err := ParseScope(string(s))
	return err
}

// String renders the scope.
func (s Scope) String() string { return string(s) }

// resourceKind distinguishes the two things a permission can be about.
type resourceKind uint8

const (
	// resourceInvalid is the zero value, so a Resource nobody built matches
	// nothing rather than everything.
	resourceInvalid resourceKind = iota
	resourceSystem
	resourceRepository
)

// Resource is what a permission is being checked against: either the system
// itself or one repository.
//
// It is a struct rather than a string so that "system" the keyword and
// "system" the repository name cannot be confused, and so that the zero value
// is meaningless rather than dangerous.
type Resource struct {
	kind resourceKind
	name string
}

// System returns the resource that non-repository permissions are checked
// against.
func System() Resource { return Resource{kind: resourceSystem} }

// Repository returns the resource for one repository, or an error if the name
// is not a legal one. Names arrive from URLs, so this is a gate rather than a
// formality.
func Repository(name string) (Resource, error) {
	if err := reponame.Validate(name); err != nil {
		return Resource{}, err
	}
	return Resource{kind: resourceRepository, name: name}, nil
}

// IsSystem reports whether the resource is the system itself.
func (r Resource) IsSystem() bool { return r.kind == resourceSystem }

// IsRepository reports whether the resource is a repository.
func (r Resource) IsRepository() bool { return r.kind == resourceRepository }

// Name is the repository's name, or empty for the system resource.
func (r Resource) Name() string { return r.name }

// String renders the resource for logs and audit records.
func (r Resource) String() string {
	switch r.kind {
	case resourceSystem:
		return "system"
	case resourceRepository:
		return "repository " + r.name
	default:
		return "invalid resource"
	}
}

// Matches reports whether the scope covers the resource.
//
// The system scope and the repository scopes are disjoint: nothing that grants
// access to every repository also grants user administration, and nothing
// granted at "system" reaches a repository. An administrator holds both.
func (s Scope) Matches(r Resource) bool {
	if s.Validate() != nil {
		return false
	}

	switch r.kind {
	case resourceSystem:
		return s == SystemScope
	case resourceRepository:
		switch {
		case s == SystemScope:
			return false
		case s == AllRepositories:
			return true
		}
		if prefix, found := strings.CutSuffix(string(s), wildcardSuffix); found {
			// "team-a/*" covers what is under team-a, not team-a itself: the
			// repository named exactly "team-a" needs its own scope.
			return strings.HasPrefix(r.name, prefix+"/") && len(r.name) > len(prefix)+1
		}
		return string(s) == r.name
	default:
		// A resource nobody built. Matching nothing is the only safe answer.
		return false
	}
}
