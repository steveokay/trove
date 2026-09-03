package authz

import "strings"

// Filter is a scope compiled into the shape a query needs: match everything,
// match one name, or match one prefix.
//
// The query layer builds its WHERE clause from these rather than from the
// bindings directly, so a listing and a Decide call are answering the same
// question with the same values. Two implementations of "what does this scope
// cover" -- one in Go for the decision, one in SQL for the listing -- is the
// classic way a catalog ends up showing a repository the subject cannot pull
// (ADR 0001, ADR 0003).
//
// It deliberately carries no SQL. This package does not know which engine is
// underneath and must not import one (Z-009); the storage layer turns a Filter
// into a predicate, and a differential test pins the two together.
type Filter struct {
	// All matches every repository.
	All bool
	// Exact matches one repository name.
	Exact string
	// Prefix matches every name strictly under a path, e.g. "team-a/" for
	// "team-a/*". The trailing separator is part of the value, so a caller
	// comparing prefixes does not have to remember to add it.
	Prefix string
}

// Matches reports whether the filter selects a repository name.
//
// It exists so the compiled form can be checked against the scope it came
// from: Scope.Matches and Filter.Matches must agree on every input, and a test
// proves it rather than a comment asserting it.
func (f Filter) Matches(name string) bool {
	switch {
	case f.All:
		return true
	case f.Exact != "":
		return name == f.Exact
	case f.Prefix != "":
		return strings.HasPrefix(name, f.Prefix) && len(name) > len(f.Prefix)
	default:
		// A filter nobody built selects nothing, which is the right reading of
		// a subject holding no bindings.
		return false
	}
}

// Filter compiles a scope for the query layer. The second result is false for
// the system scope, which selects no repositories at all -- a listing built
// from it must return nothing rather than everything.
func (s Scope) Filter() (Filter, bool) {
	if s.Validate() != nil {
		return Filter{}, false
	}
	switch {
	case s == SystemScope:
		return Filter{}, false
	case s == AllRepositories:
		return Filter{All: true}, true
	}
	if prefix, found := strings.CutSuffix(string(s), wildcardSuffix); found {
		return Filter{Prefix: prefix + "/"}, true
	}
	return Filter{Exact: string(s)}, true
}

// Filters compiles the scopes of every binding that grants a verb, dropping
// the ones that select no repositories.
//
// The result is what a permission-filtered listing is built from. An empty
// result means the subject can see nothing, which is different from an
// unrestricted one: callers must not treat "no filters" as "no filtering"
// (ADR 0003).
func Filters(scopes []Scope) []Filter {
	out := make([]Filter, 0, len(scopes))
	for _, scope := range scopes {
		if filter, ok := scope.Filter(); ok {
			out = append(out, filter)
		}
	}
	return out
}

// VisibleScopes returns the scopes of the bindings that grant verb, which is
// the input Filters expects.
//
// Listing and deciding therefore start from the same bindings: the query layer
// asks which scopes grant repo:list, compiles those, and filters with them,
// instead of assembling its own idea of what the subject can see.
func VisibleScopes(bindings []Binding, verb Verb) []Scope {
	var out []Scope
	for _, binding := range bindings {
		if binding.Grants(verb) {
			out = append(out, binding.Scope)
		}
	}
	return out
}
