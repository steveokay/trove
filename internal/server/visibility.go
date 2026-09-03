package server

import (
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
)

// VisibilityFor compiles a subject's effective bindings into the Visibility a
// permission-filtered listing runs under (Z-012).
//
// The listing and the decision start from the same bindings: the scopes that
// grant verb are compiled into filters, and the store builds its WHERE clause
// from those and nothing else, so a catalog and a Decide call cannot disagree
// about what the subject sees (ADR 0001, ADR 0003). Catalog-shaped listings
// compile from authz.RepoList; surfaces scoped to readability, such as tag
// lists, compile from authz.RepoRead. The differential tests in authz pin this
// translation against the scope matcher and the SQL predicate.
//
// The result is never Unrestricted. A subject bound to every repository gets
// an all-matching filter -- the same rows, through the filtered path --
// because Unrestricted is reserved for internal callers with no subject:
// migrations, garbage collection, maintenance. A subject none of whose
// bindings grant verb gets a Visibility that shows nothing, which is the
// correct reading of "no grants", not an absence of filtering (ADR 0003).
func VisibilityFor(bindings []authz.Binding, verb authz.Verb) meta.Visibility {
	filters := authz.Filters(authz.VisibleScopes(bindings, verb))
	compiled := make([]meta.ScopeFilter, len(filters))
	for i, filter := range filters {
		compiled[i] = meta.ScopeFilter{All: filter.All, Exact: filter.Exact, Prefix: filter.Prefix}
	}
	return meta.VisibleTo(compiled...)
}
