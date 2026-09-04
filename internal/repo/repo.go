// Package repo models repository entities and routes requests to hosted,
// proxy, or group entities (ADR 0005).
//
// An entity is mounted at a prefix: the first path segment of an OCI
// repository name. `docker pull registry.example.com/all/library/nginx`
// resolves to entity "all" with remainder "library/nginx", and the full name
// "all/library/nginx" is what bindings, catalogs, and events use — the prefix
// is routing, the full name is identity.
package repo

import (
	"fmt"
	"strings"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/reponame"
)

// ReservedPrefix is the entity name no repository may claim. The whole
// `system` prefix is reserved (Z-007): a binding written `admin@system/*` by
// somebody meaning the global scope would grant nothing while looking like it
// granted everything, so no repository may exist for such a binding to almost
// match.
const ReservedPrefix = "system"

// Split resolves a full OCI repository name into the entity it routes to and
// the remainder inside that entity. The remainder is empty when the name is
// the entity itself. The name is validated first: nothing that fails the
// grammar gets far enough to route (§11).
func Split(name string) (entity, remainder string, err error) {
	if err := reponame.Validate(name); err != nil {
		return "", "", err
	}
	entity, remainder, _ = strings.Cut(name, "/")
	return entity, remainder, nil
}

// ValidateEntityName reports whether a name may name a repository entity: one
// legal path segment, and not the reserved `system` prefix. This is the check
// the admin API creates through (C-016), kept here so the router and the
// creator cannot disagree about what an entity is.
func ValidateEntityName(name string) error {
	if err := reponame.Validate(name); err != nil {
		return err
	}
	if strings.Contains(name, "/") {
		return reponame.Invalid(name, "an entity is one path segment: it is mounted at a prefix, and the rest of the name is the remainder inside it (ADR 0005)")
	}
	if name == ReservedPrefix {
		return reponame.Invalid(name, fmt.Sprintf("%q is reserved: a binding scoped %s/... must never almost-match a repository (Z-007)", ReservedPrefix, ReservedPrefix))
	}
	return nil
}

// Writable reports whether clients may write to an entity of the given type.
//
// Only hosted entities take client writes. There is no configuration through
// which a proxy becomes writable — the answer is a function of the type alone,
// which is what "no config combination makes a proxy writable" means
// structurally (ADR 0005). A group is read-only here too: a group write is a
// routed write to its designated hosted writeTarget (C-011), so the write
// happens to a hosted entity or not at all.
func Writable(t meta.RepositoryType) bool { return t == meta.Hosted }
