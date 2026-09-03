package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
)

// BindingStore is the part of the metadata store an authorization check needs.
// It is declared here, by the consumer, so the server depends on two methods
// rather than on the whole store (§11).
type BindingStore interface {
	// ListEffectiveBindings returns every binding reaching a subject, directly
	// or through a group, in one query.
	ListEffectiveBindings(ctx context.Context, subject string) ([]meta.EffectiveBinding, error)
	// GetRole returns a role's expanded verb set.
	GetRole(ctx context.Context, name string) (meta.Role, error)
}

// FetchBindings resolves a subject's effective bindings into the values the
// decision takes.
//
// The store answers "which bindings reach this subject" in one query,
// including group membership and the disabled check, so group expansion has
// already happened by the time anything is decided (ADR 0001). What is left is
// turning each binding's role name into its verbs, which is why this is a
// function rather than a straight type conversion.
//
// A binding whose role has vanished is skipped rather than treated as an
// error. Deleting a role deletes the bindings that granted it, so the only way
// to see one is to race that delete -- and a binding to a role that no longer
// exists grants nothing either way.
func FetchBindings(ctx context.Context, store BindingStore, subject string) ([]authz.Binding, error) {
	effective, err := store.ListEffectiveBindings(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list effective bindings for %q: %w", subject, err)
	}

	// Roles repeat across bindings -- a subject bound to "developer" in three
	// scopes is ordinary -- so each is read once.
	verbs := make(map[string][]authz.Verb, len(effective))
	out := make([]authz.Binding, 0, len(effective))

	for _, binding := range effective {
		roleVerbs, cached := verbs[binding.Role]
		if !cached {
			role, err := store.GetRole(ctx, binding.Role)
			switch {
			case errors.Is(err, meta.ErrNotFound):
				verbs[binding.Role] = nil
				continue
			case err != nil:
				return nil, fmt.Errorf("read role %q: %w", binding.Role, err)
			}
			roleVerbs = make([]authz.Verb, 0, len(role.Verbs))
			for _, verb := range role.Verbs {
				roleVerbs = append(roleVerbs, authz.Verb(verb))
			}
			verbs[binding.Role] = roleVerbs
		}
		if roleVerbs == nil {
			continue
		}

		out = append(out, authz.Binding{
			ID:       binding.ID,
			Role:     binding.Role,
			Scope:    authz.Scope(binding.Scope),
			Verbs:    roleVerbs,
			ViaGroup: binding.ViaGroup,
		})
	}

	authz.SortBindings(out)
	return out, nil
}
