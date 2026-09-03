package authz

import (
	"errors"
	"fmt"
	"sort"
)

// Binding is one grant as the decision sees it: a role's verbs, the scope they
// apply in, and enough identity to explain where it came from.
//
// It is not the stored binding. The metadata store holds a role name and the
// role's verbs separately; the caller resolves them and expands group
// membership before calling Decide, which is what keeps the decision a pure
// function over values (ADR 0001) and what lets the explainer say "through the
// platform-team group" rather than just "you have it".
//
// Verbs are expanded and explicit -- never wildcards (ADR 0002) -- so the
// enumeration test and the explainer both see concrete verbs.
type Binding struct {
	// ID is the stored binding's identifier, carried so a decision can name
	// exactly which grant allowed something.
	ID string
	// Role is the role's name, for the explainer and the audit record.
	Role string
	// Scope is where the grant applies.
	Scope Scope
	// Verbs is the role's expanded verb set.
	Verbs []Verb
	// ViaGroup names the group that carried the binding, or is empty when it
	// is attached to the subject directly.
	ViaGroup string
}

// ErrInvalidBinding reports a binding that cannot be evaluated.
var ErrInvalidBinding = errors.New("invalid binding")

// Validate reports whether the binding is well formed.
//
// Decide does not call it: an invalid binding grants nothing there, because
// its scope matches nothing and its unknown verbs are not in the vocabulary.
// This is for the write path, where refusing a binding that could never grant
// anything is better than storing one that silently does nothing.
func (b Binding) Validate() error {
	if b.Role == "" {
		return fmt.Errorf("%w: role must not be empty", ErrInvalidBinding)
	}
	if err := b.Scope.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidBinding, err)
	}
	for _, verb := range b.Verbs {
		if !verb.Valid() {
			return fmt.Errorf("%w: %w", ErrInvalidBinding, &UnknownVerbError{Verb: string(verb)})
		}
	}
	return nil
}

// Grants reports whether the binding's role includes the verb, ignoring scope.
//
// Scope is a separate question because the query layer asks this one on its
// own: "which scopes grant repo:list" is what a permission-filtered listing is
// built from, and it has no single resource to check against.
func (b Binding) Grants(verb Verb) bool {
	for _, candidate := range b.Verbs {
		if candidate == verb {
			return true
		}
	}
	return false
}

// Allows reports whether the binding grants the verb on the resource. It is
// the whole of the authorization rule for one binding; Decide is the union of
// this over every binding the subject holds.
func (b Binding) Allows(verb Verb, resource Resource) bool {
	return b.Grants(verb) && b.Scope.Matches(resource)
}

// SortBindings orders bindings by id, so a decision's explanation and an audit
// record read the same way every time.
func SortBindings(bindings []Binding) {
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].ID < bindings[j].ID })
}
