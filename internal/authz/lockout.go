package authz

import (
	"errors"
	"fmt"
	"slices"
)

// ErrLastAdmin reports a change that would leave nobody able to administer
// roles and bindings (§5, Z-015). The API surfaces its message verbatim, so
// it says what to do rather than only what was refused.
var ErrLastAdmin = errors.New("nobody would hold role:write at the system scope")

// AdminGrant reports whether the bindings grant role:write at the system
// scope -- what makes a subject able to administer roles and bindings, and
// therefore able to recover any other misconfiguration. Breadth is not
// administration: a grant at "*" reaches every repository and no part of the
// system scope (scope disjointness, ADR 0001).
func AdminGrant(bindings []Binding) bool {
	return Allows(bindings, RoleWrite, System())
}

// EnsureAdminRemains refuses a state in which the deployment can no longer
// administer itself.
//
// after holds each remaining enabled subject's effective bindings as they
// would stand once a proposed change lands. The caller assembles it the same
// way a request is decided -- one effective-bindings fetch per subject, with
// group expansion done and role verbs expanded -- and simulates the change
// with the Without* helpers, or by omitting a subject that would be deleted
// or disabled (a disabled subject has no effective bindings at all).
//
// This is the pure half of self-lockout prevention: the mutation handlers for
// bindings, roles, groups, and subjects (C-016, U-007's server half) call it
// inside their transaction before committing, and Z-019's suite drives the
// end-to-end scenario once those handlers exist. It deliberately counts every
// vector the §5 scenario names: deleting a binding, deleting a role (whose
// bindings cascade), removing a group membership, deleting a group, deleting
// or disabling a subject, and narrowing a role's verbs -- the subtle one,
// where every binding survives and none of them matters.
func EnsureAdminRemains(after [][]Binding) error {
	if slices.ContainsFunc(after, AdminGrant) {
		return nil
	}
	return fmt.Errorf("%w: grant role:write at system to another subject before removing this one", ErrLastAdmin)
}

// WithoutBinding simulates deleting one binding by id. It copies rather than
// mutates, so a caller can test several changes against one fetched state.
func WithoutBinding(bindings []Binding, id string) []Binding {
	return without(bindings, func(b Binding) bool { return b.ID == id })
}

// WithoutRole simulates deleting a role: the store cascades every binding
// that granted it (F-005b), so they all go.
func WithoutRole(bindings []Binding, role string) []Binding {
	return without(bindings, func(b Binding) bool { return b.Role == role })
}

// WithoutGroup simulates a subject leaving a group -- by membership removal
// or by the group's deletion. Only the bindings that reached the subject
// through that group disappear; a direct binding to the same role stays.
func WithoutGroup(bindings []Binding, group string) []Binding {
	return without(bindings, func(b Binding) bool { return b.ViaGroup == group })
}

func without(bindings []Binding, drop func(Binding) bool) []Binding {
	out := make([]Binding, 0, len(bindings))
	for _, binding := range bindings {
		if !drop(binding) {
			out = append(out, binding)
		}
	}
	return out
}
