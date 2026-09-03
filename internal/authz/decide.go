package authz

import (
	"fmt"
	"strings"
)

// Decision is the outcome of an authorization check together with every
// binding that contributed to it.
//
// The matched bindings are not diagnostics. The effective-permission explainer
// (`trove auth explain`, Z-013) is this same call rendered differently, rather
// than a parallel implementation that can drift from the one that actually
// decides -- which is what makes "why does alice have this?" answerable with
// the truth instead of a reconstruction.
type Decision struct {
	// Allowed is the answer.
	Allowed bool
	// Verb and Resource are what was asked, carried so an audit record and a
	// denial metric can be built from the decision alone (ADR 0001).
	Verb     Verb
	Resource Resource
	// Matched holds every binding that granted the verb on the resource,
	// ordered by binding id. It is empty for a denial: there is nothing to
	// explain except the absence.
	Matched []Binding
}

// Decide answers whether the bindings permit the verb on the resource.
//
// It is pure: no I/O, no clock, no configuration. The caller resolves the
// subject to its effective bindings first -- its own plus those reaching it
// through a group, with each role's verbs expanded, and with a disabled
// subject resolving to none -- so this function sees only values (ADR 0001).
//
// The rule is a union with no subtraction: allowed if at least one binding
// grants the verb at a scope covering the resource. There are no deny rules
// (Q14), so overlapping patterns need no precedence, evaluation order cannot
// matter, and adding a binding can never take access away. That is what makes
// the whole model property-testable rather than merely tested.
func Decide(bindings []Binding, verb Verb, resource Resource) Decision {
	decision := Decision{Verb: verb, Resource: resource}

	// A verb outside the vocabulary is refused before any binding is
	// considered. A binding could hold one -- nothing stops a row being
	// edited in the database -- and a permission nothing enforces must not
	// become one that everything does.
	if !verb.Valid() {
		return decision
	}

	for _, binding := range bindings {
		if binding.Allows(verb, resource) {
			decision.Allowed = true
			decision.Matched = append(decision.Matched, binding)
		}
	}
	SortBindings(decision.Matched)
	return decision
}

// Allows is the common case, where the caller wants the answer and not the
// explanation.
func Allows(bindings []Binding, verb Verb, resource Resource) bool {
	return Decide(bindings, verb, resource).Allowed
}

// String renders a decision the way an audit record and the explainer report
// it: the answer, what was asked, and which grants produced it.
func (d Decision) String() string {
	var out strings.Builder
	if d.Allowed {
		out.WriteString("allowed ")
	} else {
		out.WriteString("denied ")
	}
	fmt.Fprintf(&out, "%s on %s", d.Verb, d.Resource)

	if !d.Allowed {
		// Naming what was missing rather than listing what was held: an
		// operator reading a denial wants to know what to grant.
		out.WriteString(": no binding grants it")
		return out.String()
	}

	out.WriteString(" by ")
	for i, binding := range d.Matched {
		if i > 0 {
			out.WriteString(", ")
		}
		fmt.Fprintf(&out, "%s (role %s at %s", binding.ID, binding.Role, binding.Scope)
		if binding.ViaGroup != "" {
			// The group is the answer to "why do I have this?" more often
			// than the binding id is.
			fmt.Fprintf(&out, " via group %s", binding.ViaGroup)
		}
		out.WriteString(")")
	}
	return out.String()
}
