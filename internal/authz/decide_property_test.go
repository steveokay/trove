package authz_test

import (
	"testing"

	"github.com/steveokay/trove/internal/authz"
)

// The properties below are the reason the model is additive with no deny
// rules (Q14). Each one is something an operator relies on without being told:
// granting never takes access away, an unrelated grant changes nothing, and
// the answer does not depend on what order the store returned rows in.
//
// They are checked over generated binding sets rather than examples, because
// an example only ever proves the case somebody thought of.

// scopes and verbs are the alphabet the generated bindings are built from --
// small on purpose, so that overlaps, near-misses and disjoint cases all occur
// frequently rather than by luck.
var (
	propertyScopes = []authz.Scope{
		"system", "*", "team-a/*", "team-a/api", "team-a/sub/*", "team-b/*", "nginx",
	}
	propertyVerbs = []authz.Verb{
		authz.RepoRead, authz.RepoWrite, authz.RepoList, authz.UserWrite, authz.GCRun,
	}
	propertyResources = []string{
		"", // the system resource
		"team-a/api", "team-a", "team-a/sub/api", "team-b/api", "nginx", "other/thing",
	}
)

// bindingsFrom turns a byte string into a binding set, so a fuzzer can explore
// combinations without knowing anything about the types.
func bindingsFrom(seed []byte) []authz.Binding {
	var out []authz.Binding
	for i := 0; i+1 < len(seed) && i < 16; i += 2 {
		scope := propertyScopes[int(seed[i])%len(propertyScopes)]
		verb := propertyVerbs[int(seed[i+1])%len(propertyVerbs)]
		out = append(out, authz.Binding{
			ID:    string(rune('a' + i/2)),
			Role:  "generated",
			Scope: scope,
			Verbs: []authz.Verb{verb},
		})
	}
	return out
}

func resourceFrom(t *testing.T, index byte) authz.Resource {
	t.Helper()

	name := propertyResources[int(index)%len(propertyResources)]
	if name == "" {
		return authz.System()
	}
	return repository(t, name)
}

// FuzzDecideIsSoundAndComplete pins the decision to its definition: allowed
// exactly when some binding grants the verb at a covering scope, and Matched
// is exactly those bindings.
//
// Everything else in this file is a consequence of this one, but stating it
// separately is what turns a bug into a one-line diagnosis rather than a
// puzzle about which property broke.
func FuzzDecideIsSoundAndComplete(f *testing.F) {
	f.Add([]byte{0, 0}, byte(0), byte(0))
	f.Add([]byte{1, 1, 2, 2, 3, 3}, byte(1), byte(1))
	f.Add([]byte{}, byte(0), byte(2))

	f.Fuzz(func(t *testing.T, seed []byte, resourceIndex, verbIndex byte) {
		bindings := bindingsFrom(seed)
		resource := resourceFrom(t, resourceIndex)
		verb := propertyVerbs[int(verbIndex)%len(propertyVerbs)]

		decision := authz.Decide(bindings, verb, resource)

		var expected []string
		for _, b := range bindings {
			if b.Grants(verb) && b.Scope.Matches(resource) {
				expected = append(expected, b.ID)
			}
		}

		if decision.Allowed != (len(expected) > 0) {
			t.Fatalf("Allowed = %v but %d bindings grant %s on %s",
				decision.Allowed, len(expected), verb, resource)
		}
		if len(decision.Matched) != len(expected) {
			t.Fatalf("matched %d bindings, want %d (%v)", len(decision.Matched), len(expected), expected)
		}
		for i, b := range decision.Matched {
			if !b.Allows(verb, resource) {
				t.Fatalf("matched binding %s does not itself allow %s on %s", b.ID, verb, resource)
			}
			if i > 0 && decision.Matched[i-1].ID > b.ID {
				t.Fatalf("matched bindings are not ordered by id: %v", decision.Matched)
			}
		}
	})
}

// FuzzDecideIsMonotonic: adding a binding never revokes access.
//
// This is the property that makes "no deny rules" worth having. It is why an
// administrator can grant a team access to one more repository without
// auditing every other binding first, and why the order bindings are applied
// in cannot matter.
func FuzzDecideIsMonotonic(f *testing.F) {
	f.Add([]byte{0, 0}, []byte{1, 1}, byte(0), byte(0))
	f.Add([]byte{2, 2, 3, 3}, []byte{4, 4}, byte(1), byte(2))

	f.Fuzz(func(t *testing.T, seed, extra []byte, resourceIndex, verbIndex byte) {
		bindings := bindingsFrom(seed)
		added := bindingsFrom(extra)
		resource := resourceFrom(t, resourceIndex)
		verb := propertyVerbs[int(verbIndex)%len(propertyVerbs)]

		before := authz.Decide(bindings, verb, resource)
		after := authz.Decide(append(append([]authz.Binding{}, bindings...), added...), verb, resource)

		if before.Allowed && !after.Allowed {
			t.Fatalf("adding bindings revoked %s on %s", verb, resource)
		}
		if len(after.Matched) < len(before.Matched) {
			t.Fatalf("adding bindings dropped a matched binding: %v then %v",
				before.Matched, after.Matched)
		}
	})
}

// FuzzDecideIgnoresIrrelevantBindings: a binding that grants a different verb,
// or covers a different resource, changes nothing at all -- not the answer,
// and not the explanation an operator reads.
func FuzzDecideIgnoresIrrelevantBindings(f *testing.F) {
	f.Add([]byte{0, 0}, byte(0), byte(0), byte(3), byte(3))
	f.Add([]byte{1, 1, 2, 2}, byte(1), byte(1), byte(2), byte(4))

	f.Fuzz(func(t *testing.T, seed []byte, resourceIndex, verbIndex, otherScope, otherVerb byte) {
		bindings := bindingsFrom(seed)
		resource := resourceFrom(t, resourceIndex)
		verb := propertyVerbs[int(verbIndex)%len(propertyVerbs)]

		irrelevant := authz.Binding{
			ID:    "irrelevant",
			Role:  "generated",
			Scope: propertyScopes[int(otherScope)%len(propertyScopes)],
			Verbs: []authz.Verb{propertyVerbs[int(otherVerb)%len(propertyVerbs)]},
		}
		if irrelevant.Allows(verb, resource) {
			// It is relevant after all; monotonicity covers that case.
			return
		}

		before := authz.Decide(bindings, verb, resource)
		after := authz.Decide(append(append([]authz.Binding{}, bindings...), irrelevant), verb, resource)

		if before.Allowed != after.Allowed || len(before.Matched) != len(after.Matched) {
			t.Fatalf("an irrelevant binding changed the decision: %s then %s", before, after)
		}
		for _, b := range after.Matched {
			if b.ID == irrelevant.ID {
				t.Fatalf("an irrelevant binding was reported as a reason: %s", after)
			}
		}
	})
}

// FuzzDecideIsOrderIndependent: the store may return bindings in any order,
// and two subjects with the same grants must get the same answer and the same
// explanation.
func FuzzDecideIsOrderIndependent(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 2, 2}, byte(0), byte(0))
	f.Add([]byte{3, 3, 4, 4}, byte(2), byte(1))

	f.Fuzz(func(t *testing.T, seed []byte, resourceIndex, verbIndex byte) {
		bindings := bindingsFrom(seed)
		if len(bindings) < 2 {
			return
		}
		resource := resourceFrom(t, resourceIndex)
		verb := propertyVerbs[int(verbIndex)%len(propertyVerbs)]

		forward := authz.Decide(bindings, verb, resource)

		reversed := make([]authz.Binding, len(bindings))
		for i, b := range bindings {
			reversed[len(bindings)-1-i] = b
		}
		backward := authz.Decide(reversed, verb, resource)

		if forward.Allowed != backward.Allowed {
			t.Fatalf("order changed the answer: %v then %v", forward.Allowed, backward.Allowed)
		}
		if forward.String() != backward.String() {
			t.Fatalf("order changed the explanation:\n %s\n %s", forward, backward)
		}
	})
}

// FuzzDecideRespectsScopeBoundaries: no set of repository-scoped bindings ever
// authorizes anything at system scope, and nothing granted at system reaches a
// repository. The two are disjoint, which is why an administrator holds both.
func FuzzDecideRespectsScopeBoundaries(f *testing.F) {
	f.Add([]byte{1, 3}, byte(3))
	f.Add([]byte{2, 4, 6, 0}, byte(1))

	f.Fuzz(func(t *testing.T, seed []byte, verbIndex byte) {
		verb := propertyVerbs[int(verbIndex)%len(propertyVerbs)]

		var repositoryOnly, systemOnly []authz.Binding
		for _, b := range bindingsFrom(seed) {
			if b.Scope == authz.SystemScope {
				systemOnly = append(systemOnly, b)
				continue
			}
			repositoryOnly = append(repositoryOnly, b)
		}

		if authz.Allows(repositoryOnly, verb, authz.System()) {
			t.Fatalf("repository bindings authorized %s at system scope", verb)
		}
		for _, name := range propertyResources {
			if name == "" {
				continue
			}
			if authz.Allows(systemOnly, verb, repository(t, name)) {
				t.Fatalf("system bindings authorized %s on repository %s", verb, name)
			}
		}
	})
}
