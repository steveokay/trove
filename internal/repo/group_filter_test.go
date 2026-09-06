package repo_test

import (
	"reflect"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
)

// C-012: the members a subject cannot read are removed before resolution, and
// what remains is indistinguishable from a group that never had them.
//
// The property under test is a *negative* one -- no observable difference --
// so most of these cases are differential: the same request against a filtered
// group and against a group configured without the hidden member must produce
// results that are equal field for field.

// filterBinding grants repo:read within a scope.
func filterBinding(t *testing.T, scope string) authz.Binding {
	t.Helper()

	parsed, err := authz.ParseScope(scope)
	if err != nil {
		t.Fatalf("ParseScope(%q): %v", scope, err)
	}
	return authz.Binding{
		ID:    "b-" + scope,
		Role:  "developer",
		Scope: parsed,
		Verbs: []authz.Verb{authz.RepoRead},
	}
}

// filterMember builds one member of a group serving `library/nginx`.
func filterMember(entity string, position int) repo.MemberState {
	return repo.MemberState{
		Repository: entity,
		Content:    entity + "/library/nginx",
		Type:       meta.Proxy,
		Position:   position,
	}
}

func TestVisibleMembersFiltersByContentName(t *testing.T) {
	t.Parallel()

	members := []repo.MemberState{
		filterMember("internal", 0),
		filterMember("dockerhub", 1),
	}

	cases := []struct {
		name    string
		scopes  []string
		want    []string
		comment string
	}{
		{
			name:   "a scope over the member's content admits it",
			scopes: []string{"dockerhub/*"},
			want:   []string{"dockerhub"},
		},
		{
			// The decision is about the content the member would serve, not
			// about the entity: a subject scoped `dockerhub/*` may read
			// `dockerhub/library/nginx` and may not read the bare name, so
			// deciding against the entity would hide a member whose content
			// this subject is entitled to.
			name:   "a scope over the bare entity does not admit its content",
			scopes: []string{"dockerhub"},
			want:   nil,
		},
		{
			name:   "an exact scope over the content admits it",
			scopes: []string{"dockerhub/library/nginx"},
			want:   []string{"dockerhub"},
		},
		{
			name:   "the global scope admits every member",
			scopes: []string{"*"},
			want:   []string{"internal", "dockerhub"},
		},
		{
			name:   "no bindings admit nothing",
			scopes: nil,
			want:   nil,
		},
		{
			name:   "an unrelated scope admits nothing",
			scopes: []string{"team-a/*"},
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bindings := make([]authz.Binding, 0, len(tc.scopes))
			for _, scope := range tc.scopes {
				bindings = append(bindings, filterBinding(t, scope))
			}

			set := repo.VisibleMembers(members, bindings)
			got := make([]string, 0, set.Len())
			for _, member := range set.Members() {
				got = append(got, member.Repository)
			}
			if len(got) == 0 {
				got = nil
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("visible members = %v, want %v", got, tc.want)
			}
		})
	}
}

// A member the caller did not say how to address is dropped. It is fail-closed
// on purpose: no decision was reached about it, and a check that did not
// complete must not admit the request.
func TestVisibleMembersDropsUnaddressableMembers(t *testing.T) {
	t.Parallel()

	bindings := []authz.Binding{filterBinding(t, "*")}
	cases := []struct {
		name    string
		content string
	}{
		{"no content at all", ""},
		{"a name outside the grammar", "Dockerhub/Library"},
		{"a traversal attempt", "../etc/passwd"},
		{"a name with a path escape inside it", "dockerhub/../secret"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			member := filterMember("dockerhub", 0)
			member.Content = tc.content
			if set := repo.VisibleMembers([]repo.MemberState{member}, bindings); set.Len() != 0 {
				t.Errorf("visible members = %+v, want the member dropped", set.Members())
			}
		})
	}
}

// The acceptance criterion: a subject that may read only the second member gets
// the second member's answer, even though the first would have won.
func TestHiddenMemberCannotWin(t *testing.T) {
	t.Parallel()

	// `internal` is first in the order and has the reference; `dockerhub` is
	// second and also has it. A subject who may read both gets `internal`.
	members := []repo.MemberState{
		filterMember("internal", 0),
		filterMember("dockerhub", 1),
	}
	answers := map[string]repo.MemberOutcome{
		"internal":  repo.MemberServed,
		"dockerhub": repo.MemberServed,
	}

	everything := repo.VisibleMembers(members, []authz.Binding{filterBinding(t, "*")}).With(answers)
	if got := repo.Resolve(everything, "latest"); got.Member != "internal" {
		t.Fatalf("member = %q, want the first in the order", got.Member)
	}

	// The subject who may not read `internal` gets `dockerhub`, and the answer
	// is identical to the one a group configured without `internal` gives.
	restricted := repo.VisibleMembers(members, []authz.Binding{filterBinding(t, "dockerhub/*")}).With(answers)
	got := repo.Resolve(restricted, "latest")

	absent := repo.Resolve(repo.AllMembers(filterMember("dockerhub", 1)).With(answers), "latest")
	if !reflect.DeepEqual(got, absent) {
		t.Errorf("filtered resolution = %+v, want it identical to the absent-member one %+v", got, absent)
	}
	if got.Member != "dockerhub" {
		t.Errorf("member = %q, want dockerhub", got.Member)
	}
}

// Every way a hidden member could make itself felt, and the group that never
// had it, produce the same answer. This is the differential half of the
// criterion: not "the right member won" but "nothing observable changed".
func TestFilteredAndAbsentAreIndistinguishable(t *testing.T) {
	t.Parallel()

	hidden := filterMember("internal", 0)
	visible := filterMember("dockerhub", 1)

	cases := []struct {
		name string
		// hiddenOutcome is what the hidden member would have said, if anybody
		// had asked it. Nobody does -- it is filtered before the asking -- and
		// the point is that the group's answer does not depend on it.
		hiddenOutcome repo.MemberOutcome
		// hiddenRequired marks the hidden member as one the group supposedly
		// cannot answer without.
		hiddenRequired bool
		visibleOutcome repo.MemberOutcome
	}{
		{"the hidden member would have served", repo.MemberServed, false, repo.MemberServed},
		{"the hidden member would have missed", repo.MemberNotFound, false, repo.MemberServed},
		{"the hidden member is down", repo.MemberDown, false, repo.MemberServed},
		{"the hidden member answered with rubbish", repo.MemberMalformed, false, repo.MemberServed},
		{
			// The sharpest case. A required member that is down fails the whole
			// group 503-class -- but only for a subject that may read it. For
			// everybody else it does not exist, and a group that does not have
			// it answers from whoever does.
			name: "the hidden member is required and down", hiddenOutcome: repo.MemberDown,
			hiddenRequired: true, visibleOutcome: repo.MemberServed,
		},
		{"nobody has it", repo.MemberNotFound, false, repo.MemberNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			member := hidden
			member.Required = tc.hiddenRequired
			answers := map[string]repo.MemberOutcome{
				"internal":  tc.hiddenOutcome,
				"dockerhub": tc.visibleOutcome,
			}

			filtered := repo.VisibleMembers([]repo.MemberState{member, visible},
				[]authz.Binding{filterBinding(t, "dockerhub/*")}).With(answers)
			absent := repo.AllMembers(visible).With(answers)

			got := repo.Resolve(filtered, "latest")
			want := repo.Resolve(absent, "latest")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("filtered = %+v, want the absent-member answer %+v", got, want)
			}
			// And the hidden member is named nowhere in what comes back: not
			// as the winner, not in the skip list an event would be built from.
			if got.Member == "internal" {
				t.Error("a filtered member won the resolution")
			}
			for _, skipped := range got.Skipped {
				if skipped.Repository == "internal" {
					t.Error("a filtered member appears in the skip list")
				}
			}
		})
	}
}

// A subject that may read nothing gets the answer a group with no members
// gives -- not an error, not a 503, and nothing that says "there was something
// here".
func TestGroupWithEveryMemberFilteredIsAnEmptyGroup(t *testing.T) {
	t.Parallel()

	members := []repo.MemberState{filterMember("internal", 0), filterMember("dockerhub", 1)}
	members[0].Required = true

	blind := repo.VisibleMembers(members, nil)
	if blind.Len() != 0 {
		t.Fatalf("visible members = %+v, want none", blind.Members())
	}

	got := repo.Resolve(blind, "latest")
	want := repo.Resolve(repo.AllMembers(), "latest")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolution = %+v, want the empty-group answer %+v", got, want)
	}
	if got.Outcome != repo.GroupNotFound {
		t.Errorf("outcome = %s, want not-found", got.Outcome)
	}
}

// The set is a copy in both directions: a caller cannot add a filtered member
// back by editing what it was handed, and cannot answer for one that was never
// in the set.
func TestMemberSetIsNotAWindow(t *testing.T) {
	t.Parallel()

	members := []repo.MemberState{filterMember("internal", 0), filterMember("dockerhub", 1)}
	set := repo.VisibleMembers(members, []authz.Binding{filterBinding(t, "dockerhub/*")})

	edited := set.Members()
	edited[0].Repository = "internal"
	edited[0].Outcome = repo.MemberServed
	if got := set.Members(); got[0].Repository != "dockerhub" || got[0].Outcome != repo.MemberUnasked {
		t.Errorf("member = %+v, want the set unchanged by an edit to its copy", got[0])
	}

	// An outcome for a member outside the set is ignored rather than added:
	// nothing may re-enter the subject's view through an answer.
	answered := set.With(map[string]repo.MemberOutcome{
		"internal":  repo.MemberServed,
		"dockerhub": repo.MemberNotFound,
	})
	if answered.Len() != 1 {
		t.Fatalf("set = %+v, want only the visible member", answered.Members())
	}
	if got := repo.Resolve(answered, "latest"); got.Outcome != repo.GroupNotFound {
		t.Errorf("outcome = %s, want not-found: the outside answer must not count", got.Outcome)
	}

	// A member the caller did not answer for stays unasked, which Resolve
	// refuses rather than guessing about.
	unanswered := set.With(nil)
	if got := repo.Resolve(unanswered, "latest"); got.Outcome != repo.GroupInvalid {
		t.Errorf("outcome = %s, want invalid for an unasked member", got.Outcome)
	}
}

// Positions are stored configuration and survive filtering with their gaps
// intact: renumbering would make a subject's view of the ordering depend on
// what it cannot see.
func TestFilteringPreservesPositions(t *testing.T) {
	t.Parallel()

	members := []repo.MemberState{
		filterMember("internal", 0),
		filterMember("dockerhub", 7),
		filterMember("quay", 9),
	}
	set := repo.VisibleMembers(members, []authz.Binding{
		filterBinding(t, "dockerhub/*"), filterBinding(t, "quay/*"),
	})

	got := set.Members()
	if len(got) != 2 {
		t.Fatalf("visible members = %+v, want two", got)
	}
	if got[0].Position != 7 || got[1].Position != 9 {
		t.Errorf("positions = %d, %d, want them preserved as 7 and 9", got[0].Position, got[1].Position)
	}
}
