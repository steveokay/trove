package disclosure

import (
	"context"
	"reflect"
	"testing"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
	"github.com/steveokay/trove/internal/server"
)

// Surface: group resolution (ADR 0003, C-012).
//
// A group resolves first-match-wins over an ordered member list, so which
// member answers is observable in the digest that comes back. If a member the
// subject cannot read could win, could fail the group, or could merely appear
// in a skip list, the subject would learn it exists -- and §4 calls this the
// single easiest place in the registry to leak.
//
// The members are filtered before resolution and what remains answers exactly
// as a group configured without them would. These cases run the real pipeline
// the serving path will: the subject's effective bindings out of the store,
// compiled by the same filter, folded by the same resolution function. The
// HTTP half arrives with the task that mounts group serving on /v2/; when it
// does, it inherits this contract rather than restating it.

// groupMembers is the member list every case below filters: `secret` first --
// so it would win -- and `team-a` behind it. carol may read `team-a/api` and
// not `secret/vault`; root may read both.
func groupMembers() []repo.MemberState {
	return []repo.MemberState{
		{Repository: "secret", Content: "secret/vault", Type: meta.Hosted, Position: 0},
		{Repository: "team-a", Content: "team-a/api", Type: meta.Hosted, Position: 1},
	}
}

// memberBindings is the pipeline a group handler runs before resolving: the
// subject's effective bindings, exactly as every other guarded path fetches
// them.
func memberBindings(t *testing.T, f fixture, subject string) []authz.Binding {
	t.Helper()

	bindings, err := server.FetchBindings(context.Background(), f.store, subject)
	if err != nil {
		t.Fatalf("FetchBindings(%q): %v", subject, err)
	}
	return bindings
}

// resolveFor runs the whole pipeline for one subject: filter, then answer for
// every member that survived, then resolve.
func resolveFor(t *testing.T, f fixture, subject string, outcomes map[string]repo.MemberOutcome) repo.Resolution {
	t.Helper()

	set := repo.VisibleMembers(groupMembers(), memberBindings(t, f, subject))
	return repo.Resolve(set.With(outcomes), "latest")
}

func TestSurfaceGroupResolution(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	both := map[string]repo.MemberOutcome{
		"secret": repo.MemberServed,
		"team-a": repo.MemberServed,
	}

	// root reads both members, so the first in the order wins -- which is what
	// makes the next case meaningful: the hidden member really would have won.
	if got := resolveFor(t, f, "root", both); got.Member != "secret" {
		t.Fatalf("root's resolution served %q, want the first member %q", got.Member, "secret")
	}

	// carol reads only `team-a`, and gets its answer.
	got := resolveFor(t, f, "carol", both)
	if got.Member != "team-a" {
		t.Errorf("carol's resolution served %q, want %q", got.Member, "team-a")
	}

	// And it is identical, field for field, to what a group configured without
	// the hidden member returns -- not merely "also successful".
	absent := repo.Resolve(repo.AllMembers(groupMembers()[1]).With(both), "latest")
	if !reflect.DeepEqual(got, absent) {
		t.Errorf("filtered resolution = %+v, want the absent-member answer %+v", got, absent)
	}
}

// The hidden member cannot make itself felt through failure either. A required
// member that is down fails a group 503-class for a subject that may read it,
// and does not exist at all for one that may not.
func TestSurfaceGroupHiddenMemberCannotFailTheGroup(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	members := groupMembers()
	members[0].Required = true
	outcomes := map[string]repo.MemberOutcome{
		"secret": repo.MemberDown,
		"team-a": repo.MemberServed,
	}

	forRoot := repo.VisibleMembers(members, memberBindings(t, f, "root")).With(outcomes)
	if got := repo.Resolve(forRoot, "latest"); got.Outcome != repo.GroupUnavailable {
		t.Fatalf("root's resolution = %s, want the required member to fail the group", got.Outcome)
	}

	forCarol := repo.VisibleMembers(members, memberBindings(t, f, "carol")).With(outcomes)
	got := repo.Resolve(forCarol, "latest")
	if got.Outcome != repo.GroupServed || got.Member != "team-a" {
		t.Errorf("carol's resolution = %+v, want it served from team-a", got)
	}
	for _, skipped := range got.Skipped {
		if skipped.Repository == "secret" {
			// A skip is reported to the caller and becomes an event payload
			// naming the member: the one place a filtered member could still
			// speak.
			t.Error("a hidden member appears in carol's skip list")
		}
	}
}

// A subject that may read no member gets the answer an empty group gives.
// Anonymous holds nothing in this fixture, so it is the strongest version of
// the case: not "a group it may not use" but "a group with nothing in it".
func TestSurfaceGroupWithNoReadableMembers(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	outcomes := map[string]repo.MemberOutcome{
		"secret": repo.MemberServed,
		"team-a": repo.MemberServed,
	}
	set := repo.VisibleMembers(groupMembers(), memberBindings(t, f, meta.AnonymousSubjectName))
	if set.Len() != 0 {
		t.Fatalf("anonymous sees %+v, want nothing", set.Members())
	}

	got := repo.Resolve(set.With(outcomes), "latest")
	want := repo.Resolve(repo.AllMembers(), "latest")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolution = %+v, want the empty-group answer %+v", got, want)
	}
	if got.Outcome != repo.GroupNotFound {
		t.Errorf("outcome = %s, want not-found", got.Outcome)
	}
}
