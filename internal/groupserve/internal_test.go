package groupserve

import (
	"context"
	"log/slog"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
)

// The branches a stored configuration cannot reach.
//
// The store refuses a group as a member of a group, refuses duplicate
// positions, and only ever writes the three repository types -- so the
// defences below cannot fire from a request. They are still here, because this
// package decides which repositories get asked for content and a value nothing
// recognises must not become one of them. Tested at the unit level, which is
// the only level they exist at.

func TestDelegateForFailsClosedOnATypeNothingServes(t *testing.T) {
	t.Parallel()

	s := &Server{log: slog.New(slog.DiscardHandler)}
	for _, typ := range []meta.RepositoryType{meta.Group, meta.RepositoryType("virtual"), ""} {
		member := repo.MemberState{Repository: "member", Type: typ}
		delegate, outcome, askable := s.delegateFor(context.Background(), member)
		if askable || delegate != nil {
			t.Errorf("type %q produced a delegate", typ)
		}
		if outcome != repo.MemberDown {
			t.Errorf("type %q recorded %v, want down: the member exists and cannot be asked", typ, outcome)
		}
	}
}

func TestDelegateForReportsAMemberTypeWithNothingWiredAsDown(t *testing.T) {
	t.Parallel()

	// A proxy member in a deployment that has not wired proxying: it exists,
	// and this deployment cannot ask it.
	s := &Server{log: slog.New(slog.DiscardHandler)}
	member := repo.MemberState{Repository: "hub", Type: meta.Proxy}
	_, outcome, askable := s.delegateFor(context.Background(), member)
	if askable {
		t.Error("a member with no delegate was reported askable")
	}
	if outcome != repo.MemberDown {
		t.Errorf("outcome = %v, want down", outcome)
	}
}

func TestSortByPositionOrdersMembers(t *testing.T) {
	t.Parallel()

	members := []repo.MemberState{
		{Repository: "c", Position: 3},
		{Repository: "a", Position: 1},
		{Repository: "b", Position: 2},
	}
	sortByPosition(members)

	for i, want := range []string{"a", "b", "c"} {
		if members[i].Repository != want {
			t.Fatalf("order = %v, want a, b, c", members)
		}
	}
}
