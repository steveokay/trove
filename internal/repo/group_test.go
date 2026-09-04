package repo_test

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
)

// member builds a member state with the fields a case is not about left at
// their ordinary values: a hosted member that nobody marked required.
func member(name string, position int, outcome repo.MemberOutcome) repo.MemberState {
	return repo.MemberState{
		Repository: name,
		Type:       meta.Hosted,
		Position:   position,
		Outcome:    outcome,
	}
}

func required(m repo.MemberState) repo.MemberState {
	m.Required = true
	return m
}

func proxyMember(m repo.MemberState) repo.MemberState {
	m.Type = meta.Proxy
	return m
}

// The exhaustive matrix C-011 names. Every row is one shape of group the
// serving path can meet, and what it must answer.
func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		members  []repo.MemberState
		outcome  repo.GroupOutcome
		member   string
		position int
		reason   repo.SkipReason
		skipped  []repo.SkippedMember
	}{
		{
			// The whole point of the product: internal images win over the
			// cache, because the operator put them first.
			name: "same tag in two members, the earlier position wins",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberServed),
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
			},
			outcome: repo.GroupServed, member: "internal", position: 0,
		},
		{
			// And the answer depends on position, not on the order the caller
			// happened to collect the answers in.
			name: "position decides, not slice order",
			members: []repo.MemberState{
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
				member("internal", 0, repo.MemberServed),
			},
			outcome: repo.GroupServed, member: "internal", position: 0,
		},
		{
			name: "a member without the reference is passed over silently",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberNotFound),
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
			},
			outcome: repo.GroupServed, member: "dockerhub", position: 1,
		},
		{
			name: "a member being down does not fail the group",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberDown),
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
			},
			outcome: repo.GroupServed, member: "dockerhub", position: 1,
			skipped: []repo.SkippedMember{{Repository: "internal", Position: 0, Reason: repo.SkippedDown}},
		},
		{
			// Content that failed verification is not content. It is treated
			// as down for this request and never served through.
			name: "a malformed member is treated as down",
			members: []repo.MemberState{
				proxyMember(member("dockerhub", 0, repo.MemberMalformed)),
				member("internal", 1, repo.MemberServed),
			},
			outcome: repo.GroupServed, member: "internal", position: 1,
			skipped: []repo.SkippedMember{{Repository: "dockerhub", Position: 0, Reason: repo.SkippedMalformed}},
		},
		{
			name: "every skipped member before the winner is recorded, in position order",
			members: []repo.MemberState{
				member("c", 2, repo.MemberServed),
				proxyMember(member("b", 1, repo.MemberMalformed)),
				member("a", 0, repo.MemberDown),
			},
			outcome: repo.GroupServed, member: "c", position: 2,
			skipped: []repo.SkippedMember{
				{Repository: "a", Position: 0, Reason: repo.SkippedDown},
				{Repository: "b", Position: 1, Reason: repo.SkippedMalformed},
			},
		},
		{
			// A required member is one the operator says must be consulted
			// before anything else answers. Skipping it would serve a proxy's
			// copy of something the hosted member may have superseded.
			name: "a required member that is down fails the group",
			members: []repo.MemberState{
				required(member("internal", 0, repo.MemberDown)),
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
			},
			outcome: repo.GroupUnavailable, member: "internal", position: 0, reason: repo.SkippedDown,
		},
		{
			name: "a required member that is malformed fails the group",
			members: []repo.MemberState{
				required(member("internal", 0, repo.MemberMalformed)),
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
			},
			outcome: repo.GroupUnavailable, member: "internal", position: 0, reason: repo.SkippedMalformed,
		},
		{
			// Not having the reference is not failing. A required member is
			// required to be reachable, not to hold everything.
			name: "a required member that simply lacks the reference is passed over",
			members: []repo.MemberState{
				required(member("internal", 0, repo.MemberNotFound)),
				proxyMember(member("dockerhub", 1, repo.MemberServed)),
			},
			outcome: repo.GroupServed, member: "dockerhub", position: 1,
		},
		{
			// A member later in the order could not have won: an earlier one
			// already had the reference. Failing here would make the answer
			// depend on whether the caller asked eagerly or lazily.
			name: "a required member after the winner does not fail the group",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberServed),
				required(proxyMember(member("dockerhub", 1, repo.MemberDown))),
			},
			outcome: repo.GroupServed, member: "internal", position: 0,
		},
		{
			name: "an unasked member after the winner is not examined",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberServed),
				proxyMember(member("dockerhub", 1, repo.MemberUnasked)),
			},
			outcome: repo.GroupServed, member: "internal", position: 0,
		},
		{
			name: "the earlier required failure is the one that fails the group",
			members: []repo.MemberState{
				required(member("a", 0, repo.MemberDown)),
				required(member("b", 1, repo.MemberMalformed)),
			},
			outcome: repo.GroupUnavailable, member: "a", position: 0, reason: repo.SkippedDown,
		},
		{
			name: "all members lack the reference",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberNotFound),
				proxyMember(member("dockerhub", 1, repo.MemberNotFound)),
			},
			outcome: repo.GroupNotFound,
		},
		{
			name: "every member is down and none is required",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberDown),
				proxyMember(member("dockerhub", 1, repo.MemberDown)),
			},
			outcome: repo.GroupNotFound,
			skipped: []repo.SkippedMember{
				{Repository: "internal", Position: 0, Reason: repo.SkippedDown},
				{Repository: "dockerhub", Position: 1, Reason: repo.SkippedDown},
			},
		},
		{
			// A group whose members the subject may all read but which has
			// none, and a group whose members were all filtered away, are the
			// same list here -- which is what makes the filtering invisible
			// (C-012).
			name: "empty member list", members: nil, outcome: repo.GroupNotFound,
		},
		{
			name: "empty member list, non-nil slice", members: []repo.MemberState{}, outcome: repo.GroupNotFound,
		},
		{
			name:    "negative positions still order",
			members: []repo.MemberState{member("b", 3, repo.MemberServed), member("a", -1, repo.MemberNotFound)},
			outcome: repo.GroupServed, member: "b", position: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The caller's slice must come back untouched: a pure function
			// that reorders its input is not one.
			before := slices.Clone(tt.members)
			got := repo.Resolve(tt.members, "v1.2.3")
			if !slices.Equal(tt.members, before) {
				t.Errorf("Resolve reordered its caller's slice: %+v", tt.members)
			}

			if got.Err != nil {
				t.Fatalf("Resolve: %v", got.Err)
			}
			if got.Outcome != tt.outcome || got.Member != tt.member || got.Position != tt.position || got.Reason != tt.reason {
				t.Errorf("Resolve = %+v, want outcome=%v member=%q position=%d reason=%q",
					got, tt.outcome, tt.member, tt.position, tt.reason)
			}
			if got.Reference != "v1.2.3" {
				t.Errorf("resolution carries reference %q, want %q", got.Reference, "v1.2.3")
			}
			if !slices.Equal(got.Skipped, tt.skipped) {
				t.Errorf("skipped = %+v, want %+v", got.Skipped, tt.skipped)
			}
			if got.String() == "" {
				t.Error("String() is empty")
			}
		})
	}
}

// The lists Resolve refuses rather than resolves. Each is something the
// metadata schema or the configuration layer already prevents, which is exactly
// why the failure has to be loud: a silent one would be a group serving a digest
// nobody can account for.
func TestResolveRefusesUnresolvableMemberLists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members []repo.MemberState
	}{
		{
			// ADR 0005: groups do not nest. The configuration layer refuses to
			// create such a member; this is the assertion that it held.
			name: "a member that is itself a group",
			members: []repo.MemberState{
				{Repository: "inner", Type: meta.Group, Position: 0, Outcome: repo.MemberServed},
			},
		},
		{
			name: "a nested group behind a member that would have served first",
			members: []repo.MemberState{
				member("internal", 0, repo.MemberServed),
				{Repository: "inner", Type: meta.Group, Position: 1, Outcome: repo.MemberNotFound},
			},
		},
		{
			name: "a member of no known type",
			members: []repo.MemberState{
				{Repository: "odd", Type: meta.RepositoryType("virtual"), Position: 0, Outcome: repo.MemberServed},
			},
		},
		{
			name: "a member with no type at all",
			members: []repo.MemberState{
				{Repository: "odd", Position: 0, Outcome: repo.MemberServed},
			},
		},
		{
			// A tie in an ordering that decides which digest gets served is an
			// error, never a coin flip.
			name: "two members at one position",
			members: []repo.MemberState{
				member("a", 0, repo.MemberServed),
				member("b", 0, repo.MemberServed),
			},
		},
		{
			name: "one member listed twice",
			members: []repo.MemberState{
				member("a", 0, repo.MemberNotFound),
				member("a", 1, repo.MemberServed),
			},
		},
		{
			name:    "a member name that is not a legal entity name",
			members: []repo.MemberState{member("Internal", 0, repo.MemberServed)},
		},
		{
			name:    "a member name that spans segments",
			members: []repo.MemberState{member("team-a/api", 0, repo.MemberServed)},
		},
		{
			name:    "a member name that traverses",
			members: []repo.MemberState{member("../etc", 0, repo.MemberServed)},
		},
		{
			name:    "an empty member name",
			members: []repo.MemberState{member("", 0, repo.MemberServed)},
		},
		{
			name:    "a member claiming the reserved prefix",
			members: []repo.MemberState{member("system", 0, repo.MemberServed)},
		},
		{
			// Nobody established what this member would have said, and
			// guessing is how a group serves the wrong digest.
			name:    "a member before the winner that was never asked",
			members: []repo.MemberState{member("a", 0, repo.MemberUnasked), member("b", 1, repo.MemberServed)},
		},
		{
			name:    "a member outcome outside the vocabulary",
			members: []repo.MemberState{member("a", 0, repo.MemberOutcome(99))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := repo.Resolve(tt.members, "latest")
			if got.Outcome != repo.GroupInvalid {
				t.Fatalf("Resolve = %+v, want GroupInvalid", got)
			}
			if got.Err == nil {
				t.Fatal("a refused member list came back with no error")
			}
			if !errors.Is(got.Err, repo.ErrInvalidGroup) {
				t.Errorf("error %v is not repo.ErrInvalidGroup", got.Err)
			}
			// A refusal must not also carry half a resolution: events for
			// members that were walked before the bad one would be emitted for
			// a request that never happened.
			if got.Member != "" || got.Skipped != nil {
				t.Errorf("a refusal carries a partial resolution: %+v", got)
			}
			if got.String() == "" {
				t.Error("String() is empty")
			}
		})
	}
}

// A refusal names the member, because "invalid group" on its own leaves an
// operator reading every row of the member list.
func TestGroupErrorNamesTheMember(t *testing.T) {
	t.Parallel()

	got := repo.Resolve([]repo.MemberState{
		{Repository: "inner", Type: meta.Group, Position: 0, Outcome: repo.MemberServed},
	}, "latest")
	var groupErr *repo.GroupError
	if !errors.As(got.Err, &groupErr) {
		t.Fatalf("error %v is not a *repo.GroupError", got.Err)
	}
	if groupErr.Member != "inner" {
		t.Errorf("error names member %q, want %q", groupErr.Member, "inner")
	}

	// The rendering without a member is the other half of the type, and it has
	// to still say what went wrong.
	bare := &repo.GroupError{Reason: "something structural"}
	if bare.Error() == "" || bare.Member != "" {
		t.Errorf("GroupError{Reason: ...}.Error() = %q", bare.Error())
	}
}

// The stringers are what a log line and an error message are built from, so
// every value in both vocabularies has to render as something an operator can
// read -- including the ones that should never occur.
func TestOutcomeStrings(t *testing.T) {
	t.Parallel()

	for outcome, want := range map[repo.MemberOutcome]string{
		repo.MemberUnasked:     "unasked",
		repo.MemberServed:      "served",
		repo.MemberNotFound:    "not-found",
		repo.MemberDown:        "down",
		repo.MemberMalformed:   "malformed",
		repo.MemberOutcome(99): "outcome(99)",
	} {
		if got := outcome.String(); got != want {
			t.Errorf("MemberOutcome(%d).String() = %q, want %q", outcome, got, want)
		}
	}
	for outcome, want := range map[repo.GroupOutcome]string{
		repo.GroupInvalid:     "invalid",
		repo.GroupServed:      "served",
		repo.GroupNotFound:    "not-found",
		repo.GroupUnavailable: "unavailable",
		repo.GroupOutcome(99): "outcome(99)",
	} {
		if got := outcome.String(); got != want {
			t.Errorf("GroupOutcome(%d).String() = %q, want %q", outcome, got, want)
		}
	}
	// A Resolution nobody built renders as the refusal it is, rather than as a
	// successful one with empty fields.
	var zero repo.Resolution
	if zero.Outcome != repo.GroupInvalid || zero.String() == "" {
		t.Errorf("the zero Resolution = %+v / %q", zero, zero.String())
	}
}

// EventMemberSkipped is the wire name of an event operators subscribe webhooks
// to, so it is contract rather than an implementation detail.
func TestSkippedEventName(t *testing.T) {
	t.Parallel()

	if repo.EventMemberSkipped != "group.member.skipped" {
		t.Errorf("EventMemberSkipped = %q, want group.member.skipped", repo.EventMemberSkipped)
	}
}

// Determinism is the property the whole design exists for. The result depends
// on the members' positions and states and on nothing else -- not on the order
// the caller collected the answers in, which is what lets a caller ask its
// members concurrently.
func TestResolveIsDeterministicUnderPermutation(t *testing.T) {
	t.Parallel()

	members := []repo.MemberState{
		member("a", 0, repo.MemberDown),
		proxyMember(member("b", 1, repo.MemberMalformed)),
		required(member("c", 2, repo.MemberNotFound)),
		proxyMember(member("d", 3, repo.MemberServed)),
		member("e", 4, repo.MemberServed),
	}
	want := repo.Resolve(members, "latest")
	if want.Outcome != repo.GroupServed || want.Member != "d" {
		t.Fatalf("fixture resolves to %+v, which is not the case this test is about", want)
	}

	permuted := slices.Clone(members)
	rng := rand.New(rand.NewSource(1))
	for range 200 {
		rng.Shuffle(len(permuted), func(i, j int) { permuted[i], permuted[j] = permuted[j], permuted[i] })
		if got := repo.Resolve(permuted, "latest"); !reflect.DeepEqual(got, want) {
			t.Fatalf("permutation %+v resolved to %+v, want %+v", permuted, got, want)
		}
	}
}

// fuzzMembers decodes a fuzzer's bytes into a member list: one byte per member,
// each carrying a type, a required flag, and an outcome. Positions come from
// the index, so the list is always well formed structurally -- the shapes this
// target is about are the state combinations, not the ones
// TestResolveRefusesUnresolvableMemberLists already covers.
func fuzzMembers(encoded []byte) []repo.MemberState {
	outcomes := []repo.MemberOutcome{
		repo.MemberUnasked, repo.MemberServed, repo.MemberNotFound,
		repo.MemberDown, repo.MemberMalformed,
	}
	types := []meta.RepositoryType{meta.Hosted, meta.Proxy}

	members := make([]repo.MemberState, 0, len(encoded))
	for i, b := range encoded {
		members = append(members, repo.MemberState{
			Repository: fmt.Sprintf("m%d", i),
			Type:       types[int(b>>5)%len(types)],
			Position:   i,
			Required:   b&0x10 != 0,
			Outcome:    outcomes[int(b&0x0f)%len(outcomes)],
		})
	}
	return members
}

// FuzzResolve asserts what the table cannot enumerate: over every combination
// of member states, resolution stays deterministic under permutation, never
// serves through a member that could not answer, and never quietly answers past
// a required member that failed.
func FuzzResolve(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{},
		{0x01},
		{0x02, 0x01},
		{0x03, 0x11, 0x01},
		{0x13, 0x01},
		{0x04, 0x14, 0x02},
		{0x00, 0x01},
		{0x02, 0x02, 0x02, 0x02},
		{0xff, 0x7f, 0x3f, 0x1f, 0x0f},
	} {
		f.Add(seed, uint64(7))
	}

	f.Fuzz(func(t *testing.T, encoded []byte, seed uint64) {
		// A bound, so a pathological input is a slow test rather than a
		// timeout; the invariants do not get more interesting past it.
		if len(encoded) > 64 {
			encoded = encoded[:64]
		}
		members := fuzzMembers(encoded)
		got := repo.Resolve(members, "latest")

		// The list is structurally well formed by construction, so a refusal
		// can only mean an unasked member before the winner.
		if got.Outcome == repo.GroupInvalid {
			if !errors.Is(got.Err, repo.ErrInvalidGroup) {
				t.Fatalf("refusal %v is not ErrInvalidGroup", got.Err)
			}
			if got.Skipped != nil || got.Member != "" {
				t.Fatalf("refusal carries a partial resolution: %+v", got)
			}
			return
		}
		if got.Err != nil {
			t.Fatalf("%v outcome carries an error: %v", got.Outcome, got.Err)
		}

		// Determinism: the answer is a function of positions and states.
		permuted := slices.Clone(members)
		// A reproducible shuffle, so a failing permutation is replayable from
		// the corpus entry rather than only from the crasher.
		rng := rand.New(rand.NewSource(int64(seed)))
		rng.Shuffle(len(permuted), func(i, j int) { permuted[i], permuted[j] = permuted[j], permuted[i] })
		if again := repo.Resolve(permuted, "latest"); !reflect.DeepEqual(again, got) {
			t.Fatalf("permuting the member list changed the answer: %+v vs %+v", again, got)
		}

		byName := make(map[string]repo.MemberState, len(members))
		for _, m := range members {
			byName[m.Repository] = m
		}

		// Nothing is ever served through a member that did not serve, and the
		// winner is the earliest member that could.
		switch got.Outcome {
		case repo.GroupServed:
			winner, ok := byName[got.Member]
			if !ok || winner.Outcome != repo.MemberServed {
				t.Fatalf("served from %q, whose outcome is %v", got.Member, winner.Outcome)
			}
			if winner.Position != got.Position {
				t.Fatalf("served from %q at position %d, want %d", got.Member, got.Position, winner.Position)
			}
			for _, m := range members {
				if m.Position < winner.Position && m.Outcome == repo.MemberServed {
					t.Fatalf("served from position %d while position %d also served", winner.Position, m.Position)
				}
			}
		case repo.GroupUnavailable:
			failed, ok := byName[got.Member]
			if !ok || !failed.Required {
				t.Fatalf("the group failed on %q, which is not a required member", got.Member)
			}
			if failed.Outcome != repo.MemberDown && failed.Outcome != repo.MemberMalformed {
				t.Fatalf("the group failed on %q, whose outcome is %v", got.Member, failed.Outcome)
			}
		case repo.GroupNotFound:
			for _, m := range members {
				if m.Outcome == repo.MemberServed {
					t.Fatalf("not-found while member %q served", m.Repository)
				}
			}
		default:
			t.Fatalf("outcome %v is outside the vocabulary", got.Outcome)
		}

		// A required member that failed before anything served always fails
		// the group: it is the whole meaning of the flag, and skipping it
		// would answer from a member the operator said must be consulted
		// first.
		firstServed := len(members)
		for _, m := range members {
			if m.Outcome == repo.MemberServed && m.Position < firstServed {
				firstServed = m.Position
			}
		}
		firstRequiredFailure := -1
		for _, m := range members {
			failed := m.Outcome == repo.MemberDown || m.Outcome == repo.MemberMalformed
			if m.Required && failed && m.Position < firstServed {
				if firstRequiredFailure == -1 || m.Position < firstRequiredFailure {
					firstRequiredFailure = m.Position
				}
			}
		}
		if firstRequiredFailure >= 0 {
			if got.Outcome != repo.GroupUnavailable {
				t.Fatalf("required member at position %d failed and the group answered %v",
					firstRequiredFailure, got.Outcome)
			}
			if got.Position != firstRequiredFailure {
				t.Fatalf("the group failed at position %d, want the earliest at %d",
					got.Position, firstRequiredFailure)
			}
		}

		// Every recorded skip is a member that really could not answer, they
		// are in position order, and none of them is the required member that
		// stopped the resolution.
		var lastPosition = -1 - len(members)
		for _, skipped := range got.Skipped {
			m, ok := byName[skipped.Repository]
			if !ok {
				t.Fatalf("skipped %q, which is not a member", skipped.Repository)
			}
			if m.Required {
				t.Fatalf("skipped the required member %q instead of failing the group", skipped.Repository)
			}
			wantReason := repo.SkippedDown
			if m.Outcome == repo.MemberMalformed {
				wantReason = repo.SkippedMalformed
			}
			if m.Outcome != repo.MemberDown && m.Outcome != repo.MemberMalformed {
				t.Fatalf("skipped %q, whose outcome is %v", skipped.Repository, m.Outcome)
			}
			if skipped.Reason != wantReason || skipped.Position != m.Position {
				t.Fatalf("skip record %+v does not describe member %+v", skipped, m)
			}
			if skipped.Position <= lastPosition {
				t.Fatalf("skip records are out of position order: %+v", got.Skipped)
			}
			lastPosition = skipped.Position
		}
	})
}
