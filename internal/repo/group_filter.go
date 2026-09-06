package repo

import (
	"slices"

	"github.com/steveokay/trove/internal/authz"
)

// Permission filtering before group resolution (C-012).
//
// A group is the single easiest place in this registry to leak the existence of
// a repository (§4). Resolution is first-match-wins over an ordered member list,
// so *which* member answers is observable in the digest that comes back -- and
// if an unreadable member could win, or could fail, or could merely take longer
// than the readable one behind it, a subject would learn that it exists.
//
// The rule is therefore that filtering happens *before* resolution, and that a
// member the subject cannot read is removed rather than skipped: a skipped
// member appears in the resolution and in a `group.member.skipped` event, and a
// removed one appears nowhere. What remains looks exactly like a group that was
// configured without it.
//
// The wall is the type. Resolve does not take a slice of members; it takes a
// MemberSet, and the only ways to build one are to filter for a subject or to
// say in as many words that this caller has no subject to filter for. That is
// the same shape meta.Visibility uses for the same reason (§5.3): a bare slice
// reads as "no filtering" and would silently mean "everything".

// MemberSet is a group's member list as one subject may see it.
//
// The zero value is an empty set -- a group with no readable members -- which
// resolves exactly as a group with no members at all does. That equivalence is
// what makes the filtering invisible, and it is C-011's property rather than
// this file's: an empty member list answers GroupNotFound.
type MemberSet struct {
	members []MemberState
}

// AllMembers returns an unfiltered set.
//
// It is the subjectless path -- a maintenance task, a configuration check, a
// test -- and it is named rather than implicit so that a reviewer reading a
// call site can ask "whose members are these?" and get an answer. Nothing that
// serves a request may use it: a request always has a subject, even when that
// subject is anonymous (ADR 0001).
func AllMembers(members ...MemberState) MemberSet {
	return MemberSet{members: slices.Clone(members)}
}

// VisibleMembers returns the members the subject's bindings permit reading.
//
// The decision is `repo:read` against each member's Content -- the full content
// name a request would ask that member for -- and not against the member entity.
// A subject bound to `dockerhub/*` can read `dockerhub/library/nginx` and cannot
// read the bare name `dockerhub` (ADR 0001's scope grammar), so deciding against
// the entity would hide a member whose content the subject is entitled to and
// turn a legitimate pull into a 404.
//
// A member with no Content, or a Content that is not a legal repository name, is
// dropped. That is fail-closed and deliberate: a member the caller did not say
// how to address is one no decision was reached about, and a check that did not
// complete must not admit the request (§5). Dropped looks exactly like
// unreadable, which looks exactly like absent.
//
// Order and positions are preserved untouched. Positions are stored
// configuration and gaps are expected: renumbering after filtering would make a
// subject's view of the ordering depend on what it cannot see.
func VisibleMembers(members []MemberState, bindings []authz.Binding) MemberSet {
	visible := make([]MemberState, 0, len(members))
	for _, member := range members {
		resource, err := authz.Repository(member.Content)
		if err != nil {
			continue
		}
		if !authz.Allows(bindings, authz.RepoRead, resource) {
			continue
		}
		visible = append(visible, member)
	}
	return MemberSet{members: visible}
}

// Members returns the set's members, for a caller that has to ask them.
//
// It is a copy: the set is what Resolve folds over, and a caller that could
// edit it in place could add back a member the filter removed.
func (s MemberSet) Members() []MemberState { return slices.Clone(s.members) }

// Len reports how many members the subject may see.
func (s MemberSet) Len() int { return len(s.members) }

// With returns the set with outcomes filled in, keyed by member repository.
//
// A member absent from the map keeps the outcome it had, which for a set fresh
// from a filter means MemberUnasked -- the honest record of a caller that
// stopped asking once something served. An outcome for a member not in the set
// is ignored rather than added: the set is the subject's view of the group, and
// nothing outside it may re-enter through an answer.
func (s MemberSet) With(outcomes map[string]MemberOutcome) MemberSet {
	answered := slices.Clone(s.members)
	for i, member := range answered {
		if outcome, ok := outcomes[member.Repository]; ok {
			answered[i].Outcome = outcome
		}
	}
	return MemberSet{members: answered}
}
