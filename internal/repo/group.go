package repo

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/steveokay/trove/internal/meta"
)

// EventMemberSkipped is the event type emitted for each member a group passed
// over because it could not answer (ADR 0005, §8). Resolve does not emit it --
// it does no I/O -- it returns the payloads and the caller publishes them.
const EventMemberSkipped = "group.member.skipped"

// ErrInvalidGroup reports a member list Resolve refuses to resolve at all.
// Callers assert with errors.Is.
var ErrInvalidGroup = errors.New("invalid group member list")

// GroupError names the member that made a list unresolvable and why.
type GroupError struct {
	Member string
	Reason string
}

func (e *GroupError) Error() string {
	if e.Member == "" {
		return fmt.Sprintf("invalid group member list: %s", e.Reason)
	}
	return fmt.Sprintf("invalid group member list: member %q: %s", e.Member, e.Reason)
}

// Is makes errors.Is(err, ErrInvalidGroup) true for this typed error.
func (e *GroupError) Is(target error) bool { return target == ErrInvalidGroup }

func groupErr(member, reason string) error { return &GroupError{Member: member, Reason: reason} }

// MemberOutcome is what asking one member for a reference produced. The caller
// does the asking; this is how it reports the answer.
type MemberOutcome uint8

// The outcomes a member can produce. The zero value means the member was not
// asked, so a MemberState nobody filled in is refused rather than read as a
// clean miss.
const (
	// MemberUnasked is the zero value. Resolve stops at the first member that
	// serves, so a caller that asks lazily may leave the members after it
	// unasked; one before the winner is a caller bug and is refused.
	MemberUnasked MemberOutcome = iota
	// MemberServed: the member has the reference and can serve it.
	MemberServed
	// MemberNotFound: the member does not have the reference. The ordinary
	// answer, and not a fault -- it is passed over silently.
	MemberNotFound
	// MemberDown: the member could not be asked -- unreachable upstream, a
	// dial or DNS failure, a 5xx, a timeout, a rate-limit backoff.
	MemberDown
	// MemberMalformed: the member answered with content that did not verify --
	// a malformed manifest, or a digest that is not the one requested. Treated
	// as down for this request and never served through (ADR 0005): content
	// that failed verification is not content.
	MemberMalformed
)

// String renders an outcome for errors and log lines.
func (o MemberOutcome) String() string {
	switch o {
	case MemberUnasked:
		return "unasked"
	case MemberServed:
		return "served"
	case MemberNotFound:
		return "not-found"
	case MemberDown:
		return "down"
	case MemberMalformed:
		return "malformed"
	default:
		return fmt.Sprintf("outcome(%d)", uint8(o))
	}
}

// MemberState is one group member the subject may read, together with the
// outcome of asking it for the reference.
//
// It carries no store, no client, and no upstream: the caller asks the members
// and hands in the answers. That is what keeps Resolve pure and exhaustively
// table-testable, and it is what lets C-012 drop the members the subject cannot
// read before this function ever sees a list.
type MemberState struct {
	// Repository is the member entity's name.
	Repository string
	// Type is the member's repository type, carried so that a group inside a
	// group is caught here rather than resolved. Groups do not nest (ADR 0005)
	// and the configuration layer refuses to create such a member; this is the
	// assertion that the refusal held.
	Type meta.RepositoryType
	// Position is the member's place in the group's explicit ordering. It is
	// the only thing that orders resolution -- the order of the slice handed in
	// does not matter, which is what makes the result reproducible from stored
	// configuration alone.
	Position int
	// Required marks a member the group cannot answer without. A required
	// member that fails takes the group down instead of being skipped.
	Required bool
	// Outcome is what asking the member produced.
	Outcome MemberOutcome
}

// SkipReason says why a member could not answer. It distinguishes an
// unreachable member from one that answered with content that did not verify,
// because those are different operational problems even though the group treats
// them the same way.
type SkipReason string

// The two ways a member fails to answer.
const (
	// SkippedDown: the member could not be reached.
	SkippedDown SkipReason = "down"
	// SkippedMalformed: the member answered, and the answer did not verify.
	SkippedMalformed SkipReason = "malformed"
)

// SkippedMember is one member the group passed over because it could not
// answer. It is the payload of an EventMemberSkipped event.
type SkippedMember struct {
	Repository string
	Position   int
	Reason     SkipReason
}

// GroupOutcome is what resolving a group produced.
type GroupOutcome uint8

// The four answers a group resolution can give.
const (
	// GroupInvalid is the zero value: a Resolution nobody built resolves to
	// nothing, and a member list Resolve refuses lands here too. It is a
	// 500-class answer -- a bug in the configuration layer, not in the request.
	GroupInvalid GroupOutcome = iota
	// GroupServed: a member has the reference. 200-class.
	GroupServed
	// GroupNotFound: no readable member has it. 404-class, NAME_UNKNOWN or
	// MANIFEST_UNKNOWN per ADR 0003. An empty member list lands here, which is
	// what makes a group whose members are all filtered away indistinguishable
	// from a group with no members (C-012).
	GroupNotFound
	// GroupUnavailable: a required member could not answer. 503-class.
	GroupUnavailable
)

// String renders an outcome for log lines.
func (o GroupOutcome) String() string {
	switch o {
	case GroupInvalid:
		return "invalid"
	case GroupServed:
		return "served"
	case GroupNotFound:
		return "not-found"
	case GroupUnavailable:
		return "unavailable"
	default:
		return fmt.Sprintf("outcome(%d)", uint8(o))
	}
}

// Resolution is what a group did with one reference.
type Resolution struct {
	// Outcome is the answer.
	Outcome GroupOutcome
	// Reference is what was asked for, carried so a log line or an event can
	// be built from the resolution alone.
	Reference string
	// Member and Position name the member the outcome is about: the one that
	// served for GroupServed, and the required member that failed for
	// GroupUnavailable. Empty and zero for the other two outcomes.
	Member   string
	Position int
	// Reason says how the required member failed, for GroupUnavailable. Empty
	// otherwise.
	Reason SkipReason
	// Skipped lists, in position order, every member passed over because it
	// could not answer -- one EventMemberSkipped event each, for the caller to
	// emit. A required member that failed the group is not in here: it did not
	// get skipped, it stopped the resolution, and Member names it.
	Skipped []SkippedMember
	// Err explains a GroupInvalid outcome and is nil for every other one.
	Err error
}

// String renders a resolution for log lines.
func (r Resolution) String() string {
	switch r.Outcome {
	case GroupServed:
		return fmt.Sprintf("served %q from member %q (position %d), %d member(s) skipped",
			r.Reference, r.Member, r.Position, len(r.Skipped))
	case GroupNotFound:
		return fmt.Sprintf("no member has %q, %d member(s) skipped", r.Reference, len(r.Skipped))
	case GroupUnavailable:
		return fmt.Sprintf("required member %q (position %d) is %s, cannot resolve %q",
			r.Member, r.Position, r.Reason, r.Reference)
	default:
		return fmt.Sprintf("cannot resolve %q: %v", r.Reference, r.Err)
	}
}

// Resolve is the group resolution function of ADR 0005: a pure fold over an
// already permission-filtered member list.
//
// It performs no I/O, takes no store and no clock, and holds no upstream
// client. The caller asks the members -- in whatever order and with whatever
// concurrency it likes -- and hands in what they said. The rules:
//
//   - The first member by position that can serve the reference wins. Order is
//     explicit configuration and nothing else; the slice order is irrelevant.
//   - A member that does not have the reference is passed over silently. Not
//     having it is the ordinary answer.
//   - A member that is down is skipped, and the resolution records an
//     EventMemberSkipped payload for the caller to emit. One member being down
//     must not fail a group.
//   - Unless that member is Required, in which case the group fails
//     GroupUnavailable rather than quietly answering from a member the operator
//     said must be consulted first.
//   - A member whose content did not verify -- malformed manifest, digest
//     mismatch -- is treated exactly as down for this request and is never
//     served through.
//
// Members after the winner are not examined: the caller may have stopped asking
// there, and the answer must not depend on whether it did. A required member
// after the winner therefore does not fail the group -- it could not have won
// anyway, because a member earlier in the explicit order already had the
// reference.
//
// Determinism is the property the whole design exists for: the result is a
// function of the member states and their positions, so an operator can
// reproduce a resolution from stored configuration and a set of answers. The
// list is refused outright -- GroupOutcome GroupInvalid, Err set -- when it
// could not be resolved deterministically or when it describes something the
// configuration layer should have made impossible: a member that is itself a
// group, two members at one position, one member listed twice, a member whose
// name is not a legal entity name, or a member before the winner that was never
// asked. Those are 500-class programming errors and refusing loudly is the
// point; the metadata schema already makes the first three impossible, which is
// why this is an assertion rather than a code path with a recovery.
func Resolve(members []MemberState, reference string) Resolution {
	resolution := Resolution{Reference: reference}

	// The list is checked whole and before anything is resolved: a member list
	// that is wrong is wrong regardless of which member happens to answer
	// first, and finding that out only when a particular member goes down is
	// how a latent misconfiguration becomes an outage.
	ordered, err := orderMembers(members)
	if err != nil {
		resolution.Err = err
		return resolution
	}

	for _, member := range ordered {
		switch member.Outcome {
		case MemberServed:
			resolution.Outcome = GroupServed
			resolution.Member = member.Repository
			resolution.Position = member.Position
			return resolution

		case MemberNotFound:
			continue

		case MemberDown, MemberMalformed:
			reason := SkippedDown
			if member.Outcome == MemberMalformed {
				reason = SkippedMalformed
			}
			if member.Required {
				resolution.Outcome = GroupUnavailable
				resolution.Member = member.Repository
				resolution.Position = member.Position
				resolution.Reason = reason
				return resolution
			}
			resolution.Skipped = append(resolution.Skipped, SkippedMember{
				Repository: member.Repository,
				Position:   member.Position,
				Reason:     reason,
			})

		default:
			// MemberUnasked, or a value outside the enum. Either way nobody
			// established what this member would have said, and guessing is
			// how a group serves the wrong digest.
			resolution.Skipped = nil
			resolution.Err = groupErr(member.Repository,
				fmt.Sprintf("outcome is %s: every member before the one that serves must have been asked", member.Outcome))
			return resolution
		}
	}

	resolution.Outcome = GroupNotFound
	return resolution
}

// orderMembers copies the member list, refuses everything that would make
// resolution non-deterministic or that the configuration layer should have
// prevented, and returns the members in explicit position order.
//
// It copies rather than sorting in place because a pure function that reorders
// its caller's slice is not one.
func orderMembers(members []MemberState) ([]MemberState, error) {
	ordered := slices.Clone(members)

	seenName := make(map[string]struct{}, len(ordered))
	seenPosition := make(map[int]struct{}, len(ordered))
	for _, member := range ordered {
		if err := ValidateEntityName(member.Repository); err != nil {
			return nil, groupErr(member.Repository, err.Error())
		}
		switch member.Type {
		case meta.Hosted, meta.Proxy:
		case meta.Group:
			// Groups do not nest (ADR 0005): resolution stays one level deep
			// so orderings stay auditable and no cycle detection is needed.
			return nil, groupErr(member.Repository, "a group cannot be a group member: groups do not nest")
		default:
			return nil, groupErr(member.Repository, fmt.Sprintf("unknown repository type %q", member.Type))
		}
		if _, duplicate := seenName[member.Repository]; duplicate {
			return nil, groupErr(member.Repository, "listed twice")
		}
		seenName[member.Repository] = struct{}{}
		if _, duplicate := seenPosition[member.Position]; duplicate {
			// Two members at one position is a tie, and a tie in an ordering
			// that decides which digest gets served is an error, never a coin
			// flip.
			return nil, groupErr(member.Repository, fmt.Sprintf("position %d is already taken: member order must be total", member.Position))
		}
		seenPosition[member.Position] = struct{}{}
	}

	// cmp.Compare rather than subtraction: positions come from stored
	// configuration, and a difference that overflows would sort backwards.
	slices.SortFunc(ordered, func(a, b MemberState) int { return cmp.Compare(a.Position, b.Position) })
	return ordered, nil
}
