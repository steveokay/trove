// Package groupserve resolves a group repository's reads over the
// distribution API (C-019).
//
// A group is the point of the product (§1): one registry URL in a cluster, and
// internal images, Docker Hub, ghcr and quay resolved in a defined order, all
// cached and all governed by one policy and permission model. This package is
// where that ordering happens over HTTP.
//
// It owns almost no logic. Ordering and first-match-wins are `repo.Resolve`,
// which is pure and exhaustively table-tested (C-011); permission filtering is
// `repo.VisibleMembers` (C-012); asking a member is the same `ContentServer`
// interface the dispatcher uses, so a hosted member and a proxy member are
// asked the same question. What is left here is the sequencing, and one rule
// that cannot be delegated:
//
//	**Members the subject cannot read are removed before resolution runs.**
//
// Not skipped -- removed. A skipped member appears in the resolution as a
// SkippedMember and would become an event naming it, so filtering by skipping
// would disclose through the event stream exactly what the listing hid. This
// is the single easiest place in trove to leak (§4), and the disclosure suite
// asserts the property from the outside.
package groupserve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/repo"
	"github.com/steveokay/trove/internal/server"
)

// Store is the slice of the metadata store this package reads.
type Store interface {
	GetRepository(ctx context.Context, name string) (meta.Repository, error)
	ListGroupMembers(ctx context.Context, group string) ([]meta.GroupMember, error)
}

// Bindings supplies a subject's effective bindings, which is what member
// filtering decides against. server.BindingStore satisfies it, and
// server.FetchBindings is what turns the rows into a decision's input -- there
// is one conversion in this codebase and this package does not add a second.
type Bindings = server.BindingStore

// Publisher accepts events. Nil means the skips happen unobserved.
type Publisher interface {
	Publish(ctx context.Context, e event.Event)
}

// Members are the delegates a group asks, by member type. A member of a type
// with no delegate cannot answer, which is the same outcome as a member that
// is down -- and is what happens to a proxy member in a deployment that has
// not wired proxying.
type Members struct {
	// Hosted serves hosted members (registry.HostedContent).
	Hosted registry.ContentServer
	// Proxy serves proxy members (proxyserve.Server).
	Proxy registry.ContentServer
}

// Server resolves group repositories.
type Server struct {
	meta     Store
	bindings Bindings
	members  Members
	events   Publisher
	log      *slog.Logger
}

// Options configures a Server. Meta and Bindings are required.
type Options struct {
	// Meta reads the group and its member list.
	Meta Store

	// Bindings resolves the asking subject's grants.
	//
	// It is required, and there is deliberately no way to build a Server
	// without it: a group that could not filter its members would resolve
	// against every one of them, and the first pull would disclose a member's
	// existence to a subject with no right to know.
	Bindings Bindings

	// Members are the delegates. A nil member type cannot answer.
	Members Members

	// Events receives group.member.skipped. Nil means nobody is listening.
	Events Publisher

	// Log is the fallback logger. Nil means slog.Default.
	Log *slog.Logger
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Meta == nil:
		return nil, errInvalid("a metadata store is required")
	case opts.Bindings == nil:
		return nil, errInvalid("a binding source is required: a group that cannot filter its members must not resolve")
	}

	s := &Server{
		meta: opts.Meta, bindings: opts.Bindings, members: opts.Members,
		events: opts.Events, log: opts.Log,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// ErrInvalidOptions reports a Server that cannot be built from what it was
// given. Callers assert with errors.Is.
var ErrInvalidOptions = errors.New("groupserve: invalid options")

func errInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOptions, fmt.Sprintf(format, args...))
}

// Manifest resolves a manifest read across the group's members.
func (s *Server) Manifest(ctx context.Context, name, reference string) (registry.ServedManifest, error) {
	var served registry.ServedManifest
	err := s.resolve(ctx, name, reference, func(ctx context.Context, member registry.ContentServer, content string) error {
		result, err := member.Manifest(ctx, content, reference)
		if err == nil {
			served = result
		}
		return err
	})
	if err != nil {
		return registry.ServedManifest{}, err
	}
	return served, nil
}

// Blob resolves a blob read across the group's members.
//
// The winning member's stream is handed back open. A member that answered and
// then lost -- because a required member ahead of it turned out to be down --
// has its stream closed rather than leaked, which is the reason this is not
// simply "ask until one succeeds".
func (s *Server) Blob(ctx context.Context, name string, digest blob.Digest) (registry.ServedBlob, error) {
	var served registry.ServedBlob
	err := s.resolve(ctx, name, digest.String(), func(ctx context.Context, member registry.ContentServer, content string) error {
		result, err := member.Blob(ctx, content, digest)
		if err == nil {
			served = result
		}
		return err
	})
	if err != nil {
		if served.Content != nil {
			_ = served.Content.Close()
		}
		return registry.ServedBlob{}, err
	}
	return served, nil
}

// ask is one attempt against one member: the caller's read, against the
// member's own content name.
type ask func(ctx context.Context, member registry.ContentServer, content string) error

// resolve runs the group's ordering for one reference.
//
// The shape is: read the members, filter them by what the subject may read,
// ask them in position order until one serves, then hand every outcome to
// repo.Resolve and obey it. Asking stops early at the first member that
// serves, but the verdict is still Resolve's -- a required member ahead of the
// winner that could not answer takes the group down, and only Resolve knows
// that rule.
func (s *Server) resolve(ctx context.Context, name, reference string, attempt ask) error {
	group, remainder, err := repo.Split(name)
	if err != nil {
		return fmt.Errorf("%w: %s", registry.ErrContentUnknown, err)
	}

	record, err := s.meta.GetRepository(ctx, group)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return registry.ErrContentUnknown
	case err != nil:
		return fmt.Errorf("read the group %q: %w", group, err)
	case record.Type != meta.Group:
		// The dispatcher only sends groups here. Checked anyway: this is the
		// function that decides which repositories get asked for content.
		return fmt.Errorf("%w: %q is a %s, not a group", registry.ErrContentUnknown, group, record.Type)
	}

	stored, err := s.meta.ListGroupMembers(ctx, group)
	if err != nil {
		return fmt.Errorf("read the members of %q: %w", group, err)
	}

	visible, err := s.visibleMembers(ctx, stored, remainder)
	if err != nil {
		return err
	}

	// Asked through the filtered set and resolved through it: the outcomes go
	// back into the same MemberSet rather than into a list rebuilt beside it,
	// so there is no point at which an unfiltered member could rejoin the
	// resolution (C-012's type carries that guarantee).
	outcomes := s.askMembers(ctx, visible.Members(), attempt)
	resolution := repo.Resolve(visible.With(outcomes), reference)
	s.publishSkips(ctx, name, resolution)

	switch resolution.Outcome {
	case repo.GroupServed:
		return nil
	case repo.GroupNotFound:
		return registry.ErrContentUnknown
	case repo.GroupUnavailable:
		s.log.WarnContext(ctx, "group could not resolve a reference",
			"group", name, "reference", reference, "resolution", resolution.String())
		return registry.ErrUpstreamUnavailable
	default:
		// GroupInvalid: a member list that cannot be resolved -- a duplicate
		// position, a group nested in a group. It is a configuration failure
		// and is reported as one rather than as missing content.
		return fmt.Errorf("group %q cannot be resolved: %w", name, resolution.Err)
	}
}

// visibleMembers turns stored members into the states Resolve consumes,
// keeping only those the subject may read.
//
// The decision is `repo:read` on each member's *content* name (C-012): a
// subject scoped to `dockerhub/*` may read `dockerhub/library/nginx` and may
// not read the bare entity, and deciding against the entity would hide a
// member whose content the subject is entitled to.
func (s *Server) visibleMembers(ctx context.Context, stored []meta.GroupMember, remainder string) (repo.MemberSet, error) {
	subject, ok := server.SubjectFrom(ctx)
	if !ok {
		// Every request carries a subject, even an anonymous one (Z-001), so
		// a context without one is a wiring error. It fails closed: resolving
		// without knowing who is asking is how a group serves what a subject
		// may not see.
		return repo.MemberSet{}, errors.New("no subject on the request context: a group cannot resolve without one")
	}

	// Keyed by name, as every other caller of FetchBindings is: the store's
	// effective-binding query is a name lookup, and the guard, the token
	// minter and the explainer all pass the name.
	bindings, err := server.FetchBindings(ctx, s.bindings, subject.Name)
	if err != nil {
		return repo.MemberSet{}, fmt.Errorf("read the effective bindings of %q: %w", subject.Name, err)
	}

	candidates := make([]repo.MemberState, 0, len(stored))
	for _, member := range stored {
		memberType, err := s.typeOf(ctx, member.Repository)
		if err != nil {
			return repo.MemberSet{}, err
		}
		candidates = append(candidates, repo.MemberState{
			Repository: member.Repository,
			Content:    contentNameFor(member.Repository, remainder),
			Type:       memberType,
			Position:   member.Position,
			Required:   member.Required,
		})
	}

	return repo.VisibleMembers(candidates, bindings), nil
}

// typeOf reads a member's repository type, which decides who is asked.
//
// It is a store read per member per request, and it is not cached here for the
// reason the proxy's configuration is not: a member retyped or deleted takes
// effect on the next pull rather than whenever something happened to expire.
//
// **A member whose row cannot be read fails the whole resolution**, missing or
// unreadable alike. The alternative -- dropping it and carrying on -- would let
// a group quietly serve a *different* member's image than the ordering says it
// should, which is the one failure a group must never have: an operator who put
// an internal registry first is relying on it being asked first. Stale
// configuration is loud here rather than silently routed around, and a store
// that cannot answer is a check that did not complete, which must not admit the
// request.
func (s *Server) typeOf(ctx context.Context, member string) (meta.RepositoryType, error) {
	record, err := s.meta.GetRepository(ctx, member)
	if err != nil {
		return "", fmt.Errorf("read the group member %q: %w", member, err)
	}
	return record.Type, nil
}

// askMembers asks each member in position order, stopping at the first that
// serves.
//
// Members after the winner are left unasked, which Resolve accepts: a group
// serves the first member that can, so asking the rest would be work whose
// answer cannot change the outcome. Members *before* it are all asked, because
// their outcomes are what decide whether a required one takes the group down.
func (s *Server) askMembers(ctx context.Context, members []repo.MemberState, attempt ask) map[string]repo.MemberOutcome {
	ordered := make([]repo.MemberState, len(members))
	copy(ordered, members)
	sortByPosition(ordered)

	outcomes := make(map[string]repo.MemberOutcome, len(ordered))
	for _, member := range ordered {
		delegate, outcome, askable := s.delegateFor(ctx, member)
		if !askable {
			outcomes[member.Repository] = outcome
			continue
		}

		outcomes[member.Repository] = outcomeOf(attempt(ctx, delegate, member.Content))
		if outcomes[member.Repository] == repo.MemberServed {
			break
		}
	}
	return outcomes
}

// delegateFor finds the server for a member's type, recording the outcome when
// there is none.
//
// A member type with no delegate is *down*, not absent: the member exists and
// this deployment cannot ask it, which is exactly what an unreachable upstream
// means. Calling it not-found would let a group quietly answer as though the
// member had been consulted and had nothing.
func (s *Server) delegateFor(ctx context.Context, member repo.MemberState) (registry.ContentServer, repo.MemberOutcome, bool) {
	var delegate registry.ContentServer
	switch member.Type {
	case meta.Hosted:
		delegate = s.members.Hosted
	case meta.Proxy:
		delegate = s.members.Proxy
	default:
		// A type this package does not serve. Nesting cannot arrive here --
		// the store refuses a group as a member of a group (ADR 0005) and
		// Resolve refuses one too -- so this is the third refusal of something
		// that should never have been stored, and it fails closed.
		return nil, repo.MemberDown, false
	}

	if delegate == nil {
		s.log.WarnContext(ctx, "group member cannot be asked: nothing serves its type",
			"member", member.Repository, "type", string(member.Type))
		return nil, repo.MemberDown, false
	}
	return delegate, repo.MemberUnasked, true
}

// outcomeOf turns a delegate's answer into the outcome Resolve ranks on.
func outcomeOf(err error) repo.MemberOutcome {
	switch {
	case err == nil:
		return repo.MemberServed
	case errors.Is(err, registry.ErrContentUnknown):
		// The ordinary answer: this member does not have it. Passed over
		// silently, because a group of five upstreams would otherwise emit
		// four events for every successful pull.
		return repo.MemberNotFound
	default:
		// Unreachable, throttled, or a failure nobody classified. All of them
		// mean the same thing to the group: this member did not answer, and
		// the next one gets its turn.
		return repo.MemberDown
	}
}

// publishSkips emits one event per member passed over, so an operator can see
// a member that is quietly failing before it becomes the last one standing.
func (s *Server) publishSkips(ctx context.Context, group string, resolution repo.Resolution) {
	if s.events == nil {
		return
	}
	for _, skipped := range resolution.Skipped {
		s.events.Publish(ctx, event.Event{
			Type:       event.GroupMemberSkipped,
			Repository: group,
			Resource:   skipped.Repository,
			Payload: event.GroupMemberSkippedPayload{
				Group:     group,
				Member:    skipped.Repository,
				Reference: resolution.Reference,
				Reason:    string(skipped.Reason),
			},
		})
	}
}

// contentNameFor is the full name a member would be asked for: the member
// entity, then the remainder the group was asked about.
func contentNameFor(member, remainder string) string {
	if remainder == "" {
		return member
	}
	return member + "/" + remainder
}

// sortByPosition orders members by their explicit position, which is the only
// thing that orders resolution (ADR 0005).
func sortByPosition(members []repo.MemberState) {
	for i := 1; i < len(members); i++ {
		for j := i; j > 0 && members[j].Position < members[j-1].Position; j-- {
			members[j], members[j-1] = members[j-1], members[j]
		}
	}
}

// Server implements the registry's delegate contract.
var _ registry.ContentServer = (*Server)(nil)
