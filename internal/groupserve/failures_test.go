package groupserve_test

import (
	"context"
	"errors"
	"testing"

	"github.com/steveokay/trove/internal/groupserve"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/registry"
)

// What a group does when something other than a member fails: the store, the
// bindings, the member list, or the configuration itself.
//
// The theme is one rule. None of these is "no such image": a group that could
// not be read has not answered, and a client that cached a not-found from one
// would keep failing after the failure was fixed.

// failingStore fails the call a test names, delegating the rest.
type failingStore struct {
	inner     groupserve.Store
	repos     error
	members   error
	memberSet []meta.GroupMember
	failRepo  string
}

func (f failingStore) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if f.repos != nil && (f.failRepo == "" || f.failRepo == name) {
		return meta.Repository{}, f.repos
	}
	return f.inner.GetRepository(ctx, name)
}

func (f failingStore) ListGroupMembers(ctx context.Context, group string) ([]meta.GroupMember, error) {
	if f.members != nil {
		return nil, f.members
	}
	if f.memberSet != nil {
		return f.memberSet, nil
	}
	return f.inner.ListGroupMembers(ctx, group)
}

// failingBindings cannot answer what a subject may read.
type failingBindings struct {
	inner bindingSource
	err   error
}

func (f failingBindings) ListEffectiveBindings(ctx context.Context, subject string) ([]meta.EffectiveBinding, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.inner.ListEffectiveBindings(ctx, subject)
}

func (f failingBindings) GetRole(ctx context.Context, name string) (meta.Role, error) {
	return f.inner.GetRole(ctx, name)
}

// bindingSource is what a group filters with: the effective rows and the roles
// they name (server.BindingStore).
type bindingSource interface {
	ListEffectiveBindings(ctx context.Context, subject string) ([]meta.EffectiveBinding, error)
	GetRole(ctx context.Context, name string) (meta.Role, error)
}

// serverWith builds a group server with one collaborator replaced.
func (e *env) serverWith(t *testing.T, tweak func(*groupserve.Options)) *groupserve.Server {
	t.Helper()

	opts := groupserve.Options{
		Meta: e.meta, Bindings: e.meta, Events: e.events, Log: discardLogger(),
		Members: groupserve.Members{
			Hosted: byName{members: e.hosted},
			Proxy:  byName{members: e.proxies},
		},
	}
	tweak(&opts)
	s, err := groupserve.New(opts)
	if err != nil {
		t.Fatalf("groupserve.New: %v", err)
	}
	return s
}

func TestStoreFailuresAreNotMissingContent(t *testing.T) {
	t.Parallel()

	broken := errors.New("the database is not answering")
	for _, tc := range []struct {
		name  string
		build func(env *env) groupserve.Store
	}{
		{
			name: "the group row",
			build: func(e *env) groupserve.Store {
				return failingStore{inner: e.meta, repos: broken, failRepo: "fleet"}
			},
		},
		{
			name: "the member list",
			build: func(e *env) groupserve.Store {
				return failingStore{inner: e.meta, members: broken}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newEnv(t, "a")
			s := env.serverWith(t, func(o *groupserve.Options) { o.Meta = tc.build(env) })

			_, err := s.Manifest(env.as("alice"), "fleet/app", "v1")
			if !errors.Is(err, broken) {
				t.Fatalf("error = %v, want the store's failure", err)
			}
			if errors.Is(err, registry.ErrContentUnknown) {
				t.Error("a store failure was reported as missing content")
			}
		})
	}
}

// TestBindingsThatCannotBeReadResolveNothing: without knowing what the subject
// may see, the only safe answer is none. Resolving anyway would ask members
// the subject might have no right to know exist.
func TestBindingsThatCannotBeReadResolveNothing(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	env.member("a").holding("a/app", "from a")
	broken := errors.New("the database is not answering")

	s := env.serverWith(t, func(o *groupserve.Options) {
		o.Bindings = failingBindings{inner: env.meta, err: broken}
	})
	_, err := s.Manifest(env.as("alice"), "fleet/app", "v1")
	if !errors.Is(err, broken) {
		t.Fatalf("error = %v, want the binding failure", err)
	}
	if asked := env.member("a").wasAsked(); len(asked) != 0 {
		t.Errorf("a member was asked before the subject's grants were known: %v", asked)
	}
}

// TestAMemberThatCannotBeReadFailsTheResolution.
//
// The alternative -- dropping it and carrying on -- would let the group serve
// a *different* member's image than the ordering says it should, and an
// operator who put an internal registry first is relying on it being asked
// first. Stale configuration is loud rather than silently routed around.
func TestAMemberThatCannotBeReadFailsTheResolution(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.member("b").holding("b/app", "from b")
	broken := errors.New("member row unreadable")

	s := env.serverWith(t, func(o *groupserve.Options) {
		o.Meta = failingStore{inner: env.meta, repos: broken, failRepo: "a"}
	})

	_, err := s.Manifest(env.as("alice"), "fleet/app", "v1")
	if !errors.Is(err, broken) {
		t.Fatalf("error = %v, want the store failure", err)
	}
	if errors.Is(err, registry.ErrContentUnknown) {
		t.Error("an unreadable member was reported as missing content")
	}
	if asked := env.member("b").wasAsked(); len(asked) != 0 {
		t.Errorf("a later member served around an unreadable one: %v", asked)
	}
}

// A nested group never reaches this package: SetGroupMembers refuses one
// (ADR 0005), which the store's own contract suite asserts. The delegate
// switch still fails closed on a type it does not serve -- three refusals of
// something that should never have been stored.

// TestMembersAreAskedInPositionOrder: position is the only thing that orders
// resolution, so a member list handed back in any order resolves the same way.
func TestMembersAreAskedInPositionOrder(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b", "c")
	if err := env.meta.SetGroupMembers(context.Background(), "fleet", []meta.GroupMember{
		{Repository: "c", Position: 3},
		{Repository: "a", Position: 1},
		{Repository: "b", Position: 2},
	}); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}
	env.member("b").holding("b/app", "from b")
	env.member("c").holding("c/app", "from c")

	served, err := env.server().Manifest(env.as("alice"), "fleet/app", "v1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if string(served.Payload) != "from b" {
		t.Errorf("served %q, want position order to decide", served.Payload)
	}
	if asked := env.member("c").wasAsked(); len(asked) != 0 {
		t.Errorf("the member at position 3 was asked: %v", asked)
	}
}

// TestContentDirectlyAtAMemberEntity: a group pull of the entity itself asks
// each member for its own bare name, not for one with a trailing slash.
func TestContentDirectlyAtAMemberEntity(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	env.member("a").holding("a", "content at the entity")

	served, err := env.server().Manifest(env.as("alice"), "fleet", "v1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if string(served.Payload) != "content at the entity" {
		t.Errorf("served %q", served.Payload)
	}
	if asked := env.member("a").wasAsked(); len(asked) != 1 || asked[0] != "a" {
		t.Errorf("member was asked %v, want its bare name", asked)
	}
}

// TestAnUnusableGroupNameIsAbsent. The dispatcher validated the name before
// deciding anything, so this is unreachable from a request -- and it fails
// closed rather than asking members about a name nothing checked.
func TestAnUnusableGroupNameIsAbsent(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	for _, name := range []string{"UPPER/case", "fleet/../escape", ""} {
		if _, err := env.server().Manifest(env.as("alice"), name, "v1"); !errors.Is(err, registry.ErrContentUnknown) {
			t.Errorf("Manifest(%q) = %v, want ErrContentUnknown", name, err)
		}
	}
	if asked := env.member("a").wasAsked(); len(asked) != 0 {
		t.Errorf("an unusable name reached a member: %v", asked)
	}
}

// TestAServerWithoutAPublisherOrLoggerStillResolves: events are how an
// operator sees a failing member, never a condition of serving.
func TestAServerWithoutAPublisherOrLoggerStillResolves(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.member("a").failing(registry.ErrUpstreamUnavailable)
	env.member("b").holding("b/app", "from b")

	s, err := groupserve.New(groupserve.Options{
		Meta: env.meta, Bindings: env.meta,
		Members: groupserve.Members{Hosted: byName{members: env.hosted}},
	})
	if err != nil {
		t.Fatalf("groupserve.New: %v", err)
	}
	served, err := s.Manifest(env.as("alice"), "fleet/app", "v1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if string(served.Payload) != "from b" {
		t.Errorf("served %q", served.Payload)
	}
}

// TestAMemberListThatCannotBeOrderedIsRefused: two members at one position is
// a tie, and a tie in resolution order is an error rather than a coin flip
// (§7's rule for retention priorities, and the same reasoning here). The store
// refuses to write one, so this is what happens if a row arrives another way.
func TestAMemberListThatCannotBeOrderedIsRefused(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.member("a").holding("a/app", "from a")
	env.member("b").holding("b/app", "from b")

	s := env.serverWith(t, func(o *groupserve.Options) {
		o.Meta = failingStore{inner: env.meta, memberSet: []meta.GroupMember{
			{Repository: "a", Position: 1},
			{Repository: "b", Position: 1},
		}}
	})

	_, err := s.Manifest(env.as("alice"), "fleet/app", "v1")
	if err == nil {
		t.Fatal("a member list that cannot be ordered resolved anyway")
	}
	if errors.Is(err, registry.ErrContentUnknown) {
		t.Error("a broken member list was reported as missing content")
	}
}
