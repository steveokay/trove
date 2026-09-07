package groupserve_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/groupserve"
	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/server"
)

var testTime = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// member is a ContentServer standing in for one repository: it answers for the
// content names it was given and records what it was asked.
type member struct {
	name    string
	content map[string]registry.ServedManifest
	err     error

	mu    sync.Mutex
	asked []string
	body  *countingBody
}

func newMember(name string) *member {
	return &member{name: name, content: map[string]registry.ServedManifest{}}
}

// holding gives the member a manifest under a content name.
func (m *member) holding(content, payload string) *member {
	bytes := []byte(payload)
	m.content[content] = registry.ServedManifest{
		Digest:    blob.FromBytes(blob.SHA256, bytes),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Payload:   bytes,
	}
	return m
}

// failing makes every answer this member gives a failure.
func (m *member) failing(err error) *member {
	m.err = err
	return m
}

func (m *member) Manifest(_ context.Context, content, _ string) (registry.ServedManifest, error) {
	m.mu.Lock()
	m.asked = append(m.asked, content)
	m.mu.Unlock()
	if m.err != nil {
		return registry.ServedManifest{}, m.err
	}
	served, ok := m.content[content]
	if !ok {
		return registry.ServedManifest{}, registry.ErrContentUnknown
	}
	return served, nil
}

func (m *member) Blob(_ context.Context, content string, digest blob.Digest) (registry.ServedBlob, error) {
	m.mu.Lock()
	m.asked = append(m.asked, content)
	m.mu.Unlock()
	if m.err != nil {
		return registry.ServedBlob{}, m.err
	}
	served, ok := m.content[content]
	if !ok {
		return registry.ServedBlob{}, registry.ErrContentUnknown
	}
	body := &countingBody{Reader: strings.NewReader(string(served.Payload))}
	m.mu.Lock()
	m.body = body
	m.mu.Unlock()
	return registry.ServedBlob{Content: body, Size: int64(len(served.Payload)), Digest: digest}, nil
}

func (m *member) wasAsked() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.asked...)
}

// lastBody is the most recent stream this member handed out, so a test can
// assert it was closed.
func (m *member) lastBody() *countingBody {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.body
}

// countingBody reports whether a stream was closed.
type countingBody struct {
	*strings.Reader
	mu     sync.Mutex
	closed int
}

func (b *countingBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed++
	return nil
}

func (b *countingBody) closes() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// byName routes a content name to whichever member owns its entity, so one
// fake can stand in for every member of a type.
type byName struct {
	members map[string]*member
}

func (b byName) Manifest(ctx context.Context, content, reference string) (registry.ServedManifest, error) {
	m, ok := b.members[entityOf(content)]
	if !ok {
		return registry.ServedManifest{}, registry.ErrContentUnknown
	}
	return m.Manifest(ctx, content, reference)
}

func (b byName) Blob(ctx context.Context, content string, digest blob.Digest) (registry.ServedBlob, error) {
	m, ok := b.members[entityOf(content)]
	if !ok {
		return registry.ServedBlob{}, registry.ErrContentUnknown
	}
	return m.Blob(ctx, content, digest)
}

func entityOf(content string) string {
	entity, _, _ := strings.Cut(content, "/")
	return entity
}

// recorder collects published events.
type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Publish(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) skipped() []event.GroupMemberSkippedPayload {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []event.GroupMemberSkippedPayload
	for _, e := range r.events {
		if payload, ok := e.Payload.(event.GroupMemberSkippedPayload); ok {
			out = append(out, payload)
		}
	}
	return out
}

// env is a group with members, a subject, and the server over them.
type env struct {
	t       *testing.T
	meta    *metamemory.Store
	hosted  map[string]*member
	proxies map[string]*member
	events  *recorder
}

// newEnv builds `fleet`, a group over the members named, in the order given.
// A member name prefixed "p:" is a proxy; anything else is hosted.
func newEnv(t *testing.T, members ...string) *env {
	t.Helper()

	ctx := context.Background()
	store := metamemory.New()
	t.Cleanup(func() { _ = store.Close() })

	e := &env{t: t, meta: store, hosted: map[string]*member{}, proxies: map[string]*member{}, events: &recorder{}}

	if _, err := store.CreateRepository(ctx, meta.Repository{
		Name: "fleet", Type: meta.Group, CreatedAt: testTime, UpdatedAt: testTime,
	}); err != nil {
		t.Fatalf("CreateRepository(fleet): %v", err)
	}

	stored := make([]meta.GroupMember, 0, len(members))
	for i, spec := range members {
		name, typ := spec, meta.Hosted
		if after, ok := strings.CutPrefix(spec, "p:"); ok {
			name, typ = after, meta.Proxy
		}
		if _, err := store.CreateRepository(ctx, meta.Repository{
			Name: name, Type: typ, Config: proxyConfigFor(typ),
			CreatedAt: testTime, UpdatedAt: testTime,
		}); err != nil {
			t.Fatalf("CreateRepository(%q): %v", name, err)
		}
		if typ == meta.Proxy {
			e.proxies[name] = newMember(name)
		} else {
			e.hosted[name] = newMember(name)
		}
		stored = append(stored, meta.GroupMember{Repository: name, Position: i + 1})
	}
	if err := store.SetGroupMembers(ctx, "fleet", stored); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}

	// alice may read the group and every member of it, so any filtering a
	// test observes is filtering that test asked for. A test that wants a
	// hidden member uses its own subject.
	scopes := []string{"fleet/*", "fleet"}
	for _, member := range stored {
		scopes = append(scopes, member.Repository+"/*", member.Repository)
	}
	e.seedSubject(t, "alice", scopes...)
	return e
}

func proxyConfigFor(typ meta.RepositoryType) []byte {
	if typ == meta.Proxy {
		return []byte(`{"upstream":"https://ghcr.io"}`)
	}
	return nil
}

// seedSubject creates a reader with the given scopes.
func (e *env) seedSubject(t *testing.T, name string, scopes ...string) {
	t.Helper()

	ctx := context.Background()
	if err := e.meta.CreateSubject(ctx, meta.Subject{ID: "u-" + name, Kind: meta.User, Name: name}); err != nil {
		t.Fatalf("CreateSubject(%q): %v", name, err)
	}
	if _, err := e.meta.GetRole(ctx, "reader"); err != nil {
		if err := e.meta.CreateRole(ctx, meta.Role{Name: "reader", Verbs: []string{"repo:read"}}); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
	}
	for i, scope := range scopes {
		if err := e.meta.CreateBinding(ctx, meta.Binding{
			ID: name + "-" + scope, PrincipalKind: meta.PrincipalSubject, PrincipalID: "u-" + name,
			Role: "reader", Scope: scope,
		}); err != nil {
			t.Fatalf("CreateBinding(%q): %v", scope, err)
		}
		_ = i
	}
}

// requireMember marks a member the group cannot answer without.
func (e *env) requireMember(t *testing.T, name string) {
	t.Helper()

	ctx := context.Background()
	stored, err := e.meta.ListGroupMembers(ctx, "fleet")
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	for i := range stored {
		if stored[i].Repository == name {
			stored[i].Required = true
		}
	}
	if err := e.meta.SetGroupMembers(ctx, "fleet", stored); err != nil {
		t.Fatalf("SetGroupMembers: %v", err)
	}
}

// member returns the fake for a member name.
func (e *env) member(name string) *member {
	e.t.Helper()

	if m, ok := e.hosted[name]; ok {
		return m
	}
	if m, ok := e.proxies[name]; ok {
		return m
	}
	e.t.Fatalf("no member %q in the fixture", name)
	return nil
}

// server builds the group server over the fixture.
func (e *env) server() *groupserve.Server {
	e.t.Helper()

	s, err := groupserve.New(groupserve.Options{
		Meta: e.meta, Bindings: e.meta, Events: e.events, Log: discardLogger(),
		Members: groupserve.Members{
			Hosted: byName{members: e.hosted},
			Proxy:  byName{members: e.proxies},
		},
	})
	if err != nil {
		e.t.Fatalf("groupserve.New: %v", err)
	}
	return s
}

// as returns a context carrying a subject, the way the guard supplies one.
func (e *env) as(name string) context.Context {
	return server.ContextWithSubject(context.Background(), authn.Subject{
		ID: "u-" + name, Kind: authn.User, Name: name,
	})
}

func TestNewRefusesUnusableOptions(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	for _, tc := range []struct {
		name string
		opts groupserve.Options
	}{
		{name: "no store", opts: groupserve.Options{Bindings: env.meta}},
		{
			// The one that matters: a group that cannot filter its members
			// would resolve against all of them.
			name: "no bindings", opts: groupserve.Options{Meta: env.meta},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := groupserve.New(tc.opts); !errors.Is(err, groupserve.ErrInvalidOptions) {
				t.Fatalf("New error = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

// TestFirstMemberThatHasItWins, and the ones after it are never asked: a group
// serves the first member that can, so asking the rest is work whose answer
// cannot change the outcome.
func TestFirstMemberThatHasItWins(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b", "c")
	env.member("b").holding("b/app", "from b")
	env.member("c").holding("c/app", "from c")

	served, err := env.server().Manifest(env.as("alice"), "fleet/app", "v1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if string(served.Payload) != "from b" {
		t.Errorf("served %q, want the first member that had it", served.Payload)
	}
	if asked := env.member("a").wasAsked(); len(asked) != 1 || asked[0] != "a/app" {
		t.Errorf("member a was asked %v, want its own content name", asked)
	}
	if asked := env.member("c").wasAsked(); len(asked) != 0 {
		t.Errorf("a member after the winner was asked: %v", asked)
	}
}

// TestNoMemberHasItIsNotFound, and a member that simply does not have the
// content is passed over silently -- a group of five upstreams would otherwise
// emit four events for every successful pull.
func TestNoMemberHasItIsNotFound(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	_, err := env.server().Manifest(env.as("alice"), "fleet/app", "v1")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Fatalf("error = %v, want ErrContentUnknown", err)
	}
	if skipped := env.events.skipped(); len(skipped) != 0 {
		t.Errorf("a member that merely lacked the content was reported as skipped: %v", skipped)
	}
}

// TestADownMemberIsSkippedAndReported: unlike a miss, a member that could not
// answer is an operator's business -- it is how a quietly failing member is
// noticed before it is the last one standing.
func TestADownMemberIsSkippedAndReported(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.member("a").failing(registry.ErrUpstreamUnavailable)
	env.member("b").holding("b/app", "from b")

	served, err := env.server().Manifest(env.as("alice"), "fleet/app", "v1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if string(served.Payload) != "from b" {
		t.Errorf("served %q, want the member that answered", served.Payload)
	}

	skipped := env.events.skipped()
	if len(skipped) != 1 {
		t.Fatalf("published %v, want one skip", skipped)
	}
	if skipped[0].Member != "a" || skipped[0].Group != "fleet/app" {
		t.Errorf("skip = %+v, want member a of the group", skipped[0])
	}
}

// TestARequiredMemberTakesTheGroupDown: a member marked required is one the
// group cannot answer without, so a later member having the content does not
// rescue it.
func TestARequiredMemberTakesTheGroupDown(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.requireMember(t, "a")
	env.member("a").failing(registry.ErrUpstreamUnavailable)
	env.member("b").holding("b/app", "from b")

	_, err := env.server().Manifest(env.as("alice"), "fleet/app", "v1")
	if !errors.Is(err, registry.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, want ErrUpstreamUnavailable", err)
	}
}

// TestAMemberTheSubjectCannotReadIsRemovedNotSkipped is the disclosure rule.
// Filtering by skipping would name the member in an event, disclosing through
// the event stream exactly what the listing hid (§4).
func TestAMemberTheSubjectCannotReadIsRemovedNotSkipped(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.member("a").holding("a/app", "from a")
	env.member("b").holding("b/app", "from b")
	// bob may read the group and member b, and knows nothing of member a.
	env.seedSubject(t, "bob", "fleet/*", "b/*")

	served, err := env.server().Manifest(env.as("bob"), "fleet/app", "v1")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if string(served.Payload) != "from b" {
		t.Errorf("served %q, want the member bob may read", served.Payload)
	}
	if asked := env.member("a").wasAsked(); len(asked) != 0 {
		t.Errorf("a member bob cannot read was asked: %v", asked)
	}
	for _, skip := range env.events.skipped() {
		if skip.Member == "a" {
			t.Errorf("a filtered member appeared in the event stream: %+v", skip)
		}
	}
}

// TestAFilteredMemberIsIndistinguishableFromAnAbsentOne compares two whole
// resolutions rather than spot-checking one: the subject who cannot see a
// member must get exactly what a subject would get in a group that never had
// it.
func TestAFilteredMemberIsIndistinguishableFromAnAbsentOne(t *testing.T) {
	t.Parallel()

	// The group with a hidden first member that *would* have served.
	withHidden := newEnv(t, "a", "b")
	withHidden.member("a").holding("a/app", "from a")
	withHidden.member("b").holding("b/app", "from b")
	withHidden.seedSubject(t, "bob", "fleet/*", "b/*")

	// The same group without that member at all.
	without := newEnv(t, "b")
	without.member("b").holding("b/app", "from b")
	without.seedSubject(t, "bob", "fleet/*", "b/*")

	hiddenServed, hiddenErr := withHidden.server().Manifest(withHidden.as("bob"), "fleet/app", "v1")
	absentServed, absentErr := without.server().Manifest(without.as("bob"), "fleet/app", "v1")

	if hiddenErr != nil || absentErr != nil {
		t.Fatalf("errors: hidden %v, absent %v", hiddenErr, absentErr)
	}
	if hiddenServed.Digest != absentServed.Digest || string(hiddenServed.Payload) != string(absentServed.Payload) {
		t.Errorf("a hidden member changed what was served: %+v vs %+v", hiddenServed, absentServed)
	}
	if len(withHidden.events.skipped()) != len(without.events.skipped()) {
		t.Errorf("a hidden member changed the event stream: %v vs %v",
			withHidden.events.skipped(), without.events.skipped())
	}
}

// TestBlobsResolveTheSameWay, and the winner's stream comes back open.
func TestBlobsResolveTheSameWay(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.member("b").holding("b/app", "layer bytes")
	digest := blob.FromBytes(blob.SHA256, []byte("layer bytes"))

	served, err := env.server().Blob(env.as("alice"), "fleet/app", digest)
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	defer func() { _ = served.Content.Close() }()

	body, err := io.ReadAll(served.Content)
	if err != nil || string(body) != "layer bytes" {
		t.Errorf("body = %q, %v", body, err)
	}
	if served.Size != int64(len("layer bytes")) {
		t.Errorf("size = %d", served.Size)
	}
}

// TestALosingBlobStreamIsClosed: a member that answered and then lost, because
// a required member ahead of it turned out to be down, must not leak its
// stream.
func TestALosingBlobStreamIsClosed(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a", "b")
	env.requireMember(t, "a")
	env.member("a").failing(registry.ErrUpstreamUnavailable)
	env.member("b").holding("b/app", "layer bytes")
	digest := blob.FromBytes(blob.SHA256, []byte("layer bytes"))

	// b is behind a required member that is down, so the group fails even
	// though b answered.
	if _, err := env.server().Blob(env.as("alice"), "fleet/app", digest); !errors.Is(err, registry.ErrUpstreamUnavailable) {
		t.Fatalf("error = %v, want ErrUpstreamUnavailable", err)
	}
	if body := env.member("b").lastBody(); body != nil && body.closes() == 0 {
		t.Error("the losing member's stream was left open")
	}
}

// TestAMemberTypeNothingServesIsDownRatherThanAbsent: a proxy member in a
// deployment that has not wired proxying exists and cannot be asked, which is
// what an unreachable upstream means. Calling it not-found would let the group
// answer as though the member had been consulted.
func TestAMemberTypeNothingServesIsDownRatherThanAbsent(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "p:hub", "b")
	env.member("b").holding("b/app", "from b")

	s, err := groupserve.New(groupserve.Options{
		Meta: env.meta, Bindings: env.meta, Events: env.events, Log: discardLogger(),
		// Only hosted members can be asked.
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
	skipped := env.events.skipped()
	if len(skipped) != 1 || skipped[0].Member != "hub" {
		t.Errorf("skips = %v, want the unservable member reported", skipped)
	}
}

// TestARepositoryThatIsNotAGroupIsRefused: the dispatcher only sends groups
// here, and this is the function that decides which repositories get asked for
// content.
func TestARepositoryThatIsNotAGroupIsRefused(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	_, err := env.server().Manifest(env.as("alice"), "a/app", "v1")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Errorf("error = %v, want ErrContentUnknown", err)
	}
}

// TestAnUnknownGroupIsAbsent.
func TestAnUnknownGroupIsAbsent(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	_, err := env.server().Manifest(env.as("alice"), "ghost/app", "v1")
	if !errors.Is(err, registry.ErrContentUnknown) {
		t.Errorf("error = %v, want ErrContentUnknown", err)
	}
}

// TestAContextWithoutASubjectResolvesNothing: every request carries a subject,
// even an anonymous one, so a context without one is a wiring error -- and it
// fails closed, because resolving without knowing who is asking is how a group
// serves what a subject may not see.
func TestAContextWithoutASubjectResolvesNothing(t *testing.T) {
	t.Parallel()

	env := newEnv(t, "a")
	env.member("a").holding("a/app", "from a")

	_, err := env.server().Manifest(context.Background(), "fleet/app", "v1")
	if err == nil {
		t.Fatal("a group resolved without a subject")
	}
	if errors.Is(err, registry.ErrContentUnknown) {
		t.Error("a missing subject was reported as missing content")
	}
	if asked := env.member("a").wasAsked(); len(asked) != 0 {
		t.Errorf("a member was asked without a subject: %v", asked)
	}
}
