package authn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
)

func store(t *testing.T) *memory.Store {
	t.Helper()

	s := memory.New()
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func mustCreate(t *testing.T, s *memory.Store, name string, kind meta.SubjectKind) {
	t.Helper()

	if err := s.CreateSubject(context.Background(), meta.Subject{
		ID: "id-" + name, Kind: kind, Name: name,
	}); err != nil {
		t.Fatalf("CreateSubject(%q): %v", name, err)
	}
}

// All three kinds come back through one call. The anonymous case differs only
// in which row is read, so everything downstream runs identically for a robot,
// a person, and a stranger (ADR 0001).
func TestResolveEveryKind(t *testing.T) {
	t.Parallel()

	s := store(t)
	mustCreate(t, s, "alice", meta.User)
	mustCreate(t, s, "robot$ci", meta.Robot)

	tests := []struct {
		name       string
		credential string // empty means the request presented none
		wantName   string
		wantKind   authn.Kind
	}{
		{name: "user", credential: "alice", wantName: "alice", wantKind: authn.User},
		{name: "robot", credential: "robot$ci", wantName: "robot$ci", wantKind: authn.Robot},
		{
			name:     "no credentials",
			wantName: authn.AnonymousName,
			wantKind: authn.Anonymous,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject, err := authn.Resolve(context.Background(), s, tt.credential)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tt.credential, err)
			}
			if subject.Name != tt.wantName {
				t.Errorf("name = %q, want %q", subject.Name, tt.wantName)
			}
			if subject.Kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", subject.Kind, tt.wantKind)
			}
			if subject.ID == "" {
				t.Error("subject has no id: bindings would have nothing to attach to")
			}
			if subject.IsAnonymous() != (tt.wantKind == authn.Anonymous) {
				t.Errorf("IsAnonymous() = %v for kind %q", subject.IsAnonymous(), subject.Kind)
			}
			if subject.String() != tt.wantName {
				t.Errorf("String() = %q, want the name %q", subject, tt.wantName)
			}
		})
	}
}

// The anonymous subject is a real row with the reserved id, because bindings
// reference ids: an operator granting anonymous access binds to this value.
func TestResolveAnonymousIsTheSeededRow(t *testing.T) {
	t.Parallel()

	s := store(t)
	subject, err := authn.Resolve(context.Background(), s, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if subject.ID != authn.AnonymousID {
		t.Errorf("id = %q, want the reserved %q", subject.ID, authn.AnonymousID)
	}

	// Naming it explicitly resolves to the same subject: there is one row and
	// one path, not a credentialled route and an anonymous one.
	named, err := authn.Resolve(context.Background(), s, authn.AnonymousName)
	if err != nil {
		t.Fatalf("Resolve(anonymous): %v", err)
	}
	if named != subject {
		t.Errorf("resolving by name gave %+v, want %+v", named, subject)
	}
}

// Disabling is how an operator turns anonymous access off wholesale, without
// unpicking whatever bindings it holds.
func TestResolveRefusesDisabledSubjects(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := store(t)
	mustCreate(t, s, "alice", meta.User)

	for _, name := range []string{"alice", authn.AnonymousName} {
		if err := s.SetSubjectDisabled(ctx, name, true); err != nil {
			t.Fatalf("SetSubjectDisabled(%q): %v", name, err)
		}
	}

	// A distinct sentinel: whoever has to explain the failure needs to tell
	// "switched off" from "never existed", even though the client sees the
	// same response either way.
	credentials := map[string]string{"alice": "alice", "anonymous": ""}
	for name, credential := range credentials {
		t.Run(name, func(t *testing.T) {
			_, err := authn.Resolve(ctx, s, credential)
			if !errors.Is(err, authn.ErrDisabled) {
				t.Fatalf("Resolve(%q) = %v, want ErrDisabled", credential, err)
			}
			if errors.Is(err, authn.ErrUnknownSubject) {
				t.Error("a disabled subject reports as unknown")
			}
		})
	}

	// Re-enabling restores it: disabling is reversible, deleting is not.
	if err := s.SetSubjectDisabled(ctx, "alice", false); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}
	if _, err := authn.Resolve(ctx, s, "alice"); err != nil {
		t.Errorf("Resolve after re-enabling: %v", err)
	}
}

func TestResolveUnknownSubject(t *testing.T) {
	t.Parallel()

	_, err := authn.Resolve(context.Background(), store(t), "nobody")
	if !errors.Is(err, authn.ErrUnknownSubject) {
		t.Errorf("Resolve = %v, want ErrUnknownSubject", err)
	}
}

// A store with no anonymous row is a broken deployment, not a request
// problem: the row is seeded by migration, and without it an unauthenticated
// request has no subject to be.
func TestResolveReportsAMissingAnonymousSubject(t *testing.T) {
	t.Parallel()

	_, err := authn.Resolve(context.Background(), emptyStore{}, "")
	if !errors.Is(err, authn.ErrNoAnonymousSubject) {
		t.Errorf("Resolve = %v, want ErrNoAnonymousSubject", err)
	}
	// It is not reported as an unknown subject: nobody presented a credential.
	if errors.Is(err, authn.ErrUnknownSubject) {
		t.Error("a missing anonymous row reports as an unknown subject")
	}
}

// emptyStore is a store that has lost its seeded row.
type emptyStore struct{}

func (emptyStore) GetSubject(context.Context, string) (meta.Subject, error) {
	return meta.Subject{}, meta.NotFound("subject", "anonymous")
}

func TestResolvePropagatesStoreFailures(t *testing.T) {
	t.Parallel()

	failure := errors.New("database is gone")
	_, err := authn.Resolve(context.Background(), failingStore{err: failure}, "alice")
	if !errors.Is(err, failure) {
		t.Errorf("Resolve = %v, want the store's error", err)
	}
	// A broken store must not read as "no such subject", which would let a
	// database outage look like a revoked account.
	if errors.Is(err, authn.ErrUnknownSubject) {
		t.Error("a store failure reports as an unknown subject")
	}
}

type failingStore struct{ err error }

func (f failingStore) GetSubject(context.Context, string) (meta.Subject, error) {
	return meta.Subject{}, f.err
}

func TestKinds(t *testing.T) {
	t.Parallel()

	for _, kind := range []authn.Kind{authn.User, authn.Robot, authn.Anonymous} {
		if !kind.Valid() {
			t.Errorf("%q is not valid", kind)
		}
	}
	for _, kind := range []authn.Kind{"", "service", "USER", "user "} {
		if kind.Valid() {
			t.Errorf("%q reports valid", kind)
		}
	}

	// A subject nobody built renders as something an operator can read rather
	// than as an empty string in an audit line.
	var zero authn.Subject
	if zero.String() != "unknown subject" {
		t.Errorf("String() = %q, want a readable placeholder", zero)
	}
	if zero.IsAnonymous() {
		t.Error("the zero Subject claims to be anonymous")
	}
}
