// Package authn resolves who is making a request.
//
// It answers one question -- which subject is this? -- and answers it the same
// way for everybody. A request with no credentials resolves to the anonymous
// subject, which is a real stored row with real bindings rather than a nil
// pointer and a special case (ADR 0001). There is no branch anywhere that says
// "if unauthenticated, skip the check": anonymous access is off because the
// anonymous subject holds no bindings, not because a code path avoided asking.
//
// Authorization is somebody else's job. This package says who you are;
// internal/authz says what that lets you do.
package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/steveokay/trove/internal/meta"
)

// Kind distinguishes the three kinds of actor (ADR 0004). Anonymous is one of
// them, not the absence of one.
type Kind string

// The subject kinds.
const (
	// User is a person with a password.
	User Kind = "user"
	// Robot is a machine account: mandatory expiry, revocable, no password.
	Robot Kind = "robot"
	// Anonymous is the subject every request with no credentials resolves to.
	Anonymous Kind = "anonymous"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case User, Robot, Anonymous:
		return true
	default:
		return false
	}
}

// AnonymousName is the reserved name of the built-in anonymous subject, and
// AnonymousID its reserved identifier.
//
// The identifier is a fixed word rather than a generated one because bindings
// reference it: an operator granting anonymous access binds a role to this id,
// and a value that differed between deployments would make that grant
// unportable and the seeding migration non-deterministic.
const (
	AnonymousName = meta.AnonymousSubjectName
	AnonymousID   = "anonymous"
)

// Subject is who a request is from.
type Subject struct {
	// ID is the stable identifier bindings attach to.
	ID string
	// Kind is what sort of actor this is.
	Kind Kind
	// Name is the handle an operator types and an audit record shows.
	Name string
	// Disabled means the subject exists but may do nothing. Disabling is
	// reversible and keeps bindings intact; deleting is not.
	Disabled bool
}

// IsAnonymous reports whether this is the anonymous subject.
func (s Subject) IsAnonymous() bool { return s.Kind == Anonymous }

// String renders the subject for logs and audit records. It is the name rather
// than the id, because the name is what an operator recognises.
func (s Subject) String() string {
	if s.Name == "" {
		return "unknown subject"
	}
	return s.Name
}

// Sentinel errors from resolution. Callers assert with errors.Is.
var (
	// ErrDisabled reports a subject that exists but has been switched off. It
	// is distinct from ErrUnknownSubject on purpose: an operator debugging a
	// failing robot account needs to know the difference between "revoked" and
	// "never existed", and the two produce the same response to the client.
	ErrDisabled = errors.New("subject is disabled")

	// ErrUnknownSubject reports credentials naming a subject that is not
	// there.
	ErrUnknownSubject = errors.New("unknown subject")

	// ErrNoAnonymousSubject reports that the anonymous subject is missing from
	// the store. It is a broken deployment rather than a request problem: the
	// row is seeded by migration, and without it there is no subject for an
	// unauthenticated request to be.
	ErrNoAnonymousSubject = errors.New("the anonymous subject is missing")
)

// SubjectStore is the part of the metadata store resolution needs. It is
// declared here, by the consumer, so this package depends on one method rather
// than on the whole store (§11).
type SubjectStore interface {
	GetSubject(ctx context.Context, name string) (meta.Subject, error)
}

// Resolve turns a credential's subject name into a subject.
//
// An empty name means the request presented no credentials, and resolves to
// the anonymous subject. That is the single resolution path: the anonymous
// case differs only in which row is read, so everything downstream -- binding
// lookup, the decision, the audit record -- runs identically for a robot, a
// person, and a stranger.
//
// A disabled subject is an error rather than a subject with no permissions,
// because the distinction matters to whoever has to explain the failure.
// Disabling the anonymous subject is therefore how an operator turns
// anonymous access off wholesale, without unpicking its bindings.
func Resolve(ctx context.Context, store SubjectStore, name string) (Subject, error) {
	anonymous := name == ""
	if anonymous {
		name = AnonymousName
	}

	stored, err := store.GetSubject(ctx, name)
	switch {
	case errors.Is(err, meta.ErrNotFound) && anonymous:
		return Subject{}, fmt.Errorf("%w: it is seeded by migration and must not be deleted", ErrNoAnonymousSubject)
	case errors.Is(err, meta.ErrNotFound):
		return Subject{}, fmt.Errorf("%w: %q", ErrUnknownSubject, name)
	case err != nil:
		return Subject{}, fmt.Errorf("resolve subject: %w", err)
	}

	subject := fromStored(stored)
	if subject.Disabled {
		return Subject{}, fmt.Errorf("%w: %s", ErrDisabled, subject)
	}
	return subject, nil
}

// fromStored converts the stored shape into this package's.
func fromStored(stored meta.Subject) Subject {
	return Subject{
		ID:       stored.ID,
		Kind:     Kind(stored.Kind),
		Name:     stored.Name,
		Disabled: stored.Disabled,
	}
}
