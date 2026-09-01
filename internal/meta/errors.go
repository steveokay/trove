package meta

import (
	"errors"
	"fmt"
)

// Sentinel errors every implementation must return for these conditions.
// Callers assert with errors.Is; no caller may match on message text (§11).
var (
	// ErrNotFound reports that the requested entity does not exist. Callers
	// translate it per ADR 0003: an unauthorized read is indistinguishable
	// from a missing one on the wire.
	ErrNotFound = errors.New("not found")

	// ErrConflict reports that the write collides with existing state, such as
	// creating a repository whose name is taken.
	ErrConflict = errors.New("conflict")

	// ErrStale reports a failed optimistic-concurrency check: the caller's
	// expected version no longer matches. Re-read and retry.
	ErrStale = errors.New("stale version")

	// ErrInvalid reports that the argument could not be stored as given. It
	// covers store-level invariants only; validating a repository name or a
	// media type is the edge's job, not the store's.
	ErrInvalid = errors.New("invalid argument")

	// ErrReferenced reports that an entity cannot be deleted because something
	// still points at it, such as a child manifest held by a live index
	// (Q10, ADR 0005).
	ErrReferenced = errors.New("still referenced")
)

// NotFoundError names what was missing while satisfying errors.Is(ErrNotFound).
type NotFoundError struct {
	Kind string
	ID   string
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s %q not found", e.Kind, e.ID) }

// Is makes errors.Is(err, ErrNotFound) true for this typed error.
func (e *NotFoundError) Is(target error) bool { return target == ErrNotFound }

// NotFound builds a NotFoundError.
func NotFound(kind, id string) error { return &NotFoundError{Kind: kind, ID: id} }

// ConflictError names the entity that already exists.
type ConflictError struct {
	Kind string
	ID   string
}

func (e *ConflictError) Error() string { return fmt.Sprintf("%s %q already exists", e.Kind, e.ID) }

// Is makes errors.Is(err, ErrConflict) true for this typed error.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// Conflict builds a ConflictError.
func Conflict(kind, id string) error { return &ConflictError{Kind: kind, ID: id} }

// ReferencedError names both the entity and what still references it, so the
// caller can tell an operator which index to delete first.
type ReferencedError struct {
	Kind string
	ID   string
	By   []string
}

func (e *ReferencedError) Error() string {
	return fmt.Sprintf("%s %q is still referenced by %v", e.Kind, e.ID, e.By)
}

// Is makes errors.Is(err, ErrReferenced) true for this typed error.
func (e *ReferencedError) Is(target error) bool { return target == ErrReferenced }

// Referenced builds a ReferencedError.
func Referenced(kind, id string, by []string) error {
	return &ReferencedError{Kind: kind, ID: id, By: by}
}

// InvalidError explains why an argument could not be stored.
type InvalidError struct {
	Field  string
	Reason string
}

func (e *InvalidError) Error() string { return fmt.Sprintf("invalid %s: %s", e.Field, e.Reason) }

// Is makes errors.Is(err, ErrInvalid) true for this typed error.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Invalid builds an InvalidError.
func Invalid(field, reason string) error { return &InvalidError{Field: field, Reason: reason} }
