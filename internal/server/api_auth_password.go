package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
)

// MinPasswordLength is the floor on a new password. Eight is OWASP's minimum;
// anything stricter is an operator policy for a later task, and anything
// looser is not a password.
const MinPasswordLength = 8

// PasswordStore is the slice of the store a rotation writes: the new
// verifier, and the end of every session that was opened under the old one.
type PasswordStore interface {
	PutUserCredential(ctx context.Context, cred meta.UserCredential) error
	DeleteSubjectSessions(ctx context.Context, subject string) (int, error)
}

// AuthPassword serves password rotation (Z-014, ADR 0004):
//
//	POST /api/v1/auth/password  {"current_password": ..., "new_password": ...}
//
// It is always about the calling subject -- there is no subject parameter;
// resetting somebody else's password is the user admin API's job under
// user:write -- and it is the one route a must-rotate subject may reach,
// because it is the door the gate points at.
type AuthPassword struct {
	// Login verifies the current password, with the same limiter and the
	// same answers as logging in: proving you know the old password is an
	// authentication attempt, whatever the URL says.
	Login *authn.PasswordLogin
	// Store persists the rotation.
	Store PasswordStore
	// Hasher produces the new verifier.
	Hasher authn.Hasher
	// Now supplies the rotation timestamp. Nil means time.Now.
	Now func() time.Time
	// Errors renders refusals. Nil means ProblemErrors.
	Errors ErrorRenderer
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the route on the table.
func (h *AuthPassword) Register(r *Router) {
	r.HandleFunc(http.MethodPost, "/api/v1/auth/password", Permission{
		// The verb is never consulted -- the route is always self-access --
		// but the table must say what changing a password is, and it is a
		// user write.
		Verb:           authz.UserWrite,
		Self:           func(*http.Request) (string, error) { return "", nil },
		RotationExempt: true,
	}, h.serve)
}

type passwordChange struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *AuthPassword) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	caller, ok := SubjectFrom(ctx)
	if !ok {
		Logger(ctx, h.Log).Error("password rotation served without a subject in context")
		errs.Internal(w, r)
		return
	}
	if caller.Kind != authn.User {
		// Only users have passwords. The subject is real and authenticated,
		// so a helpful refusal costs nothing.
		errs.Forbidden(w, r)
		return
	}

	var change passwordChange
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&change); err != nil {
		errs.BadRequest(w, r, "the body must be JSON with current_password and new_password")
		return
	}
	if len(change.NewPassword) < MinPasswordLength {
		errs.BadRequest(w, r, "the new password must be at least 8 characters")
		return
	}
	if change.NewPassword == change.CurrentPassword {
		errs.BadRequest(w, r, "the new password must differ from the current one")
		return
	}

	// Knowing the current password is what authorizes the change -- an
	// authenticated session alone must not be enough to lock its owner out.
	// The check goes through the login path so it is rate-limited like one.
	var limited *authn.RateLimitedError
	switch err := h.Login.Authenticate(ctx, caller.Name, change.CurrentPassword, remoteHost(r)); {
	case errors.As(err, &limited):
		errs.TooManyRequests(w, r, limited.RetryAfter)
		return
	case errors.Is(err, authn.ErrBadCredentials):
		errs.BadRequest(w, r, "the current password is incorrect")
		return
	case err != nil:
		Logger(ctx, h.Log).Error("password rotation could not verify the current password",
			"subject", caller.Name, "error", err)
		errs.Internal(w, r)
		return
	}

	hash, err := h.Hasher.Hash(change.NewPassword)
	if err != nil {
		Logger(ctx, h.Log).Error("password rotation could not hash", "subject", caller.Name, "error", err)
		errs.Internal(w, r)
		return
	}
	now := h.Now
	if now == nil {
		now = time.Now
	}
	if err := h.Store.PutUserCredential(ctx, meta.UserCredential{
		Subject: caller.Name, Hash: hash, RotatedAt: now(),
	}); err != nil {
		Logger(ctx, h.Log).Error("password rotation could not store the verifier",
			"subject", caller.Name, "error", err)
		errs.Internal(w, r)
		return
	}
	// Sessions opened under the old password die with it (ADR 0004). The
	// write already happened: a failure here is logged, not unwound, because
	// the new password is real either way.
	if _, err := h.Store.DeleteSubjectSessions(ctx, caller.Name); err != nil {
		Logger(ctx, h.Log).Error("password rotation could not end old sessions",
			"subject", caller.Name, "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthPassword) errors() ErrorRenderer {
	if h.Errors == nil {
		return ProblemErrors{}
	}
	return h.Errors
}
