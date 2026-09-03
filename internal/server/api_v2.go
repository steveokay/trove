package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/steveokay/trove/internal/authn"
)

// V2Root serves GET /v2/, the OCI base endpoint (ADR 0004 step 1): the
// client's authentication probe. An unauthenticated request gets 401 with the
// bearer challenge -- that is how docker discovers the token endpoint -- and
// an authenticated one gets 200 with an empty body, which discloses nothing
// beyond "your credentials are valid": no repository, no listing, no count.
//
// The route is public with the check in the handler because the question it
// answers is authentication, not authorization: there is no verb for "is
// anyone there", and inventing one would put a fake permission in the
// vocabulary. The anonymous subject answers 401 even with a valid anonymous
// token, because the probe's yes means "you are someone" (ADR 0003: the
// client may be able to authenticate into visibility).
type V2Root struct {
	// Credentials and Subjects mirror the guard's resolution exactly, so the
	// probe and the guarded routes cannot disagree about who a request is.
	Credentials CredentialFunc
	Subjects    authn.SubjectStore
	// Challenge is the WWW-Authenticate value for the 401.
	Challenge func(*http.Request) string
	// Errors renders refusals. Nil means ProblemErrors until R-008 supplies
	// the spec's envelope.
	Errors ErrorRenderer
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the route on the table.
func (h *V2Root) Register(r *Router) {
	r.HandlePublic(http.MethodGet, "/v2/{$}",
		"the OCI base endpoint answers only whether the client is authenticated (ADR 0004): 401 with the challenge, or 200 disclosing nothing",
		http.HandlerFunc(h.serve))
}

func (h *V2Root) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	credentials := h.Credentials
	if credentials == nil {
		credentials = NoCredentials
	}
	name, err := credentials(r)
	if err != nil {
		var limited *authn.RateLimitedError
		switch {
		case errors.As(err, &limited):
			errs.TooManyRequests(w, r, limited.RetryAfter)
		case errors.Is(err, authn.ErrBadCredentials):
			errs.Unauthorized(w, r, h.challenge(r))
		default:
			Logger(ctx, h.Log).Error("v2 probe could not check credentials", "error", err)
			errs.Internal(w, r)
		}
		return
	}

	subject, err := authn.Resolve(ctx, h.Subjects, name)
	switch {
	case errors.Is(err, authn.ErrUnknownSubject), errors.Is(err, authn.ErrDisabled):
		errs.Unauthorized(w, r, h.challenge(r))
		return
	case err != nil:
		Logger(ctx, h.Log).Error("v2 probe could not resolve the subject", "error", err)
		errs.Internal(w, r)
		return
	case subject.IsAnonymous():
		errs.Unauthorized(w, r, h.challenge(r))
		return
	}

	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

func (h *V2Root) challenge(r *http.Request) string {
	if h.Challenge == nil {
		return DefaultChallenge
	}
	return h.Challenge(r)
}

func (h *V2Root) errors() ErrorRenderer {
	if h.Errors == nil {
		return ProblemErrors{}
	}
	return h.Errors
}
