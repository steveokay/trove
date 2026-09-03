package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authn/token"
)

// TokenChallenge builds the WWW-Authenticate value the OCI token flow needs
// (ADR 0004): an absolute realm pointing at this registry's token endpoint.
// With no external URL configured the realm is derived from the request --
// the Host the client used, over the scheme it used -- which is what a
// single-VM deployment without config gets right by default.
func TokenChallenge(externalURL string) func(*http.Request) string {
	return func(r *http.Request) string {
		base := externalURL
		if base == "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			base = scheme + "://" + r.Host
		}
		return fmt.Sprintf(`Bearer realm=%q,service=%q`, base+"/token", token.Audience)
	}
}

// Bearer layers JWT verification in front of another CredentialFunc: a
// request presenting a bearer token authenticates as the token's subject, and
// anything else falls through -- to basic auth, or to anonymous.
//
// The token only names the subject. Scopes inside it are the protocol's
// fail-fast, never the authority: the guard re-fetches bindings and re-decides
// on every request (ADR 0004 §5), which is what makes a revoked binding take
// effect within one request rather than one token lifetime.
func Bearer(signer *token.Signer, next CredentialFunc) CredentialFunc {
	return func(r *http.Request) (string, error) {
		raw, ok := bearerToken(r)
		if !ok {
			return next(r)
		}
		claims, err := signer.Verify(raw)
		if err != nil || claims.Subject == "" {
			// Present-but-invalid credentials must not degrade to anonymous:
			// the client asked to be someone, and the answer is no.
			return "", authn.ErrBadCredentials
		}
		return claims.Subject, nil
	}
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return "", false
	}
	return value[len(prefix):], true
}

// TokenEndpoint serves GET /token, the distribution token scheme's exchange
// (Z-004, ADR 0004): basic credentials -- a user's password or a robot's
// secret -- or none at all, plus requested scopes; out comes a short-lived
// JWT carrying the intersection of what was asked and what the subject's
// bindings grant at this moment.
type TokenEndpoint struct {
	// Credentials authenticates the request; BasicAuth in production, so the
	// endpoint is rate-limited exactly like every other login surface.
	Credentials CredentialFunc
	// Subjects resolves the authenticated name to a subject.
	Subjects authn.SubjectStore
	// Bindings supplies the subject's effective bindings for the intersection.
	Bindings BindingStore
	// Signer mints the token.
	Signer *token.Signer
	// Challenge is sent with a 401, so a client that failed here knows this
	// is still the place to authenticate.
	Challenge func(*http.Request) string
	// Errors renders refusals. Nil means ProblemErrors.
	Errors ErrorRenderer
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the route on the table. It is public by design and on the
// frozen list: the endpoint that issues credentials cannot require them.
func (h *TokenEndpoint) Register(r *Router) {
	r.HandlePublic(http.MethodGet, "/token",
		"the token endpoint issues credentials, so it cannot require them",
		http.HandlerFunc(h.serve))
}

// tokenResponse is the wire shape docker expects. Both token fields carry the
// same value: older clients read "token", newer ones "access_token".
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

func (h *TokenEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()

	if service := r.URL.Query().Get("service"); service != "" && service != token.Audience {
		errs.BadRequest(w, r, fmt.Sprintf("unknown service %q", service))
		return
	}

	name, err := h.Credentials(r)
	if err != nil {
		var limited *authn.RateLimitedError
		switch {
		case errors.As(err, &limited):
			errs.TooManyRequests(w, r, limited.RetryAfter)
		case errors.Is(err, authn.ErrBadCredentials):
			errs.Unauthorized(w, r, h.challenge(r))
		default:
			Logger(ctx, h.Log).Error("token endpoint could not check credentials", "error", err)
			errs.Internal(w, r)
		}
		return
	}

	subject, err := authn.Resolve(ctx, h.Subjects, name)
	if err != nil {
		switch {
		case errors.Is(err, authn.ErrUnknownSubject), errors.Is(err, authn.ErrDisabled):
			errs.Unauthorized(w, r, h.challenge(r))
		default:
			Logger(ctx, h.Log).Error("token endpoint could not resolve the subject",
				"error", err)
			errs.Internal(w, r)
		}
		return
	}

	bindings, err := FetchBindings(ctx, h.Bindings, subject.Name)
	if err != nil {
		Logger(ctx, h.Log).Error("token endpoint could not read bindings",
			"subject", subject.Name, "error", err)
		errs.Internal(w, r)
		return
	}

	// Request wide, receive narrow: the token carries only what the bindings
	// grant right now, and an anonymous mint with no grants is still a token
	// -- that is how public pulls bootstrap.
	granted := token.Grant(bindings, token.ParseScopes(r.URL.Query()["scope"]))
	minted, err := h.Signer.Mint(subject.Name, granted)
	if err != nil {
		Logger(ctx, h.Log).Error("token endpoint could not mint", "subject", subject.Name, "error", err)
		errs.Internal(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResponse{
		Token:       minted.JWT,
		AccessToken: minted.JWT,
		ExpiresIn:   minted.ExpiresIn,
		IssuedAt:    minted.IssuedAt.UTC().Format(time.RFC3339),
	}); err != nil {
		Logger(ctx, h.Log).Error("token response write failed", "error", err)
	}
}

func (h *TokenEndpoint) challenge(r *http.Request) string {
	if h.Challenge == nil {
		return DefaultChallenge
	}
	return h.Challenge(r)
}

func (h *TokenEndpoint) errors() ErrorRenderer {
	if h.Errors == nil {
		return ProblemErrors{}
	}
	return h.Errors
}
