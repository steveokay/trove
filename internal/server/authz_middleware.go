package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
)

// Permission is what a route requires: one verb, and the resource it applies
// to.
//
// Every route declares exactly one verb (ADR 0002). A route that needed two
// would be a route doing two things, and the second check would be the one
// somebody forgets.
type Permission struct {
	// Verb is the permission the route requires.
	Verb authz.Verb
	// Resource extracts what the verb applies to from the request -- usually a
	// repository name out of the path. A nil Resource means the route is about
	// the system itself: user administration, garbage collection, maintenance.
	Resource func(*http.Request) (authz.Resource, error)
	// Self, when set, marks a route about a subject rather than a repository:
	// the explainer, password rotation, a subject's own tokens. It extracts
	// the subject name the request asks about, with empty meaning the caller.
	//
	// A subject may always act on itself -- that is the rule, declared here so
	// the route table shows it, not a bypass of one (ADR 0003 surface 8). Verb
	// is consulted only when the target is somebody else, at the system scope,
	// since subjects are not repositories. A self-admitted request carries no
	// Decision in its context: nothing was decided, the rule is structural.
	//
	// Mutually exclusive with Resource; Handle refuses a route with both.
	Self func(*http.Request) (string, error)
	// RotationExempt lets a subject whose password demands rotation reach
	// this route. It exists for exactly one route -- the rotation endpoint --
	// because a gate with no door is a lockout, not a policy (Z-014). Every
	// other route answers such a subject with the rotation-required refusal.
	RotationExempt bool
}

// resolve returns the resource a request is about.
func (p Permission) resolve(r *http.Request) (authz.Resource, error) {
	if p.Resource == nil {
		return authz.System(), nil
	}
	return p.Resource(r)
}

// CredentialFunc extracts the subject name a request presents, returning an
// empty name when it presents no credentials at all.
//
// It exists as a seam because verifying credentials is Z-002 through Z-004's
// job; what the guard needs to know is only who the request claims to be,
// after that verification has happened.
type CredentialFunc func(*http.Request) (string, error)

// NoCredentials treats every request as unauthenticated, which resolves it to
// the anonymous subject. It is the default until the authentication paths land.
func NoCredentials(*http.Request) (string, error) { return "", nil }

// Guard turns a Permission into an answer.
//
// One guard, one path, no bypass branch: an anonymous request is a request by
// the anonymous subject, and it reaches the same resolution, the same binding
// fetch and the same decision as any other (ADR 0001).
type Guard struct {
	// Subjects resolves credentials to a subject.
	Subjects authn.SubjectStore
	// Bindings supplies what the subject may do.
	Bindings BindingStore
	// Credentials says who the request claims to be. Nil means NoCredentials.
	Credentials CredentialFunc
	// Challenge produces the WWW-Authenticate value sent with a 401.
	// `docker login` depends on it, so it is never omitted (ADR 0003). It is
	// a function of the request because the realm is an absolute URL: with no
	// external_url configured it is derived from the Host the client used
	// (Z-004). Nil means DefaultChallenge.
	Challenge func(*http.Request) string
	// Errors renders refusals. Nil means ProblemErrors, the admin API's shape;
	// the OCI routes supply their own spec-shaped renderer (R-008).
	Errors ErrorRenderer
	// Rotation supplies password credentials for the must-rotate gate
	// (Z-014): a user whose credential demands rotation is refused on every
	// route not marked RotationExempt, so a bootstrap password cannot be used
	// for anything except replacing itself. Nil disables the gate -- for
	// deployments wired before credentials existed, and for tests that are
	// not about it.
	Rotation RotationStore
	// OnDenied is called for every refusal. Z-016 hangs the authz.denied event
	// and its metric here; until then the guard logs each one, because a
	// denial nobody can see is a misconfiguration nobody can find.
	OnDenied func(ctx context.Context, subject authn.Subject, decision authz.Decision)
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// DefaultChallenge is what a 401 offers when nothing more specific is
// configured. Z-004 replaces it with the realm of the token endpoint.
const DefaultChallenge = `Bearer realm="trove"`

// The guard's context keys continue this package's private key type, declared
// with the request-id and logger keys in middleware.go.
const (
	subjectKey contextKey = iota + 100
	decisionKey
)

// SubjectFrom returns the subject a guarded handler is serving. The second
// result is false outside a guarded route.
func SubjectFrom(ctx context.Context) (authn.Subject, bool) {
	subject, ok := ctx.Value(subjectKey).(authn.Subject)
	return subject, ok
}

// DecisionFrom returns the decision that admitted the request, which is what
// an audit record names as the reason access was allowed.
func DecisionFrom(ctx context.Context) (authz.Decision, bool) {
	decision, ok := ctx.Value(decisionKey).(authz.Decision)
	return decision, ok
}

// Require wraps a handler so it runs only for a subject the permission allows.
//
// The refusals follow ADR 0003's matrix exactly, and the reasoning behind each
// is worth keeping next to the code:
//
//   - No usable credentials, or an anonymous subject that lacks the
//     permission: 401 with a challenge. The client may be able to authenticate
//     into visibility, and telling it so is the `docker login` contract.
//   - Authenticated but cannot read the resource: 404, identical to a resource
//     that is genuinely absent. Existence is information; a 403 here would let
//     any authenticated probe enumerate repository names.
//   - Authenticated, can read, but lacks the verb: 403. Readability already
//     disclosed existence, so a helpful answer costs nothing and saves an
//     afternoon.
func (g *Guard) Require(perm Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		errs := g.errors()

		resource, err := perm.resolve(r)
		if err != nil {
			// The resource comes out of the URL, so an unusable one is the
			// client's mistake and is refused before any lookup.
			errs.BadRequest(w, r, err.Error())
			return
		}
		var target string
		if perm.Self != nil {
			// The target comes out of the request the same way a resource
			// does, and an unusable one is refused the same way: before
			// anything is looked up or decided.
			if target, err = perm.Self(r); err != nil {
				errs.BadRequest(w, r, err.Error())
				return
			}
		}

		subject, err := g.subject(ctx, r)
		if err != nil {
			g.refuseUnauthenticated(w, r, err)
			return
		}

		if !perm.RotationExempt {
			switch blocked, err := g.rotationDue(ctx, subject); {
			case err != nil:
				// The gate could not be evaluated, so it has not passed:
				// same fail-closed rule as an unreadable binding.
				Logger(ctx, g.Log).Error("the rotation gate could not read the credential",
					"subject", subject.Name, "error", err)
				errs.Internal(w, r)
				return
			case blocked:
				Logger(ctx, g.Log).Info("refused pending password rotation", "subject", subject.Name)
				errs.RotationRequired(w, r)
				return
			}
		}

		if perm.Self != nil && (target == "" || target == subject.Name) {
			// Self-access. No bindings are consulted and no Decision is
			// stored: the admission is the declared rule, not a grant.
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, subjectKey, subject)))
			return
		}

		bindings, err := FetchBindings(ctx, g.Bindings, subject.Name)
		if err != nil {
			// Failing closed on a broken store: an authorization check that
			// cannot read its bindings has not decided anything, and treating
			// that as a grant is how an outage becomes an incident.
			Logger(ctx, g.Log).Error("authorization could not read bindings",
				"subject", subject.Name, "verb", perm.Verb, "error", err)
			errs.Internal(w, r)
			return
		}

		decision := authz.Decide(bindings, perm.Verb, resource)
		if !decision.Allowed {
			g.refuse(w, r, subject, bindings, decision)
			return
		}

		ctx = context.WithValue(ctx, subjectKey, subject)
		ctx = context.WithValue(ctx, decisionKey, decision)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RotationStore is the slice of the store the must-rotate gate reads.
type RotationStore interface {
	GetUserCredential(ctx context.Context, subject string) (meta.UserCredential, error)
}

// rotationDue reports whether the subject is barred pending a password
// change. Only users have passwords; a user without a password credential --
// token-only, or password login disabled -- has nothing to rotate.
func (g *Guard) rotationDue(ctx context.Context, subject authn.Subject) (bool, error) {
	if g.Rotation == nil || subject.Kind != authn.User {
		return false, nil
	}
	cred, err := g.Rotation.GetUserCredential(ctx, subject.Name)
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	return cred.MustRotate, nil
}

// subject resolves who the request is from.
func (g *Guard) subject(ctx context.Context, r *http.Request) (authn.Subject, error) {
	credentials := g.Credentials
	if credentials == nil {
		credentials = NoCredentials
	}
	name, err := credentials(r)
	if err != nil {
		return authn.Subject{}, err
	}
	return authn.Resolve(ctx, g.Subjects, name)
}

// refuseUnauthenticated answers a request whose subject could not be resolved.
func (g *Guard) refuseUnauthenticated(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()

	var limited *authn.RateLimitedError
	switch {
	case errors.As(err, &limited):
		// The limiter refused before anything was evaluated; the wait is
		// exact, so the Retry-After can be honest (Z-002).
		Logger(ctx, g.Log).Info("authentication rate limited", "retry_after", limited.RetryAfter)
		g.errors().TooManyRequests(w, r, limited.RetryAfter)
	case errors.Is(err, authn.ErrBadCredentials):
		// Wrong password and unknown user arrive here as the same error on
		// purpose; the client gets the challenge and may try again.
		Logger(ctx, g.Log).Info("authentication failed", "error", err)
		g.errors().Unauthorized(w, r, g.challenge(r))
	case errors.Is(err, authn.ErrNoAnonymousSubject):
		// The deployment is broken, not the request: without that row there is
		// no subject for an unauthenticated request to be.
		Logger(ctx, g.Log).Error("the anonymous subject is missing", "error", err)
		g.errors().Internal(w, r)
	case errors.Is(err, authn.ErrUnknownSubject), errors.Is(err, authn.ErrDisabled):
		// Presented credentials that are no longer good. The client may have
		// others, so it gets the challenge rather than a refusal.
		Logger(ctx, g.Log).Info("authentication failed", "error", err)
		g.errors().Unauthorized(w, r, g.challenge(r))
	default:
		Logger(ctx, g.Log).Error("could not resolve the request's subject", "error", err)
		g.errors().Internal(w, r)
	}
}

// refuse answers a request the decision did not allow.
func (g *Guard) refuse(w http.ResponseWriter, r *http.Request, subject authn.Subject,
	bindings []authz.Binding, decision authz.Decision,
) {
	ctx := r.Context()
	if g.OnDenied != nil {
		g.OnDenied(ctx, subject, decision)
	}
	// Until the event bus and the denial metric exist (Z-016), the log is how
	// an operator finds a misconfiguration.
	Logger(ctx, g.Log).Info("authorization denied",
		"subject", subject.Name, "verb", decision.Verb, "resource", decision.Resource.String())

	switch {
	case subject.IsAnonymous():
		// Anonymous lacking access gets the challenge, not a 404: the client
		// may be able to authenticate into visibility (ADR 0003).
		g.errors().Unauthorized(w, r, g.challenge(r))
	case canRead(bindings, decision.Resource):
		g.errors().Forbidden(w, r)
	default:
		// Indistinguishable from a resource that is not there.
		g.errors().NotFound(w, r)
	}
}

// canRead reports whether the subject already knows the resource exists.
//
// Either verb settles it: repo:read pulls from it, repo:list sees it in a
// catalog. Once existence has been disclosed, a 403 tells the client nothing
// it could not already learn, which is what makes the helpful answer safe.
// The system resource is not a secret, so anyone authenticated "can read" it.
func canRead(bindings []authz.Binding, resource authz.Resource) bool {
	if resource.IsSystem() {
		return true
	}
	return authz.Allows(bindings, authz.RepoRead, resource) ||
		authz.Allows(bindings, authz.RepoList, resource)
}

func (g *Guard) challenge(r *http.Request) string {
	if g.Challenge == nil {
		return DefaultChallenge
	}
	return g.Challenge(r)
}

func (g *Guard) errors() ErrorRenderer {
	if g.Errors == nil {
		return ProblemErrors{}
	}
	return g.Errors
}
