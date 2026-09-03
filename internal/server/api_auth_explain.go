package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
)

// AuthExplain serves the effective-permission explainer (Z-013, ADR 0015):
//
//	GET /api/v1/auth/explain?subject=&verb=&resource=
//
// The answer is authz.Decide rendered, not a parallel implementation: the
// matched bindings in the response are the bindings that would admit the real
// request, so the explainer cannot drift from the decision it explains
// (ADR 0001). The CLI and the UI are both clients of this endpoint and add
// formatting only.
//
// A subject may always explain itself; explaining anybody else requires
// user:read (ADR 0003 surface 8), which the route declares through the
// guard's Self permission rather than checking by hand.
type AuthExplain struct {
	// Subjects looks up the target subject when it is not the caller.
	Subjects authn.SubjectStore
	// Bindings supplies the target's effective bindings.
	Bindings BindingStore
	// Errors renders refusals. Nil means ProblemErrors, the admin API's shape.
	Errors ErrorRenderer
	// Log is the fallback logger when a request carries none.
	Log *slog.Logger
}

// Register puts the route on the table.
func (h *AuthExplain) Register(r *Router) {
	r.HandleFunc(http.MethodGet, "/api/v1/auth/explain", Permission{
		Verb: authz.UserRead,
		Self: func(r *http.Request) (string, error) { return r.URL.Query().Get("subject"), nil },
	}, h.serve)
}

// explainResponse is the wire contract. Field names are stable: the CLI's
// --json output and the UI both pass them through.
type explainResponse struct {
	Subject  explainSubject   `json:"subject"`
	Verb     string           `json:"verb"`
	Resource string           `json:"resource"`
	Allowed  bool             `json:"allowed"`
	Matched  []explainBinding `json:"matched"`
}

type explainSubject struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Disabled explains an otherwise puzzling answer: the grants are still on
	// the books, but a disabled subject has no effective bindings at all.
	Disabled bool `json:"disabled"`
}

type explainBinding struct {
	Binding string `json:"binding"`
	Role    string `json:"role"`
	Scope   string `json:"scope"`
	// ViaGroup names the group that carried the binding. It is usually the
	// real answer to "why do I have this?".
	ViaGroup string `json:"via_group,omitempty"`
}

func (h *AuthExplain) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	errs := h.errors()
	query := r.URL.Query()

	verb, err := authz.ParseVerb(query.Get("verb"))
	if err != nil {
		errs.BadRequest(w, r, err.Error())
		return
	}
	// No resource means the system scope. There is no "system" keyword here:
	// a non-empty resource is always a repository name.
	resource := authz.System()
	resourceName := "system"
	if name := query.Get("resource"); name != "" {
		if resource, err = authz.Repository(name); err != nil {
			errs.BadRequest(w, r, err.Error())
			return
		}
		resourceName = name
	}

	caller, ok := SubjectFrom(ctx)
	if !ok {
		// Unreachable behind the guard. Serving an unattributed request would
		// be worse than refusing one, so this fails closed.
		Logger(ctx, h.Log).Error("explain served without a subject in context")
		errs.Internal(w, r)
		return
	}

	target := query.Get("subject")
	if target == "" {
		target = caller.Name
	}
	subject := explainSubject{Name: caller.Name, Kind: string(caller.Kind), Disabled: caller.Disabled}
	if target != caller.Name {
		stored, err := h.Subjects.GetSubject(ctx, target)
		switch {
		case errors.Is(err, meta.ErrNotFound):
			errs.NotFound(w, r)
			return
		case err != nil:
			Logger(ctx, h.Log).Error("explain could not read the subject",
				"subject", target, "error", err)
			errs.Internal(w, r)
			return
		}
		subject = explainSubject{Name: stored.Name, Kind: string(stored.Kind), Disabled: stored.Disabled}
	}

	bindings, err := FetchBindings(ctx, h.Bindings, target)
	if err != nil {
		Logger(ctx, h.Log).Error("explain could not read bindings",
			"subject", target, "error", err)
		errs.Internal(w, r)
		return
	}

	decision := authz.Decide(bindings, verb, resource)
	matched := make([]explainBinding, 0, len(decision.Matched))
	for _, binding := range decision.Matched {
		matched = append(matched, explainBinding{
			Binding:  binding.ID,
			Role:     binding.Role,
			Scope:    string(binding.Scope),
			ViaGroup: binding.ViaGroup,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(explainResponse{
		Subject:  subject,
		Verb:     string(decision.Verb),
		Resource: resourceName,
		Allowed:  decision.Allowed,
		Matched:  matched,
	}); err != nil {
		// The status line is gone; all that is left is to say so.
		Logger(ctx, h.Log).Error("explain response write failed", "error", err)
	}
}

func (h *AuthExplain) errors() ErrorRenderer {
	if h.Errors == nil {
		return ProblemErrors{}
	}
	return h.Errors
}
