package token

import (
	"sort"
	"strings"

	"github.com/steveokay/trove/internal/authz"
)

// The distribution scope actions this registry understands, and the verbs
// they fail-fast against at mint time. The mapping is deliberately small: the
// token's access claim satisfies the protocol, while every handler re-decides
// with the full vocabulary (ADR 0004).
var actionVerbs = map[string]authz.Verb{
	"pull":   authz.RepoRead,
	"push":   authz.RepoWrite,
	"delete": authz.ManifestDelete,
}

// ParseScopes turns the token endpoint's scope parameters into requests.
//
// Each parameter may itself hold several space-separated scopes -- clients
// disagree about which form to send -- and each scope reads
// "repository:<name>:<action>[,<action>]". Anything else grants nothing and
// fails nothing: an unknown resource type, a malformed entry, an illegal
// repository name, or an unknown action simply is not in the token, which is
// how the scheme expects narrowing to look. The "*" action expands to every
// action this registry knows.
func ParseScopes(values []string) []ResourceActions {
	var out []ResourceActions
	for _, value := range values {
		for _, scope := range strings.Fields(value) {
			if request, ok := parseScope(scope); ok {
				out = append(out, request)
			}
		}
	}
	return out
}

func parseScope(scope string) (ResourceActions, bool) {
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 || parts[0] != "repository" {
		return ResourceActions{}, false
	}
	name := parts[1]
	if _, err := authz.Repository(name); err != nil {
		// The name gate (ADR 0007's grammar) runs before anything touches a
		// path or a query; a scope that fails it never reaches a decision.
		return ResourceActions{}, false
	}

	seen := map[string]bool{}
	for _, action := range strings.Split(parts[2], ",") {
		if action == "*" {
			for known := range actionVerbs {
				seen[known] = true
			}
			continue
		}
		if _, ok := actionVerbs[action]; ok {
			seen[action] = true
		}
	}
	if len(seen) == 0 {
		return ResourceActions{}, false
	}

	actions := make([]string, 0, len(seen))
	for action := range seen {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return ResourceActions{Type: "repository", Name: name, Actions: actions}, true
}

// Grant intersects requested scopes with the subject's effective bindings:
// each action survives only if the bindings allow its verb on that repository
// right now, and a scope left with no actions vanishes from the token.
//
// This is mint-time narrowing (ADR 0004): request wide, receive narrow. It
// asks authz.Allows -- the same decision the handlers make -- so the token
// can never claim more than a live request would be allowed.
func Grant(bindings []authz.Binding, requests []ResourceActions) []ResourceActions {
	var out []ResourceActions
	for _, request := range requests {
		resource, err := authz.Repository(request.Name)
		if err != nil {
			continue
		}
		var granted []string
		for _, action := range request.Actions {
			if authz.Allows(bindings, actionVerbs[action], resource) {
				granted = append(granted, action)
			}
		}
		if len(granted) > 0 {
			out = append(out, ResourceActions{Type: request.Type, Name: request.Name, Actions: granted})
		}
	}
	return out
}
