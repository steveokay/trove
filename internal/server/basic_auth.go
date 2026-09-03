package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/steveokay/trove/internal/authn"
)

// BasicAuth returns a CredentialFunc accepting HTTP basic authentication for
// the admin API -- ADR 0004's bootstrap-era ergonomics, and how the freshly
// bootstrapped admin reaches the rotation endpoint before any token flow
// exists. A request with no Authorization header passes through as anonymous;
// the bearer flow (Z-004) layers alongside without changing this.
//
// The username decides which credential is checked: the robot$ prefix names a
// robot account whose password field carries its secret (Z-003b); anything
// else is a user's password. robots may be nil until the keyring is wired,
// which sends robot-shaped usernames down the password path, where they fail
// as bad credentials rather than half-working.
func BasicAuth(login *authn.PasswordLogin, robots *authn.RobotSecrets) CredentialFunc {
	return func(r *http.Request) (string, error) {
		username, password, ok := r.BasicAuth()
		if !ok {
			return "", nil
		}

		if robots != nil && strings.HasPrefix(username, authn.RobotNamePrefix) {
			if err := robots.Verify(r.Context(), username, password, remoteHost(r)); err != nil {
				return "", err
			}
			return username, nil
		}

		if err := login.Authenticate(r.Context(), username, password, remoteHost(r)); err != nil {
			return "", err
		}
		return username, nil
	}
}

// remoteHost is the request's source address without the port: the
// per-address limit keys on the host alone, so one client is one key no
// matter how many source ports it cycles through.
func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
