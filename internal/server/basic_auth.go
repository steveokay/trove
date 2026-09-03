package server

import (
	"net"
	"net/http"

	"github.com/steveokay/trove/internal/authn"
)

// BasicAuth returns a CredentialFunc accepting HTTP basic authentication for
// the admin API -- ADR 0004's bootstrap-era ergonomics, and how the freshly
// bootstrapped admin reaches the rotation endpoint before any token flow
// exists. A request with no Authorization header passes through as anonymous;
// the bearer flows (Z-003b, Z-004) layer alongside without changing this.
func BasicAuth(login *authn.PasswordLogin) CredentialFunc {
	return func(r *http.Request) (string, error) {
		username, password, ok := r.BasicAuth()
		if !ok {
			return "", nil
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
