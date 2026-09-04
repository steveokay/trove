package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The upstream token dance: an anonymous request, a 401 carrying a
// WWW-Authenticate challenge, a token fetched from the realm the challenge
// names, and the original request again with a bearer token. It is the
// distribution spec's auth flow and every public registry uses it.
//
// Two things about it are security-relevant and easy to miss. The realm is a
// URL the *upstream* chose, and the client is about to send the operator's
// upstream password to it, so it goes through the same RedirectPolicy a
// Location header does. And the token that comes back is scoped to one
// repository: it is cached under that scope, never reused across repositories,
// so a token minted for a public repository cannot be replayed at a private
// one.

const (
	// maxChallengeParams bounds what the client will parse out of one
	// WWW-Authenticate header, so a hostile upstream cannot make the parser
	// allocate.
	maxChallengeParams = 32

	// maxTokenBytes bounds a token endpoint's response body.
	maxTokenBytes = 1 << 20

	// defaultTokenLifetime is what the spec says to assume when the token
	// endpoint does not say.
	defaultTokenLifetime = 60 * time.Second

	// tokenExpirySkew is subtracted from a token's lifetime so that a token
	// about to expire is refetched rather than used and rejected.
	tokenExpirySkew = 10 * time.Second

	// basicAuthMemory is how long the client remembers that an upstream
	// answers Basic rather than Bearer. Remembering it saves a 401 round-trip
	// on every fetch against an htpasswd-protected mirror; forgetting it
	// periodically means a mirror that switches to bearer auth recovers
	// without a restart.
	basicAuthMemory = 5 * time.Minute
)

// challenge is a parsed WWW-Authenticate header.
type challenge struct {
	scheme string
	params map[string]string
}

// parseChallenge returns the first usable challenge among the header values.
// Bearer wins over Basic when an upstream offers both, because a bearer token
// keeps the password off every subsequent request.
//
// It reports false for a header that names no scheme this client speaks, which
// the caller turns into ErrUnauthorized: an upstream demanding Negotiate or
// something invented is one we cannot authenticate to, and guessing is worse
// than saying so.
func parseChallenge(values []string) (challenge, bool) {
	var basic challenge
	haveBasic := false

	for _, value := range values {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(value), " ")
		switch strings.ToLower(scheme) {
		case "bearer":
			return challenge{scheme: "bearer", params: parseChallengeParams(rest)}, true
		case "basic":
			if !haveBasic {
				basic = challenge{scheme: "basic", params: parseChallengeParams(rest)}
				haveBasic = true
			}
		}
	}
	return basic, haveBasic
}

// parseChallengeParams reads the comma-separated key=value list off a
// challenge. Values may be quoted, and a quoted value may contain a comma,
// which is why this is a scanner and not a Split.
func parseChallengeParams(s string) map[string]string {
	params := make(map[string]string)
	for len(params) < maxChallengeParams {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			return params
		}
		key, rest, found := strings.Cut(s, "=")
		if !found {
			return params
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rest = strings.TrimLeft(rest, " \t")

		var value string
		if strings.HasPrefix(rest, `"`) {
			value, rest = scanQuoted(rest)
		} else {
			value, rest, _ = strings.Cut(rest, ",")
			value = strings.TrimSpace(value)
		}
		// A key with a space in it is the leading word of a second challenge
		// ("Bearer realm=x, Basic realm=y"), not a parameter of this one.
		if key != "" && !strings.ContainsAny(key, " \t") {
			params[key] = value
		}
		s = rest
	}
	return params
}

// scanQuoted reads a quoted string, honouring backslash escapes, and returns
// it with whatever followed.
func scanQuoted(s string) (string, string) {
	var out strings.Builder
	escaped := false
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			out.WriteByte(c)
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			return out.String(), s[i+1:]
		default:
			out.WriteByte(c)
		}
	}
	// Unterminated: take what there was. The caller either uses it and the
	// upstream rejects it, or the policy refuses the malformed realm.
	return out.String(), ""
}

// authorization is a ready-to-send Authorization header value. The empty value
// means anonymous.
type authorization struct {
	header string
}

// cachedAuth is an authorization and when it stops being usable.
type cachedAuth struct {
	auth    authorization
	expires time.Time
}

// scopeFor is the token scope for pulling from one upstream repository. The
// client only ever pulls: there is no configuration that makes a proxy
// writable (§4), so there is no code path here that asks for push.
func scopeFor(repository string) string {
	return "repository:" + repository + ":pull"
}

// authorizationFor returns a cached authorization for the scope, if one is
// still good.
func (c *RegistryClient) authorizationFor(ctx context.Context, scope string) (authorization, error) {
	c.mu.Lock()
	entry, ok := c.auth[scope]
	basicUntil := c.basicUntil
	c.mu.Unlock()

	now := c.now()
	if ok && now.Before(entry.expires) {
		return entry.auth, nil
	}
	// An upstream known to answer Basic gets the header up front rather than a
	// 401 per request.
	if !basicUntil.IsZero() && now.Before(basicUntil) && c.creds != nil {
		return c.basicAuthorization(ctx)
	}
	return authorization{}, nil
}

// basicAuthorization builds a Basic header from the configured credentials.
func (c *RegistryClient) basicAuthorization(ctx context.Context) (authorization, error) {
	if c.creds == nil {
		return authorization{}, &AuthError{Reason: "upstream requires credentials and none are configured"}
	}
	username, password, err := c.creds.Basic(ctx)
	if err != nil {
		return authorization{}, &AuthError{Reason: "credentials could not be read", Err: err}
	}
	return authorization{header: "Basic " + basicValue(username, password)}, nil
}

// authorize completes a challenge and returns the authorization to retry with.
// It caches what it learns under the scope.
//
// There is no third case: parseChallenge returns only the two schemes this
// client speaks, and a defensive branch here would be a branch no test could
// ever reach.
func (c *RegistryClient) authorize(ctx context.Context, ch challenge, scope string) (authorization, error) {
	if ch.scheme == "basic" {
		auth, err := c.basicAuthorization(ctx)
		if err != nil {
			return authorization{}, err
		}
		c.mu.Lock()
		c.basicUntil = c.now().Add(basicAuthMemory)
		c.mu.Unlock()
		return auth, nil
	}
	return c.fetchToken(ctx, ch, scope)
}

// tokenResponse is the token endpoint's document. Registries differ on which
// field they fill: the spec says "token", Docker's older endpoint says
// "access_token", and several send both.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// fetchToken performs the token exchange for one scope.
func (c *RegistryClient) fetchToken(ctx context.Context, ch challenge, scope string) (authorization, error) {
	realm := ch.params["realm"]
	if realm == "" {
		return authorization{}, &AuthError{Reason: "bearer challenge named no realm"}
	}
	realmURL, err := url.Parse(realm)
	if err != nil {
		return authorization{}, &AuthError{Reason: "bearer challenge named an unparseable realm"}
	}
	// The realm is the upstream's choice of where to send our password, so it
	// is checked exactly as a redirect target is.
	if err := c.redirects.Allow(c.base, realmURL); err != nil {
		return authorization{}, err
	}

	// The challenge's own scope is what is asked for: the upstream knows what
	// it wants to grant, and asking for something else is how a token comes
	// back valid but useless. The cache key stays the scope the *caller* asked
	// about, because that is what the next request will look up.
	requested := scope
	if challenged := ch.params["scope"]; challenged != "" {
		requested = challenged
	}
	query := realmURL.Query()
	if service := ch.params["service"]; service != "" {
		query.Set("service", service)
	}
	if requested != "" {
		query.Set("scope", requested)
	}
	tokenURL := *realmURL
	tokenURL.RawQuery = query.Encode()

	header := http.Header{}
	if c.creds != nil {
		basic, err := c.basicAuthorization(ctx)
		if err != nil {
			return authorization{}, err
		}
		header.Set("Authorization", basic.header)
	}

	// The realm is the one host outside the upstream's family that may see the
	// credential: it was just checked against the policy, and it is the whole
	// point of the exchange.
	resp, err := c.send(ctx, http.MethodGet, &tokenURL, header, authorization{}, realmURL.Hostname())
	if err != nil {
		return authorization{}, err
	}
	defer closeBody(resp)

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		reason := "token endpoint rejected our credentials"
		if c.creds == nil {
			reason = "token endpoint requires credentials and none are configured"
		}
		return authorization{}, &AuthError{Reason: reason}
	case resp.StatusCode != http.StatusOK:
		// Not an authentication failure: an unreachable or throttled token
		// endpoint is reported as what it is, so a caller does not go looking
		// for a password problem during an outage.
		return authorization{}, c.statusError(resp, http.MethodGet, tokenURL.Path)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes))
	if err != nil {
		return authorization{}, &TransportError{Op: "read token response", Err: err}
	}
	var decoded tokenResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return authorization{}, &AuthError{Reason: "token endpoint returned an unreadable document"}
	}
	token := decoded.Token
	if token == "" {
		token = decoded.AccessToken
	}
	if token == "" {
		return authorization{}, &AuthError{Reason: "token endpoint returned no token"}
	}

	lifetime := defaultTokenLifetime
	if decoded.ExpiresIn > 0 {
		lifetime = time.Duration(decoded.ExpiresIn) * time.Second
	}
	if lifetime > tokenExpirySkew {
		lifetime -= tokenExpirySkew
	}

	auth := authorization{header: "Bearer " + token}
	c.mu.Lock()
	c.auth[scope] = cachedAuth{auth: auth, expires: c.now().Add(lifetime)}
	c.mu.Unlock()
	return auth, nil
}

// basicValue encodes a username and password for a Basic header. It is the
// only place in this package that touches a plaintext secret, and it neither
// logs nor stores one: the value goes onto one request and is dropped with it.
func basicValue(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}
