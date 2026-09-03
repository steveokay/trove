// Package token implements the OCI distribution token flow's tokens
// (Z-004, ADR 0004): short-lived Ed25519 JWTs carrying the scopes a subject's
// bindings granted at mint time.
//
// The token is a protocol artifact, never the authority: every handler
// re-authorizes against live bindings (§5.2), so a revoked binding takes
// effect within one request rather than one token lifetime. This package is
// also the only importer of the JWT library, which an archtest rule enforces
// -- one place to hold the algorithm allowlist means no second place to get
// it wrong.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// Issuer and Audience are fixed: this registry mints only for itself, and a
// token minted by anything else -- or for anything else -- must not verify.
const (
	Issuer   = "trove"
	Audience = "trove"
)

// TTL bounds (ADR 0004): five minutes by default, clamped to [1m, 60m]. No
// refresh tokens -- clients re-hit the token endpoint, which re-evaluates
// bindings.
const (
	DefaultTTL = 5 * time.Minute
	MinTTL     = time.Minute
	MaxTTL     = time.Hour
)

// ResourceActions is one entry of the token's access claim, in the
// distribution token scheme's shape.
type ResourceActions struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// Minted is a freshly signed token together with the fields the token
// endpoint's response carries.
type Minted struct {
	JWT       string
	ExpiresIn int64
	IssuedAt  time.Time
}

// Claims is what Verify vouches for: who the token names and what it was
// granted at mint time.
type Claims struct {
	Subject string
	Access  []ResourceActions
}

// Signer mints and verifies this registry's tokens.
type Signer struct {
	key ed25519.PrivateKey
	ttl time.Duration
	now func() time.Time
	// random supplies token ids. Injected so a test can pin whole tokens:
	// Ed25519 signatures are deterministic, so a fixed id makes the bytes
	// golden-able.
	random io.Reader
}

// NewSigner builds a signer. A zero ttl means DefaultTTL and anything outside
// [MinTTL, MaxTTL] is clamped rather than honoured -- a config typo must not
// hand out day-long credentials. Nil now and random mean the real clock and
// entropy source.
func NewSigner(key ed25519.PrivateKey, ttl time.Duration, now func() time.Time, random io.Reader) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	switch {
	case ttl == 0:
		ttl = DefaultTTL
	case ttl < MinTTL:
		ttl = MinTTL
	case ttl > MaxTTL:
		ttl = MaxTTL
	}
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &Signer{key: key, ttl: ttl, now: now, random: random}, nil
}

// tokenClaims is the JWT payload: registered claims plus the distribution
// scheme's access array.
type tokenClaims struct {
	jwtlib.RegisteredClaims
	Access []ResourceActions `json:"access"`
}

// Mint signs a token naming the subject and carrying the granted access.
func (s *Signer) Mint(subject string, access []ResourceActions) (Minted, error) {
	id := make([]byte, 16)
	if _, err := io.ReadFull(s.random, id); err != nil {
		return Minted{}, fmt.Errorf("token id: %w", err)
	}

	now := s.now()
	claims := tokenClaims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    Issuer,
			Audience:  jwtlib.ClaimStrings{Audience},
			Subject:   subject,
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(s.ttl)),
			ID:        hex.EncodeToString(id),
		},
		Access: access,
	}

	signed, err := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, claims).SignedString(s.key)
	if err != nil {
		return Minted{}, fmt.Errorf("sign token: %w", err)
	}
	return Minted{JWT: signed, ExpiresIn: int64(s.ttl / time.Second), IssuedAt: now}, nil
}

// Verify parses and checks a presented token: EdDSA under this signer's key
// and nothing else -- the algorithm allowlist is what makes the classic
// HS256-with-the-public-key forgery a parse error instead of a login -- with
// the issuer, audience, and validity window all enforced.
func (s *Signer) Verify(raw string) (Claims, error) {
	var claims tokenClaims
	_, err := jwtlib.ParseWithClaims(raw, &claims,
		func(*jwtlib.Token) (any, error) { return s.key.Public(), nil },
		jwtlib.WithValidMethods([]string{jwtlib.SigningMethodEdDSA.Alg()}),
		jwtlib.WithIssuer(Issuer),
		jwtlib.WithAudience(Audience),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithTimeFunc(s.now),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("verify token: %w", err)
	}
	return Claims{Subject: claims.Subject, Access: claims.Access}, nil
}
