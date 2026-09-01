package meta

import "time"

// This file models secrets at rest. Two rules hold throughout, and the types
// are shaped to make breaking them awkward:
//
//   - The store never sees a plaintext secret. Passwords arrive as Argon2id
//     hashes and tokens as HMAC digests, both computed in authn (ADR 0004).
//     Every field here is named for what it actually holds.
//   - Expiry is enforced on read, not left to the caller. Lookups take the
//     current time and refuse anything expired, because "check the expiry
//     afterwards" is a check somebody eventually forgets.

// UserCredential is a user's password verifier. Hash is a complete Argon2id
// encoded hash: it carries its own salt and parameters, so the parameters can
// be raised later without invalidating existing passwords.
type UserCredential struct {
	Subject string
	Hash    string
	// MustRotate forces a password change at next login. Bootstrap sets it,
	// so the generated admin password cannot become permanent (Z-014).
	MustRotate bool
	RotatedAt  time.Time
}

// RobotCredential is a robot account's secret. Only the HMAC digest is stored,
// so a database copy does not yield usable credentials, and the secret itself
// is unrecoverable -- it can only be regenerated.
//
// ExpiresAt is mandatory: robot accounts always expire (ADR 0004).
type RobotCredential struct {
	Subject    string
	SecretHash []byte
	ExpiresAt  time.Time
	RotatedAt  time.Time
}

// AccessToken is a personal access token: a long-lived named credential
// belonging to a subject, used by the CLI and API clients. It carries no
// permissions of its own -- authorization always reads live bindings -- so
// revoking it is the only thing revocation here has to mean.
type AccessToken struct {
	ID        string
	Subject   string
	Name      string
	TokenHash []byte
	CreatedAt time.Time
	// ExpiresAt is optional; the zero time means the token does not expire.
	ExpiresAt time.Time
	// LastUsedAt supports "this token has not been used in a year" hygiene.
	LastUsedAt time.Time
}

// Expired reports whether the token has passed its expiry at the given time.
func (t AccessToken) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// Session is a browser session for the web UI. CSRFToken is the value the
// double-submit check compares against; it is bound to the session rather than
// derived from it, so leaking one does not yield the other.
type Session struct {
	ID                string
	Subject           string
	CSRFToken         string
	CreatedAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// Expired reports whether the session has passed either bound. Both matter:
// the idle bound logs out an abandoned session, and the absolute bound stops a
// session living forever just because somebody keeps clicking.
func (s Session) Expired(now time.Time) bool {
	return !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt)
}
