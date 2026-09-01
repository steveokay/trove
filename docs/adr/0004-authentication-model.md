# ADR 0004 — Authentication model

- Status: accepted (2026-09-01)
- Task: D-003
- Decisions applied: Q3 (local only in v1), Q19 (local groups), Q23 (CLI is an API client)

## Context

Three client classes authenticate: OCI clients (docker/helm/oras/cosign) via the
distribution token flow, the CLI and API scripts via bearer tokens, and browsers via
the embedded UI. All resolve to the same subject model (ADR 0001); authorization is
identical regardless of how the subject arrived.

## Decision

### Identities

- **Users**: username + password, Argon2id (interactive-safe parameters, tuned at
  bootstrap and stored per-hash so parameters can be raised later). Constant-time
  comparison. Auth endpoints rate-limited per source IP and per account.
- **Robot accounts**: created under `user:write`, named `robot$<name>`. A robot has a
  mandatory expiry (default 90 days, maximum configurable) and one active secret at a
  time, shown once at (re)generation. Secrets have the form
  `trove_r_<robot-id>_<random>` and are stored as HMAC-SHA-256 digests keyed by the
  secrets key (ADR 0016) — never recoverable, only regenerable. Revocation deletes
  the digest; the next use fails regardless of any outstanding token lifetime.
- **Anonymous**: the built-in subject; used whenever no credentials are presented and
  the endpoint permits evaluation. Gets whatever bindings an admin gave it — none by
  default.
- **Groups**: local, flat, managed under `user:write`; binding targets only.

### OCI token flow (Z-004)

Standard distribution token scheme:

1. Unauthenticated `/v2/` requests get `401` with
   `WWW-Authenticate: Bearer realm="https://<host>/token",service="trove"`.
2. The token endpoint accepts basic auth (user or robot credentials) or no
   credentials (anonymous) plus requested `scope`s.
3. Requested scopes are intersected with the subject's effective permissions at mint
   time (ADR 0001 Decide); the token carries only granted scopes.
4. Access tokens are JWTs signed with an Ed25519 key generated at first run and
   stored beside the secrets key. TTL 5 minutes (config-clamped 1–60). No refresh
   tokens — clients re-hit the token endpoint, which is cheap and re-evaluates
   bindings.
5. **Handlers re-authorize every request** against current bindings (§5.2). Token
   scopes exist to satisfy the protocol and fail fast, never as the authority — a
   revoked binding takes effect within one request, not one token lifetime (Z-019).

### API / CLI authentication

- The admin API accepts the same bearer JWTs, and basic auth for bootstrap-era
  ergonomics (rate-limited identically).
- `trove login` exchanges credentials for a **personal access token** — a long-lived
  named credential (`trove_p_<id>_<random>`, hashed at rest like robot secrets,
  listable and revocable per subject, optional expiry). Stored in
  `~/.config/trove/credentials` (0600) or supplied via `TROVE_TOKEN`.
- PATs authenticate as their owning subject; they carry no scopes of their own —
  authorization is always live bindings.

### UI sessions (Z-020)

- Cookie-based server-side sessions: opaque 256-bit ID, `HttpOnly`, `Secure`,
  `SameSite=Lax`; server-side session row holds subject + expiry (idle 24 h,
  absolute 7 d, both configurable).
- CSRF: double-submit token bound to the session, required on every mutating
  request; the API distinguishes cookie-auth (CSRF enforced) from bearer-auth
  (exempt — no ambient authority).
- Login page rate-limited with the same limiter as the token endpoint; sessions
  invalidated on password change.

### Bootstrap and recovery

- First run creates `admin` with a generated password printed once to stdout;
  forced rotation on first login (Z-014).
- Password recovery is admin-mediated (`user:write` resets, forcing rotation).
  Lost sole-admin password: `trove admin reset-password --offline` against the data
  directory with the server stopped — the documented break-glass, requiring host
  access, which is the actual trust boundary of a self-hosted system.

## Rejected alternatives

- **OIDC/LDAP in v1** — deferred (Q3); external groups will map onto local groups,
  so nothing here changes shape in v1.1.
- **Refresh tokens** — statefulness and revocation complexity for no benefit when
  the token endpoint is local and cheap.
- **Scope-authoritative tokens (no per-request authz)** — violates §5.2; revocation
  latency becomes token TTL.
- **bcrypt/scrypt** — Argon2id is the current OWASP first choice and has a pure-Go
  implementation (`golang.org/x/crypto/argon2`), keeping CGO_ENABLED=0.

## Consequences

- `internal/authn` owns credentials, hashing, tokens, and sessions; it emits a
  `Subject` and nothing else — `internal/authz` never sees a password or token.
- Three credential formats (`trove_r_`, `trove_p_`, session cookie) are prefix-
  distinguishable, making support-bundle redaction and secret scanning reliable.
- The Ed25519 signing key and secrets key (ADR 0016) form the "must back up"
  key material set, documented together.
