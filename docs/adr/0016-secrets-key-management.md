# ADR 0016 — Secrets key management

- Status: accepted (2026-09-01)
- Task: D-021
- Decisions applied: Q21 (auto-generated keyfile), Q13 (blob encryption out of scope)

## Context

trove stores small secrets that must survive restarts but never appear in
plaintext at rest or in any read path: proxy upstream credentials (C-003), webhook
signing secrets (ADR 0012). Distinct from these encrypted-at-rest secrets are
hashed-at-rest credentials (robot/PAT HMACs, ADR 0004) and the JWT signing key.
Blob payloads are explicitly out of scope (Q13).

## Decision

### Key material

- `<data>/keys/secrets.key` — 32-byte keys, created on first run with 0600
  permissions (and a warning if the directory is group/world accessible). Path
  overridable via `auth.secrets_key_file` for operators mounting a secret from
  their platform.
- `<data>/keys/token-signing.key` — the Ed25519 seed (ADR 0004), same handling.
- Both are the operator's **must-back-up** set, documented together in DOC-002:
  a database backup without the keyfiles cannot decrypt upstream credentials or
  keep sessions/tokens valid. `trove support-bundle` reports their existence and
  fingerprints (never contents).

### Encryption format

- AES-256-GCM, random 96-bit nonce per value. Stored as
  `v1:<key-id>:<base64(nonce ‖ ciphertext)>` — the version and key-id prefix make
  rotation and future algorithm changes data-driven.
- `key-id` = first 8 hex chars of SHA-256(key). The keyfile can hold multiple
  keys (line-delimited): the first is active for encryption; the rest decrypt
  only — this is what makes rotation a two-step, no-downtime operation.
- The associated-data field binds ciphertexts to their column context
  (e.g. `proxy-credential:<repo-id>`), so a ciphertext copied between rows fails
  to decrypt rather than decrypting in the wrong context.

### Rotation

- `trove admin rotate-secrets`: generates a new key, prepends it to the keyfile,
  re-encrypts every stored secret via the API-server code path (an `--offline`
  variant exists per ADR 0015), then reports old-key ciphertext count zero and
  instructs removal of the retired line. Audited.
- Robot/PAT HMACs are keyed by the secrets key too; rotation re-HMACs digests in
  the same pass (possible because rotation has both keys in hand).

### Handling rules

- Secrets are decrypted only at point of use (an upstream request, a webhook
  signature), held in memory transiently, never logged, never serialized into
  events, errors, or support bundles; config dumps print `<redacted:key-id>`.
  The `proxy:credentials` verb gates writing and *whether the API ever returns*
  a credential — and the API never returns one regardless of verb; it returns
  only "set/unset" + last-rotated (C-003's acceptance criterion, stronger than
  the verb).
- A missing or unreadable keyfile at startup with encrypted values present in the
  database is a fatal, loudly-explained startup error — never a silent re-key.

### Clarifications (Z-003a, 2026-09-03)

Three points this ADR left ambiguous, resolved while implementing
`internal/secretbox`. The decisions above are unchanged; these say what they
mean in practice.

- **The keyfile is text, one base64-encoded 32-byte key per line.** "32 random
  bytes" and "line-delimited" are incompatible read literally: raw key material
  contains `0x0a`, so a multi-key file could not be split into lines. Standard
  base64 per line is the only reading that satisfies both.
- **Blank lines and `#` comments are ignored.** Rotation is a two-step
  operation with a retired key sitting in the file until the operator removes
  it; being unable to label that line makes the instruction "remove the retired
  line" harder to follow than it needs to be. A file containing nothing but
  blanks and comments is an error, not an empty keyring.
- **The permission check is strict by default with an explicit opt-out.** A
  group- or world-readable keyfile is refused, because that is almost always an
  accident. Platform-mounted secrets are named above as a supported path and
  arrive 0644 (a Kubernetes secret volume, for instance), so the loader takes an
  option to accept them deliberately. The check is skipped on Windows, where the
  bits do not mean what they say (Q25).
- **HMAC keying stays in `internal/secretbox`.** Robot and PAT digests are keyed
  by the secrets key (above), and the obvious place for that helper is
  `internal/authn`, where the digests are used. It goes here instead: handing
  `authn` the raw key material to do its own HMAC would spread key handling
  across two packages and cost exactly the property this ADR's consequences
  claim — that every use of key material is auditable in one file. Z-003b
  consumes a helper exposed here rather than exporting the key.

## Rejected alternatives

- **Passphrase-derived key (Argon2id)** — a passphrase in env/config is a keyfile
  with worse entropy and worse rotation ergonomics (Q21).
- **External KMS/Vault in v1** — violates optional-dependencies; the keyfile
  format's key-id indirection leaves room for a v1.1 KMS provider behind the same
  interface.
- **Encrypting the whole SQLite file (SQLCipher)** — requires CGO, protects
  nothing on a live system (the process holds the key), and complicates Postgres
  parity.
- **One global key, no key-id** — makes rotation a downtime event and algorithm
  migration a schema migration.

## Consequences

- `internal/config` owns key loading; a tiny `internal/secretbox` package owns
  encrypt/decrypt/rotate and is the only importer of the AEAD primitives —
  auditable in one file.
- Adversarial tests (Z-019/C-015 families): reading a proxy secret via every API
  read path with `proxy:write` and even `proxy:credentials` (must get
  set/unset only), ciphertext swapped between rows (must fail AAD), support
  bundle and config dump scanned for the `trove_r_`/`trove_p_`/`v1:` prefixes.
