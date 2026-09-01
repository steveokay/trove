# ADR 0015 — Admin API and CLI conventions

- Status: accepted (2026-09-01)
- Task: D-020
- Decisions applied: Q23 (CLI is an API client with named offline exceptions)

## Context

Everything that isn't the OCI distribution API is the admin API: repositories,
identity, roles/bindings, policies, scanning, webhooks, quotas, audit, search,
system operations. The API is the contract; the UI and CLI are both clients of it
(§10). Nothing is UI-only or CLI-only.

## Decision

### API surface

- Prefix `/api/v1/…`. Version in the path; breaking changes mean `/api/v2` (not
  expected within v1.x). The OCI API stays at `/v2/` untouched.
- JSON everywhere. Errors are RFC 9457 `application/problem+json` with a stable
  machine-readable `type` slug per error class, plus `trace_id`. The OCI API keeps
  its spec-shaped error envelope — two contracts, both golden-tested, never mixed.
- Naming: plural resources, kebab-case paths, snake_case JSON fields.
  `GET/POST /api/v1/repositories`, `GET /api/v1/repositories/{name}`,
  `POST /api/v1/roles/{name}/bindings`, `POST /api/v1/system/gc`, etc.
  Long-running operations (GC, migration import, policy apply) return a task
  resource (`/api/v1/tasks/{id}`) to poll.
- Pagination: cursor-based (`?limit=&cursor=`), opaque cursors, `next_cursor` in
  the body. No offset pagination — filtered counts leak (ADR 0003) and offsets
  skew under mutation.
- Every listing is permission-filtered at the query layer; every mutating route
  declares its ADR 0002 verb; unauthorized reads follow ADR 0003.
- The OpenAPI document is hand-written at `docs/api/openapi.yaml`, versioned with
  the code, and CI-checked against the route table (route exists ⟺ spec entry
  exists) — spec drift fails the build.

### CLI

- `trove` subcommands are thin API clients: `login`, `repo`, `tag`, `user`,
  `robot`, `group`, `role`, `binding`, `auth explain`, `policy` (incl. `plan` /
  `apply`), `scan`, `webhook`, `quota`, `audit`, `gc`, `db`, `admin`,
  `support-bundle`, `migrate`, `serve`, `version`.
- Connection: `--server` / `TROVE_SERVER`, token from `trove login` (stored
  0600 in `~/.config/trove/credentials`, ADR 0004) or `TROVE_TOKEN`.
- Output: human tables by default, `--json` for scripts (stable field names =
  the API's), exit codes 0/1/2 (ok / operation failed / usage error).
- **Offline exceptions** (Q23), each refusing to run against a live server's data
  directory (lock file check): `serve`; `version`; `db import --offline`;
  `admin reset-password --offline` (ADR 0004 break-glass); `verify --offline`
  (P-012 against a cold data dir for restore validation). Everything else
  requires the API — no second data-access path to drift.

### Compatibility policy

- Within v1.x: additive changes only (new fields, new endpoints); removals or
  type changes require `/api/v2`. The CLI tolerates unknown response fields.
- The UI consumes the same endpoints with the same tokens (session-cookie auth +
  CSRF per ADR 0004); anything the UI needs that the API lacks is an API gap to
  fix, never a private endpoint.

## Rejected alternatives

- **gRPC for the admin plane** — contradicts the monolith/no-gRPC rule (§3) and
  makes curl-ability and UI consumption worse for zero benefit in-process.
- **Direct-DB CLI** — rejected per Q23: bypasses authz/audit, breaks against
  SQLite locking with a live server, and duplicates business logic outside the
  contract.
- **Generated OpenAPI from code annotations** — generation drift is invisible in
  review; a hand-written spec checked *against* the route table makes the
  contract the reviewed artifact.
- **Offset pagination** — leaks filtered totals and is unstable under writes.

## Consequences

- The route-guard test (Z-011) walks both `/v2/` and `/api/v1/` tables.
- Golden files exist per contract: OCI error envelope, problem+json shapes, and
  representative resource payloads.
- `trove auth explain` (Z-013) is `GET /api/v1/auth/explain?subject=&verb=&resource=`
  — the CLI adds formatting only, so API, CLI, and UI cannot disagree about
  effective permissions.
