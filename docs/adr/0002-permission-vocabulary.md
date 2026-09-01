# ADR 0002 — Permission vocabulary

- Status: accepted (2026-09-01)
- Task: D-018
- Depends on: ADR 0001 (RBAC model)

## Context

Verbs must map to real operations, not HTTP methods, and every verb needs a positive
and a negative test (§9). The vocabulary is closed: handlers reference these constants,
a route-table test proves no route lacks one, and an enumeration test fails if any verb
lacks both test polarities. Adding a verb is an ADR-level change.

## Decision

### Vocabulary

Grouped by resource. *Scope* says which binding scopes the verb is meaningful at.

**Repository content** (scope: repo pattern)

| Verb | Operation |
|---|---|
| `repo:list` | repository appears in catalog, search results, UI listings |
| `repo:read` | pull: blobs, manifests, tag list of the repository |
| `repo:write` | push: blob upload, manifest put, tag create/move (subject to tag policy) |
| `tag:delete` | delete a tag reference |
| `manifest:delete` | delete a manifest (and, per Q22, cascade its referrers) |
| `referrer:read` | list/read referrers — additionally requires `repo:read` on the subject artifact |

**Repository lifecycle** (scope: `system` for create; repo pattern for the rest)

| Verb | Operation |
|---|---|
| `repo:create` | create a hosted/proxy/group repository (C-016) |
| `repo:configure` | change a repository's settings: type-specific config, TTLs, member order, routing rules, tag policy assignment |
| `repo:delete` | delete the repository itself, including all content |

**Scanning & vulnerabilities** (scope: repo pattern)

| Verb | Operation |
|---|---|
| `scan:read` | read scan results, CVE rollups, SBOM-derived reports |
| `scan:trigger` | request an on-demand (re)scan |

**Policy** (scope: repo pattern; `policy:write` also at `system` for global rules)

| Verb | Operation |
|---|---|
| `policy:read` | read rules and dry-run plans |
| `policy:write` | author or edit retention/tag/gating rules |
| `policy:apply` | execute a destructive retention plan |
| `gate:override` | break-glass pull past a gating block; always audited |

**Proxy upstreams** (scope: repo pattern of the proxy repo)

| Verb | Operation |
|---|---|
| `proxy:read` | read upstream config (credentials redacted) |
| `proxy:write` | change upstream URL, TTLs, routing rules |
| `proxy:credentials` | set or reveal upstream credentials |

**Quotas, webhooks, search** (scope: repo pattern; global quota at `system`)

| Verb | Operation |
|---|---|
| `quota:read` / `quota:write` | read / set storage limits |
| `webhook:read` / `webhook:write` | read / manage subscriptions (deliveries filtered by owner's readability, E-004) |
| `search:read` | use cross-repo search (results still filtered per-repo by `repo:list`/`repo:read`) |

**Administration** (scope: `system` only)

| Verb | Operation |
|---|---|
| `user:read` / `user:write` | manage users, robot accounts, groups |
| `role:read` / `role:write` | manage roles and bindings |
| `audit:read` | query/export the audit log |
| `gc:run` | trigger garbage collection |
| `system:maintenance` | toggle read-only mode; CVE DB import/update; support bundle |

### Deliberate non-implications

Each split exists because collapsing it is a real incident class; each gets an
adversarial test (Z-019):

- `repo:write` ↛ `repo:delete`, `tag:delete`, `manifest:delete` — pushing is not purging.
- `repo:configure` ↛ `repo:delete` and ↛ `repo:write` — changing settings is neither
  destroying nor publishing.
- `policy:write` ↛ `policy:apply` — authoring a rule is not executing a deletion plan.
- `proxy:write` ↛ `proxy:credentials` — changing a remote must not reveal its secret.
- `gate:override` is implied by nothing, including `admin`-shaped custom roles unless
  explicitly granted.
- `webhook:write` ↛ receiving events beyond the owner's readable resources.
- `referrer:read` alone grants nothing without `repo:read` on the subject.

### Mapping rules

- Every route declares exactly one verb (or "anonymous-allowed", used only by
  `/healthz`, the token endpoint, and static UI assets); Z-011 walks the table.
- OCI API: pull → `repo:read`; push → `repo:write`; `/v2/_catalog` → `repo:list`;
  referrers → `referrer:read`+`repo:read`. Admin API and CLI use the same constants.

## Rejected alternatives

- **HTTP-method-derived permissions** (`GET`=read, `POST`=write) — collapses every
  deliberate split above and can't express `gate:override`.
- **A generic `repo:admin` bundle verb** — bundles belong in roles, not the
  vocabulary; a bundle verb would be a second, untestable grant path.
- **Per-verb wildcards in roles (`repo:*`)** — expansion-at-grant-time is fine for
  UX in the role editor, but stored roles hold the expanded explicit list so the
  enumeration test and explainer see concrete verbs.

## Consequences

- 33 verbs total. The vocabulary enumeration test (§9) iterates this exact list.
- `repo:create`/`repo:configure` are new relative to CLAUDE.md §5's minimum set,
  closing the gap C-016 exposed (repository CRUD had no verb). CLAUDE.md §5 remains
  the summary; this ADR is authoritative.
- Built-in role definitions in ADR 0001 compose only these verbs.
