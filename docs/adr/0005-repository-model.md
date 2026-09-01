# ADR 0005 — Repository model: hosted / proxy / group

- Status: accepted (2026-09-01)
- Task: D-011
- Decisions applied: Q7 (disabled presets), Q10 (index-child delete is an error)

## Context

The repository is the central abstraction (§1): hosted (writable, irreplaceable),
proxy (read-only cache of an upstream), group (ordered virtual view). The router must
map every `/v2/<name>/...` request to exactly one repository entity, and group
resolution must be a pure, permission-filtered function (§4).

## Decision

### Naming and routing

- A **repository entity** (hosted/proxy/group) is mounted at a **prefix**: the first
  path segment of the OCI repository name. `docker pull registry.example.com/all/library/nginx`
  → entity `all`, **remainder** `library/nginx`.
- The full OCI repository name (`all/library/nginx`) is what RBAC scopes match
  (ADR 0001) and what appears in catalogs, bindings, and events. The entity prefix is
  routing; the full name is identity.
- Entity names and remainders are validated against the distribution-spec name
  grammar plus our stricter allowlist (no `..`, no empty segments) before any lookup.
- A request whose first segment matches no entity is `NAME_UNKNOWN` (per ADR 0003,
  indistinguishable from an unreadable entity).

### Hosted

- Fully writable per bindings; content lives in the hosted blob/manifest stores.
- Deleting a child manifest still referenced by a multi-arch index fails with
  `DENIED`-class spec error naming the referencing index digest (Q10); deleting the
  index first releases the children.

### Proxy

- Client pushes fail with `DENIED` unconditionally — no configuration makes a proxy
  writable.
- Config: upstream URL, optional credentials (ADR 0016), optional **path rewrite**
  (default: remainder passes through; Docker Hub preset maps bare `nginx` →
  `library/nginx`), routing allow/block patterns evaluated allow-first with a
  default-deny option (C-010), TTLs (ADR 0007-cache), offline strictness.
- Presets for Docker Hub, ghcr.io, quay.io, registry.k8s.io, gcr.io ship **disabled**
  (Q7); enabling one is an explicit `repo:configure` action.

### Group

- Ordered member list of hosted and proxy entities; order is explicit configuration,
  never implicit. Hosted-before-proxy is the preset ordering in the quickstart, not
  a rule.
- Resolution is a pure function: `resolve(filteredMembers, reference) → (member, result)`.
  - **Permission filtering happens first**: members the subject cannot read are
    removed before resolution runs (C-012). No behaviour — digest served, error
    shape, latency class — may depend on a filtered member.
  - First member that can serve the reference wins. A member returning
    NOT-FOUND-class results is passed over; a member that is *down* is skipped with
    an event (`group.member.skipped`) unless marked `required`, in which case the
    group returns 503-class failure.
  - A member returning a malformed or digest-mismatched manifest is treated as down
    for that request (skip + event), never served through.
- Writes: a group is read-only unless exactly one hosted member is designated
  `writeTarget`; pushes then route to it and appear group-wide by construction.
- Groups cannot contain groups (no nesting) — resolution stays one level deep,
  orderings stay auditable.

### Lifecycle (C-016)

- `repo:create` (system scope) creates entities; `repo:configure` mutates config;
  `repo:delete` removes an entity — for hosted this is destructive and requires the
  same confirmation flow as `policy:apply`; for proxy it drops config and cache
  (recoverable by re-creation); a group deletion never touches member content.
- Config changes are audited with before/after (§8) and versioned in the metadata
  store so a support bundle shows config history.

## Rejected alternatives

- **Flat single namespace with per-repo type flags** (every OCI name is its own
  entity) — makes "one URL for everything" groups impossible and explodes proxy
  config duplication.
- **Nexus-style `/repository/<name>/` URL prefix** — breaks the `/v2/` path
  contract that clients hardcode.
- **Nested groups** — resolution becomes recursive with cycle detection; ordering
  semantics stop being explainable in one sentence.
- **Regex routing rules** — the allow/block patterns use the same trailing-wildcard
  grammar as binding scopes (ADR 0001); one grammar, one fuzzer.

## Consequences

- `internal/repo` owns entities, the router, and group resolution; resolution takes
  already-filtered member state, keeping it pure and exhaustively table-testable.
- The catalog lists full OCI names, assembled per entity type: hosted enumerate
  their manifests; proxies enumerate cached content only (never the upstream);
  groups enumerate the union of readable members' listings.
- Binding scopes naturally express entity-level grants (`all/*`) and sub-tree
  grants (`all/library/*`) with no new mechanism.
