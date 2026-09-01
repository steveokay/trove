# ADR 0001 — RBAC model

- Status: accepted (2026-09-01)
- Task: D-017
- Decisions applied: Q14 (additive-only), Q18 (404 on unauthorized reads),
  Q19 (subjects + local groups), Q20 (repository-pattern scopes only)

## Context

trove is single-tenant but multi-user: one organisation, many people and robots with
different roles, administered centrally. Authorization is load-bearing for group
resolution, search, events, metrics, and the UI (CLAUDE.md §5). The model must be
simple enough to property-test exhaustively and to explain to an operator in one
screen, and it must make disclosure bugs structurally hard, not just discouraged.

## Decision

### Concepts

Three concepts, stored and evaluated separately:

**Subject.** A user, a robot account, or the built-in `anonymous` subject. Anonymous
is a real subject row with real bindings — there is exactly one authorization code
path and no bypass branch. Robot accounts are subjects with mandatory expiry and
revocation; they hold bindings like any user.

**Group.** A local, named set of subjects (Q19). Groups exist purely as binding
targets — they carry no permissions themselves and cannot nest (no groups of
groups; nesting makes effective membership a graph problem for little gain at
single-organisation scale). External identity (v1.1, Q3) will map IdP groups onto
these local groups, so the binding model never changes.

**Role.** A named set of permission verbs from the fixed vocabulary (ADR 0002).
Built-in roles ship read-only and non-deletable. Custom roles compose from the same
vocabulary; no verb exists that a custom role cannot be granted, and none bypasses a
check.

**Binding.** `(subject-or-group, role, scope)`. The complete grant model — nothing
else confers permissions.

### Scope grammar

A scope is exactly one of:

| Form | Meaning |
|---|---|
| `system` | global, non-repository permissions (user admin, GC, maintenance, …) |
| `*` | every repository |
| `team-a/api` | exactly this repository |
| `team-a/*` | every repository whose name starts with `team-a/`, at any depth |

Rules:

- The only wildcard is a single trailing `/*` (or bare `*`). No mid-pattern or
  multi-wildcard forms (`team-*/api`, `*/prod`) — they reintroduce precedence-like
  reasoning and are hard to fuzz convincingly.
- Patterns are validated against the same strict repository-name allowlist regex as
  repository names themselves, before storage. A pattern that could not name a legal
  repository is rejected at write time (this closes traversal-via-binding-pattern).
- Matching is pure string-prefix logic over validated names — no filesystem, no
  regex engine at decision time.
- No tag-level scoping (Q20). Tag-shaped needs (protect `v*`, allow `dev-*`) are
  per-repository tag policies (§7), which apply to everyone, not per-subject grants.

### Decision semantics

**Additive-only. No deny rules (Q14).** The decision is:

```
Decide(subject, bindings, verb, resource) → Decision
```

- Pure function, no I/O, injectable nothing — it takes plain values. The caller
  (middleware, token minting, query-filter builder) fetches the subject's bindings —
  its own plus those of every group it belongs to — before calling.
- `allowed = true` iff at least one binding's role contains `verb` and its scope
  matches `resource`. Union of matches; overlap between patterns is irrelevant
  because nothing can subtract.
- `Decision` carries the outcome **and the full list of matched bindings** — the
  effective-permission explainer (Z-013) is the same call, not a parallel
  implementation that can drift.
- Group membership expansion happens *before* Decide, at binding-fetch time, keeping
  the function pure and making "why does alice have this?" answerable: the
  contributing binding names the group.

### Enforcement invariants (restated from CLAUDE.md §5, binding them to this model)

1. Enforced at every handler and at token minting; token scopes are an optimisation,
   never the authority.
2. Listings, search, events, and metrics are built from permission-filtered queries.
   The query filter is *derived from the same bindings* Decide would use — a scope
   pattern compiles to a SQL prefix predicate, so the query layer and Decide cannot
   disagree.
3. Unauthorized reads return `404` / `NAME_UNKNOWN` uniformly (Q18);
   unauthenticated requests get `401` + `WWW-Authenticate`.
4. Referrers inherit the subject artifact's read permission.
5. The last binding granting `role:write` at `system` scope cannot be removed.
6. Every denial emits an audit event and a metric.

### Built-in roles

| Role | Grants |
|---|---|
| `admin` | every verb, `system` + `*` |
| `operator` | everything except `user:*`, `role:*` |
| `publisher` | `repo:list/read/write`, `tag:delete`, `referrer:read`, `scan:read`, `search:read` in scope |
| `developer` | `repo:list/read`, `referrer:read`, `scan:read`, `search:read` in scope |
| `auditor` | every `*:read` verb + `audit:read`, no writes anywhere |
| `anonymous-reader` | `repo:list/read`, `referrer:read` in scope — exists but ships **unbound**; anonymous access is off until an admin binds it |

Bootstrap creates one admin user bound to `admin`@`system`+`*` with a generated
password printed once and forced rotation (Z-014).

## Rejected alternatives

- **Deny rules / precedence ordering** — makes effective permissions
  order-dependent, kills the union property that makes Decide property-testable,
  and is not retrofittable-away. Rejected per Q14.
- **Tag-level binding scopes** — pushes scope matching into manifest/tag handlers
  and the explainer; per-repo tag policies cover the real use cases. Rejected per Q20.
- **Nested groups** — graph-walk at binding-fetch time, cycles to detect, and the
  explainer output stops being flat. Not worth it at one-organisation scale.
- **Per-repository ACLs instead of roles** (ECR-style resource policies) — two
  places to look for a grant; the explainer and the query filter would need to merge
  two models. One mechanism (bindings) instead.

## Consequences

- `internal/authz` holds subjects/groups/roles/bindings types, the scope grammar +
  validator, and Decide. It imports no registry, repo, or storage package (Z-009
  guards this).
- Carve-outs are impossible by design: granting `team-a/*` grants `team-a/secret`.
  The remedy is repository naming discipline, documented in the RBAC guide (DOC-003).
- The scope grammar's simplicity is what makes Z-007's fuzz target meaningful:
  validator + matcher are each a handful of lines with a small input alphabet.
