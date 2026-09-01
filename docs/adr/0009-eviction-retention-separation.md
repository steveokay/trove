# ADR 0009 — Cache eviction and hosted deletion are separate systems

- Status: accepted (2026-09-01)
- Task: D-013
- Depends on: ADR 0006 (schema families), ADR 0007 (disjoint stores)

## Context

Evicting a cached blob is always recoverable; deleting a hosted blob is not. §4
demands this separation be a type-system obligation with a test proving it — not a
convention. This ADR pins the mechanisms that make crossing the line unwritable.

## Decision

Four independent walls, any one of which stops a crossing:

1. **Distinct types.** Hosted and cached content use distinct Go types with no
   shared interface that includes deletion:
   `meta.HostedManifest` / `meta.CachedManifest`, `blob.HostedRef` / `blob.CachedRef`
   (digest newtypes). There is no `Deletable` abstraction spanning both. A function
   that evicts takes `CachedRef`; one that GC-deletes takes `HostedRef`; passing one
   where the other is expected does not compile.

2. **Distinct store wiring.** Per ADR 0007, `internal/cache` is constructed with
   only the cache-rooted `blob.Store` and the cached-family `meta` view;
   `internal/gc` and `internal/policy` with only the hosted ones. The wiring lives
   in `internal/server` and nowhere else.

3. **Import boundaries.** `internal/cache` must not import `internal/gc` or
   `internal/policy`, and vice versa. The Z-009-style import-allowlist test covers
   these packages too.

4. **Distinct schema families.** ADR 0006's separate table families mean even a raw
   SQL statement in the wrong package has no table to reach.

Operational separation on top:

- **Separate schedules and triggers**: eviction runs on budget pressure and its own
  timer; retention/GC run as scheduled policy tasks (P-006). Neither invokes the
  other.
- **Separate audit event types**: `cache.evicted` vs `artifact.deleted` /
  `gc.swept` — an operator can always answer "was this recoverable?" from the event
  type alone.
- **Separate accounting**: storage metrics and quota usage report `hosted` and
  `cache` as distinct series (Q8); a support bundle shows both numbers.
- **Retention rules cannot select cached content**: the retention evaluator's
  inventory type is built from hosted tables only — a proxy repository contributes
  nothing to a retention inventory, and a policy scoped to a proxy repo evaluates
  to an empty plan with an explanatory note, not an error and not an eviction.

The proving test (§4) asserts: (a) the wiring in `internal/server` passes disjoint
instances; (b) the import allowlist holds; (c) a retention plan built over a fixture
containing both families selects only hosted manifests; (d) an eviction pass over
the same fixture touches only cached rows and cache-store paths (observed via
instrumented fakes).

## Rejected alternatives

- **One deletion engine with a `recoverable` flag** — the flag is data, and data
  gets miswired; types don't.
- **Sharing "delete blob + row" helper code** — the helper would need a store and a
  table name as parameters, reintroducing the crossable seam. Duplication of ~30
  lines is the cheaper risk.
- **Runtime assertions only** (path-prefix checks before delete) — kept as
  defense-in-depth in the blob drivers (a hosted store refuses digests outside its
  root by construction), but runtime checks alone turn a compile error into an
  incident.

## Consequences

- Slight duplication between eviction and GC low-level code, accepted knowingly.
- New deletion-adjacent features (e.g. R-011 upload reaping, E-013 audit pruning)
  must declare which side they live on; upload reaping is hosted-side (it deletes
  staged uploads, never committed blobs), audit pruning is neither (its own table,
  its own path).
- The C-015/adversarial item "a cache-eviction path reaching a hosted blob (must be
  impossible)" is discharged by the proving test above rather than by exploratory
  testing.
