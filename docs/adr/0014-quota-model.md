# ADR 0014 — Quota accounting and enforcement

- Status: accepted (2026-09-01)
- Task: D-016
- Decisions applied: Q8 (per-repo + global; deny push; cache evicts, never fails pulls)

## Context

Quotas exist so one team's repository cannot eat the disk (per-repo) and so the
operator can cap total footprint (global). Cached content is re-fetchable, so its
budget behaves differently from hosted limits (§7, ADR 0009).

## Decision

### Accounting

- **Hosted, per-repository**: sum of blob sizes referenced by the repository's
  manifests, deduplicated *within* the repository. A blob shared across
  repositories counts once per repository that references it — attribution over
  physical truth, because quota is a fairness tool and "your repo references 40 GB"
  is the actionable number.
- **Hosted, global**: sum of unique hosted blob sizes — physical truth, because
  the global limit protects the disk.
- **Cache**: physical bytes under the cache tree, one global number (plus
  per-proxy carve-outs, ADR 0008); tracked as `quota_usage(scope=cache)`.
- Usage rows update transactionally with blob/manifest commits (delta updates);
  `trove verify` recomputes from scratch and repairs drift, making the counters
  self-healing rather than load-bearing for correctness.

### Enforcement

- **Soft threshold** (default 85 % of hard): crossing it emits `quota.warned`
  (event + webhook-able + metric). Once per crossing, not per push (hysteresis:
  re-arms below 80 %).
- **Hard limit, hosted**: blob upload *start* is rejected when
  `usage + declared_size > hard` (chunked uploads without a declared size are
  checked at each chunk commit and at final commit). Error: HTTP 413 with OCI
  error code `DENIED`, message naming the quota and current usage — spec-shaped
  (the spec's code list has no quota code; `DENIED` + detail is the conventional
  choice and golden-tested). Manifest PUT is also checked (it can add tiny bytes
  but is the operation that makes content live).
- **Hard limit, cache**: never rejects a pull or a cache fill. Breach triggers
  synchronous eviction pressure (ADR 0008): the fill proceeds, eviction reclaims
  concurrently. If eviction cannot keep up (everything pinned by active leases),
  the cache may transiently exceed its budget — documented, bounded by lease TTLs,
  and surfaced by `quota.exceeded(scope=cache)` so the operator sizes the budget
  up rather than trove breaking cluster pulls (Q8).
- Quota changes require `quota:write`; reads `quota:read`; per-repo quotas at
  repo scope, global at `system` (ADR 0002).

### Interactions

- Read-only/maintenance mode: quota enforcement is moot for writes (all rejected);
  accounting still serves reads.
- GC and retention *reduce* usage; the delta updates ride the same transactions.
- Migration import (PK-006) respects hard limits and fails with a pre-flight
  size estimate rather than mid-import.

## Rejected alternatives

- **Physical-only per-repo accounting** (shared blobs count once, first-referrer
  pays) — makes usage numbers depend on push order; unactionable and unfair.
- **Rejecting cache fills on breach** — rejected per Q8: blocking re-fetchable
  bytes breaks running clusters to save disk that LRU can reclaim.
- **Async usage recomputation as the primary mechanism** — windows of unbounded
  overshoot; transactional deltas with verify-time repair give accuracy and
  self-healing.
- **429/TOOMANYREQUESTS for quota breaches** — semantically wrong (nothing about
  rate); 413 + `DENIED` detail matches client retry behaviour better.

## Consequences

- `internal/quota` exposes `Check(scope, delta) error` and `Apply(scope, delta)`
  used inside upload/manifest transactions — callers cannot forget the check
  without failing the route-guard-style test that asserts upload paths call it.
- Soft-warn hysteresis state lives in the usage row, surviving restarts.
- The UI storage view reports hosted-per-repo, hosted-global, and cache as three
  distinct series (ADR 0009 accounting separation).
