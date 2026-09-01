# Phase 6 — Policies, retention, GC, quotas: task specs

ADRs: 0010 (retention/GC), 0011 (referrers), 0014 (quotas). P-010/P-011 are Dropped.
Parallelization: P-001/P-002 first (policy core), then P-004→P-006 serial;
P-007/P-008 (GC) and P-009 (quota) parallel to the policy track; P-012 last.

---

## P-001 Tag policies: immutability, prefix exceptions, protected tags
- **Deps:** R-003
- **Files:** `internal/policy/tags.go`, enforcement in `internal/registry/manifests.go`
- **Do:** Per-repo tag policy: immutable flag with exception patterns (Z-007
  grammar, e.g. everything immutable except `dev-*`), protected-tag list/patterns.
  Immutable: tag re-point → `TAG_INVALID`-class error (delete also refused).
  Protected: excluded from every retention inventory (ADR 0010 layer 1) and from
  manual tag delete without `?force` + `tag:delete`.
- **Accept:** Protected/immutable beat every retention rule — adversarial tests;
  push of a new tag unaffected.
- **Test:** Enforcement matrix (push-new/re-point/delete × mutable/immutable/
  excepted/protected); retention-interaction fixtures (P-002 reuse).

## P-002 Retention evaluator (pure)
- **Deps:** D-008 ✓, D-022 ✓
- **Files:** `internal/policy/{retention.go,inventory.go,plan.go}`
- **Do:** ADR 0010: `Evaluate(inventory, rules, now) → Plan`; rules keep-last-N,
  keep-newer-than, keep-if-pulled-since, regex include/exclude, tag-status; integer
  priorities, equal-priority conflict = typed error; protected/immutable/index-
  referenced/live-referrer manifests excluded at inventory build; plan entries
  carry selecting rule + referrer subtree (ADR 0011).
- **Accept:** Zero I/O (archtest: policy imports no store packages for the
  evaluator file set); plan explains every entry; cannot select a referrer of a
  live subject.
- **Test:** Property tests (determinism, protection dominance, priority total
  order, monotonicity: adding a keep-rule never grows the plan); fuzz rule sets;
  the §9 adversarial "select a protected tag" (must be structurally impossible —
  assert inventory excludes it).

## P-003 `keep-if-pulled-since`
- **Deps:** P-002, R-010
- **Files:** rule in `internal/policy/retention.go`
- **Do:** Uses `pull_stats` snapshot in the inventory; document the 60 s flush
  precision bound (ADR 0010); never-pulled falls back to `created_at` comparison
  (explicit in rule semantics, documented).
- **Accept:** Recently-pulled tag survives where an untouched twin is planned.
- **Test:** Clock-injected tables incl. never-pulled, pulled-exactly-at-boundary,
  stats-lagging-behind cases.

## P-004 Dry-run plan output
- **Deps:** P-002, D-020 ✓
- **Files:** `internal/server/api_policies.go` (plan endpoints), `cmd/trove/policy.go`
- **Do:** `POST /api/v1/policies/{id}/plan` → task resource → Plan JSON (entries:
  digest, tags, rule, why-not-saved, referrer subtree, byte estimate); plan
  content-hash included (ADR 0010 apply pinning); gated `policy:read`.
- **Accept:** Dry-run is the only default behavior; CLI renders human + `--json`.
- **Test:** Plan payload golden; hash stability test (same state ⇒ same hash);
  authz matrix.

## P-005 Apply path
- **Deps:** P-004, Z-005
- **Files:** `internal/policy/apply.go`, API apply endpoint
- **Do:** `policy:apply` + plan-hash confirmation; re-validate each entry against
  live state inside the delete transaction (ADR 0010 layer 2 — stale entries
  skipped + reported); per-manifest audit records incl. cascade members; emits
  `artifact.deleted`.
- **Accept:** Stale plan (state changed) rejected wholesale by hash; per-entry
  re-check skips newly-protected items; `policy:write` alone cannot apply (Z-019).
- **Test:** Hash-mismatch rejection; concurrent tag-push-during-apply race
  (pushed tag's manifest survives); audit completeness assertion.

## P-006 Scheduler
- **Deps:** P-005
- **Files:** `internal/policy/scheduler.go`
- **Do:** Cron-like in-process scheduler (`Lease` no-op seam per ADR 0018) running:
  retention plans+auto-apply (only where a policy explicitly opts in
  `auto_apply: true` — default manual), GC (P-007), eviction (C-013), upload
  reaping (R-011), audit pruning (E-013), DB update (S-004). Overlap guard: a
  job kind never runs concurrently with itself.
- **Accept:** Overlapping runs cannot double-delete (guard test); schedules
  configurable + visible via API.
- **Test:** Clock-injected schedule tests; overlap guard under a slow fake job;
  registration completeness test (every scheduled job kind present).

## P-007 Mark-and-sweep GC
- **Deps:** D-008 ✓, F-009
- **Files:** `internal/gc/{mark.go,sweep.go,run.go}`
- **Do:** ADR 0010 exactly: transaction-consistent mark from live manifests via
  `manifest_refs`; sweep conditions (unmarked ∧ older-than-grace ∧ no upload
  session) re-checked in the per-blob delete transaction (`FOR UPDATE` on
  Postgres); row-before-bytes order; batch cursor persisted in `gc_runs`;
  mark-snapshot age bound for resume; hosted instances only (ADR 0009).
- **Accept:** Cannot delete a blob referenced by a concurrent upload — the P-008
  matrix; resumable mid-sweep; `gc.completed` event with counts.
- **Test:** See P-008 (separate task for the matrix); unit tests for mark
  reachability (index chains, referrer chains as roots per ADR 0011 orphan rule)
  and cursor persistence.

## P-008 GC race tests
- **Deps:** P-007
- **Files:** `internal/gc/race_test.go`, `test/gcrace/` integration variant
- **Do:** The ADR 0010 matrix as deterministic interleaving tests (injected
  sync-points in the sweep loop) + a chaos variant under `-race`: GC vs blob
  upload, GC vs manifest PUT referencing a candidate, GC vs manifest delete,
  interrupt+resume at each phase boundary, grace-window boundary cases.
- **Accept:** Every matrix cell has a deterministic test; chaos run green in CI
  nightly.
- **Test:** This is the test task; sync-point injection itself unit-tested.

## P-009 Quota accounting + enforcement
- **Deps:** D-016 ✓, F-006
- **Files:** `internal/quota/{account.go,enforce.go}`, wiring in upload/manifest
  transactions and C-013
- **Do:** ADR 0014: attribution per-repo + physical global + cache scope;
  transactional deltas; `Check` at upload start/chunk/commit and manifest PUT;
  hysteresis soft-warn (85 %/re-arm 80 %) → `quota.warned`; hard hosted breach →
  413 + `DENIED` detail; cache breach → eviction pressure + `quota.exceeded`,
  never a failed pull.
- **Accept:** All Q8 behaviors; upload paths provably call Check (guard test à la
  Z-011 over mutation paths).
- **Test:** Accounting property (delta sum == recount) under concurrent
  pushes/deletes; hysteresis clock tests; breach matrix per scope; verify-repair
  drift test (with P-012).

## P-012 `trove verify` integrity scrub
- **Deps:** F-006, F-008, P-009
- **Files:** `internal/gc/verify.go` (read-only — lives beside GC but writes
  nothing except quarantine moves), `cmd/trove/verify.go`, API task endpoint
- **Do:** Walk both blob stores re-hashing at rest; reconcile rows↔bytes both
  directions (bytes-without-row = leak report; row-without-bytes = corruption
  alert + event); recompute quota usage and repair counters (ADR 0014);
  `--offline` mode for restore validation (ADR 0015).
- **Accept:** Detects a bit-flipped blob, a leaked orphan, a missing blob, and
  quota drift in fixtures; read-only guarantee (archtest: no delete calls except
  quarantine).
- **Test:** Corruption-fixture matrix; offline-mode against a cold copy of a
  fixture data dir; quota-repair assertion; runtime bound test (streams, no
  full-file loads).
