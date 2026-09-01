# Phase 5 — Scanning and vulnerability assessment: task specs

ADRs: 0013 (gating), 0017 (scanner). Parallelization: S-001 freezes the interface;
then S-002 (adapter) and S-003/S-006 (queue/model) proceed in parallel; S-011 last.

---

## S-001 `scan.Scanner` interface + fake
- **Deps:** D-002 ✓
- **Files:** `internal/scan/{scanner.go,report.go,fake/fake.go}`
- **Do:** ADR 0017 interface + normalised `Report` types; `fake.Scanner` is
  scriptable (findings per digest, latency, failure injection) and drives every
  non-adapter test in this phase and ADR 0013's gating tests.
- **Accept:** Interface frozen; archtest rule active (only `internal/scan/trivy`
  may import trivy — enforced even before that package exists).
- **Test:** Fake's own behavioral tests; report type invariants (severity enum
  total, no vendor types leak).

## S-002 Trivy adapter + normalisation
- **Deps:** S-001
- **Files:** `internal/scan/trivy/{adapter.go,normalize.go}`,
  `internal/scan/trivy/testdata/corpus/*`
- **Do:** ADR 0017: pinned trivy library, OCI-layout handoff from our blob store,
  vuln-only mode; severity mapping (unknown → low, never dropped); vendor JSON
  discarded post-mapping (debug dump flag to disk only).
- **Accept:** Golden corpus (≥3 fixture images: distroless-clean, alpine-with-CVEs,
  multi-ecosystem) maps to exact normalised output; corpus re-run gates trivy
  upgrades.
- **Test:** Golden corpus; mapping edge table (unknown severity, missing fixed
  version, duplicate CVE across layers); `make vendor-audit` diff recorded in PR.

## S-003 Async scan queue
- **Deps:** S-001, F-006
- **Files:** `internal/scan/queue.go`
- **Do:** Table-backed queue (transactional row claims per ADR 0018), triggers:
  push, cache-fill, DB-update, schedule, manual. Concurrency default 1; retry with
  backoff, terminal-failure state visible. Push path only inserts a row.
- **Accept:** R-012's backlog benchmark: push latency unchanged with 1k queued
  scans; queue survives restart.
- **Test:** Claim-contention test (two workers, no double-scan); retry/terminal
  table; restart-resume test.

## S-004 CVE DB lifecycle
- **Deps:** S-002
- **Files:** `internal/scan/trivy/dbupdate.go`, `cmd/trove/db.go`, API task endpoint
- **Do:** ADR 0017: scheduled online update (12 h default, disableable);
  `trove db import <file>` (API + `--offline`) validating archive digest/format;
  DB version recorded + exposed (metrics, `/readyz` detail).
- **Accept:** Air-gapped path proven: no-network test imports an archive fixture
  and scans successfully.
- **Test:** Import validation corpus (truncated/wrong-format/ok); no-network
  integration; version-recording assertions.

## S-005 Rescan on DB update + `scan.regressed`
- **Deps:** S-004, E-001
- **Files:** `internal/scan/rescan.go`
- **Do:** DB-version change → enqueue rescan for all live manifests (batched,
  low priority); diff new report vs prior; clean→dirty emits `scan.regressed`
  (ADR 0012 payload: digest, new findings summary).
- **Accept:** Yesterday-clean image re-flags after importing a DB containing its
  CVE; event carries the diff.
- **Test:** Fake-scanner scripted before/after reports; event payload golden;
  batching bound test (10k manifests → bounded queue insert batches).

## S-006 Vulnerability model, rollups, queries
- **Deps:** S-002, Z-012
- **Files:** `internal/vuln/{model.go,rollup.go,queries.go}`
- **Do:** Rollups per manifest/repo: counts by severity × fixability, worst
  severity, suppressed-count; queries permission-filtered (Z-012 predicates);
  feeds gating (ADR 0013 inputs) and UI/search.
- **Accept:** Fixable/not split correct; unreadable repos absent from all vuln
  queries (Z-018 subtest unskipped).
- **Test:** Rollup property tests (suppression subtraction, severity ordering);
  filtered-query fixtures on both engines.

## S-007 VEX / suppression rules
- **Deps:** S-006
- **Files:** `internal/vuln/suppress.go`, API handlers
- **Do:** ADR 0006 `suppressions`: (cve, scope-pattern, reason, actor, expiry
  mandatory); applied at rollup/gating evaluation time (findings stay stored);
  create/delete audited; expired suppressions auto-inert + event.
- **Accept:** Suppressed CVE doesn't gate or count in rollups but remains visible
  as suppressed; expiry re-activates it.
- **Test:** Clock-injected expiry; scope-pattern reuse of Z-007 grammar; audit
  record assertions.

## S-008 Scan results as OCI referrers
- **Deps:** R-005, S-002
- **Files:** `internal/scan/attest.go`
- **Do:** On scan completion, write a referrer manifest (our artifactType,
  in-toto-style predicate with normalised summary + DB version) attached to the
  subject in the same repo; replaced (not accumulated) per scanner+DB-version;
  dies with subject per ADR 0011.
- **Accept:** `oras discover` shows it; external tooling can read it; migration
  export carries it (it's just a referrer).
- **Test:** Attach/replace semantics; payload golden; cascade covered by R-002
  tests (fixture reuse).

## S-009 Scan-on-cache-fill
- **Deps:** C-004, S-003
- **Files:** wiring in `internal/proxy/fill.go` → queue insert
- **Do:** Cache fill enqueues scan of the cached manifest (Q24: fill serves
  immediately); results feed gating for subsequent pulls; cached content never
  silently exempt.
- **Accept:** Filled-then-pulled-again sequence gates on the second pull when
  policy demands; `block-until-scanned` repos hold the first serve (ADR 0013).
- **Test:** Sequence tests with fake scanner latency; strict-mode hold test;
  proxy+gating integration fixture.

## S-010 Registry-wide scan config
- **Deps:** S-003
- **Files:** `internal/scan/config.go`
- **Do:** Include/exclude repo patterns (Z-007 grammar) for on-push/on-fill
  triggers and scheduled rescan cadence; per ADR 0002 gated `policy:write`
  (scan config is policy).
- **Accept:** Excluded repo gets no automatic scans but allows `scan:trigger`.
- **Test:** Pattern-evaluation table; trigger-matrix (push/fill/schedule ×
  included/excluded).

## S-011 Pull gating enforcement
- **Deps:** D-015 ✓, S-006, S-007, C-012
- **Files:** `internal/policy/gate.go`, wiring in the manifest-serving function
- **Do:** ADR 0013 in full: pure `EvaluateGate(policy, rollup, referrerKinds,
  scanAge) → Verdict`; single enforcement door; fail-closed on lookup errors for
  gated repos; 403 + structured detail; `Trove-Gate-Override` header path
  requiring `gate:override`, mandatory reason, always audited + event.
- **Accept:** Bypass matrix green: digest ref, group member, referrer, child
  manifest — all consistent with ADR 0013 placement rules; off-by-default proven
  (no policy ⇒ zero gating overhead measured).
- **Test:** Pure-evaluator property/table tests; the four bypass adversarial
  tests; override audit assertions; fail-closed fault injection; R-012 bench
  delta with gating off.
