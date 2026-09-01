# ADR 0010 — Retention evaluation and GC safety model

- Status: accepted (2026-09-01)
- Task: D-008
- Depends on: ADR 0006 (manifest_refs, gc_runs), ADR 0009 (hosted-only scope)
- Decisions applied: Q10 (index-child error), Q16 (immediate delete, GC-lag grace)

## Context

Deletion of hosted content is the one irreversible operation trove performs. The
design principle is asymmetric: **prefer leaking a blob over losing one** (§7).
Retention decides *which manifests* should go; GC decides *which blobs* are
thereby unreferenced. They are separate stages with separate safety arguments.

## Decision

### Retention: pure evaluation, explicit plans

- `Evaluate(inventory, rules, now) → Plan` — no I/O, injectable clock. The
  inventory is a plain snapshot of one repository's tags, manifests, pull stats,
  and protection flags; the plan lists manifest digests with, per entry, the rule
  that selected it and the rules that declined to save it.
- Rules: `keep-last-N`, `keep-newer-than`, `keep-if-pulled-since`, tag regex
  include/exclude, tag-status filters (tagged/untagged). Rules carry explicit
  integer priorities; two rules at the same priority selecting differently is an
  evaluation **error**, not a coin flip (§7).
- **Protection beats everything**: protected tags, immutable tags (with prefix
  exceptions), and manifests referenced by a live multi-arch index or referrer
  chain are excluded from the inventory's selectable set *before* rules run, and
  the apply step re-checks each entry against live state inside the deletion
  transaction — two independent layers, both adversarially tested (P-001).
- Dry-run is the default everywhere; applying requires `policy:apply`, an explicit
  confirmation carrying the plan's content hash (a stale plan — state changed since
  evaluation — is rejected), and produces one audit record per deleted manifest.
- Cascade per Q22/ADR 0011: a plan entry implicitly includes the manifest's
  referrer subtree, listed visibly in the plan.

### GC: mark-and-sweep over hosted blobs

Deleting a manifest removes its rows (manifest, refs, tags) immediately — Q16 —
but blob bytes die only in GC:

- **Mark**: roots are every live hosted manifest row. Reachability follows
  `manifest_refs` edges (config, layers, child manifests). The mark set is computed
  from a single transaction-consistent read.
- **Sweep**: a blob is deletable iff (a) not in the mark set, (b) its row's
  `created_at` is older than the **grace window** (default 24 h), and (c) no
  `upload_sessions` row references its digest. The grace window is what protects
  blobs uploaded mid-sweep whose manifest hasn't been PUT yet — cross-repo blob
  mounts and normal pushes both create the blob row before the manifest row.
- **Delete order**: metadata row first (transactionally re-checking conditions
  a–c inside the delete transaction), then blob store bytes. A crash between the
  two leaks bytes — rediscovered by `trove verify` (P-012) — and never the
  reverse: a row without bytes is the corruption class we refuse to create.
- **Resumable**: the sweep cursor (last digest processed) persists in `gc_runs`
  after each batch; an interrupted sweep resumes without re-marking only if the
  mark snapshot is younger than the grace window, else it restarts mark. Progress
  is a metric and `gc.completed` an event.
- **Concurrency**: manifest PUT validates that all referenced blobs exist *and*
  inserts `manifest_refs` in the same transaction; the sweep's per-blob delete
  transaction re-checks the ref count. Under SQLite this serializes naturally;
  under Postgres the re-check runs with the blob row locked (`SELECT … FOR
  UPDATE`). The race test matrix (P-008): GC vs concurrent upload, GC vs manifest
  PUT referencing a sweep-candidate blob, GC vs delete, interrupt/resume at every
  phase boundary.

### Safety argument (proof sketch, per D-008 acceptance)

A blob is deleted only if unreferenced at mark time, unreferenced again inside the
delete transaction, older than the grace window, and not part of an active upload.
A new reference can only appear via manifest PUT, which requires the blob row to
exist and takes a conflicting lock on it during ref insertion. Therefore a
reference created before the delete transaction commits causes the re-check to see
it (abort delete); one created after commits fails manifest PUT's existence check
(client re-uploads the blob — spec-legal). The remaining window — blob uploaded,
manifest not yet PUT — is covered by the grace window plus upload-session pinning.
Every failure mode degrades to *leak*, reclaimed by a later sweep or surfaced by
`trove verify`.

## Rejected alternatives

- **Reference counting** — drifts under crashes and requires perfect bookkeeping
  at every write site; mark-and-sweep is recomputable from first principles.
- **Online/incremental GC intertwined with requests** — spreads the safety
  argument across every handler; a scheduled sweep keeps it in one place.
- **Soft-delete trash can** — rejected per Q16; the grace window plus GC lag gives
  a bounded undo affordance (`created_at`-based, documented) without a second
  lifecycle state.

## Consequences

- Push latency never pays for GC: mark/sweep run scheduled (P-006) and respect
  read-only mode (they still run — they don't write client data).
- `keep-if-pulled-since` depends on pull stats (R-010) being written reliably;
  the batched writer flushes at most 60 s behind, documented as the rule's
  precision bound.
- The evaluator's purity makes P-002's property tests straightforward: rule
  priority total order, protection dominance, plan determinism.
