# ADR 0011 — Referrer lifecycle on subject deletion

- Status: accepted (2026-09-01)
- Task: D-022
- Decisions applied: Q22 (cascade delete)

## Context

SBOMs, signatures, and scan attestations attach to a subject manifest via the OCI
v1.1 `subject` field. Referrers are untagged manifests: invisible to tag-based
retention, and not protected by GC reference rules (they point *at* the subject,
not the other way). Without an explicit lifecycle they leak forever — or worse, get
reaped while their subject lives.

## Decision

- **Deleting a subject manifest cascade-deletes its referrer tree** in the same
  operation: every manifest whose `subject_digest` chain terminates at the deleted
  subject, transitively (a signature on an SBOM dies with the SBOM). Each deleted
  referrer gets its own audit record naming the cascade origin.
- **Retention plans surface the cascade**: a plan entry for a subject lists its
  referrer subtree explicitly (ADR 0010), so `policy:apply` never deletes artifacts
  the operator didn't see in the dry run.
- **Untagged reaping protects live attachments**: the `untagged` tag-status filter
  in retention rules excludes any manifest whose `subject_digest` resolves to a
  live manifest — such a manifest is *attached*, not *orphaned*. This is enforced
  in inventory construction (the selectable set never contains them) and verified
  adversarially (P-002 criteria).
- **Orphan sweep**: a referrer whose subject is already gone (possible after crash
  between cascade steps, or via migration imports) is reaped by GC's mark phase —
  a referrer chain is only a root if it terminates at a live, tagged-or-referenced
  manifest. Orphans therefore age out through the normal sweep with the normal
  grace window.
- **Multi-arch interaction**: the Q10 rule (index-child deletion errors) takes
  precedence — a referrer that is also a child of a live index is not deletable by
  cascade; the cascade fails closed with the same spec error, and the operator
  must delete the index first. Expected to be rare (attestation manifests are not
  normally index children) but defined.
- **Cross-repo**: `subject_digest` resolution is per-repository (ADR 0006 keys
  manifests by repo); a same-digest manifest in another repository is unaffected
  by a cascade.

## Rejected alternatives

- **Orphan-then-GC as the primary mechanism** — leaves a window where the
  referrers API lists attachments of a deleted image, and makes deletion size
  unpredictable in the audit log; kept only as the crash-recovery net.
- **Blocking deletion while referrers exist** — symmetric with Q10 but
  ergonomically dead: every scanned image has referrers, so nothing could ever be
  deleted without a manual purge first.
- **Reference-counting subjects into GC roots** (treat referrer→subject as a GC
  edge keeping the *subject* alive) — inverts the ownership: a signature should
  never pin a deleted image into existence.

## Consequences

- `manifest:delete` on a subject implies deleting its referrer tree — documented
  at the verb (ADR 0002) and shown in the UI confirmation.
- The referrers API (R-005) needs no tombstone handling: after cascade, listing
  referrers of the deleted subject is `NAME_UNKNOWN`/empty per ADR 0003.
- Scan results attached as referrers (S-008) die with the image, which is correct:
  the normalised scan rows in the metadata store (ADR 0006) remain the queryable
  history until pruned by their own retention.
