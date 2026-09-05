# ADR 0017 — Scanner integration

- Status: accepted (2026-09-01)
- Task: D-002
- Decisions applied: Q2 (Trivy as a Go library), Q6 (air-gapped v1)

## Context

Scanning is core v1 (on-push, on-cache-fill, scheduled rescan, gating input), so it
must ship inside the single binary — requiring a sidecar binary undercuts the
five-minute north star. The vendor must be quarantined: results are normalised into
our model, and no package outside the adapter imports vendor code (§6).

## Decision

### Interface and adapter

```
type Scanner interface {
    Scan(ctx, ImageRef) (Report, error)   // Report is OUR normalised model
    DBVersion(ctx) (DBVersion, error)
    UpdateDB(ctx, source) error           // source: network or imported archive
}
```

- `internal/scan` defines the interface, queue, and normalised `Report`;
  `internal/scan/trivy` is the **only** package importing
  `github.com/aquasecurity/trivy` — enforced by the same import-allowlist test
  family as Z-009. A `fake` implementation drives all non-adapter tests.
- Trivy is pinned by exact version in `go.mod`; upgrades are deliberate PRs that
  re-run the adapter's golden corpus (fixed images → expected normalised output)
  to catch semantic drift in vendor output.
- Trivy scans images by reading them from **our own store** via an OCI-layout
  handoff (no re-pull through the network path, no Docker daemon), vulnerability
  detection only — Trivy's secret/license/misconfig scanners stay disabled in v1.

### Normalisation

- The adapter maps Trivy output to ADR 0006's `scans`/`findings`/`cves` rows:
  CVE id, package, installed/fixed versions, severity (our enum, mapping
  vendor severities conservatively — unknown → `low`, never dropped), source
  ecosystem. Vendor JSON is discarded after mapping (§6); a debug flag can dump
  it to disk for adapter development, never to the database.
- Severity rollups, fixable splits, VEX suppressions (S-006/S-007) operate on our
  model only — a scanner swap in v1.x cannot ripple past the adapter.

### Queue and triggers

- Asynchronous queue (table-backed like webhooks — survives restarts): triggers
  are push (hosted), cache-fill (proxy), CVE DB update (rescan affected digests),
  scheduled rescan, and manual `scan:trigger`. Concurrency default 1 (scanning is
  memory-hungry); configurable. Push latency never waits on any of this (§6).
- Rescan-on-DB-update diffs new reports against prior ones; a previously clean
  image gaining findings emits `scan.regressed` (S-005).

### CVE database lifecycle (Q6)

- Online: the adapter updates trivy-db from its OCI distribution endpoint on a
  schedule (default every 12 h, disableable — §0.6 outbound-calls rule).
- **Air-gapped**: `trove db import <file>` accepts the standard trivy-db archive
  (as produced by `trivy` tooling or downloaded out-of-band), validates its
  digest/format, installs it, records the DB version, and triggers the rescan
  pass. Works via API or `--offline` (ADR 0015). First-class and tested.
- DB version is exposed in metrics and `/readyz` detail; scan-staleness gating
  (ADR 0013) keys off it.

## Rejected alternatives

- **Pinned external Trivy binary** — cleanest dependency graph, but breaks
  single-binary install and air-gapped simplicity; an exec seam is also harder to
  test than an in-process fake (Q2).
- **Grype as library** — comparable, but Trivy's DB distribution/import tooling
  is more battle-tested and its library API is exercised by more downstreams;
  the adapter seam keeps this reversible in v1.x if Trivy's dependency tree
  becomes a problem.
- **Supporting both engines behind the interface in v1** — doubles the golden
  corpus and DB lifecycle work for no v1 user benefit; the interface already
  preserves the option.
- **Persisting vendor JSON as the record** — forbidden (§6); normalisation is
  what makes rollups, suppression, and regression detection queryable.

## Consequences

- The Trivy dependency tree is large; `go.mod` hygiene (a `deps-audit` make
  target diffing the module graph) keeps its growth visible in review.
- The adapter's golden corpus doubles as the S-002 acceptance test and the
  upgrade gate.
- Scan memory use bounds worker concurrency — documented in operator sizing docs
  (DOC-002) with the default of 1.

## Clarifications (S-001, 2026-09-05)

Freezing the interface surfaced two questions the decision above does not
settle. Both are recorded here rather than in a commit message, because the
adapter (S-002) and the gate (S-011) each need the answer.

### `SeverityUnknown` exists in the model but a conforming adapter never emits it

This ADR maps vendor-unknown to `low` ("never dropped"), while ADR 0012's
`scan.completed` payload carries an `Unknown` severity bucket. Both stay as
written, and the enum keeps `unknown`, ranked below `low`:

- The **adapter** maps vendor-unknown to `low`, exactly as decided above. A
  report produced by a conforming adapter therefore contains no `unknown`
  finding, and a policy threshold never has to reason about one.
- The **bucket** exists because findings can arrive without passing through an
  adapter: `trove db import` on an air-gapped deployment (Q6) and
  `trove migrate --from` (Q17) both carry data whose severity vocabulary is
  somebody else's. Dropping the bucket would mean silently re-labelling that
  data as `low`, which is a claim the importer cannot make.

Ranking `unknown` lowest means an imported finding can never be *more* severe
than it is known to be — it fails a `max-severity` threshold open rather than
blocking a pull on an unclassified CVE, which is consistent with gating being
off by default and observed before it is enforced (Q12).

### Scan status stays two-valued; "cannot analyse" is a failure, not a clean bill

`Report.Status` is `succeeded` or `failed`, and nothing else. A third state for
"the scanner does not understand this artifact" was considered and rejected:
ADR 0013 defines no gating meaning for it, so every gate would need a rule for
a state that only ever means "treat as unscanned" or "treat as clean" — which
the two existing states already say.

The distinction the adapter must make instead:

- An artifact that is **not an image** — a signature, an SBOM, an attestation
  (`artifact.Kind` says which, R-007) — has no vulnerabilities by construction.
  It is `succeeded` with no findings, and that is true rather than convenient.
- An **image the scanner cannot analyse** — an unsupported base, a corrupt
  layer, a format the engine rejects — is `failed`. Reporting it as
  succeeded-with-no-findings would publish a clean bill for something nobody
  examined, and `unscanned: block` exists precisely to catch that case.

S-002 must therefore branch on artifact kind before it branches on the vendor's
error, and S-011 gates on `Clean()` rather than on an empty findings list.
