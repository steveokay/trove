# Phase 3 — OCI registry core (hosted): task specs

ADRs: 0003 (errors/disclosure), 0005 (Q10), 0006 (content tables), 0007 (blob store),
0011 (referrer cascade), 0015 (error envelopes).

Parallelization: R-001 and R-002 serial (upload → manifest). R-003/R-004/R-005 fan out
after R-002. R-008 alongside any. R-009 last. R-010–R-012 independent after R-002.

---

## R-001 Blob upload (monolithic, chunked, resumable)
- **Deps:** F-009, Z-010
- **Files:** `internal/registry/{blobs.go,uploads.go}`, routes in `internal/server`
- **Do:** Distribution-spec upload API: POST (start / monolithic with digest), PATCH
  chunks, PUT commit, GET status, DELETE cancel; cross-repo mount
  (`?mount=&from=`) gated on `repo:read` of source. Sessions persist via ADR 0006
  `upload_sessions` + blob-store staging; digest verified at commit (ADR 0007).
  Quota `Check` at start/commit (interface stubbed until P-009).
- **Accept:** Conformance blob tests green; mount works; verbs: push=`repo:write`.
- **Test:** Spec-shape table tests (status codes, `Location`, `Range` headers
  golden); mismatch commit leaves no blob and no row; resume-after-restart test;
  concurrent same-digest uploads.

## R-002 Manifest put/get/delete + media-type validation
- **Deps:** R-001, F-006
- **Files:** `internal/registry/manifests.go`, `internal/artifact/{mediatypes.go,parse.go}`
- **Do:** Parse OCI/Docker-v2 manifests + indexes (`internal/artifact`); PUT
  validates every referenced blob/child exists then writes manifest +
  `manifest_refs` transactionally (ADR 0010 safety edge); GET by tag or digest;
  DELETE by digest cascades referrers (ADR 0011) and errors on index-referenced
  children (Q10, ADR 0005). Payload size cap (config, default 4 MiB) → `MANIFEST_INVALID`.
- **Accept:** Manifest referencing a missing layer → `MANIFEST_BLOB_UNKNOWN`;
  cascade + Q10 behaviors exact per ADRs.
- **Test:** Media-type matrix (image/index/helm/artifact); missing-layer,
  oversized, malformed-JSON tables; cascade tree test (sig-on-SBOM-on-image);
  Q10 error golden.

## R-003 Tag list + pagination
- **Deps:** R-002, Z-012
- **Files:** `internal/registry/tags.go`
- **Do:** `GET /v2/<name>/tags/list` with `n`+`last` per spec, backed by filtered
  queries (Z-012 predicates), lexical ordering, spec `Link` header.
- **Accept:** Counts/pages never reflect unreadable content (Z-018 subtest
  unskipped).
- **Test:** Pagination property test (stitched pages == full set, no dupes/gaps
  under concurrent tag writes); disclosure fixtures.

## R-004 Catalog endpoint
- **Deps:** Z-012
- **Files:** `internal/registry/catalog.go`
- **Do:** `GET /v2/_catalog` listing full OCI names per ADR 0005 (hosted manifests,
  proxy cached-only, group union-of-readable), filtered in-query, paginated.
- **Accept:** verb `repo:list`; Z-018 catalog subtest unskipped.
- **Test:** Per-repo-type listing semantics; pagination + disclosure fixtures.

## R-005 Referrers API
- **Deps:** R-002
- **Files:** `internal/registry/referrers.go`
- **Do:** `GET /v2/<name>/referrers/<digest>` from `subject_digest` index;
  `artifactType` filter (+ `OCI-Filters-Applied` header); requires
  `referrer:read` ∧ `repo:read` on subject (ADR 0002); empty index for absent
  referrers of a readable subject; ADR 0003 404 for unreadable subject.
- **Accept:** `oras attach` → listed; permission inheritance proven.
- **Test:** Attach/list/filter round-trip; the §9 SBOM-of-unreadable-image case
  (Z-018 subtest); golden response.

## R-006 Multi-arch index handling
- **Deps:** R-002
- **Files:** `internal/artifact/index.go`, additions in `manifests.go`
- **Do:** Index PUT records child edges in `manifest_refs`; child GET through or
  direct both work; child DELETE while index lives → Q10 error; index DELETE
  releases children (become untagged, normal retention/GC applies).
- **Accept:** Q10 exact; platform selection left to clients (we serve the index).
- **Test:** Build multi-arch fixture with oras; delete-order matrix; GC-interaction
  fixture (released children sweep after grace).

## R-007 Helm chart + SBOM artifact awareness
- **Deps:** R-005
- **Files:** `internal/artifact/kinds.go`
- **Do:** Recognize helm config media type, SPDX/CycloneDX artifactTypes, cosign
  signature types (ADR 0013 presence-check input); expose `Kind` on manifest
  records for UI/search. No behavioral branching beyond labeling + gating input.
- **Accept:** `helm push/pull` and `oras attach` SBOM round-trip in integration.
- **Test:** Kind-detection table over real payload fixtures; helm/oras integration.

## R-008 Spec error-code mapping
- **Deps:** R-002, D-019 ✓
- **Files:** `internal/registry/errors.go`, `testdata/errors/*.golden`
- **Do:** One constructor per OCI error code; ADR 0003 matrix implemented here
  (single place mapping authz outcomes to 401/403/404 envelopes). Admin API uses
  ADR 0015 problem+json — separate package, no sharing.
- **Accept:** Wire format golden-tested; hidden-vs-absent byte-identical.
- **Test:** Golden per code; the identity test is Z-018's.

## R-009 OCI conformance suite in CI
- **Deps:** R-001..R-008
- **Files:** `test/conformance/`, CI job
- **Do:** Run opencontainers/distribution-spec conformance (pull, push,
  content-discovery, content-management) against a spawned `trove serve` with a
  seeded hosted repo. Group pull-side conformance is added when C-012 lands
  (tracked skip until then).
- **Accept:** Green, required for merge.
- **Test:** The suite; harness sanity test.

## R-010 Pull statistics
- **Deps:** R-002
- **Files:** `internal/registry/pullstats.go`
- **Do:** Manifest GET (tag or digest) enqueues to a batched writer (chan +
  60 s/1000-row flush per ADR 0010 precision bound); upsert `pull_stats`; emits
  `artifact.pulled` to bus (not persisted by default, ADR 0012).
- **Accept:** Hot path adds no DB write; counts survive restart within flush bound.
- **Test:** Batcher unit tests (flush by size/time/shutdown); bench proving no
  per-pull DB write (asserted via fake store call-count).

## R-011 Stale upload-session reaping
- **Deps:** R-001
- **Files:** `internal/registry/upload_reaper.go` (scheduled via P-006's scheduler;
  interim ticker until then)
- **Do:** Sessions idle > TTL (default 24 h, config) → delete row + staging file.
  Hosted-side task; never touches committed blobs (ADR 0009 note).
- **Accept:** Active upload untouched (activity refreshes `last_chunk_at`);
  storage reclaimed.
- **Test:** Clock-injected reap table; race: chunk PATCH vs reap (PATCH on reaped
  session → 404 per spec, no partial resurrection).

## R-012 Push-latency benchmark
- **Deps:** R-001, R-002
- **Files:** `internal/registry/bench_test.go`, `scripts/bench-check.sh`, CI job
- **Do:** `testing.B` benchmarks: monolithic blob (1 MiB/100 MiB), chunked, manifest
  PUT, against in-memory-ish fixtures (tmpfs). CI records ns/op vs a checked-in
  baseline with 20 % regression tolerance; scan-backlog test (queue full of fakes)
  asserts push p50 unchanged (S-003 tie-in, activated then).
- **Accept:** Baseline committed; regression fails CI with comparison printed.
- **Test:** The benchmarks; bench-check script self-test.
