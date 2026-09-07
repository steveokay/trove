# Phase 4 — Proxy, cache, and groups: task specs

ADRs: 0005 (repo model), 0008 (cache semantics), 0009 (separation), 0016 (secrets).

Parallelization: C-001/C-002 first (model + client interface freeze), then C-003–C-010
(proxy internals) and C-011/C-012 (groups) in parallel; C-013 after ADR 0009 wiring;
C-015 last.

---

## C-001 Repository model + router
- **Deps:** D-011 ✓
- **Files:** `internal/repo/{repo.go,router.go,config.go}` + tests
- **Do:** ADR 0005: entity types with typed configs (validated on write);
  first-segment router producing `(entity, remainder, fullName)`; proxy push →
  `DENIED` unconditionally; group write only via designated `writeTarget`.
- **Accept:** Resolution matrix unit-tested; no config combination makes a proxy
  writable (constructor-level: proxy type has no write path).
- **Test:** Router table (valid/invalid names, unknown prefix → ADR 0003 404);
  config validation corpus; write-rules matrix per type.

## C-002 Upstream client interface + contract suite
- **Deps:** D-012 ✓
- **Files:** `internal/proxy/{client.go,clienttest/suite.go,registryclient.go}`
- **Do:** Interface: resolve tag (conditional), fetch manifest/blob by digest
  (streamed, digest-verifying via ADR 0007 helpers), auth (basic/bearer with
  upstream token flow), redirect policy (≤5, same-host-family, https-only unless
  config allows — SSRF posture). Contract suite runs vs `registry:2` testcontainer;
  a nightly-tagged job runs it against one real public remote.
- **Accept:** Suite green on registry:2; interface frozen for parallel work.
- **Test:** The suite: conditional-request semantics, auth challenge dance,
  redirect cap, digest mismatch rejection, timeout behavior.

## C-003 Upstream credential storage
- **Deps:** D-003 ✓, D-021 ✓, Z-003 (secretbox exists)
- **Files:** `internal/proxy/credentials.go`, API handlers in C-016's surface
- **Do:** secretbox-encrypted at rest, AAD `proxy-credential:<repo-id>`; API
  returns set/unset + rotated-at only (ADR 0016 — never the value, any verb);
  write gated `proxy:credentials`; used only inside the upstream client.
- **Accept:** No read path returns a credential; support bundle + config dump
  scanned clean; `proxy:write` alone cannot set or infer one.
- **Test:** Z-019 subtests (every read path probed); AAD swap test; redaction scan
  test over dump/bundle outputs.

## C-004 Fetch-and-cache by digest
- **Deps:** C-002, F-009
- **Files:** `internal/proxy/fill.go`
- **Do:** Digest fetch → stream-verify → cache store Put + `cached_*` rows
  (transactional); mismatch → reject, don't cache, emit event (ADR 0008); serve
  the verified stream to the waiting client while filling (tee).
- **Accept:** Mismatch never cached; concurrent fill of same digest single-flights
  at the store level (first-wins Put).
- **Test:** Mismatch/truncation via fake upstream; tee correctness (client gets
  full bytes when fill succeeds mid-stream failure aborts both).

## C-005 Tag → digest lease
- **Deps:** Q11 ✓, C-004
- **Files:** `internal/proxy/lease.go`
- **Do:** ADR 0008 lease lifecycle: TTL 15 m default (per-repo), conditional
  revalidation (HEAD, `Docker-Content-Digest`/ETag), changed → fetch new by
  digest, old stays cached; `ttl=0` → always revalidate.
- **Accept:** Stale served only in degraded mode; revalidation is conditional
  (no body on unchanged).
- **Test:** Clock-injected lease table (fresh/expired/changed/unchanged);
  upstream-call counting; `:latest`-moved scenario end-to-end.

## C-006 Single-flight
- **Deps:** C-005
- **Files:** `internal/proxy/coalesce.go` (`Coalescer` interface per ADR 0018,
  v1 = `x/sync/singleflight`)
- **Accept:** N concurrent cold pulls of one tag → exactly 1 upstream resolve+fetch.
- **Test:** Concurrency test with counting fake upstream (N=50, race detector);
  failure propagation (upstream error reaches all waiters, nothing cached).

## C-007 Negative cache
- **Deps:** C-005
- **Files:** `internal/proxy/negative.go`
- **Do:** ADR 0008: name/tag lookups only, 60 s default TTL, never digests.
- **Accept:** Typo'd tag hits upstream once per TTL; digest 404s pass through
  uncached.
- **Test:** TTL table; digest-exclusion test; interaction with lease revalidation.

## C-008 Offline / degraded mode
- **Deps:** C-005
- **Files:** `internal/proxy/degraded.go`, config knobs
- **Do:** ADR 0008: classify unreachability (dial/DNS/5xx/timeout) distinctly from
  404s; `serve-stale` default (Warning header + `cache.stale-served` event) vs
  `strict` per repo; backoff state shared with C-009.
- **Accept:** DNS-blackholed upstream (custom dialer returning NXDOMAIN/timeout):
  cached pulls succeed marked stale, uncached fail cleanly; strict mode fails both.
- **Test:** Fault-injection dialer matrix (refused/timeout/NXDOMAIN/5xx/reset);
  header + event assertions; mode-switch runtime test.

## C-009 Rate-limit handling + metrics
- **Deps:** C-002
- **Files:** `internal/proxy/backoff.go`, `internal/metrics/upstream.go`
- **Do:** Honor `Retry-After` (seconds + HTTP-date), exp backoff + jitter on 429;
  during backoff behave as offline; record `RateLimit-Remaining/-Limit` per proxy
  as gauges.
- **Accept:** 429 storm produces bounded upstream call rate; headroom visible in
  metrics.
- **Test:** Fake-upstream 429 sequences (with/without Retry-After); clock-injected
  backoff curve; metric registration test.

## C-010 Routing rules
- **Deps:** C-001
- **Files:** `internal/repo/routing_rules.go`
- **Do:** Allow/block on remainders using the ADR 0001 grammar (shared validator);
  evaluation: explicit block > explicit allow > default (allow, or deny when
  `default_deny: true`). No rule set may make the proxy an open relay when
  `default_deny` is set (C-010 criteria).
- **Accept:** `library/*`-only Docker Hub proxy expressible in one rule.
- **Test:** Rule-evaluation table incl. overlaps; fuzz shared with Z-007 corpus;
  traversal attempts via remainder.

## C-011 Group resolution
- **Deps:** C-001
- **Files:** `internal/repo/group.go`
- **Do:** ADR 0005 pure function over (filtered member states, reference):
  first-match-wins, down-member skip + event unless `required`,
  malformed/mismatched member result treated as down for the request.
- **Accept:** Exhaustive matrix green: same tag in two members (order wins),
  member offline, member required-offline, malformed manifest, empty member list.
- **Test:** Table-driven over the full matrix; property: resolution deterministic
  in member order; fuzz member-state permutations.

## C-012 Permission filtering before resolution
- **Deps:** C-011, Z-012
- **Files:** `internal/repo/group_filter.go`, serving-path wiring
- **Do:** Build the member list via Decide(`repo:read`, member) *before* calling
  C-011's pure function. Unreadable member ⇒ removed — identical treatment to
  nonexistent.
- **Accept:** Z-018 group subtest unskipped: subject with access to member B only
  gets B's digest even when hidden member A would win; no error/latency
  distinguishability (same code path as absent member).
- **Test:** Disclosure fixtures (hidden-member-wins scenarios); differential test
  filtered-vs-member-absent producing identical responses.

## C-013 Cache eviction
- **Deps:** D-013 ✓, C-004
- **Files:** `internal/cache/{evict.go,budget.go}`
- **Do:** ADR 0008/0009: global budget (50 GB default) + per-proxy carve-outs,
  LRU by `last_access_at`, own schedule + breach trigger, cached tables/store only
  (receives only the cache-rooted instances), `cache.evicted` events, quota
  integration (ADR 0014 cache scope).
- **Accept:** ADR 0009 proving test passes (eviction fixture touches zero hosted
  rows/paths); budget respected within one eviction cycle.
- **Test:** LRU order property; carve-out accounting; the ADR 0009 wall test;
  concurrent evict-vs-fill (filled blob immediately evictable but never
  half-deleted).

## C-014 Default upstream presets
- **Deps:** Q7 ✓, C-001
- **Files:** `internal/repo/presets.go`, docs
- **Do:** Five presets (Docker Hub incl. `library/` rewrite, ghcr, quay,
  registry.k8s.io, gcr) shipped disabled; enabling = `repo:configure`. Quickstart
  (DOC-001) enables Docker Hub.
- **Accept:** Fresh install makes zero outbound connections (§0.6) — asserted by
  a no-network boot test.
- **Test:** Preset config validity (validated like user config); disabled-by-default
  boot test with network-recording transport.

## C-015 Proxy adversarial suite (living)
- **Deps:** C-004..C-012
- **Files:** `test/proxyadv/suite_test.go`
- **Do:** Fake-upstream harness driving: digest mismatch, redirect loop + cap,
  redirect to private address (SSRF — must refuse), 429 storm, traversal via
  remainder/rewrite, malformed manifests, single-flight under load, stale-past-TTL
  in both modes, group member leakage (with Z-018).
- **Accept:** Every §9 proxy bullet has a subtest; suite green.
- **Test:** Suite task; harness self-tests.

## C-016 Repository admin CRUD API
- **Deps:** C-001, D-020 ✓
- **Files:** `internal/server/api_repositories.go`, OpenAPI entries
- **Do:** ADR 0015 resources: create (`repo:create`@system), get/list (filtered),
  update config (`repo:configure`), delete (`repo:delete`, hosted deletion behind
  the P-005-style confirmation once it exists; until then hosted delete requires
  `?confirm=<name>`); config history recorded (ADR 0005).
- **Accept:** All three types manageable via API; UI needs nothing extra;
  verbs enforced with positive+negative tests (Z-005 registry).
- **Test:** CRUD matrix per type; validation errors problem+json golden; authz
  matrix; config-history assertion.

---

## C-017 `/v2/` dispatch by repository type
- **Deps:** C-001 ✓, R-001 ✓, R-002 ✓
- **Files:** `internal/registry/dispatch.go`, read paths in `blobs.go`/`manifests.go`
- **Do:** `routeToEntity` already returns the entity's record; the read helpers
  discard its `Type`. Keep it, and branch: hosted unchanged, proxy and group
  delegated to `ProxyServer`/`GroupServer` seams declared by the consumer. A nil
  seam answers 404/`NAME_UNKNOWN`, byte-identical to an unknown repository, so a
  deployment that has not wired proxying discloses nothing. Writes keep refusing
  through `repo.Writable`.
- **Accept:** hosted goldens unchanged; proxy/group reads reach the seam; the
  unwired answer is indistinguishable from a missing repository.
- **Test:** route matrix per type; hosted golden diff; disclosure parity.

## C-018 Proxy pulls over `/v2/`
- **Deps:** C-017, C-004 ✓, C-005 ✓, C-010 ✓
- **Files:** `internal/registry/proxyserve.go`, namespace rewrite in `internal/repo`
- **Do:** tag → `ResolveTag`; digest → `Manifest`/`Blob` with the stream going to
  the client as it fills. Routing rules evaluate the rewritten upstream path;
  the `DefaultNamespace` rewrite itself lands here (C-015 left the assertion
  waiting). Cache hits feed the touch batcher. `Warning: 110` on stale content,
  deferred by C-008 because it needs the HTTP path.
- **Accept:** a pull through a fake upstream over HTTP, served and cached; push
  refused `DENIED`; stale content marked.
- **Test:** HTTP pull/stale/refusal matrix; the rewrite traversal assertion.

## C-019 Group pulls over `/v2/`
- **Deps:** C-017, C-011 ✓, C-012 ✓
- **Files:** `internal/registry/groupserve.go`
- **Do:** probe members in order to build `MemberState`, filtering by permission
  *first*; first match wins; skip what cannot answer; fail only on a required
  member; emit `group.member.skipped`.
- **Accept:** the disclosure suite's group surface proven over HTTP; a filtered
  member changes nothing observable.
- **Test:** HTTP group matrix; C-012's differential assertions end to end.

## C-020 Serve assembly for proxy and cache
- **Deps:** C-018, C-019, C-013 ✓, C-003 ✓, C-014 ✓
- **Files:** `internal/cli/serve.go`
- **Do:** per-entity client with decrypted credentials, `TrustedHosts` and TTLs
  from config, the cache-rooted blob store, the `Filler`, and C-013's `Evictor`
  + `Scheduler` + `TouchBatcher` with a shutdown order. Wiring lives here and
  nowhere else (ADR 0009 wall 2). Decides where a per-proxy cache carve-out is
  configured from.
- **Accept:** live `trove serve` pull through a fake upstream; ADR 0009 proving
  assertion (a) moves onto the real wiring; `test/offline` still silent at boot.
- **Test:** live serve pull; wiring disjointness; boot silence.

## C-021 Catalog over cached content
- **Deps:** C-020 — decision taken 2026-09-07 (ADR 0008 clarification).
- **Do:** `/v2/_catalog` lists cached content only. Union the cached-manifest
  content names into `meta.ListContentNames`, keeping the visibility filter
  inside the query (§0.5) — unioning first and filtering after would leak
  through pagination counts. A group contributes the union of its readable
  members (`repo.VisibleMembers` first, then union, deduplicated).
- **Test:** metatest pagination-under-filtering over the unioned query (a
  cursor must never name a hidden row); disclosure suite's catalog surface
  extended to cached and group content.

## C-022 Tag lists for proxy and group
- **Deps:** C-021, C-018, C-019 — decision taken 2026-09-07 (ADR 0008).
- **Do:** fetch tag lists from the upstream on demand and cache with a TTL,
  reusing C-005's lease shape, C-007's negative cache and C-008's degraded
  mode (unreachable → last list served stale; `strict` fails). A group returns
  the union of readable members' lists, deduplicated, member order breaking
  ties so a listing cannot disagree with a pull. A failing member is dropped,
  logged and evented — unlike resolution, where an unreadable member fails the
  call (ADR 0005 records why).
- **Test:** TTL expiry and revalidation; upstream down in both modes; two
  members holding one tag; an unreadable member contributing nothing.

## C-023 Referrers over cached content
- **Deps:** C-021, C-022 — decision taken 2026-09-07 (ADR 0008).
- **Do:** referrers are fetched and cached like any other content, so §6's
  "cached content is scanned too" and ADR 0013's signature-presence gating both
  work on proxied images. Permission is unchanged: no read on the subject
  artifact means no read of its referrers (§5.7).
- **Test:** referrers over a cached subject; disclosure suite's referrer
  surface extended to cached content; a gate seeing an upstream signature.
