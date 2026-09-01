# Phase 7 — Events, observability, operability: task specs

ADRs: 0012 (events/webhooks), 0003 (disclosure), 0015 (API). Note: E-001 is a
dependency of several earlier-phase tasks (Z-016, S-005) — in practice it is built
early, immediately after Phase 2's core; it lives in this phase for grouping only.

Parallelization: E-001 first; then webhooks (E-002–E-004, E-012), metrics/health
(E-005–E-007), audit/search (E-009, E-010, E-013), ops (E-008, E-011) — four
independent tracks.

---

## E-001 Event bus + taxonomy
- **Deps:** D-014 ✓, F-006
- **Files:** `internal/event/{bus.go,types.go,outbox.go}`
- **Do:** ADR 0012: typed closed taxonomy; synchronous non-blocking fan-out;
  outbox insert in the caller's transaction where one exists (store exposes a
  txn-scoped emitter); `artifact.pulled` bus-only unless `events.persist_pulls`.
- **Accept:** Every §8 event type defined with a typed payload + golden; an event
  row exists iff its transaction committed (crash test).
- **Test:** Payload goldens per type; outbox-transactionality test (fail txn ⇒ no
  event); consumer-panic isolation test.

## E-002 Webhook subscriptions
- **Deps:** E-001, Z-003 (secretbox)
- **Files:** `internal/event/subscriptions.go`, API handlers
- **Do:** ADR 0012 model: owner subject, URL, secretbox-encrypted secret
  (AAD `webhook-secret:<id>`), repo pattern (Z-007 grammar), event-type filter,
  active flag; `webhook:read`/`webhook:write` gated; secret shown never after
  creation.
- **Accept:** CRUD via API; filter semantics exact; disabled subscription
  enqueues nothing.
- **Test:** Filter matrix (pattern × event type); secret non-return probe (Z-019
  style); validation corpus.

## E-003 Webhook delivery
- **Deps:** E-002
- **Files:** `internal/event/delivery.go`
- **Do:** ADR 0012: table-backed worker, state machine pending→ok|failed→…→dead
  (5 attempts: 1 m, 5 m, 25 m, 2 h, 6 h + jitter), HMAC-SHA256 `Trove-Signature`,
  `Trove-Event-Id` idempotency header, dedicated HTTP client (5 s connect / 30 s
  total, no redirects), response code+truncated body retained, 30 d history
  pruning, replay endpoint for dead deliveries.
- **Accept:** At-least-once across restart proven; signature verifiable by a
  documented recipe (docs include a verification snippet).
- **Test:** State-machine table; restart-resume; backoff clock tests; signature
  vector test; replay authz (`webhook:write`).

## E-004 Webhook permission scoping
- **Deps:** E-003, Z-012
- **Files:** delivery-time check in `internal/event/delivery.go`
- **Do:** ADR 0012: before each attempt, Decide(owner, current bindings,
  required verb, event.repo) — repo events need `repo:read`; `authz.denied`
  events need `audit:read`; failure ⇒ terminal `skipped-authz` state (distinct
  from dead).
- **Accept:** Z-018 webhook subtest unskipped: revoked owner stops receiving
  mid-stream; skipped-authz visible in delivery history.
- **Test:** Revocation-mid-queue test; per-event-type verb map completeness test
  (every taxonomy type has a mapping).

## E-005 Prometheus metrics
- **Deps:** E-001
- **Files:** `internal/metrics/{registry.go,http.go,collectors…}`
- **Do:** §8 series: request rate/latency/status by operation (not by repo — see
  E-006), storage bytes by repo+type (opt-in flag, E-006), cache hit ratio,
  upstream latency + rate-limit headroom, scan queue depth/age, authz denials by
  verb, plan sizes, GC progress. `/metrics` exposure mode config:
  `metrics.exposure: local|authed|open` (default `local` = bind-address
  restriction; `authed` uses a bearer check) — the ADR 0003 surface-6 decision.
- **Accept:** Every listed series registered + populated in an integration boot;
  exposure modes enforced.
- **Test:** Registration completeness test; exposure-mode matrix; scrape golden
  (names/labels lint — stable naming contract).

## E-006 Cardinality + disclosure review
- **Deps:** E-005
- **Files:** `internal/metrics/labels.go`, `docs/operator/metrics.md`
- **Do:** Repo-name labels only behind `metrics.per_repo: true` (default false)
  with a documented cardinality warning; label-value allowlist test (no digest,
  no tag, no subject names as labels anywhere).
- **Accept:** Default scrape contains zero repository names; lint test walks all
  registered metrics.
- **Test:** The label-lint test; per_repo-flag behavior test.

## E-007 `/healthz` and `/readyz`
- **Deps:** F-004
- **Files:** `internal/server/health.go`
- **Do:** `/healthz`: process alive, always 200 once serving — no deps.
  `/readyz`: meta store ping, migrations at head, blob store writable probe,
  detail JSON (DB version, scan DB version, backoff states — informational).
  Both on the AnonymousAllowed list (Z-011), detail body only when authed
  (`system:maintenance`) to avoid version disclosure.
- **Accept:** Kill DB container ⇒ readyz 503 / healthz 200; rolling-upgrade
  semantics documented.
- **Test:** Dependency-failure matrix via fakes; detail-redaction authz test.

## E-008 Read-only / maintenance mode
- **Deps:** F-003, Z-005
- **Files:** `internal/server/readonly.go`, API toggle endpoint
- **Do:** Runtime toggle (`system:maintenance`), persisted (survives restart);
  write routes → 503 + spec `DENIED`-class/problem+json explaining maintenance;
  pulls, token minting, and health unaffected; GC/eviction/schedulers pause
  (backup consistency — DOC-002 contract); audit + event on toggle.
- **Accept:** Push rejected clearly, pull fine, backup procedure documented
  against it.
- **Test:** Route-classification test (every route declared read/write — extends
  Z-011 metadata); toggle persistence; scheduler-pause assertion.

## E-009 Audit log
- **Deps:** F-006
- **Files:** `internal/audit/{audit.go,query.go}`, API handlers
- **Do:** Append-only writer (no update/delete methods exist on the store
  interface — archtest-adjacent guarantee) recording every mutating action +
  denials + overrides with actor/verb/resource/outcome/before/after; queryable
  (`audit:read`) with filters (actor, verb, resource, time range, outcome);
  export NDJSON.
- **Accept:** Every mutating route writes audit (guard test walks write routes ×
  asserts audit emission via fake); export streams.
- **Test:** The route-coverage guard; query-filter matrix; append-only interface
  test.

## E-010 Cross-repo search
- **Deps:** Z-012, S-006
- **Files:** `internal/search/{index.go,query.go}`, API handler
- **Do:** SQL-backed search (no external engine): by name substring, tag, digest
  prefix, media type/kind, CVE id (join through findings); all through Z-012
  predicates; `search:read` + per-result `repo:list` filtering; cursor paginated.
- **Accept:** CVE-id search returns only readable repos' artifacts (Z-018
  subtest); digest-prefix ≥ 7 chars enforced.
- **Test:** Query matrix per criterion on both engines; disclosure fixtures;
  pagination property test.

## E-011 `trove support-bundle`
- **Deps:** F-003, E-009
- **Files:** `cmd/trove/supportbundle.go`, `internal/server/api_bundle.go`
- **Do:** Tar.gz: redacted config, version/build info, migration state, key
  fingerprints (ADR 0016 — never contents), role/binding summary, repo/config
  summary, recent logs (if file logging), recent audit tail, readyz detail;
  gated `system:maintenance`.
- **Accept:** Secret-scan of bundle output finds zero `trove_r_/trove_p_/v1:`
  prefixes or credential values (automated test).
- **Test:** The redaction scan; bundle-content manifest golden; API+CLI parity.

## E-012 Webhook target validation (SSRF)
- **Deps:** E-002
- **Files:** `internal/event/targetcheck.go`
- **Do:** ADR 0012: resolve at write *and* delivery; block loopback/RFC 1918/
  link-local/ULA/metadata ranges unless `webhooks.allow_private_targets`;
  re-resolve per attempt (TOCTOU); no redirects (client-level, E-003); https
  required unless explicitly allowed per subscription by an admin.
- **Accept:** Rebinding attack fixture (DNS answers public-then-private) blocked
  at delivery; allowlist works.
- **Test:** Range-classification table (IPv4+IPv6); fake-resolver rebinding test;
  config-override matrix.

## E-013 Audit retention + export rotation
- **Deps:** E-009, P-006
- **Files:** `internal/audit/prune.go`
- **Do:** Scheduled prune of audit rows older than `audit.retention` (default
  365 d) — export-before-prune: prune runs only after an NDJSON export of the
  affected range is written to `<data>/audit-archive/` (or operator sink);
  the prune itself writes an audit record with range + archive path.
- **Accept:** Bounded growth; archived range restorable/readable; prune audited.
- **Test:** Clock-injected prune; export-then-prune ordering (kill between ⇒
  re-run exports nothing twice, prunes safely); archive readability test.
