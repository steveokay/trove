# status.md

Single source of truth for project progress. Updated in the same commit as the work it
describes. See `CLAUDE.md` §14 for the protocol.

**Legend:** `todo` · `blocked` · `in-progress` · `review` · `done`

---

## Phase 0 — Decisions (Fable 5, no code)

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| D-001 | Confirm project name + module path | done | Q1 | Name agreed; `go.mod` path recorded in CLAUDE.md |
| D-002 | ADR: scanner choice (library vs binary) | done | Q2 ✓ | `docs/adr/0017-scanner-integration.md` — Trivy-as-library behind adapter, golden corpus, table-backed queue, air-gapped DB import |
| D-003 | ADR: authentication model | done | Q3 ✓ | `docs/adr/0004-authentication-model.md` — users, robots, PATs, OCI token flow, UI sessions, bootstrap/recovery |
| D-004 | ADR: HA posture for v1 | done | Q5 ✓ | `docs/adr/0018-ha-posture.md` — single node + lock file, seam table, no memory-resident correctness state |
| D-005 | ADR: UI stack + design direction | done | — | `docs/adr/0019-ui-stack.md` — Svelte 5 + Vite static SPA, near-zero runtime deps, offline pnpm builds; recorded in CLAUDE.md §10 |
| D-006 | ADR: metadata schema + migration strategy | done | D-017, D-011 | `docs/adr/0006-metadata-schema.md` — full ERD, hosted/cached table families, forward-only per-engine migrations |
| D-007 | ADR: blob storage layout + digest verification | done | — | `docs/adr/0007-blob-storage-layout.md` — layouts, atomic commit, stream-verify + quarantine, disjoint store instances |
| D-008 | ADR: retention/GC safety model | done | D-007 | `docs/adr/0010-retention-gc-safety.md` — pure evaluator + plans, mark-and-sweep with grace window, proof sketch, race matrix |
| D-009 | Choose license | done | Q9 ✓ | Apache-2.0; canonical `LICENSE` committed (repo went public ahead of F-001) |
| D-011 | ADR: repository model — hosted / proxy / group | done | D-017 | `docs/adr/0005-repository-model.md` — prefix routing, pure group resolution, write rules, lifecycle (dep flipped: D-006 now consumes this) |
| D-012 | ADR: cache semantics | done | Q11 ✓ | `docs/adr/0008-cache-semantics.md` — leases, negative cache, offline modes, single-flight, backoff, eviction defaults |
| D-013 | ADR: cache eviction vs retention separation | done | D-007, D-011 | `docs/adr/0009-eviction-retention-separation.md` — four walls: types, wiring, imports, schema; proving test defined |
| D-014 | ADR: event model + webhook delivery | done | D-006 | `docs/adr/0012-events-webhooks.md` — taxonomy, outbox pattern, live authz filtering, SSRF validation, retry/DLQ |
| D-015 | ADR: pull gating design | done | Q12 ✓, Q24 ✓ | `docs/adr/0013-pull-gating.md` — single enforcement door, bypass closure, fail-closed lookups, audited break-glass |
| D-016 | ADR: quota accounting model | done | Q8 ✓ | `docs/adr/0014-quota-model.md` — attribution vs physical accounting, hysteresis soft-warn, 413+DENIED, cache evicts |
| D-017 | **ADR: RBAC model** | done | Q14 ✓, Q19 ✓, Q20 ✓ | `docs/adr/0001-rbac-model.md` — subjects, groups, roles, bindings, scope grammar, built-in roles |
| D-018 | **ADR: permission vocabulary** | done | D-017 | `docs/adr/0002-permission-vocabulary.md` — 33 verbs incl. `repo:create`/`repo:configure`, splits justified, verb → operation mapping |
| D-019 | **ADR: visibility & disclosure policy** | done | Q18 ✓ | `docs/adr/0003-visibility-disclosure.md` — status-code matrix, ten enumerated filtered surfaces |
| D-020 | ADR: admin API + CLI conventions | done | Q23 ✓ | `docs/adr/0015-admin-api-cli.md` — /api/v1, problem+json, cursor pagination, spec-vs-route CI check, offline exceptions |
| D-021 | ADR: secrets key management | done | Q21 ✓ | `docs/adr/0016-secrets-key-management.md` — keyfile + key-id format, AAD context binding, two-step rotation, redaction rules |
| D-022 | ADR: referrer lifecycle on subject deletion | done | Q22 ✓ | `docs/adr/0011-referrer-lifecycle.md` — transitive cascade, plan visibility, live-attachment protection, orphan sweep |
| D-010 | Decompose Phases 1–8 into implementable tasks | done | D-001..D-022 | `docs/plan/phase-{1..8}-*.md` — every task has criteria, files, deps, test plan, and per-phase parallelization notes |

---

## Phase 1 — Foundations

Detailed specs (files, test plans): `docs/plan/phase-1-foundations.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| F-001 | Repo scaffold, module, Makefile, CI skeleton | done | D-001 ✓, Q25 ✓ | `make build test lint cover test-linux` green locally; CI green first run (run 33547896799): vet, gofmt, golangci-lint v1.64.8, race suite, 3-target cross-compile. Coverage 100% excluding `cmd/trove/main.go` |
| F-002 | Coverage gate script (≥95%, `-coverpkg=./...`) | review | F-001 ✓ | `scripts/coverage.sh` + 10-case self-test in CI; drop proven locally (uncovered func → 89.1%, exit 1); merges duplicate blocks; degenerate inputs exit 2. Awaiting CI run |
| F-003 | Config load/validate/defaults | todo | F-001 | Flags > env > file > defaults; invalid config refuses startup; secrets redacted |
| F-004 | Structured logging + graceful shutdown | todo | F-001 | `log/slog`; in-flight requests drain on SIGTERM |
| F-005 | `meta.Store` interface + contract test suite | todo | D-006 | One suite, green against both impls |
| F-006 | SQLite impl + migrations | todo | F-005 | Contract suite green; migrations forward-only |
| F-007 | Postgres impl | todo | F-005 | Same contract suite green |
| F-008 | `blob.Store` interface + contract test suite | todo | D-007 | Covers digest mismatch, truncation, resume |
| F-009 | Filesystem blob driver | todo | F-008 | Contract suite green; path traversal tests pass |
| F-010 | S3-compatible blob driver | todo | F-008 | Contract suite green against MinIO in testcontainers |

---

## Phase 2 — Identity and RBAC

Built before the registry handlers, not after. Retrofitting permission filtering into
existing queries is how disclosure bugs get shipped.

Detailed specs (files, test plans): `docs/plan/phase-2-identity-rbac.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| Z-001 | Subject model: users, robot accounts, anonymous | blocked | D-003 | One code path for all three; anonymous is a real subject, not a bypass |
| Z-002 | Users + Argon2id credentials | blocked | D-003 | Timing-safe compare; rate-limited auth endpoints |
| Z-003 | Robot accounts: mandatory expiry, revocation | blocked | D-003 | Revoked token rejected on next use, not on next mint; tokens stored hashed at rest |
| Z-004 | OCI token flow (`WWW-Authenticate` / bearer) | blocked | D-003 | `docker login` works end to end; scopes derived from bindings |
| Z-005 | **Permission vocabulary as typed constants** | todo | D-018 | Exhaustive; test fails if a verb has no positive and negative test |
| Z-006 | **Role model + built-in roles** | blocked | D-017 | Built-ins non-deletable; custom roles use the same vocabulary |
| Z-007 | **Binding model + repository pattern matching** | blocked | D-017, Q20 | Pattern grammar fuzz-tested; traversal and overlap cases covered |
| Z-008 | **`authz.Decide` pure decision function** | blocked | D-017 | No I/O; property-tested; additive union semantics |
| Z-009 | **Import-boundary test for `internal/authz`** | todo | Z-008 | Fails if authz imports registry, repo, or storage packages |
| Z-010 | **Handler-level enforcement middleware** | todo | Z-008 | Enforced at token mint *and* request time |
| Z-011 | **Route-table guard test (fail closed)** | todo | Z-010 | Walks every route; fails if any lacks an explicit permission check |
| Z-012 | **Permission-filtered query layer** | blocked | D-019 | Catalog, tags, search, events, metrics all filter in the query, not the handler |
| Z-013 | **Effective-permission explainer** (CLI + API) | todo | Z-008 | Returns decision *and* every contributing binding |
| Z-014 | Admin bootstrap + forced first-login rotation | todo | Z-002 | Generated password printed once; no default credential |
| Z-015 | Self-lockout prevention | todo | Z-007 | Last `role:write`@system binding cannot be removed; clear error |
| Z-016 | `authz.denied` + `role.changed` events and metrics | todo | Z-010, E-001 | Denials counted by verb; role changes audited before/after |
| Z-018 | **Disclosure adversarial suite** | blocked | D-019, Z-012 | Unreadable repo absent from catalog, search, tag list, pagination counts, events, metric labels, group resolution |
| Z-019 | **Privilege-escalation adversarial suite** | todo | Z-010 | Token replay post-revocation; `repo:write`↛`repo:delete`; `policy:write`↛`policy:apply`; `proxy:write`↛`proxy:credentials` |
| Z-020 | UI session auth: browser login, sessions, CSRF | blocked | D-003, D-020 | Separate from the OCI token flow; CSRF + session-fixation tested; rate-limited |

---

## Phase 3 — OCI registry core (hosted)

Detailed specs (files, test plans): `docs/plan/phase-3-registry-core.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| R-001 | Blob upload (monolithic, chunked, resumable) | todo | F-009, Z-010 | Spec-compliant; digest verified; conformance blob tests green |
| R-002 | Manifest put/get/delete + media-type validation | todo | R-001, F-006 | Rejects manifests referencing missing layers |
| R-003 | Tag list + pagination (permission-filtered) | todo | R-002, Z-012 | Spec-compliant `Link` headers; counts do not leak unreadable tags |
| R-004 | Catalog endpoint (permission-filtered) | todo | Z-012 | Filtered in the query; pagination consistent under filtering |
| R-005 | Referrers API (v1.1) | todo | R-002 | `artifactType` filtering; inherits subject permission on the subject artifact |
| R-006 | Multi-arch index handling | todo | R-002 | Child manifest lifecycle per Q10 |
| R-007 | Helm chart + SBOM artifact awareness | todo | R-005 | `helm push/pull` and `oras attach` round-trip |
| R-008 | Spec error-code mapping | todo | R-002, D-019 | Golden-file tests; 401 vs 403/404 uniform per decision |
| R-009 | OCI conformance suite in CI | todo | R-001..R-008 | Green, required for merge; pull-side conformance also run against a group endpoint |
| R-010 | Pull statistics: last-pulled + counts | todo | R-002 | Recorded off the hot path; feeds retention rules |
| R-011 | Stale upload-session reaping | todo | R-001 | Incomplete chunked uploads expire after a configurable TTL; storage reclaimed; active uploads untouched |
| R-012 | Push-latency benchmark | todo | R-001, R-002 | Baseline recorded; regression check in CI; push latency unaffected by scan backlog (with S-003) |

---

## Phase 4 — Proxy, cache, and groups

Detailed specs (files, test plans): `docs/plan/phase-4-proxy-cache-groups.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| C-001 | Repository model + router (hosted/proxy/group) | todo | D-011 | Push to a proxy returns `DENIED`; unit-tested resolution matrix |
| C-002 | Upstream client interface + contract suite | todo | D-012 | Suite runs against `registry:2` and one real remote |
| C-003 | Upstream credential storage (encrypted, redacted) | blocked | D-003, D-021 | Gated on `proxy:credentials`; never logged or returned on any read path |
| C-004 | Blob/manifest fetch-and-cache by digest | todo | C-002, F-009 | Digest verified on arrival; mismatch rejected and not cached |
| C-005 | Tag → digest lease with TTL + revalidation | todo | Q11 ✓ | Conditional revalidation; default TTL 15m; stale served only in degraded mode |
| C-006 | Single-flight on concurrent cache fill | todo | C-004 | N concurrent pulls of a cold tag → 1 upstream fetch |
| C-007 | Negative cache for upstream 404s | todo | C-005 | Short independent TTL; tested |
| C-008 | Offline / degraded mode | todo | C-005 | Upstream DNS-blackholed: pulls still served, marked stale |
| C-009 | Rate-limit handling + upstream quota metrics | todo | C-002 | Honours `Retry-After`; Docker Hub headroom in metrics |
| C-010 | Routing rules (allow/block patterns per proxy) | todo | C-001 | Default-deny option; no open-relay configuration reachable |
| C-011 | Group resolution (ordered, first-match-wins) | todo | C-001 | Pure function; member-down, duplicate-tag, malformed-manifest cases |
| C-012 | **Permission filtering before group resolution** | todo | C-011, Z-012 | Unreadable members removed pre-resolution; existence not inferable from behaviour |
| C-013 | Cache eviction (size/LRU budget) | todo | D-013, Q11 ✓ | Global budget default 50 GB, per-proxy override; cannot reach a hosted blob — proven by type-level test |
| C-014 | Default upstream presets | todo | Q7 ✓ | Docker Hub, ghcr, quay, registry.k8s.io, gcr shipped disabled; quickstart enables Docker Hub |
| C-015 | Proxy adversarial suite | todo | C-004..C-012 | Digest mismatch, redirect loop, 429 storm, traversal via upstream mapping, group member leakage, SSRF via upstream redirect to internal addresses |
| C-016 | Repository admin CRUD API (hosted/proxy/group) | todo | C-001, D-020 | Create/update/delete all three types; config validated; permission-gated per D-018 |

---

## Phase 5 — Scanning and vulnerability assessment

Detailed specs (files, test plans): `docs/plan/phase-5-scanning.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| S-001 | `scan.Scanner` interface + fake impl | blocked | D-002 | No vendor import outside the adapter package |
| S-002 | Scanner adapter + result normalisation | blocked | D-002 | Vendor JSON never persisted as system of record |
| S-003 | Async scan queue + retry/backoff | todo | S-001 | Push latency unaffected under scan backlog |
| S-004 | CVE DB lifecycle: online update + offline import | todo | S-002 | `trove db import` tested air-gapped |
| S-005 | Rescan on DB update + `scan.regressed` event | todo | S-004, E-001 | Previously clean image re-flags on new CVE data |
| S-006 | Vulnerability model, rollups, queries | todo | S-002, Z-012 | Fixable/not-fixable split; results permission-filtered |
| S-007 | VEX / suppression rules | todo | S-006 | Auditable; suppressions expire |
| S-008 | Attach scan results as OCI referrers | todo | R-005, S-002 | Readable by external tooling; survives migration |
| S-009 | Scan-on-cache-fill for proxied content | todo | C-004, S-003 | Cached images not silently exempt from gating |
| S-010 | Registry-wide scan config with filters | todo | S-003 | Include/exclude by repo pattern |
| S-011 | Pull gating / quarantine enforcement | blocked | D-015, Q12 ✓, Q24 ✓ | Off by default; serve-on-fill with per-policy strict mode; no bypass via digest, referrers, or group member; `gate:override` audited |

---

## Phase 6 — Policies, retention, GC, quotas

Detailed specs (files, test plans): `docs/plan/phase-6-policy-gc-quota.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P-001 | Tag policy: immutability + prefix exceptions, protected tags | todo | R-003 | Protected beats every retention rule — adversarially tested |
| P-002 | Retention evaluator as a pure function | todo | D-008, D-022 | No I/O; injectable clock; property tests; explicit rule priority; cannot select a referrer of a live subject |
| P-003 | `keep-if-pulled-since` rule | todo | P-002, R-010 | Uses pull statistics; clock-injected tests |
| P-004 | Dry-run plan output (API + CLI) | todo | P-002 | Plan explains *why* each manifest is selected; gated on `policy:read` |
| P-005 | Apply path with audit records | todo | P-004, Z-005 | Requires `policy:apply` and explicit confirmation |
| P-006 | Scheduled policy runs / task scheduler | todo | P-005 | Overlapping runs cannot double-delete |
| P-007 | Mark-and-sweep GC, resumable | todo | D-008 | Cannot delete a blob referenced by a concurrent upload |
| P-008 | GC race tests | todo | P-007 | GC vs upload, GC vs delete, interrupted sweep resume |
| P-009 | Quota accounting + enforcement | blocked | D-016, Q8 ✓ | Per-repo + global; soft-warn event then hard-deny push; cache breach evicts harder, never fails pulls |
| P-012 | `trove verify` integrity scrub | todo | F-006, F-008 | Re-verifies blob digests; detects meta↔blob drift; read-only; referenced by the restore procedure (DOC-002) |

---

## Phase 7 — Events, observability, operability

Detailed specs (files, test plans): `docs/plan/phase-7-events-observability.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| E-001 | In-process event bus + typed event taxonomy | todo | D-014 | All events in CLAUDE.md §8 emitted and tested |
| E-002 | Webhook subscriptions + filters | todo | E-001 | Per-repo, per-event-type |
| E-003 | Webhook delivery: HMAC signing, retry, DLQ | todo | E-002 | At-least-once; documented idempotency key; dead-letter visible; delivery queue durable across restart |
| E-004 | **Webhook permission scoping** | todo | E-002, Z-012 | Subscription only receives events its owning subject can read |
| E-005 | Prometheus metrics | todo | E-001 | Request, storage, cache-hit, upstream headroom, scan queue, authz denials, GC progress; `/metrics` endpoint auth decided and enforced |
| E-006 | Metric label cardinality + disclosure review | todo | E-005 | Repo names as labels justified or removed |
| E-007 | `/healthz` and `/readyz` | todo | F-004 | Distinct semantics; readiness covers migrations and deps |
| E-008 | Read-only / maintenance mode | todo | F-003, Z-005 | Runtime toggle behind `system:maintenance`; writes rejected clearly |
| E-009 | Audit log (append-only, queryable) | todo | F-006 | Every mutating action with actor, digest, rule; gated on `audit:read` |
| E-010 | Cross-repo search (permission-filtered) | todo | Z-012, S-006 | By name, tag, digest, media type, CVE ID |
| E-011 | `trove support-bundle` | todo | F-003 | Config redacted, version, migration state, role/binding summary, recent logs |
| E-012 | Webhook target validation (SSRF) | todo | E-002 | Private/link-local ranges blocked by default; operator allowlist override; redirects re-validated |
| E-013 | Audit log retention + export rotation | todo | E-009 | Bounded growth; export before prune; the prune itself is audited |

---

## Phase 8 — UI, packaging, docs

Detailed specs (files, test plans): `docs/plan/phase-8-ui-packaging-docs.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| U-001 | UI scaffold on chosen stack | todo | D-005 ✓ | Svelte 5 + Vite per ADR 0019; builds offline; embedded via `go:embed` |
| U-002 | Effective-permissions endpoint + UI gating | todo | U-001, Z-013 | Unusable actions hidden; server-side authz still enforced independently |
| U-003 | Repo/tag/manifest browsing | todo | U-002, R-003 | Copyable digests; dense tables; keyboard navigable |
| U-004 | SBOM + CVE report views | todo | U-002, S-006 | Filter by severity and fixability |
| U-005 | Policy editor with dry-run preview | todo | U-002, P-004 | Shows the plan before apply |
| U-006 | Proxy/group management screens | todo | U-002, C-011 | Upstream health, cache hit ratio, rate-limit headroom, member order |
| U-007 | **Role, binding, and user admin screens** | todo | U-002, Z-013 | Create roles, bind to scopes, explain effective permissions inline |
| U-008 | Webhook management + delivery history | todo | U-002, E-003 | Dead-letter inspection and replay |
| U-009 | Audit log viewer | todo | U-002, E-009 | Filter by actor, verb, resource, outcome |
| U-010 | Accessibility + dark mode pass | todo | U-003..U-009 | WCAG AA contrast; real focus states |
| PK-001 | systemd unit + `.deb`/`.rpm` | todo | F-001 | Zero-edit happy path |
| PK-002 | `docker-compose.yml` | todo | F-001 | Zero-edit happy path |
| PK-003 | Helm chart | todo | F-001 | Zero-edit happy path |
| PK-004 | TLS: ACME and operator-supplied certs | todo | F-003 | One config key switches modes |
| PK-005 | Cross-compiled release pipeline | todo | F-001 | linux/amd64, linux/arm64, darwin/arm64; checksums |
| PK-006 | `trove migrate --from` import | todo | Q17 ✓ | Generic distribution-spec source (catalog walk or repo list); resumable |
| DOC-001 | Quickstart: TLS registry + Docker Hub cache + admin and developer roles in <5 min | todo | PK-001, PK-004, C-005, Z-014 | Verified end to end on a clean VM |
| DOC-002 | Operator guide: backup, restore, upgrade, GC, read-only mode | todo | P-007, E-008 | Restore path actually tested |
| DOC-003 | **RBAC guide: roles, scopes, common setups, troubleshooting** | todo | Z-013 | Worked examples for 3-role and per-team setups |

---

## Decisions — all questions answered (2026-09-01)

Full statements live in CLAUDE.md §13; ADR tasks D-002…D-022 formalise them.

| ID | Decision |
|---|---|
| Q1 | `trove`, module `github.com/steveokay/trove` |
| Q2 | Trivy as a Go library, behind `scan.Scanner` in the adapter package |
| Q3 | Local users, robot accounts, local groups only in v1; OIDC → local groups in v1.1 |
| Q4 | Store + display signatures; gating may check presence; full verification v1.1 |
| Q5 | Single node for v1; in-process locking and single-flight |
| Q6 | Air-gapped install + offline CVE DB import are v1 requirements |
| Q7 | Presets for Docker Hub, ghcr, quay, registry.k8s.io, gcr — all disabled by default |
| Q8 | Per-repo + global quotas; soft-warn then hard-deny push; cache evicts, never fails pulls |
| Q9 | Apache-2.0 |
| Q10 | Deleting an index-referenced child manifest is an error naming the index |
| Q11 | Global cache budget (50 GB default) + LRU, per-proxy override; tag TTL 15m; negative TTL 60s |
| Q12 | Pull gating off by default — observe first |
| Q13 | Blob encryption delegated to filesystem/S3 layer; app encrypts secrets only |
| Q14 | RBAC additive-only, no deny rules — confirmed |
| Q15 | Promotion deferred to v1.1 (P-011 dropped) |
| Q16 | Immediate delete; GC lag is the grace window (P-010 dropped) |
| Q17 | Generic importer for any distribution-spec-compliant source, resumable |
| Q18 | Unauthorized reads return 404 / `NAME_UNKNOWN`, uniformly; unauthenticated gets 401 + challenge |
| Q19 | Bindings attach to subjects and local groups/teams |
| Q20 | Scopes are repository patterns only; tag needs met by per-repo tag policies |
| Q21 | Auto-generated 32-byte keyfile (0600), AES-256-GCM, re-encrypt rotation command |
| Q22 | Subject deletion cascade-deletes its referrers, each audited |
| Q23 | CLI is an admin-API client (`trove login`/`TROVE_TOKEN`); `serve`, `version`, `--offline db import` excepted |
| Q24 | Cache-fill pull served immediately; async scan gates subsequent pulls; per-policy strict mode |
| Q25 | Native Windows inner loop (revised 2026-09-01); `make test-linux` in a Debian-based `golang` container with docker-socket mount; Linux CI authoritative |

---

## Dropped

| ID | Task | Reason |
|---|---|---|
| Z-017 | External identity (OIDC/LDAP) → binding mapping | Q3 decided: local subjects + groups only in v1; OIDC maps onto local groups in v1.1 |
| P-010 | Soft delete / recovery window | Q16 decided: immediate delete, GC lag is the grace window; revisit in v1.1 if demanded |
| P-011 | Promotion between repositories | Q15 decided: deferred to v1.1 — wants only-if-scanned/signed policy hooks that mature with gating |
