# status.md

Single source of truth for project progress. Updated in the same commit as the work it
describes. See `CLAUDE.md` §14 for the protocol.

**Legend:** `todo` · `blocked` · `in-progress` · `review` · `done`

Acceptance cells stay short. A completed task's full write-up — design detail,
deviations, coverage, CI run — lives in `docs/notes/phase-N.md`, one frozen section
per task, and the row points there. Keep new completions to a summary in the cell
and put the story in the notes file, in the same commit.

No task is `blocked` as of 2026-09-01: every open question (Q1–Q25) is decided and all
Phase 0 ADRs have landed. A task's `Depends on` column still names the tasks that must
precede it — that is ordering, not a blocker.

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
| D-018 | **ADR: permission vocabulary** | done | D-017 | `docs/adr/0002-permission-vocabulary.md` — 30 verbs incl. `repo:create`/`repo:configure`, splits justified, verb → operation mapping (count corrected from 33 in Z-005: the ADR's tables always held 30) |
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
| F-002 | Coverage gate script (≥95%, `-coverpkg=./...`) | done | F-001 ✓ | `scripts/coverage.sh` + 10-case self-test + shellcheck, all green in CI (run 33548479273). Drop proven: uncovered func → 89.1%, exit 1. Merges duplicate blocks; degenerate inputs exit 2 |
| F-003 | Config load/validate/defaults | done | F-001 ✓ | `internal/config`: precedence flags > env > file > defaults with per-key source tracking; every validation problem reported at once; secrets redacted with no unredacted renderer. Details → `docs/notes/phase-1.md` |
| F-004 | Structured logging + graceful shutdown | done | F-001 ✓, F-003 ✓ | `internal/server`: slog by config, request IDs echoed and context-carried, levelled access log, graceful drain proven in-flight, data-dir lock. Details → `docs/notes/phase-1.md` |
| F-005 | `meta.Store` core: repositories + content | done | D-006 ✓ | `internal/meta` types/errors/Visibility, `metatest` 24-case contract suite incl. exhaustive per-method cancellation, `memory` reference impl green under `-race`. Coverage 98.6%. Amends §9: shared test harnesses excluded from the gate; CI green (run 33555464491) |
| F-005b | `meta.Store` identity + authz groups | done | F-005 ✓ | Subjects (incl. undeletable anonymous), local groups, roles with read-only built-ins, bindings, and `ListEffectiveBindings` with group provenance; 14 added contract cases, 164 subtests total. Coverage 98.7%. Credentials/sessions deferred to F-005c; CI green (run 33557505946) |
| F-005c | `meta.Store` credentials + sessions | done | F-005b ✓ | Argon2id verifiers, robot secrets with mandatory expiry, PATs, sessions with idle+absolute bounds; hashes only, expiry enforced on read, subject deletion cascades. 11 added cases, 219 subtests total. Coverage 98.9%; CI green (run 33559361399) |
| F-006 | SQLite impl + migrations | done | F-005 ✓ | `internal/meta/sqlite` (modernc, no CGO): WAL, verified foreign keys, single-writer pool, embedded forward-only migrations; `--no-auto-migrate` refuses naming what is pending. Details → `docs/notes/phase-1.md` |
| F-007 | Postgres impl | done | F-005 ✓, F-006 ✓ | `internal/meta/postgres` (pgx/v5): contract suite green unmodified against testcontainers `postgres:17`; schema-parity test holds both engines to identical columns. Details → `docs/notes/phase-1.md` |
| F-008 | `blob.Store` interface + contract test suite | done | D-007 ✓ | `internal/blob`: Store/Uploader/UploadSession per ADR 0007; the strict digest parser is the traversal gate (fuzzed: nothing accepted can carry a path); shared Verifier/Copy/VerifiedReader. Details → `docs/notes/phase-1.md` |
| F-009 | Filesystem blob driver | done | F-008 ✓ | `internal/blob/fs`: ADR 0007 layout, staging → fsync → rename atomicity (a blob path is absent or complete), corrupt reads quarantined, never served. Details → `docs/notes/phase-1.md` |
| F-010 | S3-compatible blob driver | done | F-008 ✓ | `internal/blob/s3` (minio-go): same key scheme under a prefix, multipart commit only after the digest verifies, contract suite green against a MinIO container. Details → `docs/notes/phase-1.md` |

---

## Phase 2 — Identity and RBAC

Built before the registry handlers, not after. Retrofitting permission filtering into
existing queries is how disclosure bugs get shipped.

Phase 1 closed 2026-09-02 (F-001…F-010): config, logging and shutdown, `meta.Store`
with SQLite and Postgres, and `blob.Store` with filesystem and S3 drivers, each
interface with a contract suite every implementation runs unmodified.

Detailed specs (files, test plans): `docs/plan/phase-2-identity-rbac.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| Z-001 | Subject model: users, robot accounts, anonymous | done | D-003 ✓, F-006 ✓ | `internal/authn`: one `Resolve` for users, robots, and the seeded anonymous row — no nil-subject branch anywhere; disabling the row turns anonymous off wholesale. Details → `docs/notes/phase-2.md` |
| Z-002 | **Users + Argon2id credentials** | done | D-003 ✓, Z-001 ✓ | Argon2id in PHC form with hash-carried params bounded against decompression DoS (fuzz found it twice); GCRA limiter per account and per source with an honest Retry-After. Details → `docs/notes/phase-2.md` |
| Z-003a | **Secrets encryption (`internal/secretbox`)** | done | D-021 ✓ | `internal/secretbox`: AES-256-GCM sealed values (`v1:<key-id>:`, mandatory AAD, multi-key rotation), pinned golden; sole AEAD importer, enforced by archtest. Details → `docs/notes/phase-2.md` |
| Z-003b | Robot accounts: mandatory expiry, revocation | done | D-003 ✓, Z-001 ✓, Z-003a ✓ | Robot accounts: HMAC-digested secrets at rest, one active secret, mandatory expiry enforced on read, revocation wins at next use; `robot$` dispatch in basic auth. Details → `docs/notes/phase-2.md` |
| Z-004 | OCI token flow (`WWW-Authenticate` / bearer) | done | D-003 ✓, Z-002 ✓, Z-003b ✓, Z-008 ✓ | OCI token flow: Ed25519 JWTs (library quarantined), grants intersected via `authz.Allows`, `/v2/` probe + challenge; revoking a binding kills a live bearer next request; docker login sequence proven over HTTP. Details → `docs/notes/phase-2.md` |
| Z-005 | **Permission vocabulary as typed constants** | done | D-018 ✓ | The 30-verb vocabulary as a closed set + `verbtest`: the §9 both-polarities ratchet that only shrinks. Details → `docs/notes/phase-2.md` |
| Z-006 | **Role model + built-in roles** | done | D-017 ✓ | The six ADR 0001 built-in roles; `admin`/`operator`/`auditor` derived from the vocabulary so they cannot fall behind it; DB seeding deferred to Z-014. Details → `docs/notes/phase-2.md` |
| Z-007 | **Binding model + repository pattern matching** | done | D-017 ✓, Q20 ✓ | `internal/authz/{scope,scope_sql,binding}.go`: the four-form grammar (`system` \| `*` \| exact \| trailing `/*`) as one validator, one matcher, and one filter compiler for the query layer; `Resource` is a struct so the `system` keyword and a repository named `system` cannot be confused, and its zero value matches nothing. Scope patterns validate against the repository-name grammar, now in the leaf package `internal/reponame` (new — authz cannot import `repo` under Z-009, and the registry needs the same rule in Phase 3). Decision made here: the whole `system` prefix is reserved, so `system/*` is refused rather than silently meaning a repository directory — a binding written that way by somebody meaning the global scope would grant nothing while looking like it granted everything; C-016 must refuse the matching repository names. Three fuzz targets green (`FuzzParseScope`, `FuzzScopeMatches`, `FuzzScopeMatcherAgreesWithSQL` — 1.6M+ execs, well past the 10k the plan asks for), plus `FuzzValidate` on the name grammar; the differential test runs the query layer's own predicate through SQLite and also checks `meta.ScopeFilter`, so all three readings of a pattern agree. Coverage 100% of both packages, 96.2% overall; CI green (run 33729537147) |
| Z-008 | **`authz.Decide` pure decision function** | done | Z-005 ✓, Z-006 ✓, Z-007 ✓ | `authz.Decide`: pure, returns every matched binding (the explainer is this call, not a second implementation); five fuzzed properties. Details → `docs/notes/phase-2.md` |
| Z-009 | **Import-boundary test for `internal/authz`** | done | Z-008 ✓ | `internal/archtest`: allowlist rules over `go list -deps` — authz reaches no storage, the cache↔gc wall holds both ways, primitives stay quarantined; verified by injecting a real violation. Details → `docs/notes/phase-2.md` |
| Z-010 | **Handler-level enforcement middleware** | done | Z-008 ✓, Z-001 ✓ | The Guard: subject → bindings → `Decide` — one path for every request, registration demands a Permission, ADR 0003's matrix is a table test including the byte-identical 404. Details → `docs/notes/phase-2.md` |
| Z-011 | **Route-table guard test (fail closed)** | done | Z-010 ✓ | `Router.Verify` + frozen public-route list + mux quarantine (AST scan): a table Verify rejects refuses to dispatch, and no route can exist outside it. Details → `docs/notes/phase-2.md` |
| Z-012 | **Permission-filtered query layer** | done | D-019 ✓, Z-007 ✓, F-006 ✓, F-007 ✓ | `VisibilityFor`: the one bindings→filters bridge, never Unrestricted for a subject; filtered-pagination and cursor-stability contract tests; `repo:list` off the §9 list. Details → `docs/notes/phase-2.md` |
| Z-013 | **Effective-permission explainer** (CLI + API) | done | Z-008 ✓, D-020 ✓ | `/api/v1/auth/explain` renders `Decide` itself so it cannot drift; introduces `Permission.Self`; refusal identical whether the asked-about subject exists; CLI is a client of the endpoint. Details → `docs/notes/phase-2.md` |
| Z-014 | Admin bootstrap + forced first-login rotation | done | Z-002 ✓, Z-006 ✓ | Bootstrap: built-ins converge every boot, admin created only when nobody could log in, password printed once to stdout with forced rotation; shared `PasswordLogin` (limits, decoy verifier); must-rotate gate; `trove serve` becomes real. Details → `docs/notes/phase-2.md` |
| Z-015 | Self-lockout prevention | done | Z-007 ✓ | Last-admin lockout: `EnsureAdminRemains` refused across every §5 removal vector including role-verb narrowing; enforcement contract documented for C-016/U-007's mutation handlers. Details → `docs/notes/phase-2.md` |
| Z-016 | `authz.denied` + `role.changed` events and metrics | todo | Z-010, E-001 | Denials counted by verb; role changes audited before/after |
| Z-018 | **Disclosure adversarial suite** | done | D-019 ✓, Z-012 ✓ | The disclosure suite over ADR 0003's surfaces, with a status.md-reading skip ratchet: a surface cannot go `done` without its test landing in the same commit. Details → `docs/notes/phase-2.md` |
| Z-019 | **Privilege-escalation adversarial suite** | done | Z-010 ✓, Z-004 ✓ | The privilege-escalation suite: every ADR 0002 non-implication pinned at `Decide` with an ADR-parsing drift check; robot repo-crossing and post-revocation token replay end-to-end. Details → `docs/notes/phase-2.md` |
| Z-020 | UI session auth: browser login, sessions, CSRF | todo | D-003, D-020 | Separate from the OCI token flow; CSRF + session-fixation tested; rate-limited |

---

## Phase 3 — OCI registry core (hosted)

Detailed specs (files, test plans): `docs/plan/phase-3-registry-core.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| R-001 | Blob upload (monolithic, chunked, resumable) | done | F-009 ✓, Z-010 ✓ | Distribution blob API (start/chunk/commit/status/cancel + cross-repo mount) over new `HandleOCI` routing; /v2/ speaks the spec envelope; every failed mount is an identical 202 (no probing); a mismatched commit publishes nothing. Details → `docs/notes/phase-3.md` |
| R-002 | Manifest put/get/delete + media-type validation | done | R-001 ✓, F-006 ✓ | Manifest PUT/GET/DELETE + `internal/artifact` parser (closed set of four media types); missing layer/child → `MANIFEST_BLOB_UNKNOWN`; ADR 0011 cascade with Q10 checked tree-wide and failing closed; reads re-hash (drift is a 500); `manifest:delete` enforced both ways. Details → `docs/notes/phase-3.md` |
| R-003 | Tag list + pagination (permission-filtered) | done | R-002 ✓, Z-012 ✓ | `tags/list` under `repo:read`, filtered end to end, keyset `n`/`last` pagination with spec `Link`; hidden ≡ absent byte-for-byte; disclosure surface 2 unskipped. Tag deletion stays `UNSUPPORTED` pending a route split (see notes). Details → `docs/notes/phase-3.md` |
| R-004 | Catalog endpoint (permission-filtered) | done | Z-012 ✓ | `/v2/_catalog` as the first Listing route: guard-computed Visibility, so counts and cursors come pre-filtered; anonymous with nothing visible is challenged; disclosure surface 1 unskipped. Details → `docs/notes/phase-3.md` |
| R-005 | Referrers API (v1.1) | done | R-002 ✓ | Referrers API: `referrer:read` ∧ `repo:read` (checked before the digest parses), assembled OCI index with `artifactType` filter + `OCI-Filters-Applied`, golden body, digest ordering now interface contract; surface 3 unskipped; `referrer:read` off the §9 list. Details → `docs/notes/phase-3.md` |
| R-006 | Multi-arch index handling | review | R-002 ✓ | Gap-closing over R-002: the delete-order matrix (`internal/registry/index_test.go`) — shared children, nested indexes, Docker lists, platform byte-round-trip — plus a mutation-caught test that alone pins the handler's tree-wide Q10 pre-check, and child descriptors now size-checked like blob descriptors. GC fixture deferred to P-007; oras fixtures to R-009. Details → `docs/notes/phase-3.md` |
| R-007 | Helm chart + SBOM artifact awareness | todo | R-005 | `helm push/pull` and `oras attach` round-trip |
| R-008 | Spec error-code mapping | review | R-002 ✓, D-019 ✓ | 24 goldens pin the /v2/ wire contract byte-for-byte (`internal/registry/testdata/errors/`): every `SpecErrors` renderer branch (incl. the empty-challenge and Retry-After-floor branches), one envelope per `Code*` constant, and the JSON HTML-escaping nobody chose but clients now depend on. An AST-driven ratchet means a new code cannot ship unpinned; zero rendered bytes changed. Details → `docs/notes/phase-3.md` |
| R-009 | OCI conformance suite in CI | todo | R-001..R-008 | Green, required for merge; pull-side conformance also run against a group endpoint |
| R-010 | Pull statistics: last-pulled + counts | todo | R-002 | Recorded off the hot path; feeds retention rules |
| R-011 | Stale upload-session reaping | review | R-001 ✓ | `internal/registry/upload_reaper.go` + `registry.upload_session_ttl` (default 24h) + serve's interim hourly loop (P-006 replaces the loop, keeps `ReapOnce`). Staging cancelled before the row so every crash window self-heals; activity refreshes the clock so active uploads are structurally unreachable; committed blobs untouched by construction and by test; per-session failures logged, joined, and never stop the sweep. Details → `docs/notes/phase-3.md` |
| R-012 | Push-latency benchmark | todo | R-001, R-002 | Baseline recorded; regression check in CI; push latency unaffected by scan backlog (with S-003) |

---

## Phase 4 — Proxy, cache, and groups

Detailed specs (files, test plans): `docs/plan/phase-4-proxy-cache-groups.md`

| ID | Task | Status | Depends on | Acceptance criteria |
|---|---|---|---|---|
| C-001 | Repository model + router (hosted/proxy/group) | todo | D-011 | Push to a proxy returns `DENIED`; unit-tested resolution matrix |
| C-002 | Upstream client interface + contract suite | todo | D-012 | Suite runs against `registry:2` and one real remote |
| C-003 | Upstream credential storage (encrypted, redacted) | todo | D-003, D-021 | Gated on `proxy:credentials`; never logged or returned on any read path |
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
| S-001 | `scan.Scanner` interface + fake impl | todo | D-002 | No vendor import outside the adapter package |
| S-002 | Scanner adapter + result normalisation | todo | D-002 | Vendor JSON never persisted as system of record |
| S-003 | Async scan queue + retry/backoff | todo | S-001 | Push latency unaffected under scan backlog |
| S-004 | CVE DB lifecycle: online update + offline import | todo | S-002 | `trove db import` tested air-gapped |
| S-005 | Rescan on DB update + `scan.regressed` event | todo | S-004, E-001 | Previously clean image re-flags on new CVE data |
| S-006 | Vulnerability model, rollups, queries | todo | S-002, Z-012 | Fixable/not-fixable split; results permission-filtered |
| S-007 | VEX / suppression rules | todo | S-006 | Auditable; suppressions expire |
| S-008 | Attach scan results as OCI referrers | todo | R-005, S-002 | Readable by external tooling; survives migration |
| S-009 | Scan-on-cache-fill for proxied content | todo | C-004, S-003 | Cached images not silently exempt from gating |
| S-010 | Registry-wide scan config with filters | todo | S-003 | Include/exclude by repo pattern |
| S-011 | Pull gating / quarantine enforcement | todo | D-015, Q12 ✓, Q24 ✓ | Off by default; serve-on-fill with per-policy strict mode; no bypass via digest, referrers, or group member; `gate:override` audited |

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
| P-009 | Quota accounting + enforcement | todo | D-016, Q8 ✓ | Per-repo + global; soft-warn event then hard-deny push; cache breach evicts harder, never fails pulls |
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
