# status.md

Single source of truth for project progress. Updated in the same commit as the work it
describes. See `CLAUDE.md` §14 for the protocol.

**Legend:** `todo` · `blocked` · `in-progress` · `review` · `done`

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
| F-003 | Config load/validate/defaults | done | F-001 ✓ | `internal/config`: flags > env > file > defaults with per-key source tracking; all problems reported at once naming key + layer; secrets redacted with no unredacted renderer; `trove.example.yaml` + `docs/operator/configuration.md`, drift-tested against defaults. Coverage 99.7%; CI green (run 33550551595) |
| F-004 | Structured logging + graceful shutdown | done | F-001 ✓, F-003 ✓ | `internal/server`: slog JSON/text by config, per-request IDs echoed in `Trove-Request-Id` and carried on a context logger, access log levelled by status; graceful drain proven by an in-flight-request test; ADR 0018 data-dir lock (flock/Windows `CreateFile`) with second-start refusal tested; `trove serve` wired with SIGTERM/SIGINT handling. Coverage 97.8%; CI green (run 33551971007) |
| F-005 | `meta.Store` core: repositories + content | done | D-006 ✓ | `internal/meta` types/errors/Visibility, `metatest` 24-case contract suite incl. exhaustive per-method cancellation, `memory` reference impl green under `-race`. Coverage 98.6%. Amends §9: shared test harnesses excluded from the gate; CI green (run 33555464491) |
| F-005b | `meta.Store` identity + authz groups | done | F-005 ✓ | Subjects (incl. undeletable anonymous), local groups, roles with read-only built-ins, bindings, and `ListEffectiveBindings` with group provenance; 14 added contract cases, 164 subtests total. Coverage 98.7%. Credentials/sessions deferred to F-005c; CI green (run 33557505946) |
| F-005c | `meta.Store` credentials + sessions | done | F-005b ✓ | Argon2id verifiers, robot secrets with mandatory expiry, PATs, sessions with idle+absolute bounds; hashes only, expiry enforced on read, subject deletion cascades. 11 added cases, 219 subtests total. Coverage 98.9%; CI green (run 33559361399) |
| F-006 | SQLite impl + migrations | done | F-005 ✓ | `internal/meta/sqlite` on `modernc.org/sqlite`: WAL, foreign keys verified at open, single-writer pool, embedded forward-only migrations applied per-step in a transaction; `-no-auto-migrate` refuses and names what is pending, a failed step rolls back and names its version. Contract suite green unmodified (155 subtests) plus 179 implementation subtests (dead-database and dropped-table failure tables, migration runner). Adds an upload-session cascade case to the contract; `memory` updated to match. Go directive raised to 1.25 — the driver requires it. Coverage 96.4% package, 97.9% overall; CI green (run 33618686319), lint now builds golangci-lint from source so the pin survives the toolchain bump |
| F-007 | Postgres impl | done | F-005 ✓, F-006 ✓ | `internal/meta/postgres` on `jackc/pgx/v5`: the contract suite green unmodified against a testcontainers `postgres:17-alpine`, plus a schema-parity test holding both engines to the same columns and nullability across all 18 tables (verified to fail on injected drift). Migration runner extracted to `internal/meta/migrate` and the SQL plumbing — including the single scope→SQL compiler both engines filter with — to `internal/meta/sqlutil`. Unique-violation → `ErrConflict` mapping covers the concurrent-writer race SQLite cannot have, tested with racing creates. Every Postgres `TEXT` column is `COLLATE "C"` so listings and cursors order identically on both engines; test databases are created with an ICU collation so that guarantee is provable, and removing it fails the cross-engine ordering test. Coverage 97.3% package, 97.8% overall; CI green (run 33621319625) |
| F-008 | `blob.Store` interface + contract test suite | done | D-007 ✓ | `internal/blob`: Store/Uploader/UploadSession per ADR 0007; strict digest parser (allowlisted algorithm, exact length, lowercase hex only) as the traversal gate, with `FuzzParseDigest` asserting nothing accepted can carry a separator, `..`, or a null; shared `Verifier`/`Copy` for writes and a `VerifiedReader` that withholds a blob's last byte until the hash checks out, so a corrupt read fails the client's own digest check instead of returning bad bytes with a clean EOF. `blobtest` 24-case contract suite (mismatch leaves nothing, truncation, dropped connection, idempotent and concurrent Put, Walk during writes / on error / on cancel, resume, commit mismatch and invalid digest, cancellation). Adds `internal/blob/memory` — not in the plan's file list, but the suite is unproven without an implementation and higher layers need the test double, as `meta/memory` is for F-005. 179 subtests. Coverage 100% of both non-harness packages, 98.0% overall; CI green (run 33630695310) |
| F-009 | Filesystem blob driver | done | F-008 ✓ | `internal/blob/fs`: ADR 0007 layout (`blobs/<algo>/<first-2>/<hex>`, hex-keyed so no colon reaches a Windows path), staging → fsync → chmod 0444 → rename → parent-dir fsync, so a blob path is either absent or complete. Read mismatch quarantines the bytes as evidence and fires the injected `CorruptHook` (the `blob.corrupt` source). Upload sessions keep their state on disk — file presence is existence, size is the offset — so a session survives a restart, proven by a test that resumes through a second store over the same root. Root confinement as the second wall, tested directly, plus an upload-id allowlist for the other caller-supplied path component. Adversarial: leftover staging file after a simulated crash, corrupt blob quarantined and withheld, foreign files ignored by Walk, and permission-injected failures for Put/Delete/Stat/Get/Walk/Commit/quarantine that assert a broken disk never reads as "absent". Coverage 86.6% package (remaining branches are unreachable syscall failures); CI green (run 33666830276) at 97.2% overall — higher than the 96.8% measured on Windows, where the permission-injected cases skip |
| F-010 | S3-compatible blob driver | done | F-008 ✓ | `internal/blob/s3` on `minio-go/v7`: ADR 0007 key scheme under a configurable prefix (the hosted/cache separation when they share a bucket), writes through a multipart upload completed only after the digest verifies — the object-store equivalent of stage-then-rename, so an interrupted or mismatched push never becomes an object. Sessions are chunk objects plus a marker, with offset and existence derived from the bucket, so a session survives a restart. Quarantine is copy-then-delete (no rename in S3). Presigned-redirect mode is off by default and covered by an opt-in test that fetches the URL. Contract suite green against MinIO in testcontainers; adversarial: service stopped mid-upload leaves nothing visible, a vanished bucket never reads as "blob absent". Fixed a real leak found on the way: abandoning a minio listing blocks its goroutine forever on a send nobody reads, exhausting the connection pool — both listings now drain. Adds `blob.Redirector`/`ErrNoRedirect` and moves the upload-id gate into `internal/blob` so both drivers share it. Coverage 85.4% package (rest are unreachable network failures); CI green (run 33673939068) at 96.4% overall |

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
| Z-001 | Subject model: users, robot accounts, anonymous | todo | D-003 | One code path for all three; anonymous is a real subject, not a bypass |
| Z-002 | Users + Argon2id credentials | todo | D-003 | Timing-safe compare; rate-limited auth endpoints |
| Z-003a | **Secrets encryption (`internal/secretbox`)** | review | D-021 ✓ | Split out of Z-003 (F-005 precedent) because it is a separate package and the sole importer of the AEAD primitives, which Z-009's quarantine rule now enforces. AES-256-GCM, fresh 96-bit nonce per value, wire format `v1:<key-id>:<base64(nonce‖ciphertext)>` with a **pinned golden value** so a future build that changes nonce placement or encoding fails a test instead of orphaning rows. Context (AAD) is mandatory with no default and rejects a trailing `:`, so `ProxyCredential("")` cannot bind every row to one context. Multi-key keyring: first key seals, retired keys still open, `NeedsReseal`/`Rotate` drive the two-step rotation. `Redact` never returns ciphertext. Fuzzing found a real defect: Go's base64 decoder skips CR/LF and tolerates non-zero padding bits, so one ciphertext had many spellings — the parser now requires canonical encoding. Coverage 96.2%; verified independently (cross-row and cross-column AAD rejection, 200 distinct seals of one plaintext, no secret echoed in errors). ADR 0016 clarified: keyfile is base64-per-line, comments/blanks ignored, permission check strict with an opt-out for platform mounts, HMAC keying stays in this package; its stale `keys.secrets_key_file` corrected to `auth.secrets_key_file` |
| Z-003b | Robot accounts: mandatory expiry, revocation | todo | D-003, Z-001, Z-003a ✓ | Revoked token rejected on next use, not on next mint; tokens stored hashed at rest. Uses an HMAC helper exposed by `internal/secretbox` rather than taking the raw key (ADR 0016 clarification) |
| Z-004 | OCI token flow (`WWW-Authenticate` / bearer) | todo | D-003 | `docker login` works end to end; scopes derived from bindings |
| Z-005 | **Permission vocabulary as typed constants** | done | D-018 ✓ | `internal/authz`: the 30 ADR 0002 verbs as typed constants with `AllVerbs`/`ParseVerb(s)`, closed set (every unknown verb reported at once). `internal/authz/verbtest` implements the §9 enumeration mechanism: tests mark what they exercise with `verbtest.Positive/Negative`, and the check reads those marks back out of the repository's test sources — a registry could not work, since each package's tests are a separate process. The allowlist of unwired verbs is a ratchet: a verb that gains tests fails until its entry is removed, so it can only shrink. All 30 are allowlisted today, each naming the task that will wire it. Mechanism unit-tested against fixture repositories. Coverage 96.1% overall; CI green (run 33675768033) |
| Z-006 | **Role model + built-in roles** | done | D-017 ✓ | `internal/authz/roles.go`: the six ADR 0001 built-ins, `NewRole` for custom ones (canonical: sorted, deduplicated, vocabulary-checked; no verb a custom role cannot hold). `admin`, `operator` and `auditor` are *derived* from the vocabulary rather than listed — ADR 0001 words them as "every verb", "everything except user and role administration", "every read verb", so a hand-written list would answer a different question the day a verb is added. Built-in immutability is already enforced by the store (F-005b). **Deviation:** the plan's "migration seeding built-ins" is deferred to Z-014 — a seeder must import both `authz` and `meta`, which Z-009 forbids inside `authz`, and hand-writing the verb sets into two engines' SQL would make a third copy of the vocabulary that ADR 0002 says must have one. Z-014 seeds from `authz.BuiltinRoles()`. CI green (run 33730752671) |
| Z-007 | **Binding model + repository pattern matching** | done | D-017 ✓, Q20 ✓ | `internal/authz/{scope,scope_sql,binding}.go`: the four-form grammar (`system` \| `*` \| exact \| trailing `/*`) as one validator, one matcher, and one filter compiler for the query layer; `Resource` is a struct so the `system` keyword and a repository named `system` cannot be confused, and its zero value matches nothing. Scope patterns validate against the repository-name grammar, now in the leaf package `internal/reponame` (new — authz cannot import `repo` under Z-009, and the registry needs the same rule in Phase 3). Decision made here: the whole `system` prefix is reserved, so `system/*` is refused rather than silently meaning a repository directory — a binding written that way by somebody meaning the global scope would grant nothing while looking like it granted everything; C-016 must refuse the matching repository names. Three fuzz targets green (`FuzzParseScope`, `FuzzScopeMatches`, `FuzzScopeMatcherAgreesWithSQL` — 1.6M+ execs, well past the 10k the plan asks for), plus `FuzzValidate` on the name grammar; the differential test runs the query layer's own predicate through SQLite and also checks `meta.ScopeFilter`, so all three readings of a pattern agree. Coverage 100% of both packages, 96.2% overall; CI green (run 33729537147) |
| Z-008 | **`authz.Decide` pure decision function** | done | Z-005 ✓, Z-006 ✓, Z-007 ✓ | `internal/authz/decide.go`: `Decide(bindings, verb, resource) → Decision{Allowed, Verb, Resource, Matched}`. Pure — the caller resolves the subject to its effective bindings first (group expansion and the disabled check happen at fetch time), so the function sees only values. `Matched` lists every contributing binding, which makes the explainer (Z-013) this same call rendered differently rather than a second implementation that can drift; `Decision.String()` is the audit line. A verb outside the vocabulary is refused before any binding is consulted, so a row edited in the database cannot invent a permission. Five fuzzed properties: soundness/completeness against the definition, monotonicity (adding a binding never revokes), irrelevant-binding invariance, order independence (same answer *and* same explanation), and scope disjointness (repository bindings never reach `system`, and vice versa). No verbtest marks added: Decide is verb-agnostic, and marking from here would let a verb pass §9 without anything enforcing it. CI green (run 33730752671) |
| Z-009 | **Import-boundary test for `internal/authz`** | done | Z-008 ✓ | `internal/archtest`: a generic allowlist checker over one `go list -deps -json` call, with six rules — authz reaches no storage package and no I/O package, the ADR 0009 cache↮gc/policy wall in both directions, and direct-import quarantines for Trivy (ADR 0017) and the AEAD primitives (ADR 0016). Transitive vs direct modes are distinguished because a transitive quarantine would flag `cmd/trove`'s own wiring, which must link the adapter. Non-test deps only, and a test pins that: `authz`'s external test imports `meta`/`sqlutil` for the differential scope test, and counting test deps would flag the very test that keeps the two matchers honest. Failures print the import chain. Verified by injecting a real violation into `internal/authz`, not only by the synthetic fixture module. Each rule is also fed a graph that breaks it, so a mistyped pattern cannot leave a rule silently dead. Coverage 99.2%. **Also fixes the coverage gate**: its `*test/` glob matched `internal/archtest` and silently dropped it from the denominator — harnesses are now named (`metatest`, `blobtest`, `verbtest`), §9 amended, with self-test cases both ways. CI green (run 33731147987) |
| Z-010 | **Handler-level enforcement middleware** | todo | Z-008 | Enforced at token mint *and* request time |
| Z-011 | **Route-table guard test (fail closed)** | todo | Z-010 | Walks every route; fails if any lacks an explicit permission check |
| Z-012 | **Permission-filtered query layer** | todo | D-019 | Catalog, tags, search, events, metrics all filter in the query, not the handler |
| Z-013 | **Effective-permission explainer** (CLI + API) | todo | Z-008 | Returns decision *and* every contributing binding |
| Z-014 | Admin bootstrap + forced first-login rotation | todo | Z-002, Z-006 ✓ | Generated password printed once; no default credential. **Also seeds the built-in roles** from `authz.BuiltinRoles()`, idempotently (moved here from Z-006 — see that row) |
| Z-015 | Self-lockout prevention | todo | Z-007 | Last `role:write`@system binding cannot be removed; clear error |
| Z-016 | `authz.denied` + `role.changed` events and metrics | todo | Z-010, E-001 | Denials counted by verb; role changes audited before/after |
| Z-018 | **Disclosure adversarial suite** | todo | D-019, Z-012 | Unreadable repo absent from catalog, search, tag list, pagination counts, events, metric labels, group resolution |
| Z-019 | **Privilege-escalation adversarial suite** | todo | Z-010 | Token replay post-revocation; `repo:write`↛`repo:delete`; `policy:write`↛`policy:apply`; `proxy:write`↛`proxy:credentials` |
| Z-020 | UI session auth: browser login, sessions, CSRF | todo | D-003, D-020 | Separate from the OCI token flow; CSRF + session-fixation tested; rate-limited |

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
