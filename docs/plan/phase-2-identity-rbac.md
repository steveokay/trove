# Phase 2 — Identity and RBAC: task specs

ADRs: 0001 (RBAC), 0002 (vocabulary), 0003 (disclosure), 0004 (authn), 0016 (secrets).

Parallelization: track A (authn: Z-001→Z-004, Z-020) and track B (authz: Z-005→Z-009)
are independent after F-005/F-006. Z-010+ joins them and is serial. Z-018/Z-019 are
living suites started here and extended by later phases.

---

## Z-001 Subject model
- **Deps:** D-003 ✓, F-006
- **Files:** `internal/authn/{subject.go,anonymous.go}` + tests
- **Do:** `Subject{ID, Kind(user|robot|anonymous), Name, Disabled}`. Exactly one
  resolution path: request credentials → Subject; absent credentials → the anonymous
  Subject (a real stored row seeded by migration). No nil-subject branch anywhere.
- **Accept:** All three kinds flow through one code path; disabled subjects fail
  authn with a distinct sentinel.
- **Test:** Table over kinds; anonymous row seeded exactly once (idempotent migration).

## Z-002 Users + Argon2id credentials
- **Deps:** Z-001
- **Files:** `internal/authn/{password.go,ratelimit.go}` + tests
- **Do:** `x/crypto/argon2` id-variant; per-hash parameter record (ADR 0004) so
  params can rise later; `subtle.ConstantTimeCompare` on digests. Token-bucket rate
  limiter per source IP and per account (in-memory, ADR 0018 seam noted).
- **Accept:** Hash upgrade path proven (old-params hash verifies, then re-hashes);
  brute-force test hits the limiter, legitimate login after cooldown succeeds.
- **Test:** Known-vector tests; param-upgrade table; limiter clock-injected tests.

## Z-003 Robot accounts
- **Deps:** Z-001, F-003 (key loading)
- **Files:** `internal/secretbox/secretbox.go` (ADR 0016 — created here, reused by
  C-003/E-002), `internal/authn/robot.go` + tests
- **Do:** `trove_r_<id>_<random>` secrets, HMAC-SHA-256 digests keyed by the secrets
  key, mandatory expiry (default 90 d), single active secret, revocation deletes the
  digest. secretbox implements the `v1:<key-id>:` format with AAD binding.
- **Accept:** Revoked robot fails on next use (not next mint); expired robot fails;
  secret shown exactly once.
- **Test:** secretbox round-trip + wrong-AAD + multi-key decrypt tests; robot
  lifecycle table; clock-injected expiry.

## Z-004 OCI token flow
- **Deps:** Z-002, Z-003, Z-008
- **Files:** `internal/authn/token/{jwt.go,mint.go}`, `internal/server/token_handler.go`
- **Do:** ADR 0004: Ed25519 JWT (`golang-jwt/jwt/v5`), 5 m TTL clamped 1–60 m;
  `WWW-Authenticate: Bearer realm=…` challenge on `/v2/`; requested scopes ∩
  effective permissions at mint (calls Decide); anonymous minting supported.
- **Accept:** `docker login` + push/pull green in the integration harness; scope
  narrowing proven (request wide, receive narrow).
- **Test:** JWT vector tests (alg confusion rejected: only EdDSA accepted); challenge
  golden test; integration: docker/oras against a dev server.

## Z-005 Permission vocabulary constants
- **Deps:** D-018 ✓
- **Files:** `internal/authz/verbs.go`, `internal/authz/verbs_test.go`
- **Do:** The 33 ADR 0002 verbs as typed constants + `AllVerbs()`. The enumeration
  test (§9) walks `AllVerbs()` and fails unless a registry (populated by other
  packages' tests via a build-tag-free registration helper) records ≥1 positive and
  ≥1 negative test per verb — implemented as a generated checklist file asserted in
  CI once handlers exist; starts as a stub failing for unwired verbs with an
  explicit allowlist that must shrink each phase.
- **Accept:** Closed set; adding a verb without ADR reference fails a lint test
  (comment convention checked).
- **Test:** Enumeration mechanism itself unit-tested.

## Z-006 Role model + built-ins
- **Deps:** D-017 ✓, F-006
- **Files:** `internal/authz/roles.go`, migration seeding built-ins
- **Do:** ADR 0001 built-ins seeded read-only (`builtin` flag; delete/update
  rejected in store). Custom roles store expanded verb lists (ADR 0002 — no
  wildcards at rest).
- **Accept:** Built-in deletion/modification fails with typed error; `anonymous-reader`
  seeded unbound.
- **Test:** Seed idempotency; built-in immutability; role CRUD via store suite.

## Z-007 Binding model + scope grammar
- **Deps:** D-017 ✓, F-006
- **Files:** `internal/authz/{scope.go,scope_sql.go,binding.go}` + fuzz targets
- **Do:** ADR 0001 grammar: `system` | `*` | exact | trailing `/*`. One validator,
  one matcher, one SQL-predicate compiler (`scope_sql.go`) shared with Z-012.
  Patterns validated against the repo-name allowlist regex at write time.
- **Accept:** Grammar total (every input either valid or a typed error); matcher
  and SQL compiler agree on 10k fuzz-generated (pattern, name) pairs.
- **Test:** `FuzzScopePattern`, `FuzzScopeMatch`, differential fuzz matcher-vs-SQL
  (against in-memory SQLite); traversal/overlap corpus from §9.

## Z-008 `authz.Decide`
- **Deps:** Z-005, Z-006, Z-007
- **Files:** `internal/authz/decide.go` + property tests
- **Do:** Pure `Decide(subject, bindings, verb, resource) → Decision{Allowed,
  Matched []Binding}` per ADR 0001. Group expansion is caller-side; document with
  a `FetchBindings` helper signature (implemented in Z-010).
- **Accept:** No I/O imports (enforced by Z-009); Decision lists every matched
  binding (explainer contract).
- **Test:** Property tests: additive monotonicity (adding a binding never revokes),
  irrelevant-binding invariance, scope-match soundness vs Z-007 matcher; exhaustive
  table for `system` vs repo resources.

## Z-009 Import-boundary test
- **Deps:** Z-008
- **Files:** `internal/archtest/archtest.go`, `internal/archtest/boundaries_test.go`
- **Do:** Generic allowlist checker over `go list -deps`. Rules: authz imports no
  registry/repo/storage; cache↮gc/policy (ADR 0009 wall 3); only `internal/scan/trivy`
  imports trivy (ADR 0017); only secretbox imports AEAD primitives (ADR 0016).
- **Accept:** Violations fail with the offending import chain printed.
- **Test:** Self-test with a synthetic violation fixture module.

## Z-010 Handler enforcement middleware
- **Deps:** Z-008, F-004
- **Files:** `internal/server/{authz_middleware.go,bindings.go}`
- **Do:** Route registration requires a verb (or explicit `AnonymousAllowed` marker
  — ADR 0015). Middleware: resolve subject → fetch bindings (subject + groups, one
  query) → Decide → 401/404/403 per ADR 0003 matrix. Token mint (Z-004) uses the
  same fetch+Decide.
- **Accept:** No route registrable without a verb (compile-level: the register
  function signature demands it).
- **Test:** Matrix tests over (anonymous/authed) × (no-read/read-only/write) ×
  (read/write routes) asserting exact status codes and bodies per ADR 0003.

## Z-011 Route-table guard test
- **Deps:** Z-010
- **Files:** `internal/server/routes_guard_test.go`
- **Do:** Walk the chi route tree; every route must carry a verb or be on the
  frozen `AnonymousAllowed` list (`/healthz`, token endpoint, UI static, `/readyz`).
  List changes require editing the test (reviewable).
- **Accept:** Adding an unguarded route fails CI with the route named.
- **Test:** Self-test: register a guardless route in a fixture server, assert failure.

## Z-012 Permission-filtered query layer
- **Deps:** D-019 ✓, Z-007, F-006/F-007
- **Files:** `internal/meta/*/queries.go` (listing methods), `internal/authz/scope_sql.go`
- **Do:** Listing/search/count methods accept `[]ScopePredicate` compiled from the
  caller's bindings; the WHERE clause is built by `scope_sql.go` only. No
  fetch-then-filter anywhere (grep-lint: listing handlers may not call unfiltered
  listing methods — enforced by making unfiltered variants unexported).
- **Accept:** Catalog/tags/search/events/metrics queries all take predicates;
  pagination cursors stable under filtering.
- **Test:** metatest additions: fixtures with mixed visibility, assert exact result
  sets + counts on both engines; cursor-stability property test.

## Z-013 Effective-permission explainer
- **Deps:** Z-008, (API surface: D-020 ✓)
- **Files:** `internal/authz/explain.go`, `internal/server/api_auth_explain.go`,
  `cmd/trove/auth_explain.go`
- **Do:** `GET /api/v1/auth/explain?subject=&verb=&resource=` returning Decision +
  matched bindings (+ group provenance). Self-explain allowed for any subject;
  explaining others requires `user:read` (ADR 0003 surface 8). CLI formats only.
- **Accept:** API/CLI/UI single source (the endpoint); output names every
  contributing binding and the group it came through.
- **Test:** Golden response; authz matrix on the endpoint itself; CLI snapshot test.

## Z-014 Admin bootstrap
- **Deps:** Z-002
- **Files:** `internal/authn/bootstrap.go`, wiring in `serve`
- **Do:** First run (empty subjects table): create `admin`, bind `admin`@`system`+`*`,
  print generated password once to stdout, set `must_rotate`. Never a default
  credential; re-run is a no-op.
- **Accept:** Second boot creates nothing; login before rotation forces the
  rotation flow on both API and UI.
- **Test:** First/second-boot table; must_rotate gate on every authed route except
  the rotation endpoint.

## Z-015 Self-lockout prevention
- **Deps:** Z-007
- **Files:** `internal/authz/lockout.go` (called from binding delete/update paths)
- **Do:** Refuse removing/narrowing the last binding that grants `role:write` at
  `system` (counting group-derived grants). Typed error surfaced verbatim by API.
- **Accept:** The exact §5 scenario fails with a clear message; removing a
  *redundant* admin binding succeeds.
- **Test:** Adversarial table incl. group-membership removal as the removal vector
  and two-admins-remove-one success case.

## Z-016 Authz events and metrics
- **Deps:** Z-010, E-001
- **Files:** `internal/server/authz_middleware.go` (emit), `internal/metrics/authz.go`
- **Do:** Every deny → `authz.denied` event (subject, verb, resource) + counter by
  verb. Role/binding mutations → `role.changed` with before/after (ADR 0012 payloads).
- **Accept:** Deny spike visible in metrics; role change audit shows diff.
- **Test:** Middleware emit tests with fake bus; payload golden tests.

## Z-018 Disclosure adversarial suite (living)
- **Deps:** D-019 ✓, Z-012
- **Files:** `test/disclosure/suite_test.go`
- **Do:** One suite, fixture registry with visible+hidden repos, walked by every
  surface as it lands (ADR 0003's ten surfaces as subtests; unimplemented surfaces
  skipped with a tracked skip-list that must shrink). Asserts byte-identical 404s
  (absent vs hidden).
- **Accept:** Suite exists with catalog/tags/search wired; skip-list mechanism
  fails CI if a surface ships without removing its skip.
- **Test:** This *is* a test task; its own fixtures get sanity checks.

## Z-019 Privilege-escalation adversarial suite (living)
- **Deps:** Z-010
- **Files:** `test/privesc/suite_test.go`
- **Do:** Scenarios from §9: token replay after binding revocation (must fail at
  handler despite valid JWT); robot crossing repos; each ADR 0002 non-implication
  (`repo:write`↛`repo:delete`, `policy:write`↛`policy:apply`,
  `proxy:write`↛`proxy:credentials`, `repo:configure`↛`repo:write`).
- **Accept:** Every non-implication in ADR 0002 has a subtest here (cross-checked
  against the Z-005 registry).
- **Test:** Suite task; fixtures shared with Z-018.

## Z-020 UI session auth
- **Deps:** Z-002, D-020 ✓
- **Files:** `internal/authn/session.go`, `internal/server/{session_handlers.go,csrf.go}`
- **Do:** ADR 0004: opaque 256-bit cookie sessions (HttpOnly/Secure/SameSite=Lax),
  idle 24 h / absolute 7 d, CSRF double-submit on cookie-authed mutations only,
  invalidation on password change, login rate-limited via Z-002's limiter.
- **Accept:** Bearer-auth requests bypass CSRF; cookie-auth mutation without token
  is 403; session fixation impossible (ID rotates at login).
- **Test:** CSRF matrix (cookie/bearer × safe/mutating); fixation test; expiry
  clock-injected tests.
