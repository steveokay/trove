# Phase 8 — UI, packaging, docs: task specs

ADRs: 0019 (UI stack), 0015 (API contract), 0004 (sessions). UI tasks consume only
`/api/v1` — any missing endpoint is an API gap fixed in the owning phase first.

Parallelization: U-001/U-002 serial; U-003–U-009 fan out per screen (one agent per
screen area); U-010 sweeps last. PK tasks independent of U. DOC tasks last.

---

## U-001 UI scaffold
- **Deps:** D-005 ✓
- **Files:** `web/{package.json,pnpm-lock.yaml,vite.config.ts,src/…}`,
  `web/embed.go`, Makefile `ui-build`/`ui-dev`, CI job
- **Do:** ADR 0019: Svelte 5 + Vite + TS static SPA; hash router (~50 lines,
  in-house); typed API client (hand-written against `docs/api/openapi.yaml`);
  CSS-custom-property tokens, dark reference theme; noscript block; pnpm offline
  install in CI (cached store) + `make ui-vendor`.
- **Accept:** `pnpm install --offline && pnpm build` green in CI with network
  disabled for the step; `go build` embeds `web/dist`; served at `/`.
- **Test:** Vitest setup with router + API-client unit tests; CI offline-build
  proof; embed smoke test in Go (asset served, correct content-type).

## U-002 Effective-permissions gating
- **Deps:** U-001, Z-013
- **Files:** `web/src/lib/{permissions.ts,nav.ts}`, login/session flow
- **Do:** Session login (Z-020 endpoints, CSRF wiring in the API client);
  fetch effective permissions (batched explain variant:
  `GET /api/v1/auth/permissions` returning verb→scopes map — small API addition
  owned by Z-013's package); nav sections + action buttons render only when
  usable; 403/404 responses still handled gracefully (server remains authority).
- **Accept:** `developer`-role fixture sees no admin nav; forced-URL navigation
  to a hidden screen shows the API's error, not a crash.
- **Test:** Vitest permission-gate table per nav item; Playwright: login →
  role-scoped nav assertions (fixtures: admin, developer, auditor).

## U-003 Repo/tag/manifest browsing
- **Deps:** U-002, R-003
- **Files:** `web/src/routes/repositories/…`
- **Do:** Dense tables per ADR 0019: repo list (type, storage, quota bar), tag
  table (sort/filter, immutable/protected badges, gate status), manifest detail
  (media type, platforms, layers, referrer tree, copyable digests everywhere),
  cursor pagination mapped to API.
- **Accept:** Keyboard navigable; digests copy on click with feedback; empty
  states teach (quickstart snippet with real hostname).
- **Test:** Vitest table components (sort/filter/pagination); Playwright browse
  flow against seeded server; axe pass on each screen.

## U-004 SBOM + CVE report views
- **Deps:** U-002, S-006
- **Files:** `web/src/routes/vulnerabilities/…`
- **Do:** Repo/instance rollup dashboards (severity × fixability), per-manifest
  finding table (filter severity/fixability/suppressed), suppression management
  (S-007 API), SBOM referrer viewer (raw + parsed package list), scan status +
  DB version banner.
- **Accept:** Filter by severity and fixability per criteria; suppression
  create/expire flows work.
- **Test:** Vitest filter logic; Playwright CVE-drilldown flow; axe pass.

## U-005 Policy editor + dry-run preview
- **Deps:** U-002, P-004
- **Files:** `web/src/routes/policies/…`
- **Do:** Rule builder for retention (priority-ordered list UI), tag policy and
  gating editors; plan preview renders the P-004 Plan (grouped by rule, referrer
  subtrees expandable, byte estimate); apply button (only with `policy:apply`)
  posts plan hash and shows per-entry results.
- **Accept:** The plan shown is byte-what-apply-uses (hash displayed); equal-
  priority conflict surfaced as validation error.
- **Test:** Vitest plan-rendering + editor validation; Playwright dry-run→apply
  flow on fixtures; axe pass.

## U-006 Proxy/group management
- **Deps:** U-002, C-011
- **Files:** `web/src/routes/repositories/settings/…`
- **Do:** Proxy settings (upstream, TTLs, routing rules, credential set/unset —
  never display, ADR 0016), health panel (reachability, backoff, rate-limit
  headroom, hit ratio from E-005 data via API), group member ordering
  (drag/keyboard reorder posting explicit order), preset enable flow.
- **Accept:** Member order changes are explicit saves with confirmation; C-014
  presets enable in two clicks.
- **Test:** Vitest ordering component (keyboard path included); Playwright proxy
  create→enable-preset flow; axe pass.

## U-007 Role, binding, user admin
- **Deps:** U-002, Z-013
- **Files:** `web/src/routes/access/…`
- **Do:** Users/robots/groups CRUD (robot secret shown once with copy+confirm),
  role editor (verb picker grouped per ADR 0002 tables; built-ins read-only),
  binding editor (principal, role, scope with grammar validation feedback),
  inline explainer panel (Z-013: "why does alice have repo:write here?").
- **Accept:** Explainer inline per criteria; self-lockout attempt shows Z-015's
  error verbatim; built-ins visibly immutable.
- **Test:** Vitest scope-input validation vs grammar; Playwright: create role →
  bind → explain flow; axe pass.

## U-008 Webhook management
- **Deps:** U-002, E-003
- **Files:** `web/src/routes/webhooks/…`
- **Do:** Subscription CRUD (secret once, target validation errors surfaced),
  delivery history with state filters, dead-letter inspection (response
  code/body) + replay button, signature-verification doc snippet embedded.
- **Accept:** Dead-letter replay round-trips; `skipped-authz` state explained in
  UI copy.
- **Test:** Vitest state-badge/filter logic; Playwright create→deliver(fixture)→
  inspect flow; axe pass.

## U-009 Audit log viewer
- **Deps:** U-002, E-009
- **Files:** `web/src/routes/audit/…`
- **Do:** Filterable table (actor/verb/resource/outcome/time), before/after diff
  viewer for role changes, NDJSON export button; only rendered with `audit:read`.
- **Accept:** Filter by actor, verb, resource, outcome per criteria; diffs
  readable.
- **Test:** Vitest filter/diff components; Playwright filtered-query flow; axe.

## U-010 Accessibility + dark mode pass
- **Deps:** U-003..U-009
- **Files:** sweep across `web/src`
- **Do:** Systematic pass: focus order, skip link, table semantics
  (scope/headers), WCAG AA contrast in both themes (token-level check script),
  reduced-motion, theme toggle persistence; axe assertions become CI-blocking
  for every route (they were advisory until now).
- **Accept:** axe zero violations across all routes in both themes; full
  keyboard walkthrough recorded in the PR.
- **Test:** Playwright axe matrix (routes × themes); contrast token script test.

## PK-001 systemd unit + `.deb`/`.rpm`
- **Deps:** F-001
- **Files:** `packaging/{systemd/trove.service,nfpm.yaml}`, CI release job
- **Do:** nfpm-built packages: binary, unit (hardening: DynamicUser=no,
  dedicated `trove` user, ProtectSystem=strict, ReadWritePaths=data dir),
  default config at `/etc/trove/trove.yaml`, data at `/var/lib/trove`;
  postinstall creates user; zero-edit happy path (serve on :5000 HTTP until TLS
  configured — printed loudly).
- **Accept:** `apt install ./trove.deb && systemctl start trove` works on a
  clean Debian container.
- **Test:** Container-based install test in CI (deb + rpm); unit-file lint
  (systemd-analyze verify).

## PK-002 `docker-compose.yml`
- **Deps:** F-001
- **Files:** `packaging/docker/{Dockerfile,docker-compose.yml}`, image release job
- **Do:** Distroless-style minimal image (static binary, nonroot), compose with
  volume for data dir, optional commented Postgres/MinIO blocks; zero-edit up.
- **Accept:** `docker compose up` → working registry; image published on release.
- **Test:** CI compose-up smoke (push/pull against it); image scan of our own
  image in CI (dogfood note).

## PK-003 Helm chart
- **Deps:** F-001
- **Files:** `packaging/helm/trove/…`
- **Do:** Single-replica StatefulSet (ADR 0018 — replicas>1 rejected via values
  schema), PVC, Service, optional Ingress, probes wired to E-007, secrets for
  keys, values schema validated; zero-edit install with defaults.
- **Accept:** `helm install trove ./packaging/helm/trove` on kind → working
  registry; `helm lint` + schema tests green.
- **Test:** CI kind-based install + push/pull smoke; values matrix template
  tests (helm-unittest).

## PK-004 TLS: ACME + operator certs
- **Deps:** F-003
- **Files:** `internal/server/tls.go`
- **Do:** One key switches modes (`tls.mode: acme|manual|off`): ACME via
  `golang.org/x/crypto/acme/autocert` (HTTP-01, cache dir under data), manual
  cert+key paths with reload on SIGHUP; `off` prints a loud warning. Registry
  clients require TLS in practice — docs make `off` clearly dev-only.
- **Accept:** All three modes boot; manual certs hot-reload; ACME path
  integration-tested against pebble (letsencrypt test server) container.
- **Test:** Mode matrix; pebble integration; SIGHUP reload test.

## PK-005 Release pipeline
- **Deps:** F-001, PK-001..PK-003
- **Files:** `.github/workflows/release.yml`, `scripts/release-check.sh`
- **Do:** Tag-triggered: cross-compile linux/amd64, linux/arm64, darwin/arm64
  (CGO off), UI built once and embedded in all, checksums + SBOM of our own
  binary (syft), packages + image + chart published, release notes from
  conventional commits.
- **Accept:** A tagged release produces every artifact with checksums; darwin
  binary runs `trove version` (CI on macos runner).
- **Test:** Release dry-run job on main; checksum verification step;
  version-stamp assertion per artifact.

## PK-006 `trove migrate --from`
- **Deps:** Q17 ✓, C-002 (client reuse)
- **Files:** `cmd/trove/migrate.go`, `internal/migrate/…`
- **Do:** Generic distribution-spec importer per Q17: source URL + creds, repo
  list from `_catalog` or explicit file, pulls manifests/blobs/referrers by
  digest (reusing the upstream client), writes through normal hosted paths
  (quota-checked, scanned per policy), resumable via journal table, pre-flight
  size estimate vs quota (ADR 0014).
- **Accept:** Migrates a seeded `registry:2` (multi-arch + referrers) fully;
  interrupt+resume completes without duplicates; runs via API task or
  `--offline`-less CLI (it needs the server running — it is an API-driven task).
- **Test:** Integration vs registry:2 fixture incl. kill-resume; pre-flight
  estimate accuracy test; referrer-preservation assertion.

## DOC-001 Quickstart
- **Deps:** PK-001, PK-004, C-005, Z-014
- **Files:** `docs/quickstart.md`
- **Do:** The north-star walkthrough: one VM, one command (`.deb` + systemd or
  compose), TLS via ACME, bootstrap admin, enable Docker Hub preset, create a
  hosted repo + developer role + binding, `docker login/push/pull` through a
  group. Target: under five minutes, timed.
- **Accept:** Executed end-to-end on a clean VM by following the doc verbatim
  (recorded in PR); every command copy-pasteable.
- **Test:** CI job scripts the quickstart against a fresh container (minus ACME,
  pebble-substituted) — the doc's command blocks are extracted and executed
  (doc-as-test).

## DOC-002 Operator guide
- **Deps:** P-007, E-008, PK-004
- **Files:** `docs/operator/{backup-restore.md,upgrade.md,gc.md,maintenance.md,
  sizing.md,encryption.md}`
- **Do:** Backup (read-only mode → snapshot DB + blobs + keys — ADR 0016 key
  material callout), restore + `trove verify --offline` validation, upgrade
  (migrations, `--no-auto-migrate` staging), GC/retention operations, sizing
  (scan memory, ADR 0017), encryption-at-rest recipes (Q13: LUKS/ZFS/SSE).
- **Accept:** Restore path actually tested: scripted backup→destroy→restore→
  verify in CI (doc-as-test like DOC-001).
- **Test:** The scripted restore CI job; doc lint (links, extracted commands run).

## DOC-003 RBAC guide
- **Deps:** Z-013
- **Files:** `docs/operator/rbac.md`
- **Do:** Concepts (ADR 0001 digested for operators), worked setups: 3-role
  small team, per-team scoped setup (~20 users with groups), robot accounts for
  CI, anonymous read enablement; troubleshooting with `trove auth explain`;
  naming-discipline note (no carve-outs — ADR 0001 consequence); audit-read
  visibility warning (ADR 0003).
- **Accept:** Worked examples for 3-role and per-team setups per criteria; every
  example's commands executable.
- **Test:** Doc-as-test: example command blocks executed against a fixture
  server; explain outputs in the doc regenerated from that run (drift-checked).
