# Phase 1 — Foundations: task specs

Board: `status.md`. Format per task: **Deps** · **Packages/files** · **Do** (implementation
guidance, ADR references) · **Accept** (expanded criteria) · **Test** (plan).

Parallelization: F-001→F-002 are serial. After F-003/F-004, the two interface tracks
(F-005–F-007 meta, F-008–F-010 blob) are independent — one agent each, per §2.

---

## F-001 Repo scaffold, module, Makefile, CI skeleton
- **Deps:** D-001 ✓, Q25 ✓
- **Files:** `go.mod` (`github.com/steveokay/trove`, go 1.23), `Makefile`,
  `.github/workflows/ci.yml`, `.golangci.yml`, `cmd/trove/main.go`,
  `internal/version/version.go`, `docs/dev/environment.md`
- **Do:** Create the §3 package directories (empty except doc.go where needed).
  `main.go` wires cobra-style subcommand dispatch (stdlib `flag` + manual dispatch —
  no cobra; keep deps near zero) with `version` implemented. Makefile targets:
  `build test lint cover test-linux ui-build vendor-audit`. `test-linux` (Q25 rev.):
  full suite in `golang:1.x-bookworm` via Docker Desktop — repo bind-mounted,
  `GOCACHE`/`GOMODCACHE` on a named volume, `/var/run/docker.sock` mounted so
  testcontainers works from inside. CI (ubuntu-latest): lint, `go vet`,
  `go test -race -covermode=atomic -coverpkg=./...`. Document the native-Windows +
  container-parity workflow (incl. `runtime.GOOS` skip convention for Unix-only
  tests) in `docs/dev/environment.md`.
- **Accept:** `make build test lint` green natively on Windows and in CI;
  `make test-linux` green via Docker; version stamped via `-ldflags -X`; LICENSE
  already present.
- **Test:** CI run on the PR is the test; `internal/version` unit-tested (table).

## F-002 Coverage gate script
- **Deps:** F-001
- **Files:** `scripts/coverage.sh`, CI step, `docs/dev/testing.md`
- **Do:** Compute line coverage from the merged profile; denominator excludes
  `cmd/*/main.go`, `*_mock.go`, `*.gen.go` (nothing else — §9). Fail under 95.0.
- **Accept:** Gate proven: a scratch branch with an uncovered function fails CI
  (link the red run in the PR, then delete the branch).
- **Test:** The red-run demonstration; shellcheck on the script.

## F-003 Config load/validate/defaults
- **Deps:** F-001
- **Files:** `internal/config/{config.go,load.go,validate.go,redact.go}` + tests,
  `docs/operator/configuration.md`, `trove.example.yaml`
- **Do:** Precedence flags > `TROVE_*` env > YAML file > defaults (§3). Typed struct,
  one `Load(args, lookupEnv, readFile)` entry (injectable for tests). Validation
  errors name the key and the offending source layer. `String()`/dump redacts
  secret-typed fields (`redact:"true"` struct tags). Defaults per ADRs: cache budget
  50 GB, tag TTL 15 m, negative TTL 60 s, gating off, key paths under `<data>/keys`.
- **Accept:** Invalid config refuses startup with actionable error; secrets never in
  dumps; every key documented.
- **Test:** Table-driven precedence matrix (each layer overriding each); fuzz the
  YAML loader; golden test of redacted dump; validation error catalog.

## F-004 Structured logging + graceful shutdown
- **Deps:** F-003
- **Files:** `internal/server/{server.go,shutdown.go}`, `internal/config` glue
- **Do:** `log/slog` JSON (default) or text handler by config; request-scoped logger
  with `trace_id` middleware. `http.Server` with sane timeouts; SIGTERM/SIGINT →
  drain with configurable grace (default 30 s); ADR 0018 lock file acquired before
  listen, released on exit.
- **Accept:** In-flight request completes across SIGTERM in a test; double-start
  against a locked data dir fails fast with the ADR 0018 error.
- **Test:** Shutdown drain test with a slow handler; lock-contention test; log
  output shape golden-tested.

## F-005 `meta.Store` core: repositories + content
- **Deps:** D-006 ✓
- **Scope note (amended 2026-09-01):** ADR 0006's six entity groups are staged
  rather than frozen at once. F-005 lands the harness plus repositories and
  content; F-005b adds identity/authz (needed by Phase 2); the cached-content,
  scan, and ops groups arrive with the phases that consume them, so their
  interfaces are designed against real callers instead of guesses. The suite and
  the in-memory reference implementation grow with each.
- **Files:** `internal/meta/{store.go,types.go,errors.go}`,
  `internal/meta/metatest/suite.go`
- **Do:** Interfaces partitioned by ADR 0006 entity groups (RepoStore,
  ContentStore, CachedContentStore, IdentityStore, ScanStore, OpsStore — composed
  into `Store`). Sentinel errors (`ErrNotFound`, `ErrConflict`, `ErrStale`).
  `metatest.Run(t, factory)` exercises every method incl. transactional claims
  (webhook/scan queues), scope-predicate filtering (compiler from Z-007 arrives
  later — suite takes predicates as opaque WHERE fragments until then), and the
  audit append-only property.
- **Accept:** Suite compiles against a factory; both impls will run it unmodified.
- **Test:** The suite *is* the test plan; add suite self-tests for its fixtures.

## F-006 SQLite implementation + migrations
- **Deps:** F-005
- **Files:** `internal/meta/sqlite/{store.go,migrate.go}`,
  `internal/meta/sqlite/migrations/0001_init.sql…`
- **Do:** `modernc.org/sqlite` (pure Go). WAL mode, foreign keys on, busy timeout.
  Embedded forward-only migrations applied in-transaction on open;
  `--no-auto-migrate` honored (ADR 0006). Single-writer semantics documented.
- **Accept:** Contract suite green; migration failure aborts with version named.
- **Test:** metatest suite; empty→head migration test; crash-mid-migration test
  (transaction rollback leaves prior version).

## F-007 Postgres implementation
- **Deps:** F-005, F-006 (shares migration runner shape)
- **Files:** `internal/meta/postgres/…`, `internal/meta/postgres/migrations/…`
- **Do:** `jackc/pgx/v5`. Same runner, `FOR UPDATE` row claims where ADR 0010/0012
  need them. Head-schema dump-diff check vs SQLite semantic parity (column
  names/nullability table) in the contract suite.
- **Accept:** Same metatest suite green against a testcontainers Postgres in CI.
- **Test:** metatest via testcontainers; schema-parity check.

## F-008 `blob.Store` interface + contract test suite
- **Deps:** D-007 ✓
- **Files:** `internal/blob/{store.go,digest.go,errors.go}`,
  `internal/blob/blobtest/suite.go`
- **Do:** Interface per ADR 0007 (Put/Get/Stat/Delete/Walk + UploadSession).
  `digest.go`: strict parser (algorithm allowlist, exact length, lowercase hex) —
  the traversal gate. VerifiedReader semantics defined here.
- **Accept:** Suite covers: write mismatch leaves nothing; truncated stream;
  resume; concurrent same-digest Put (first wins); Walk during writes; traversal
  strings rejected by parser before any path construction.
- **Test:** The suite + digest parser fuzz target (`FuzzParseDigest`).

## F-009 Filesystem blob driver
- **Deps:** F-008
- **Files:** `internal/blob/fs/{fs.go,upload.go,quarantine.go}`
- **Do:** ADR 0007 layout: two-level fan-out, staging + fsync + rename, 0444
  committed files, quarantine-on-read-mismatch, root confinement (driver refuses
  any path escaping its root — defense-in-depth under ADR 0009 wall 2).
- **Accept:** blobtest green; quarantine path emits `blob.corrupt` via injected
  event hook; correctness target is ext4 (CI / `test-linux`) — permission-bit and
  case-sensitivity subtests skip on win32 per the Q25 revision.
- **Test:** blobtest; crash-between-fsync-and-rename simulation (staging file
  present, blob absent, next Put succeeds); read-mismatch quarantine test with a
  deliberately corrupted file.

## F-010 S3-compatible blob driver
- **Deps:** F-008
- **Files:** `internal/blob/s3/{s3.go,multipart.go}`
- **Do:** `minio-go/v7` (light, Apache-2.0). ADR 0007 key scheme; multipart with
  abort-on-mismatch; optional presigned-redirect mode default-off behind config.
- **Accept:** blobtest green against MinIO testcontainer; redirect mode covered by
  an explicit opt-in test.
- **Test:** blobtest via testcontainers-go MinIO; network-fault injection (kill
  container mid-Put → no partial object visible).
