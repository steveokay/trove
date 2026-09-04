# Phase 1 — completion notes

The full completion write-ups for phase 1 tasks, moved verbatim out of the
`status.md` acceptance column (2026-09-04) so the table stays scannable.
`status.md` remains the source of truth for task *status*; each row links here.
One section per task, in board order, frozen at the moment the task was marked
done — these are records, not living documents.

## F-003 — Config load/validate/defaults

`internal/config`: flags > env > file > defaults with per-key source tracking; all problems reported at once naming key + layer; secrets redacted with no unredacted renderer; `trove.example.yaml` + `docs/operator/configuration.md`, drift-tested against defaults. Coverage 99.7%; CI green (run 33550551595)

## F-004 — Structured logging + graceful shutdown

`internal/server`: slog JSON/text by config, per-request IDs echoed in `Trove-Request-Id` and carried on a context logger, access log levelled by status; graceful drain proven by an in-flight-request test; ADR 0018 data-dir lock (flock/Windows `CreateFile`) with second-start refusal tested; `trove serve` wired with SIGTERM/SIGINT handling. Coverage 97.8%; CI green (run 33551971007)

## F-006 — SQLite impl + migrations

`internal/meta/sqlite` on `modernc.org/sqlite`: WAL, foreign keys verified at open, single-writer pool, embedded forward-only migrations applied per-step in a transaction; `-no-auto-migrate` refuses and names what is pending, a failed step rolls back and names its version. Contract suite green unmodified (155 subtests) plus 179 implementation subtests (dead-database and dropped-table failure tables, migration runner). Adds an upload-session cascade case to the contract; `memory` updated to match. Go directive raised to 1.25 — the driver requires it. Coverage 96.4% package, 97.9% overall; CI green (run 33618686319), lint now builds golangci-lint from source so the pin survives the toolchain bump

## F-007 — Postgres impl

`internal/meta/postgres` on `jackc/pgx/v5`: the contract suite green unmodified against a testcontainers `postgres:17-alpine`, plus a schema-parity test holding both engines to the same columns and nullability across all 18 tables (verified to fail on injected drift). Migration runner extracted to `internal/meta/migrate` and the SQL plumbing — including the single scope→SQL compiler both engines filter with — to `internal/meta/sqlutil`. Unique-violation → `ErrConflict` mapping covers the concurrent-writer race SQLite cannot have, tested with racing creates. Every Postgres `TEXT` column is `COLLATE "C"` so listings and cursors order identically on both engines; test databases are created with an ICU collation so that guarantee is provable, and removing it fails the cross-engine ordering test. Coverage 97.3% package, 97.8% overall; CI green (run 33621319625)

## F-008 — `blob.Store` interface + contract test suite

`internal/blob`: Store/Uploader/UploadSession per ADR 0007; strict digest parser (allowlisted algorithm, exact length, lowercase hex only) as the traversal gate, with `FuzzParseDigest` asserting nothing accepted can carry a separator, `..`, or a null; shared `Verifier`/`Copy` for writes and a `VerifiedReader` that withholds a blob's last byte until the hash checks out, so a corrupt read fails the client's own digest check instead of returning bad bytes with a clean EOF. `blobtest` 24-case contract suite (mismatch leaves nothing, truncation, dropped connection, idempotent and concurrent Put, Walk during writes / on error / on cancel, resume, commit mismatch and invalid digest, cancellation). Adds `internal/blob/memory` — not in the plan's file list, but the suite is unproven without an implementation and higher layers need the test double, as `meta/memory` is for F-005. 179 subtests. Coverage 100% of both non-harness packages, 98.0% overall; CI green (run 33630695310)

## F-009 — Filesystem blob driver

`internal/blob/fs`: ADR 0007 layout (`blobs/<algo>/<first-2>/<hex>`, hex-keyed so no colon reaches a Windows path), staging → fsync → chmod 0444 → rename → parent-dir fsync, so a blob path is either absent or complete. Read mismatch quarantines the bytes as evidence and fires the injected `CorruptHook` (the `blob.corrupt` source). Upload sessions keep their state on disk — file presence is existence, size is the offset — so a session survives a restart, proven by a test that resumes through a second store over the same root. Root confinement as the second wall, tested directly, plus an upload-id allowlist for the other caller-supplied path component. Adversarial: leftover staging file after a simulated crash, corrupt blob quarantined and withheld, foreign files ignored by Walk, and permission-injected failures for Put/Delete/Stat/Get/Walk/Commit/quarantine that assert a broken disk never reads as "absent". Coverage 86.6% package (remaining branches are unreachable syscall failures); CI green (run 33666830276) at 97.2% overall — higher than the 96.8% measured on Windows, where the permission-injected cases skip

## F-010 — S3-compatible blob driver

`internal/blob/s3` on `minio-go/v7`: ADR 0007 key scheme under a configurable prefix (the hosted/cache separation when they share a bucket), writes through a multipart upload completed only after the digest verifies — the object-store equivalent of stage-then-rename, so an interrupted or mismatched push never becomes an object. Sessions are chunk objects plus a marker, with offset and existence derived from the bucket, so a session survives a restart. Quarantine is copy-then-delete (no rename in S3). Presigned-redirect mode is off by default and covered by an opt-in test that fetches the URL. Contract suite green against MinIO in testcontainers; adversarial: service stopped mid-upload leaves nothing visible, a vanished bucket never reads as "blob absent". Fixed a real leak found on the way: abandoning a minio listing blocks its goroutine forever on a send nobody reads, exhausting the connection pool — both listings now drain. Adds `blob.Redirector`/`ErrNoRedirect` and moves the upload-id gate into `internal/blob` so both drivers share it. Coverage 85.4% package (rest are unreachable network failures); CI green (run 33673939068) at 96.4% overall

