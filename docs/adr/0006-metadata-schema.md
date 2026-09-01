# ADR 0006 — Metadata schema and migration strategy

- Status: accepted (2026-09-01)
- Task: D-006
- Depends on: ADR 0001 (RBAC), ADR 0004 (authn), ADR 0005 (repository model)

## Context

One `meta.Store` interface, two implementations (SQLite via `modernc.org/sqlite`,
Postgres), one shared contract test suite. The schema must make the hosted/cached
separation structural (§4), keep every listing filterable by binding scope at the
query layer (§5), and survive forward-only auto-migration (§3).

## Decision

### Conventions

- Primary keys: content-addressed rows key on digest; everything else uses ULIDs
  (sortable, no coordination, string-typed in both engines).
- Timestamps: UTC epoch-milliseconds integers (identical semantics across engines;
  no driver-dependent time zone behaviour).
- Portable SQL subset; per-engine DDL only where unavoidable, isolated in the
  migration files. No ORM — hand-written queries behind `meta.Store`.
- JSON columns only for genuinely opaque config payloads (repository config,
  webhook filter spec); anything queried or filtered gets real columns.

### Entity groups (ERD summary)

**Repositories** (ADR 0005)

- `repositories(id, name UNIQUE, type{hosted|proxy|group}, config JSON,
  config_version, created_at, updated_at, deleted_at NULL)`
- `group_members(group_id, member_id, position, required, write_target)` —
  `UNIQUE(group_id, position)`; ties are schema-impossible.
- `repository_config_history(repo_id, version, config JSON, actor, at)` — feeds
  audit and support bundle.

**Hosted content** — and, separately, **cached content**. Two parallel table
families with no shared rows and no shared foreign keys; this is the §4 separation
made structural:

- `manifests(digest PK, repo_name, media_type, artifact_type, subject_digest NULL,
  payload BLOB, size, created_at)` — `subject_digest` indexed: the referrers API is
  one query. `UNIQUE(repo_name, digest)` semantics via composite key.
- `manifest_refs(manifest_digest, child_digest, kind{layer|config|child-manifest})`
  — the GC mark edge set and the Q10 index-child check.
- `tags(repo_name, name, manifest_digest, created_at, updated_at,
  PRIMARY KEY(repo_name, name))`
- `blobs(digest PK, size, created_at)` — hosted blob presence; bytes live in the
  blob store (ADR 0007).
- `upload_sessions(id, repo_name, started_at, last_chunk_at, bytes)` — protects
  in-flight uploads from GC; R-011 reaps stale rows.
- Cached family: `cached_manifests`, `cached_manifest_refs`, `cached_blobs
  (…, last_access_at, proxy_repo)`, `tag_leases(proxy_repo, remainder_and_tag,
  digest, fetched_at, ttl_s, stale)` and `negative_cache(proxy_repo, reference,
  observed_at, ttl_s)`. `last_access_at` drives LRU eviction (C-013).

**Identity & authz** (ADRs 0001/0004)

- `subjects(id, kind{user|robot|anonymous}, name UNIQUE, disabled, created_at)`
- `user_credentials(subject_id PK, argon2_hash, params, rotated_at, must_rotate)`
- `robot_credentials(subject_id PK, secret_hmac, expires_at, rotated_at)`
- `access_tokens(id, subject_id, kind{pat}, token_hmac, name, expires_at NULL,
  last_used_at)` ; `sessions(id, subject_id, csrf, idle_expires_at, abs_expires_at)`
- `groups(id, name UNIQUE)`; `group_subjects(group_id, subject_id)`
- `roles(id, name UNIQUE, builtin)`; `role_verbs(role_id, verb)` — expanded
  explicit verbs (ADR 0002).
- `bindings(id, principal_kind{subject|group}, principal_id, role_id, scope)` —
  `scope` stores the validated pattern; the query filter compiles it to
  `name = ?` / `name LIKE 'prefix/%'` predicates, so Decide and SQL share one
  compilation function.

**Scanning & vulnerabilities** (normalised; vendor JSON never system-of-record)

- `scans(id, manifest_digest, scanner, scanner_version, db_version, started_at,
  finished_at, status)`
- `findings(scan_id, cve_id, package, installed, fixed_version NULL, severity,
  source)` ; `cves(id PK, severity, cvss, summary, published_at, modified_at)`
- `suppressions(id, cve_id, scope, reason, actor, expires_at)` — VEX-style,
  expiring, audited.

**Operations**

- `events(id ULID, type, repo_name NULL, resource, actor, payload JSON, at)` — the
  durable outbox; webhook delivery and the UI activity feed read from it.
- `webhook_subscriptions(id, owner_subject, url, secret_ref, repo_pattern,
  event_types, active)` ; `webhook_deliveries(id, subscription_id, event_id,
  attempt, state{pending|ok|failed|dead}, next_at, response_code, at)`
- `audit_log(id ULID, actor, verb, resource, outcome, before JSON, after JSON, at)`
  — append-only: no UPDATE/DELETE in any code path; E-013 prunes by export.
- `pull_stats(repo_name, tag, last_pulled_at, count)` — upserted off the hot path
  via batched writer.
- `quota_usage(scope{repo|global|cache}, key, bytes, updated_at)` ;
  `quotas(scope, key, soft_bytes, hard_bytes)`
- `gc_runs(id, phase, cursor, started_at, finished_at)` — resumability (P-007).
- `schema_migrations(version PK, applied_at)`

### Migration strategy

- Numbered, forward-only SQL files embedded per engine
  (`internal/meta/migrations/{sqlite,postgres}/NNNN_name.sql`), applied in a
  transaction each on startup; `--no-auto-migrate` gates for operators who stage
  upgrades. Failure aborts startup with the failing version named.
- No down-migrations: recovery is restore-from-backup (DOC-002), which is honest
  about what down-migrations actually deliver.
- The contract test suite runs every migration from empty → head on both engines in
  CI, then exercises the full `meta.Store` surface.

## Rejected alternatives

- **Single content table with a `hosted|cached` kind column** — one WHERE-clause
  bug away from cross-path deletion; separate families make the wrong join
  unwritable and let cache code physically lack access to hosted tables.
- **Refcounts on blobs instead of mark-and-sweep edges** — refcounts drift under
  crashes; `manifest_refs` keeps GC recomputable from first principles.
- **ORM / query builder** — two engines and a 95 % bar want hand-auditable SQL.
- **Storing vendor scan JSON as the record** — forbidden by §6; normalised tables
  are what rollups, suppression, and rescan-diffing query.

## Consequences

- `meta.Store` is wide but partitions cleanly along the entity groups above; the
  contract suite (F-005) is organised the same way.
- The binding-scope → SQL predicate compiler is shared with `authz` (one grammar,
  one compiler, used by both Decide-callers and listings) — the mechanism that
  makes §5.3 "filter at the query layer" real rather than aspirational.
- Schema changes require touching both engines' migration dirs; CI fails if the
  head schemas diverge (a dump-and-diff check in the contract suite).
