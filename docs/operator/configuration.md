# Configuration

trove reads configuration from four layers. Later layers win:

1. **Built-in defaults** — a complete, valid configuration on their own.
2. **A YAML file** — `/etc/trove/trove.yaml` by default. Its absence is fine; a
   file you explicitly asked for and that cannot be read is a startup error.
3. **Environment variables** — `TROVE_*`.
4. **Command-line flags**.

Every setting is reachable from every layer, and the three names are mechanically
derived from one canonical path:

| Layer | Form | Example |
|---|---|---|
| File | nested YAML keys | `cache:` → `tag_ttl: 15m` |
| Environment | `TROVE_` + path, dots and separators as `_`, upper-cased | `TROVE_CACHE_TAG_TTL=15m` |
| Flag | path with `_` replaced by `-` | `-cache.tag-ttl=15m` |

Selecting the file itself: `-config /path/trove.yaml` or `TROVE_CONFIG=/path/trove.yaml`.

`trove.example.yaml` in the repository root documents every key with its default
and the reasoning behind it. A test asserts it stays identical to the built-in
defaults, so it is safe to copy verbatim.

## Validation

The process refuses to start on an invalid configuration, and reports **every**
problem at once rather than one per restart. Each message names the key and the
layer that supplied the value:

```
invalid configuration: 2 problems:
  - cache.offline_mode (from file /etc/trove/trove.yaml): must be one of serve-stale, strict, got "pretend"
  - log.level (from env TROVE_LOG_LEVEL): must be one of debug, info, warn, error, got "chatty"
```

That last part matters more than it looks: when a value is set in three places,
knowing *which* one won is the difference between a one-minute fix and an hour.

## Secrets

Fields holding credentials — `database.dsn` and `storage.s3.secret_access_key` —
are marked secret in the type system. Anything that renders configuration (log
lines, the admin API, `trove support-bundle`) renders the redacted copy, and
there is deliberately no unredacted renderer to reach for by mistake.

## Derived paths

These default to locations under `data_dir`, so setting `data_dir` alone moves
everything together. Set any of them explicitly to override just that one:

| Setting | Derived default |
|---|---|
| `storage.fs.root` | `<data_dir>/storage` |
| `database.dsn` (sqlite) | `<data_dir>/trove.db` |
| `auth.secrets_key_file` | `<data_dir>/keys/secrets.key` |
| `auth.token_signing_key_file` | `<data_dir>/keys/token-signing.key` |
| `tls.acme_cache_dir` | `<data_dir>/acme` |

> **Back up the key files with the database.** A database backup without
> `keys/` cannot decrypt upstream credentials, and every existing session and
> token becomes invalid. See the operator guide's backup section.

## Value formats

**Durations** use Go's form: `30s`, `15m`, `12h`, `1h30m`.

**Sizes** accept decimal units (`50GB`, `500MB`), binary units (`512MiB`,
`1TiB`), or a plain byte count. They render back in the unit that divides them
exactly, so `50GB` stays `50GB`.

**Lists** are YAML sequences in a file, and comma-separated elsewhere:
`TROVE_TLS_ACME_DOMAINS=a.example.com,b.example.com`.

**Booleans** accept `true`/`false`. As flags they need no value: `-policy.gating-enabled`.

## Database migrations

Migrations are numbered, forward-only, and compiled into the binary, so an
offline install needs nothing extra. Each one runs in its own transaction: a
failure leaves the database at the last version that completed, never half way
through one, and startup aborts naming the version that failed.

There are no down-migrations. Recovery from a bad upgrade is restore-from-backup
(see the operator guide), which is honest about what a down-migration actually
delivers.

| Setting | Effect |
|---|---|
| `database.auto_migrate: true` (default) | Pending migrations are applied on startup. |
| `database.auto_migrate: false`, or `-no-auto-migrate` | Startup refuses a database that is behind the binary, listing the migrations it would have run. Apply them deliberately, then start. |

Two states are refused rather than papered over: a database carrying a version
this binary does not know about (an older binary pointed at a newer database),
and a migration that would be applied after a newer one had already run.

## Choosing an engine

`database.driver` takes `sqlite` (the default) or `postgres`. Both are first
class: they run the same contract suite, and a test holds their schemas to the
same columns and nullability, so an engine change is not a behaviour change.
Pick SQLite unless you already run Postgres and want trove's metadata to live
where the rest of your data does.

| | SQLite | Postgres |
|---|---|---|
| Setup | none — a file under `data_dir` | an existing server and a database |
| Concurrency | one writer at a time, by design | concurrent writers |
| Backup | copy the file (in maintenance mode) plus `keys/` | your existing Postgres backups plus `keys/` |

The SQLite store caps its connection pool at one connection, which removes lock
contention as a failure mode and matches the single-node posture of ADR 0018. It
runs in WAL mode with foreign key enforcement on; trove refuses to start if
foreign keys are off, because the schema's cascades are correctness rather than
convenience.

The Postgres store lets the server handle concurrency and uses a small pool
instead. Where two callers can now race the same create, the unique constraints
decide it and the loser gets the same "already exists" error a single-writer
store would have produced.

## Blob storage

`storage.driver` takes `fs` (the default) or `s3`. Both are content-addressed
and both verify digests on write and on read; they differ only in where the
bytes land.

| | Filesystem | S3-compatible |
|---|---|---|
| Layout | `<root>/blobs/<algorithm>/<first-2>/<hex>` | `<prefix>blobs/<algorithm>/<hex>` |
| Atomic write | staging file, fsync, rename | multipart upload completed last |
| In-progress uploads | one staging file per session | one object per chunk |
| Corrupt content on read | moved to `<root>/quarantine/` | copied to `<prefix>quarantine/` |

Hosted and cached content are always two separate stores — two roots, or two
key prefixes — so an eviction cannot reach a hosted blob (ADR 0009).

A blob whose bytes stop matching its digest is never served. The read fails one
byte short, so the client's own digest check fails too, and the content is
moved out of the served tree and kept as evidence rather than deleted. Every
such event is reported, which is what `blob.corrupt` and the audit record are
built from.

> **`storage.s3.redirect` stays off unless you mean it.** With it on, trove
> hands the client a presigned URL and steps out of the data path — which means
> nothing verifies the bytes the client receives, and you are relying on the
> object store's integrity guarantees instead of trove's. It is faster and it
> is a deliberate trade.

## Notable defaults, and why

| Setting | Default | Reason |
|---|---|---|
| `cache.tag_ttl` | `15m` | Tags move; digests do not. This bounds how long a stale `:latest` can be served before revalidation. |
| `cache.offline_mode` | `serve-stale` | An unreachable upstream should not stop a cluster from pulling images it already has. |
| `policy.gating_enabled` | `false` | Observe before blocking. A fresh install with an empty CVE database would otherwise refuse everything. |
| `metrics.exposure` | `local` | `/metrics` is not exposed publicly until you say so. |
| `metrics.per_repo` | `false` | Repository names as labels are high-cardinality *and* leak names to anyone who can scrape. |
| `webhooks.allow_private_targets` | `false` | A webhook target is an outbound request you control the URL of; private ranges are refused so subscriptions cannot probe your network. |
| `storage.s3.redirect` | `false` | Presigned redirects take trove out of the data path, skipping read-side digest verification. |
| `registry.max_manifest_bytes` | `4MiB` | Real manifests are kilobytes; the cap keeps an adversarial manifest payload out of memory. Pushes over it are refused with `MANIFEST_INVALID`. |
| `registry.upload_session_ttl` | `24h` | An interrupted push holds a session row and staged bytes; after this long idle the reaper reclaims both. Any chunk resets the clock, so an active upload is never reaped. |
| `scan.concurrency` | `1` | Scanning is memory-hungry; the safe default is one at a time. |

## Related

- `trove.example.yaml` — annotated example with every key
- `docs/adr/` — the reasoning behind each default
- `docs/dev/environment.md` — running trove from source
