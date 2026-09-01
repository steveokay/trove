# trove

A self-hosted, single-tenant OCI registry that stores, proxies, and manages container
images and OCI artifacts — with RBAC, vulnerability scanning, pull-through caching, and
group endpoints, in one static Go binary.

> **Status: pre-alpha — design phase complete, implementation in progress.**
> Nothing is runnable yet. The architecture is fully specified (19 ADRs) and the build
> is tracked task-by-task in [`status.md`](status.md).

## What it will do

Set **one registry URL** in your cluster and get your internal images, Docker Hub,
ghcr.io, quay.io, and gcr.io resolved in a defined order — all cached locally, all
scanned, all governed by one permission model:

- **Hosted repositories** — OCI distribution v1.1 push/pull, multi-arch indexes, and
  the referrers API for SBOMs, signatures, and attestations
- **Pull-through proxies** — per-upstream credentials, tag-revalidation TTLs, negative
  caching, offline/serve-stale mode, Docker Hub rate-limit awareness
- **Group endpoints** — ordered member resolution, first match wins, permission-aware
- **RBAC** — roles, scoped bindings, robot accounts, and an effective-permission
  explainer (`trove auth explain`); additive-only, no deny-rule surprises
- **Scanning & gating** — Trivy-powered scans on push and on cache-fill, scheduled
  rescans on CVE DB updates, optional pull gating with an audited break-glass
- **Lifecycle** — retention policies (dry-run by default), tag immutability and
  protected tags, mark-and-sweep GC that prefers leaking a blob over losing one,
  storage quotas
- **Operations** — webhooks with HMAC signing and a dead-letter queue, Prometheus
  metrics, append-only audit log, read-only maintenance mode, air-gapped CVE DB
  import, embedded web UI

Single binary, no required external dependencies: SQLite and local filesystem by
default; Postgres and S3-compatible storage optional. The goal: zero to a working TLS
registry with a Docker Hub cache and scoped roles in **under five minutes on one VM**.

## Design principles

- **Authorization filters at the query layer, never the render layer.** If you can't
  read a repository, it doesn't exist for you — not in the catalog, not in search, not
  in pagination counts, not in group behaviour.
- **Cached and hosted deletion never share code.** Evicting a cached blob is
  recoverable; deleting a hosted one is not. The separation is enforced by the type
  system and proven by tests.
- **The API is the contract.** The UI and CLI are ordinary clients of it. Nothing is
  UI-only.
- **Pure functions where it matters.** Authorization decisions, retention evaluation,
  and group resolution take values in and return values out — no I/O — which is what
  makes a 95 % test-coverage gate honest instead of decorative.
- **No telemetry, no phone-home.** The only outbound calls are to upstreams you
  configure, and every one is disableable.

## Project layout

| Path | Contents |
|---|---|
| [`docs/adr/`](docs/adr/) | 19 architecture decision records — the binding design |
| [`docs/plan/`](docs/plan/) | Per-phase implementation specs: files, criteria, test plans |
| [`status.md`](status.md) | The task board — single source of truth for progress |
| [`CLAUDE.md`](CLAUDE.md) | Project charter and working rules |

## Building & contributing

The Go scaffold lands with task F-001 (next up). Until then there is nothing to build.
The decision record in `docs/adr/` is the right place to start reading; open questions
have all been resolved and are summarized in `CLAUDE.md` §13.

## License

[Apache-2.0](LICENSE)
