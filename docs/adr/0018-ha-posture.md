# ADR 0018 — HA posture for v1

- Status: accepted (2026-09-01)
- Task: D-004
- Decisions applied: Q5 (single node)

## Context

Two nodes sharing Postgres + S3 would force distributed locking, cross-node
single-flight, and leader election into every subsystem now. The north star is a
single operator on a single VM (§1). The question is what v1 must do *today* so
that HA in v2 is an implementation effort, not a redesign.

## Decision

**v1 is explicitly single-node.** One process owns the data directory; a lock file
(`<data>/trove.lock`, flock-based) makes a second `serve` — or an online `--offline`
command — fail fast with a clear error.

Concurrency-sensitive mechanisms and their v1 forms:

| Mechanism | v1 implementation | Seam left for HA |
|---|---|---|
| Cache single-flight (C-006) | in-process `singleflight.Group` | behind a `Coalescer` interface |
| GC / retention / scheduled tasks (P-006) | in-process scheduler, one runner | runner takes a `Lease` interface (v1: no-op lease) |
| Webhook + scan queues | table-backed, single worker set | workers already claim rows transactionally (`state` transitions), which is multi-node-safe by construction |
| Session / token state | in the metadata store, not in memory | already shared-state-ready |
| Rate-limit counters (authn) | in-memory | acceptable loss: per-node limiting still limits |
| Quota deltas | transactional in the store | already shared-state-ready |

Rules that keep the door open (enforced in review, cheap today):

1. No correctness-bearing state lives only in process memory. Caches of DB state
   are allowed only with TTL or invalidation-on-write in the same process —
   nothing that would be *wrong* (rather than briefly stale) with a second writer.
2. The metadata store is the synchronization point. Anything that would need a
   distributed lock must instead be expressible as a transactional row claim —
   the queues already model this; future mechanisms follow it.
3. Blob store operations stay idempotent and atomic (ADR 0007's rename/commit
   semantics), which they must be anyway for crash safety — the same property
   that makes them multi-writer-tolerant.

Explicit non-goals for v1: leader election, distributed locks, node identity,
gossip/health between instances, S3-conditional-write coordination. Read-only mode
(E-008) plus fast restart is the v1 availability story; systemd `Restart=always`
and a documented restore path (DOC-002) are the recovery story.

## Rejected alternatives

- **Shared-state HA in v1** — every subsystem pays the coordination tax before a
  single user exists; SQLite (the default engine) is single-writer anyway, so HA
  would also force Postgres+S3 as the effective default, contradicting the
  zero-dependency install.
- **Active/passive with shared disk** — failover correctness (fencing) is the
  hard part and NFS/SAN semantics are exactly where blob atomicity assumptions
  die; not a shortcut, just a worse distributed system.
- **"HA-ready" abstractions everywhere now** — interface seams are cheap only
  where the v1 implementation is trivial (the table above); speculative
  distributed abstractions elsewhere would be untested code, which §9 forbids.

## Consequences

- The Q5 decision is revisited only as a v2-scale ADR; nothing in v1.x may
  introduce memory-resident correctness state without amending this ADR.
- The lock file gives single-node a crisp failure mode and doubles as the
  live-server guard for `--offline` commands (ADR 0015).
- Postgres + S3 remain fully supported *storage* choices in v1 — the deployment
  is still one trove process; operators get durability options without topology
  options.
