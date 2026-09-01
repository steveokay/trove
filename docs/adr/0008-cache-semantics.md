# ADR 0008 — Proxy cache semantics

- Status: accepted (2026-09-01)
- Task: D-012
- Decisions applied: Q11 (global budget + LRU, 15 m tag TTL, 60 s negative TTL),
  Q24 (serve on fill, scan async)

## Context

The highest-risk subsystem (§4): most of its bugs are correctness bugs that look
like caching bugs. The core distinction — digests are immutable, tags are leases —
drives everything below.

## Decision

### By-digest content

- A blob or manifest fetched **by digest** is verified on arrival (ADR 0007) and
  cached indefinitely; it never revalidates. Eviction (C-013) is the only way it
  leaves.

### Tag → digest leases

- Resolving a tag against a proxy creates a **lease**: `(repo, reference) → digest`
  with `fetched_at` and TTL (default **15 minutes**, per-repository knob,
  `0` = revalidate every pull).
- On expiry, revalidation is a conditional upstream request (HEAD with
  `Accept` manifest types; compare `Docker-Content-Digest` / ETag). Unchanged →
  refresh the lease (an upstream 304/match costs no bandwidth). Changed → fetch the
  new manifest by its digest, verify, cache, update the lease. The old content
  remains cached by digest (images pinned by digest keep working).
- **Single-flight** (C-006): concurrent resolutions of the same `(repo, reference)`
  coalesce into one upstream request in-process (Q5: single node makes this a
  `singleflight.Group`, behind an interface so HA can replace it later).

### Negative caching

- Upstream NOT-FOUND responses are cached per `(repo, reference)` for **60 seconds**
  (own knob). A negative entry is invalidated early by a successful push… never —
  proxies take no pushes; it simply expires. Negative entries never apply to
  by-digest requests (a digest 404 upstream is returned, not cached — digest
  existence can appear at any moment and mis-caching it breaks `docker push`+group
  flows).

### Offline / degraded mode

- Default (`offline_mode: serve-stale`): when the upstream is unreachable
  (connection, DNS, 5xx), expired leases are served from cache with
  `Warning: 110 - "response is stale"` and a `cache.stale-served` event; pulls of
  uncached content fail with an upstream-unreachable error.
- `strict` mode fails expired-lease pulls instead. Per-repository setting.
- "Unreachable" is tested with DNS blackholed and with TCP timeouts, not just 500s
  (C-008).

### Rate limits and backoff

- `429` and `Retry-After` are honored with exponential backoff and jitter;
  during backoff the proxy behaves as offline (serve-stale rules apply).
- Docker Hub `RateLimit-Remaining`/`RateLimit-Limit` headers are recorded per proxy
  and exported as metrics + shown in the UI (C-009). Backoff state is visible in
  `/readyz` detail but does not fail readiness.

### Eviction (C-013, separate code path — ADR 0009)

- **Global cache budget, default 50 GB**, optional per-proxy override that carves
  out of the global budget. LRU by `last_access_at` (touched on serve, batched).
- Eviction removes cached blobs/manifests and their rows; leases for evicted
  manifests drop too. Eviction never blocks a pull; it runs on its own schedule and
  on budget-breach triggers (soft: event; hard: evict harder — Q8).

### Scan interaction (Q24)

- Cache fill triggers an async scan (S-009). The triggering pull is served
  immediately; gating applies to subsequent pulls once results exist. Per-policy
  `block-until-scanned` strict mode exists for designated repos (ADR 0013).

## Rejected alternatives

- **TTL-only cache without a size budget** — unbounded disk on a single VM (Q11).
- **Caching tag→digest inside manifests' HTTP cache headers** — upstreams'
  `Cache-Control` on manifests is inconsistent across registries; our lease model
  is explicit and per-repo tunable instead of upstream-controlled.
- **Negative-caching digest lookups** — breaks push-then-pull-through-group races;
  only tag/name lookups are negative-cached.
- **Cross-node single-flight via the DB** — YAGNI at single-node (Q5); the
  interface seam is the concession to the future, not the implementation.

## Consequences

- `internal/proxy` owns upstream clients, leases, single-flight, negative cache,
  and backoff state; `internal/cache` owns only eviction. The upstream client is an
  interface with a contract suite run against `registry:2` and one real remote
  (C-002).
- Serving stale is observable three ways (header, event, metric) so operators
  notice degraded mode instead of discovering it during an incident.
- The C-015 adversarial suite maps directly onto sections above: mismatch,
  redirect loop (client caps redirects at 5, same-registry-family only — SSRF),
  429 storm, single-flight under concurrency, stale-past-TTL behaviour in both
  offline modes.
