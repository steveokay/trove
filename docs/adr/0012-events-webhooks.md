# ADR 0012 — Event model and webhook delivery

- Status: accepted (2026-09-01)
- Task: D-014
- Depends on: ADR 0001/0003 (permission filtering), ADR 0006 (events, deliveries)

## Context

One in-process event bus feeds webhooks, the audit trail's operational half,
metrics, and the UI activity feed (§8). Webhooks are an exfiltration path if
delivery ignores the subscriber's permissions, and an SSRF vector if targets are
unvalidated (E-012).

## Decision

### Event taxonomy

Typed constants, closed set (extending it is a reviewable change):

`artifact.pushed`, `artifact.pulled`, `artifact.deleted`, `cache.filled`,
`cache.evicted`, `cache.stale-served`, `group.member.skipped`, `scan.completed`,
`scan.regressed`, `policy.violated`, `authz.denied`, `role.changed`,
`quota.warned`, `quota.exceeded`, `gc.completed`, `blob.corrupt`.

Every event: `id` (ULID — also the idempotency key), `type`, `repo_name` (nullable
for system events), `resource` (digest/tag/subject as applicable), `actor`,
`payload` (typed per event type, serialized JSON), `at`.

`artifact.pulled` is high-volume: it is emitted to the bus for metrics/pull-stats
but **not persisted to the events table by default** (`events.persist_pulls: false`)
and not subscribable by webhooks unless the operator flips that knob — volume
control is an operator decision, not a silent cap.

### Bus

- In-process, synchronous fan-out to registered consumers; consumers must be
  non-blocking (metrics increment, outbox insert). Anything slow (webhook HTTP,
  scan enqueue) happens *after* the outbox row, never in the publisher's call path.
- Publishing happens in the same transaction as the state change wherever a
  transaction exists (the outbox pattern): an event exists iff its change
  committed. This is what makes at-least-once honest.

### Webhook subscriptions

- `(owner subject, url, secret, repo_pattern, event_types, active)`. The
  `repo_pattern` uses the ADR 0001 scope grammar (one grammar everywhere).
- **Permission filtering at delivery time** (E-004): before each attempt, the
  delivery worker evaluates `Decide(owner, bindings, repo:read, event.repo_name)`
  with *current* bindings. A subscription whose owner lost read on a repo stops
  receiving its events with no migration step; system events require the verb
  their surface requires (e.g. `authz.denied` events require `audit:read`).
- **Target validation** (E-012): at subscription write *and* at delivery, the
  resolved IP must not fall in loopback, RFC 1918, link-local, or ULA ranges
  unless the operator allowlists it (`webhooks.allow_private_targets`). Redirects
  are not followed. DNS re-resolution at delivery closes TOCTOU rebinding.

### Delivery

- Worker drains `webhook_deliveries` (state machine `pending → ok | failed →
  … → dead`). At-least-once: retries with exponential backoff + jitter
  (1 m, 5 m, 25 m, 2 h, 6 h; 5 attempts → `dead`). The queue is table-backed, so
  restarts lose nothing (E-003).
- Request: `POST` JSON, headers `Trove-Event-Id` (ULID — documented idempotency
  key), `Trove-Event-Type`, `Trove-Signature: sha256=<HMAC-SHA256(secret, body)>`.
  Secrets are stored encrypted (ADR 0016), never shown after creation.
- Dead-letter view: deliveries in `dead` are listable and replayable
  (`webhook:write`), with response codes/bodies (truncated) retained for
  diagnosis. Delivery history retention: 30 days, pruned with its own job.

## Rejected alternatives

- **External broker (NATS/Redis)** — violates the no-required-dependencies rule;
  the outbox table gives durability with what we already run.
- **Async bus with buffered channels as the source of truth** — loses events on
  crash; channels are fine for fan-out, not for durability, hence outbox-first.
- **Permission snapshot at subscription time** — simpler, but a revoked reader
  keeps receiving events until someone remembers the subscription; live evaluation
  matches §5's revocation-latency stance (Z-019).
- **Following redirects with re-validation** — re-validating every hop is easy to
  get wrong; not following redirects is simpler and webhook endpoints don't
  legitimately redirect.

## Consequences

- `internal/event` owns the bus, taxonomy, outbox writer, delivery worker, and
  target validation; webhook HTTP uses a dedicated client with tight timeouts
  (connect 5 s, total 30 s) and no shared transport with proxy upstream clients.
- Event payloads are contract: golden-tested (§11) since external systems parse
  them.
- The disclosure suite (Z-018) gains a webhook case: owner loses `repo:read`,
  event for that repo is not delivered, delivery row records `skipped-authz` (a
  distinct terminal state so operators can diagnose "why no events" without
  guessing).
