# CLAUDE.md

Operating instructions for AI agents working in this repository. Read this file in full
before touching any code. If anything here conflicts with a request in the chat, say so
and ask — do not silently pick one.

---

## 0. Hard rules (non-negotiable)

1. **Never attribute authorship to an AI.** Claude must never appear as co-author,
   author, maintainer, collaborator, or contributor in any commit message, commit
   trailer (`Co-Authored-By`), PR description, `AUTHORS`, `CONTRIBUTORS`, `LICENSE`,
   `CODEOWNERS`, `go.mod`, package metadata, changelog, or release note. No
   "Generated with…" footers. No AI attribution anywhere in project metadata.
2. **Do not assume. Ask.** If a requirement, interface contract, dependency choice,
   error semantic, or data model is ambiguous, stop and ask a specific question with
   2–3 concrete options and a recommendation. Do not invent a plausible answer and
   proceed. §13 records the decisions already made — do not re-litigate them silently.
3. **95% line coverage minimum**, enforced in CI, measured with `-coverpkg=./...`.
   A change that drops coverage below the gate is not done. See §9.
4. **`status.md` is the source of truth for progress.** Update it in the same commit
   as the work it describes. Never let it drift.
5. **Authorization is filtered at the query layer, never at the render layer.** If a
   subject cannot read a repository, it must not appear in any listing, search result,
   event, metric label, or API response. See §5.
6. **No secrets, no telemetry, no phone-home.** This is self-hosted software. The only
   outbound calls it makes are to upstreams the operator explicitly configured
   (proxy remotes, CVE feed) and they must all be disableable.

---

## 1. What we are building

A **self-hosted, single-tenant OCI registry** — one organisation, one deployment — that
stores, proxies, and manages:

- Container images (OCI image manifests, Docker v2 manifests, multi-arch indexes)
- Arbitrary OCI artifacts (generic `artifactType` blobs)
- SBOMs (SPDX / CycloneDX) attached to subjects via the **referrers API**
- Helm charts (`application/vnd.cncf.helm.config.v1+json`)
- Signatures and attestations (cosign / in-toto), stored as referrers

**Single-tenant means one organisation, not one user.** Many people with different roles
share this deployment, and an administrator decides who sees and does what. RBAC is a
core v1 feature (§5). What we are *not* building is tenancy isolation: no per-tenant data
partitioning, no tenant-scoped storage or quota trees, no tenant administrators. One
global role and permission namespace, administered centrally.

### Repository types

The central storage abstraction. Borrowed from Nexus because it is the right model, and
much of the rest of the design hangs off it.

| Type | Writable by clients | Backed by | Deletion safety |
|---|---|---|---|
| **hosted** | yes | our blob store | destructive — blobs are irreplaceable |
| **proxy** | **no** | an upstream registry, cached locally | safe — cached blobs are always re-fetchable |
| **group** | no (or delegated to one hosted member) | ordered list of hosted + proxy members | n/a — resolves, never stores |

**A group endpoint is the point of the product.** An operator sets one registry URL in
their cluster and gets internal images, Docker Hub, ghcr, quay, and gcr resolved in a
defined order, all scanned, all cached, all governed by one policy and permission model.

### Feature scope

| Feature | Scope |
|---|---|
| OCI distribution v1.1 (hosted) | push/pull, referrers, multi-arch indexes |
| Pull-through cache (proxy) | per-upstream credentials, TTLs, offline mode, rate-limit awareness — §4 |
| Group / virtual endpoints | ordered member resolution, first-match wins — §4 |
| **RBAC** | roles, permissions, scoped bindings, visibility filtering, effective-permission explainer — §5 |
| Authentication | local users, robot accounts, tokens, OCI token flow, anonymous subject |
| Container scanning | on-push (hosted), on-cache-fill (proxy), scheduled rescan |
| Vulnerability assessment | CVE inventory, severity rollups, fixable split, VEX/suppressions |
| Pull gating / quarantine | refuse to serve artifacts violating a severity or signature policy |
| Tag policies | immutability + prefix exceptions, allowed patterns, protected tags |
| Cleanup / retention | keep-last-N, keep-newer-than, last-pulled-before, regex filters, untagged reaping, **dry-run by default** |
| Cache eviction | size/LRU-bounded, separate code path from retention (§7) |
| Garbage collection | mark-and-sweep, resumable, cannot delete a referenced blob |
| Webhooks / events | push, delete, scan-complete, policy-violation, authz-denied, quota-breach |
| Pull statistics | last-pulled timestamp and pull counts per tag — feeds retention rules |
| Quotas | per-repository and global storage limits, soft-warn then hard-deny |
| Search | across readable repos by name, tag, digest, media type, CVE ID |
| Observability | Prometheus metrics, `/healthz`, `/readyz`, structured audit log |
| Read-only / maintenance mode | for backup and upgrade windows |
| Migration import | seed from an existing registry (`trove migrate --from`) |
| Web UI | browse, inspect, CVE reports, policy editor, role and permission admin |

**Design north star:** a single operator, on a single VM, should get from zero to a
working TLS registry — hosted repos plus a Docker Hub cache, with an admin account and at
least one scoped developer role — in under five minutes and one command.

> **Name confirmed: `trove`** (Q1, 2026-09-01). Module path
> `github.com/steveokay/trove`. License: Apache-2.0 (Q9).

### Explicitly not in scope for v1

Multi-tenancy and tenant isolation, geo-replication between trove instances, and non-OCI
formats (Maven, npm, PyPI, apt). If a task seems to require one of these, that is a
signal to ask, not to build it.

---

## 2. Model routing and agent workflow

| Phase | Model | Output |
|---|---|---|
| Requirements, architecture, ADRs, task decomposition, sequencing | **Fable 5** | Written plan in `docs/adr/` + tasks in `status.md`. No code. |
| UI stack selection and visual design direction | **Fable 5** | `docs/adr/00XX-ui-stack.md` with a decision + rejected alternatives |
| Implementation, refactors, tests, debugging | **Opus 5** | Code + tests |

Rules:

- **Plan before code, always.** An implementation session starts by reading the relevant
  ADR and the `status.md` task. If no task exists, stop and go back to planning.
- **Planning output must be executable by someone else.** Each task in `status.md` gets:
  acceptance criteria, the files it touches, its dependencies, and its test plan.
- **Parallel subagents** are encouraged for genuinely independent work — the blob driver,
  the scanner adapter, the proxy client, and the authz evaluator can be built
  concurrently once their interfaces are frozen in an ADR.
  - Freeze the interface first. Parallel work against an unfrozen interface produces
    three incompatible implementations.
  - **Never** run two agents editing the same file or the same package.
  - Each parallel agent owns one package and one `status.md` task ID.
  - Reconcile serially: merge, run the full suite, update `status.md`, then fan out again.
- One task → one commit → one `status.md` update.

---

## 3. Architecture

Single Go binary. Embedded UI. Optional external dependencies, never required.

```
                    ┌──────────────────────────────┐
   docker/helm ───▶ │  HTTP: OCI distribution v1.1 │
   oras/cosign      │        + admin API           │
   browser ───────▶ │        + embedded UI         │
                    └──────────────┬───────────────┘
                                   │
                         ┌─────────▼─────────┐
                         │  authn → authz    │  every request, no exceptions
                         └─────────┬─────────┘
                                   │
                         ┌─────────▼─────────┐
                         │  repo router      │  hosted | proxy | group
                         └─────────┬─────────┘
                                   │
        ┌───────────┬──────────────┼──────────────┬───────────┐
        ▼           ▼              ▼              ▼           ▼
   blob store  metadata store  proxy client   scan engine  policy engine
  (fs|S3-compat)(SQLite|Postgres)(upstreams)   (adapter)  (retention/gate/GC)
                                   │
                              ┌────▼────┐
                              │ events  │──▶ webhooks, audit log, metrics
                              └─────────┘
```

Deliberate contrast with `oci-janus`: that project is multi-tenant Go microservices with
gRPC + mTLS. **This one is a monolith on purpose.** Do not reintroduce service
boundaries, message queues, or gRPC between internal components. In-process interfaces
only. The seam between components lives in the type system, not on the network.

### Package layout

```
cmd/trove/              # single entrypoint; serve, migrate, gc, db, policy, auth, admin, version
internal/registry/      # OCI distribution-spec v1.1 handlers (blobs, manifests, tags, referrers)
internal/repo/          # repository model + router: hosted / proxy / group resolution
internal/proxy/         # upstream clients, cache semantics, TTL/revalidation, rate-limit handling
internal/blob/          # BlobStore interface + filesystem and S3-compatible drivers
internal/meta/          # metadata store interface + sqlite/postgres impls, migrations
internal/artifact/      # media-type awareness: image, index, helm chart, SBOM, attestation
internal/authn/         # identity: users, robot accounts, tokens, OCI token flow, anonymous
internal/authz/         # RBAC: roles, permissions, bindings, decision engine, scope filters
internal/scan/          # Scanner interface + adapter, CVE DB lifecycle, result normalisation
internal/vuln/          # CVE model, severity rollups, VEX/suppression rules, queries
internal/policy/        # tag rules, retention evaluation, pull gating, dry-run planner
internal/cache/         # proxy cache eviction (size/LRU) — SEPARATE from policy/ and gc/
internal/gc/            # mark-and-sweep blob GC, resumable, reference-safe
internal/quota/         # storage accounting and enforcement
internal/event/         # event bus, webhook delivery with retry/backoff, signing
internal/audit/         # append-only audit log
internal/search/        # cross-repo search index and queries (permission-filtered)
internal/metrics/       # Prometheus collectors, health/readiness
internal/config/        # config load/validate/defaults, env + file
internal/server/        # HTTP wiring, middleware, graceful shutdown, read-only mode
web/                    # UI source (stack TBD — Fable 5 decides)
web/embed.go            # go:embed of built assets
docs/adr/               # architecture decision records
test/conformance/       # OCI distribution-spec conformance harness
```

`internal/authz` must not import `internal/registry`, `internal/repo`, or any storage
package. The decision engine takes plain values in and returns a decision. Enforce this
with an import-cycle/allowlist test.

### Locked technical decisions

- **Go 1.23+**, `CGO_ENABLED=0`, static binary, cross-compiled for linux/amd64,
  linux/arm64, darwin/arm64.
- **OCI distribution-spec v1.1** including the referrers API — this is how SBOMs,
  signatures, and scan attestations attach to images. Do not invent a bespoke sidecar
  table for attachments when the spec already models this.
- **SQLite by default** (pure-Go `modernc.org/sqlite`, no CGO), **Postgres optional**.
  Same `meta.Store` interface, two impls, one shared contract test suite.
- **Filesystem blob storage by default**, S3-compatible optional. Content-addressed,
  digest-verified on read and write.
- **stdlib `net/http` + `chi`** for routing. No heavyweight framework.
- **`log/slog`** for structured logging. No logging framework.
- **Config precedence:** flags > env (`TROVE_*`) > config file > defaults. Validated at
  startup; the process refuses to start on an invalid config.
- **Migrations run automatically on startup**, forward-only, with `--no-auto-migrate`.

### Install targets

`trove serve` on a bare host with a systemd unit is the primary path. Also ship a
single-file `docker-compose.yml`, a Helm chart, and `.deb`/`.rpm`. Every one must work
with zero editing for the happy path. TLS via embedded ACME **or** operator-supplied
cert paths — both, switched by one config key.

---

## 4. Pull-through cache, proxies, and groups

The highest-risk subsystem in the project. Most of its bugs are correctness bugs that
look like caching bugs.

### Correctness rules

- **Proxy repositories reject client pushes** with the spec error `DENIED`. There is no
  configuration that makes a proxy writable.
- **Digests are immutable; tags are not.** A blob or manifest fetched by digest may be
  cached forever. A **tag → digest** mapping is a lease with a TTL, revalidated against
  the upstream with a conditional request on expiry. Getting this wrong means serving a
  stale `:latest` for a week — treat tag-resolution TTL as a first-class per-repository
  config knob.
- **Negative caching** for upstream 404s, with its own short TTL, so a typo does not
  hammer the upstream.
- **Offline / degraded mode:** when the upstream is unreachable, serve cached content and
  mark it stale rather than failing the pull. A `strict` mode that fails instead must
  exist, but the default keeps the cluster running. Test with the upstream
  DNS-blackholed, not just returning 500s.
- **Rate-limit awareness:** honour `Retry-After`, back off on 429, and surface remaining
  upstream quota (Docker Hub's `RateLimit-Remaining`) in metrics and the UI. Avoiding
  Docker Hub throttling is a primary reason operators deploy this.
- **Upstream credentials** are encrypted at rest, never logged, never returned by any API
  read path, and redacted in config dumps and support bundles. Reading or writing them
  is its own permission (§5), not implied by repository admin.
- **Routing rules** per proxy: allow/block patterns on repository paths, so a proxy can
  be restricted to `library/*` without becoming an open relay.
- **Cached content is scanned too**, on cache-fill rather than on push. An unscanned
  cached image must not be silently exempt from pull gating.

### Groups

- Ordered member list, **first match wins**, hosted members before proxy members by
  default. Order is explicit config, never implicit.
- A group is read-only unless a single hosted member is designated as the write target.
- A member being down must not fail the whole group: skip, log, emit an event, continue —
  unless the member is marked required.
- **Permission filtering happens before resolution.** Members the subject cannot read are
  removed from the member list, then resolution runs against what remains. A subject must
  not be able to infer a member's existence, or the digest it would have served, from
  group behaviour. This is the single easiest place to leak — test it directly.
- Group resolution is a **pure function** over (filtered member state, reference). Test
  exhaustively: same tag in two members, member offline, member unreadable, member
  returning a malformed manifest.

### Cache storage is not hosted storage

**Never share deletion code between cached and hosted blobs.** Evicting a cached blob is
always recoverable; deleting a hosted blob is not. Separate types, separate packages
(`internal/cache` vs `internal/gc`), separate audit event types. Storage accounting
reports them separately. A retention policy must never be able to select a hosted
artifact through a cache-eviction code path or vice versa — this is a type-system
obligation, and there is a test that proves it.

---

## 5. Authentication and RBAC

An administrator controls who can see and do what. This is a v1 feature and it is load-
bearing for §4 (group resolution), §8 (search, events, metrics), and the UI.

### Model

Three concepts, kept separate:

- **Subject** — a user, a robot account, or the built-in `anonymous` subject. Anonymous
  is a real subject with real bindings, not a bypass branch. There is exactly one code
  path for authorization.
- **Role** — a named set of permissions. Built-in roles ship read-only and
  non-deletable; custom roles are composed from the same permission vocabulary. No
  permission exists that a custom role cannot be granted, and none that bypasses a check.
- **Binding** — `(subject or group, role, scope)`. Scope is a repository pattern
  (`team-a/*`, `library/nginx`) or the special scope `system` for global permissions.

**Bindings are additive. There are no deny rules.** The decision is the union of every
binding that matches. This is the Kubernetes model and it is chosen deliberately: deny
rules make effective permissions unpredictable and effectively untestable. If a subject
should not have access, do not grant it.

Precedence questions that would arise from overlapping patterns (`team-a/*` vs
`team-a/secret`) therefore do not arise. Confirmed as the model for v1 (Q14). Bindings
attach to subjects and to local groups/teams (Q19); scopes are repository patterns only,
never tag-level (Q20).

### Permission vocabulary

Verbs are granular and map to real operations, not to HTTP methods. Minimum set:

```
repo:list        repo:read        repo:write       repo:delete
tag:delete       manifest:delete  referrer:read
scan:read        scan:trigger
policy:read      policy:write     policy:apply      gate:override
proxy:read       proxy:write      proxy:credentials
quota:read       quota:write
webhook:read     webhook:write
user:read        user:write       role:read         role:write
audit:read       search:read
system:maintenance   gc:run
```

Deliberate splits, each of which exists because collapsing it is a real incident:

- `policy:write` (author a rule) vs `policy:apply` (execute a destructive plan)
- `proxy:write` (change a remote) vs `proxy:credentials` (see or set its secret)
- `gate:override` (break-glass past a vulnerability block) is never implied by anything
- `repo:delete` is never implied by `repo:write`

Suggested built-in roles: `admin` (all), `operator` (everything but user/role
management), `publisher` (read + write in scope), `developer` (read in scope),
`auditor` (read + `audit:read` + `scan:read`, no write anywhere), `anonymous-reader`.

### Enforcement rules

1. **One decision function, pure:** `Decide(subject, bindings, verb, resource) → Decision`
   with no I/O. Everything else is a caller. Property-test it.
2. **Enforce at the handler, every request.** Token scopes are a transport optimisation,
   never the sole authority — roles change mid-token-lifetime. Enforce at token minting
   *and* at request handling.
3. **Filter at the query layer.** `/v2/_catalog`, tag lists, search, the UI, event
   subscriptions, and metric labels are all built from permission-filtered queries.
   Never fetch everything and filter in the handler or the template — that leaks through
   pagination counts, timing, and any future code path that forgets.
4. **Existence is information.** Unauthorized reads return `404` / `NAME_UNKNOWN`
   (decided, Q18) — applied uniformly across the registry API, the admin API,
   referrers, and group members. Inconsistency here is the leak.
5. **Unauthenticated requests get `401` with a `WWW-Authenticate` challenge**, because
   `docker login` depends on it. Authenticated-but-unauthorized is a different answer.
6. **Robot accounts get bindings like anyone else.** No implicit privilege, mandatory
   expiry, revocable, and their tokens are scoped to the bindings held *at mint time*
   and re-checked at use time.
7. **Referrers inherit the subject's permission on the subject artifact.** A user who
   cannot read an image cannot read its SBOM, signature, or scan result.
8. **Every denial is an audit event and a metric**, with subject, verb, and resource.
   A spike in denials is how an operator notices a misconfiguration or an attack.

### Administration

- **Bootstrap:** first run creates one admin with a generated password printed once and
  forced rotation on first login. Never a default credential.
- **Self-lockout prevention:** the last binding granting `role:write` at `system` scope
  cannot be removed. Refuse with a clear error.
- **Effective-permission explainer:** `trove auth explain --subject alice --verb repo:write
  --repo team-a/api` returns the decision *and every binding that contributed to it*.
  Expose the same thing in the admin API and UI. This is the feature that makes RBAC
  operable instead of a source of tickets, and it is trivially testable — build it early.
- **Role and binding changes are audited** with before/after state.
- External identity (OIDC/LDAP) is **v1.1** (Q3): external groups will map onto the
  local groups that already carry bindings, so the binding model does not change.

### UI and RBAC

The UI hides what the subject cannot use, driven by an effective-permissions endpoint.
**This is ergonomics, never security** — every action is authorized server-side
regardless of what the UI rendered.

---

## 6. Scanning and vulnerability assessment

- The scanner sits behind a **`scan.Scanner` interface**. The default implementation is
  an adapter; no other package imports a scanner vendor package directly.
- Scans are **asynchronous and queued**. A push never blocks on a scan. Push latency is
  a hard SLO; scan latency is not.
- Results are **normalised into our own CVE model** before storage. Never persist a
  vendor's raw JSON as the system of record.
- **The CVE database must be updatable offline.** `trove db import <file>` for air-gapped
  operators. First-class path, tested, not an afterthought.
- **Rescan on CVE DB update**, not just on push. A clean image yesterday is not clean
  today. Emit `scan.regressed` when a previously clean artifact goes bad.
- Scan results attach to the subject **as OCI referrers**, so they survive migration and
  are readable by external tooling.
- **Pull gating:** a policy may refuse to serve an artifact above a severity threshold,
  one that is unsigned, or one never scanned. Enforced in the pull path for hosted *and*
  proxy content, auditable, with a break-glass that requires `gate:override` and is
  itself logged.

---

## 7. Policies, retention, GC, quotas

- **Dry-run is the default.** Every retention rule evaluates to a *plan* — the manifests
  that would be deleted, and why. Deletion needs an explicit apply and `policy:apply`.
- Retention evaluation is a **pure function**: `(inventory, rules, now) → plan`. No I/O
  inside the evaluator. This is what makes it testable to the coverage bar, and what
  makes it trustworthy.
- Rules compose from: keep-last-N, keep-newer-than, **keep-if-pulled-since** (needs pull
  statistics), tag regex include/exclude, tag-status filters, and explicit priority
  ordering. Ties are an error, not a coin flip.
- Injectable clock everywhere. No `time.Now()` in business logic.
- **Protected and immutable tags beat every retention rule.** Always. Immutability
  supports prefix exceptions (everything immutable except `dev-*`). Test adversarially.
- Cache eviction is size/LRU-bounded, on its own schedule, reported separately. See §4.
- GC is mark-and-sweep, resumable, and refuses to delete a blob referenced by any
  manifest, including one uploaded mid-sweep. **Prefer leaking a blob over losing one.**
- Quotas: per-repository and global, soft-warn threshold emitting an event, hard limit
  rejecting uploads with a spec-shaped error. Cached content counts against a separate
  cache budget.
- Every delete and eviction writes an audit record with actor, rule, and digest.

---

## 8. Events, observability, operability

- **Event bus** in `internal/event`, in-process, typed: `artifact.pushed`,
  `artifact.deleted`, `artifact.pulled`, `cache.filled`, `cache.evicted`,
  `scan.completed`, `scan.regressed`, `policy.violated`, `authz.denied`,
  `role.changed`, `quota.warned`, `quota.exceeded`, `gc.completed`.
- **Webhooks** deliver those events: per-repository subscriptions, event-type filters,
  HMAC-signed payloads, at-least-once delivery with exponential backoff, a dead-letter
  view, visible delivery history, documented idempotency key. **A subscription only
  receives events for resources its owning subject can read** — webhooks are an
  exfiltration path if you forget this.
- **Prometheus metrics**: request rate/latency/status by operation, storage bytes by repo
  and type, cache hit ratio, upstream latency and rate-limit headroom, scan queue depth
  and age, authz denials by verb, policy plan sizes, GC progress. Be careful with
  repository names as label values — high cardinality *and* a disclosure surface.
- `/healthz` (process alive) and `/readyz` (deps reachable, migrations applied), kept
  distinct, because conflating them makes rolling upgrades unsafe.
- **Read-only / maintenance mode** toggled at runtime (`system:maintenance`): rejects
  writes clearly, keeps serving pulls. This is the supported backup and upgrade procedure.
- **Audit log** append-only, queryable (`audit:read`), exportable, covering every mutating
  action including config changes, role changes, and break-glass overrides.
- **Support bundle:** `trove support-bundle` collects config (secrets redacted), version,
  migration state, role/binding summary, and recent logs into one file.

---

## 9. Testing (the 95% bar)

**Gate:** `go test ./... -covermode=atomic -coverpkg=./...` must report ≥95.0% line
coverage. CI fails below it. Excluded from the denominator: generated code, mocks, and
`cmd/*/main.go` wiring — nothing else.

The bar is achievable only if the code is designed for it:

- Interfaces at every I/O boundary (blob store, meta store, scanner, upstream client,
  clock, filesystem, webhook transport, identity provider).
- No package-level mutable state. No `init()` side effects. Constructor injection.
- Errors are values, wrapped with `%w`, asserted with `errors.Is`/`errors.As` — never by
  string matching.

**Do not pad coverage.** Tests that call a function and assert nothing, or that only
assert a mock was called, are worse than no test: they buy a number and sell confidence.
If a package is hard to test, the package is wrong — fix the design, and ask if unsure.

Required test layers:

1. **Unit** — table-driven, `t.Parallel()`, no network, no sleeps.
2. **Contract** — one shared suite per interface, run against every implementation (fs
   and S3 blob stores; SQLite and Postgres meta stores; each upstream client).
3. **Conformance** — the official OCI distribution-spec conformance suite, in CI, green.
4. **Integration** — real push/pull with `oras`, `helm push`, `docker push`, `cosign`;
   a real registry (`registry:2`) as a proxy upstream in testcontainers.
5. **Property/fuzz** — digest parsing, tag validation, reference parsing, retention
   evaluation, group resolution, **repository pattern matching in bindings**.
6. **Adversarial** — the tests that matter most:
   - GC racing an upload; interrupted sweep resuming correctly
   - retention selecting a protected or immutable tag (must be impossible)
   - a cache-eviction path reaching a hosted blob (must be impossible)
   - path traversal in repository names, upstream mappings, **and binding patterns**
   - digest mismatch, truncated blob, manifest referencing a missing layer
   - upstream returning a manifest whose digest does not match what was requested
   - upstream unreachable / 429 / redirect loop; stale tag past TTL; concurrent
     revalidation of one tag (single-flight)
   - **authz:** scope escalation via token replay after a binding is revoked; robot
     account crossing repositories; `repo:write` implying `repo:delete`; `policy:write`
     implying `policy:apply`; reading a proxy secret with `proxy:write` alone
   - **disclosure:** unreadable repo appearing in catalog, search, tag list, pagination
     count, event delivery, metric label, or group resolution behaviour
   - **referrers:** reading an SBOM for an image the subject cannot read
   - pull gating bypass via digest reference, via referrers, or via a group member
   - last-admin lockout attempt

**Every permission in the §5 vocabulary needs at least one positive and one negative
test.** A permission with no negative test is an unenforced permission. Add a test that
enumerates the vocabulary and fails if any verb lacks both.

Golden files for API responses. Race detector on in CI. No flaky tests — a flaky test is
fixed or deleted the day it flakes, never retried.

---

## 10. UI

Stack is **chosen by Fable 5 in an ADR**, not by whoever writes the first component.
Constraints the decision must satisfy:

- Builds to static assets embeddable via `go:embed`. One binary ships everything.
- Builds offline / in CI with no network fetch at build time.
- Works with JS disabled at least far enough to say so.
- Accessible: keyboard navigable, WCAG AA contrast, real focus states.
- Dark mode.
- Dense, information-first design — an operator tool. Tables, filters, copyable digests.
  Not a marketing page.
- Renders from an effective-permissions endpoint; hides unusable actions (§5).
- The API is the contract; the UI is one client of it. Nothing is UI-only.

**Chosen stack (ADR 0019, `docs/adr/0019-ui-stack.md`):** Svelte 5 + Vite static
SPA, TypeScript, near-zero runtime dependencies, hash-based routing, pnpm with a
committed lockfile and cached store for offline CI builds, `go:embed` of
`web/dist`. Dark is the reference theme; axe/WCAG-AA checks run in the Playwright
smoke suite. Follow it.

---

## 11. Conventions

**Go style.** `gofmt`, `go vet`, `golangci-lint` (errcheck, staticcheck, gosec, revive)
clean. Accept interfaces, return structs. Interfaces defined by the consumer.
`context.Context` first parameter on anything doing I/O. No naked returns. No `panic`
outside `main`.

**Errors.** Sentinel errors for control flow, typed errors for data. Registry errors map
to spec-defined OCI error codes (`BLOB_UNKNOWN`, `MANIFEST_INVALID`, `DENIED`,
`UNAUTHORIZED`, `TOOMANYREQUESTS`, …) — the wire format is contract and is golden-tested.

**Security posture.** All input validated at the edge. Repository names matched against a
strict allowlist regex before touching a path, an upstream URL, or a binding pattern.
Digests verified on every read and write, including content from an upstream.
Constant-time token comparison. Argon2id for passwords. Rate limiting on auth endpoints.
Default deny — a new endpoint with no explicit permission check must fail closed, and
there is a test that walks the route table to prove none is unguarded.

**Commits.** Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`,
`chore:`). Subject ≤72 chars, imperative. Body explains why. Reference the `status.md`
task ID. Re-read §0.1 before writing the trailer.

**Docs.** Every exported symbol has a doc comment. Operator-facing docs live in `docs/`
and are updated in the same PR as the behaviour they describe.

---

## 12. Feature parity checklist

Derived from Nexus Repository and AWS ECR. If a task adds something outside this table,
it needs an ADR first.

| Capability | Prior art | Target |
|---|---|---|
| Hosted repositories | both | v1 |
| Proxy / pull-through cache | Nexus proxy, ECR PTC rules | v1 |
| Group / virtual repositories | Nexus groups | v1 |
| Upstream credentials per remote | both | v1 |
| Negative cache TTL, tag revalidation TTL | Nexus | v1 |
| Routing / allow-block rules on proxies | Nexus routing rules | v1 |
| **Roles and privileges** | Nexus roles/privileges, ECR IAM | v1 |
| **Repository-scoped role bindings** | Nexus content selectors, ECR repo policies | v1 |
| **Anonymous access control** | both | v1 |
| **Robot accounts / user tokens** | Nexus user tokens, ECR auth token | v1 |
| **Effective-permission explainer** | AWS IAM policy simulator | v1 |
| External identity (OIDC/LDAP/SAML) | Nexus realms | v1.1 (Q3: local subjects + groups in v1) |
| Cleanup & retention policies | both | v1 |
| Retention dry-run / preview | ECR lifecycle policy preview | v1 |
| Tag immutability + prefix exceptions | ECR | v1 |
| Last-pulled timestamp & pull counts | ECR `lastRecordedPullTime` | v1 |
| On-push scanning | both | v1 |
| Continuous / scheduled rescan | ECR enhanced scanning | v1 |
| Registry-wide scan config with filters | ECR | v1 |
| Vulnerability blocking on pull | Nexus Firewall / Harbor | v1 |
| Storage quotas | Nexus blob store quota | v1 |
| Events / webhooks | ECR + EventBridge, Nexus | v1 |
| Audit log | both | v1 |
| Read-only maintenance mode | Nexus | v1 |
| Scheduled maintenance tasks | Nexus task scheduler | v1 |
| Blob store compaction / GC | Nexus compact task | v1 |
| Prometheus metrics + health endpoints | Nexus metrics | v1 |
| Search across repositories | Nexus search | v1 |
| Full REST API parity with the UI | both | v1 |
| Encryption at rest | ECR KMS | delegated to fs/S3 layer (Q13); app-encrypted secrets only |
| Signature verification & enforcement | ECR/cosign, Harbor | v1: store/display + presence gating; full verify v1.1 (Q4) |
| Staging / promotion between repos | Nexus staging | v1.1 (Q15) |
| Replication between instances | ECR replication rules | v1.1 |
| Repository creation templates | ECR | v1.1 |
| Soft delete with recovery window | — | no — immediate delete, GC lag as grace (Q16) |
| Non-OCI formats (Maven/npm/PyPI) | Nexus | no |
| Multi-tenancy / tenant isolation | Harbor | no |

---

## 13. Decisions — all questions resolved (2026-09-01)

Every open question is decided. Do not re-litigate these in implementation sessions;
the ADRs (D-002 … D-022 in `status.md`) formalise the details. If new evidence
challenges one, raise it explicitly — never silently diverge.

| Q | Decision |
|---|---|
| Q1 | Name **`trove`**, module `github.com/steveokay/trove`. |
| Q2 | **Trivy as a Go library**, in-process, quarantined behind `scan.Scanner` in the adapter package. |
| Q3 | **Local users, robot accounts, and local groups only in v1.** OIDC lands in v1.1 by mapping external groups onto local groups. |
| Q4 | **Store + display signatures in v1**; pull gating may check signature *presence* ("unsigned"). Full cryptographic verification (keys, Fulcio/Rekor) is v1.1. |
| Q5 | **Single node for v1.** In-process locking, GC, and single-flight; interfaces keep the door open for shared-state HA later. |
| Q6 | **Air-gapped is a v1 requirement**: offline install + `trove db import` for the CVE DB. |
| Q7 | Ship **presets for Docker Hub, ghcr.io, quay.io, registry.k8s.io, gcr.io — all disabled** until enabled by the operator. Quickstart enables Docker Hub. |
| Q8 | **Per-repo and global quotas in v1.** Hosted: soft-warn event, then hard-deny pushes. Cache breach never fails pulls — it evicts harder (LRU) instead. |
| Q9 | **Apache-2.0.** |
| Q10 | Deleting a child manifest still referenced by an index is an **error** (spec-shaped, names the referencing index). Delete the index first. |
| Q11 | **Global cache budget (default 50 GB) + LRU**, overridable per proxy; **tag-revalidation TTL 15 m** (conditional requests); **negative-cache TTL 60 s**. All per-repo tunable. |
| Q12 | **Pull gating off by default** — observe first; operators enable per policy. |
| Q13 | Blob encryption at rest **delegated to the filesystem/S3 layer** (LUKS/ZFS/SSE), documented. App-level encryption applies to secrets only (Q21). |
| Q14 | **RBAC is additive-only. No deny rules.** Decision is the union of matching bindings. |
| Q15 | **Promotion workflow deferred to v1.1.** |
| Q16 | **Immediate delete; GC lag is the natural grace window.** No trash-can model in v1. |
| Q17 | `trove migrate --from` supports **any distribution-spec-compliant registry, generically** (catalog walk or explicit repo list), resumable. Source-specific config import deferred. |
| Q18 | Unauthorized reads return **404 / `NAME_UNKNOWN`** — existence is hidden, uniformly across registry API, admin API, referrers, and group behaviour. Unauthenticated still gets `401` + challenge. |
| Q19 | Bindings attach to **subjects and local groups/teams**. |
| Q20 | Binding scopes are **repository patterns only** — no tag-level scoping. Tag-level needs are met by per-repo tag policies (immutability, protected tags). |
| Q21 | Secrets encrypted with an **auto-generated 32-byte keyfile** (0600, path configurable), AES-256-GCM. Rotation via a re-encrypt command. Backups must include the keyfile — documented. |
| Q22 | Deleting a subject artifact **cascade-deletes its referrers** (SBOMs, signatures, scan results), each audited individually. |
| Q23 | The CLI is a **client of the admin API** (`trove login`, `TROVE_TOKEN`). Offline exceptions: `serve`, `version`, and an explicit `--offline` mode for `db import` / disaster recovery. |
| Q24 | The pull that triggers a cache fill is **served immediately**; scan runs async and gates subsequent pulls. Per-policy strict "block-until-scanned" mode exists for high-security repos. |
| Q25 | **Native Windows dev** for the inner loop (revised 2026-09-01; was WSL2). Unix-only tests skip on win32 via `runtime.GOOS`. `make test-linux` runs the full suite in an Ubuntu-based Go container (repo bind-mounted, Go caches on a named volume, docker socket mounted so testcontainers works). Linux CI remains the authoritative gate. |

---

## 14. `status.md` protocol

`status.md` at the repo root tracks every task. Update it in the same commit as the work.

Each task carries: ID, title, phase, status (`todo` / `blocked` / `in-progress` /
`review` / `done`), owner, dependencies, acceptance criteria, and current coverage for
the packages it touched.

- Planning sessions **add** tasks. Implementation sessions **move** them.
- A task reaches `done` only when: acceptance criteria met, tests written, coverage gate
  green, lint clean, docs updated.
- `blocked` tasks name the blocker and the question that would unblock them — every open
  item in §13 that blocks work has a `blocked` task pointing at it.
- Never delete a task. Move it to `Dropped` with a one-line reason.
- Parallel agents update only their own task rows. Reconcile before fanning out.

---

## 15. Definition of done

- [ ] `go build ./...`, `go vet ./...`, `golangci-lint run` clean
- [ ] `go test ./... -race -covermode=atomic -coverpkg=./...` green, coverage ≥95%
- [ ] OCI conformance suite green
- [ ] Adversarial and edge cases tested, not just the happy path
- [ ] Every new endpoint has an explicit permission check; route-table guard test passes
- [ ] Every new permission verb has a positive *and* a negative test
- [ ] New listings/queries are permission-filtered at the query layer (§0.5)
- [ ] Cached and hosted deletion paths still provably separate (§4)
- [ ] Operator-facing docs updated
- [ ] `status.md` updated
- [ ] No AI attribution anywhere in the commit or metadata (§0.1)
