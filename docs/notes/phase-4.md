# Phase 4 — completion notes

The full completion write-ups for phase 4 tasks, moved out of the `status.md`
acceptance column per the CLAUDE.md §14 convention. One frozen section per
task, in board order.

## C-001 — Repository model + router (hosted/proxy/group)

`internal/repo` is the pure model half of ADR 0005, built ahead of its handler integration (which lands with C-016, where entities become creatable and hence routable). **The router:** `Split(fullName) → (entity, remainder)` — entity is the first path segment, remainder the rest, and nothing that fails `reponame`'s grammar gets far enough to route. `FuzzSplit` holds it to two invariants over 6M+ executions: it never accepts what the grammar rejects, and its output always reassembles into exactly the input with a single-segment entity. **`ValidateEntityName`** is the creation-side check C-016 must use, kept beside the router so creator and router cannot disagree about what an entity is: one legal segment, and `system` reserved — the Z-007 decision that a binding written `admin@system/*` must never almost-match a real repository. **`Writable(type)`** answers the §4 rule structurally: hosted only, and the signature has no config parameter, so "no configuration makes a proxy writable" is a property of the function type rather than a check somebody remembers; a group write is a routed write to its hosted writeTarget (C-011) or nothing. **Typed configs** (`ParseConfig`, strict decode refusing unknown fields and trailing documents): `ProxyConfig` carries the upstream root URL (scheme+host only — credentials refused outright because upstream secrets are their own `proxy:credentials` resource per C-003, paths/queries refused because the /v2/ prefix is added per request), the Docker Hub-style `default_namespace`, allow/block routing patterns validated by the binding-scope grammar (`authz.ParseScope`, one grammar one fuzzer, with the `system` form refused as meaningless in routing), per-repo TTL and offline-mode overrides (empty defers to global config); `HostedConfig` and `GroupConfig` are deliberately empty — hosted behaviour belongs to policies and quotas, and group members are relational (the `group_members` table keeps ordering schema-unique) rather than config. Per-proxy cache-budget override joins the shape with C-013's eviction. Config validation corpus covers every refusal with field-naming errors, because the admin API relays them to an operator fixing a YAML file. Coverage 95.4% overall.

## C-001 (integration) — prefix routing through the serving path

The bridge between the pure model and C-016, landed as one squashed change. **Routing:** `routeToEntity` in the registry resolves `repo.Split(name)` → entity row; an absent entity answers the byte-identical NAME_UNKNOWN; `hostedRepo` refuses writes via `repo.Writable`; the cross-repo mount resolves its source through the entity too (it would otherwise have silently stopped mounting). Full names remain what handlers key content by and what bindings match. **The data-model correction:** the F-006-era schema gave `manifests`/`upload_sessions` a foreign key to `repositories(name)` — invisible while entities were full names, contradictory under ADR 0005. Migration 0004 drops those FKs (Postgres by named constraint so a wrong name fails loudly; SQLite by table rebuild, with two recorded hazards: `PRAGMA foreign_keys` is a no-op inside the transaction every migration runs in, so the rebuild had to be correct with enforcement ON, and a naive `DROP TABLE manifests` would have fired `tags`/`manifest_refs` cascades and silently emptied both — rows are parked and restored, and a dedicated test seeds every affected table across the migration and counts everything back). The entity rule lives on as an explicit `reponame.Prefix` existence check in `PutManifest`/`PutTag`/`CreateUpload`. **A doc-vs-contract drift surfaced and was resolved:** store.go claimed `DeleteRepository` leaves content; the contract suite pinned the FK cascade that deleted it. Cascade won (Q16 immediate-delete; C-016 adds the `?confirm` gate), now explicit and implemented over a **range instead of `LIKE`** — `_` is both a LIKE wildcard and a legal name character, so `LIKE 'team_a/%'` would have deleted into `teamXa/api`. **Catalog:** `meta.ListContentNames` (DISTINCT content names, visibility in the query, keyset cursors that never name a hidden repository; contract cases for filtering, boundary pagination, cursor stability, distinctness, and the engines' failure tables) replaces entity listing in the handler; proxy (C-004) and group (C-012) enumeration documented as contributing nothing rather than answering wrongly. **Sweep:** fixtures became real entities (`team-a` hosted, `mirror` proxy, `secret` hosted) with bindings for bare-entity names and a granted-but-absent `ghost/*` so the handler's 404 is comparable against the guard's; ListTags's "known" rule became "entity exists and the name is the entity or holds content" so a typo stays NAME_UNKNOWN rather than a plausible empty page. Two follow-ups recorded: `internal/server/{listing,visibility}_test.go` still seed multi-segment repository rows (harmless, off-model), and `go test` compiles-but-never-runs benchmarks — the broken-and-green `bench_test.go` was caught with `-bench . -benchtime 1x`, worth a CI step. Coverage 95.3% overall.

## C-016 — Repository admin CRUD API

Five routes under `/api/v1/repositories`, all problem+json (ADR 0015), all over **entities** rather than content names — an entity is what an operator creates and configures, a content name is what a client pulls, and the catalog answers the other question. Creation takes `repo:create` at system scope (the repository does not exist yet to be scoped against) and runs the name through `repo.ValidateEntityName`, which is what makes the Z-007 `system` reservation real at the only door that could have violated it; type must be one of the three; config is validated by `repo.ParseConfig` before the store sees it. Listing is a Listing route (guard-computed Visibility, cursor-paginated) and deliberately carries **no configurations** — a listing that inlined them would either decide `proxy:read` once per row or leak upstreams to anyone who may list. **Two ADR 0002 conjunctions live in the handler**, for the same reason the referrers API's does (one verb per route): reading a proxy's configuration needs `proxy:read` on top of the `repo:list` that admitted the request — and the key is *omitted rather than nulled*, so "you may not see this" and "there is nothing here" are the same absence — while changing one needs `proxy:write` on top of `repo:configure`, refused with 403 rather than 404 because `repo:configure` already disclosed existence. Hosted deletion demands `?confirm=<name>` repeated exactly: the store's delete cascades every manifest, tag, and upload under the entity (the C-001 integration made that cascade explicit) and blob bytes wait for GC, which is the only grace window there is (Q16). Proxy and group deletions need no confirmation, and that is not leniency — a proxy's content is re-fetchable and a group stores nothing at all. **Config history** (migration 0005 in both engines; `UpdateRepositoryConfig` gains an actor and an injected time) appends the *superseded* revision inside the update's own transaction, so a crash cannot leave a version nobody can account for; creation writes no row because the live row is revision 1, and the history cascades with the entity so a recreated name never inherits a predecessor's upstreams. `ListConfigHistory` exists for tests and the future support bundle; no HTTP endpoint yet, because its proxy-config disclosure story belongs with that task. **Verbs:** `repo:create`, `repo:configure`, `repo:delete`, `proxy:read`, `proxy:write` all come off the §9 pending list (23 → 18), each with a positive and a negative proving ADR 0002's splits — every fixture subject is bound at `*` **and** `system` at once, so no refusal can be an artifact of scope shape rather than of the verb. Store failures are problem-shaped 500s through a faulty wrapper that leaves the guard's own lookups working, and an unreadable bindings store fails both sub-decisions closed. **Provenance:** built by an agent that hit its session limit after finishing the meta layer and handler; the reconciler wrote the test suites, wired serve, and closed the coverage gap its absence left (the first pass measured 94.8% — a store-closing failure test was tripping the guard before reaching any handler branch, which is exactly the trap the registry's faulty-store pattern exists to avoid). Coverage 95.3% overall.

## C-010 — Proxy routing rules

`internal/repo/routing_rules.go`: `CompileRoutingRules(ProxyConfig) → RoutingRules` parses each allow/block pattern once into an `authz.Scope` — ADR 0005's "one grammar, one fuzzer" taken literally, so there is no second matcher to disagree with binding scopes — and `Evaluate(path) → RoutingDecision` answers in a fixed precedence: an explicit block, then an explicit allow, then the default (allow, or deny under `default_deny`). The decision carries **which** pattern matched and why, because an operator debugging a blocked pull needs that and the UI will show it. Compilation re-validates rather than trusting `ProxyConfig.Validate`, and additionally refuses the bare `system` scope, which matches no repository and so could never fire as a rule. **Traversal closure:** `Evaluate` runs the path through `authz.Repository`, so the check that validates and the check that decides are the same check; an illegal or empty path is an error with a zero (non-allowing) decision under *both* defaults, rather than matching nothing and falling through to default-allow into the upstream URL builder. A `FuzzRoutingRules` target seeded from Z-007's adversarial corpus ran 8.1M executions asserting, among other things, that no input is ever both allowed and blocked and that `default_deny` with no allow rules admits nothing.

**The one real ADR 0005 gap, and how it was settled.** ADR 0005 and the phase plan both say rules apply "on remainders", but the Docker Hub preset rewrites `nginx` → `library/nginx`, and the two readings disagree about the most common pull there is. The agent implemented it as a caller's choice, documented the raw remainder as intended, and flagged it — correctly, since the code cannot settle a question about intent. **Reconciled to the rewritten upstream path**: the rules exist so a proxy cannot become an open relay, which is a statement about what we fetch *from the upstream*, and C-010's own acceptance criterion is a Docker Hub proxy restricted to official images in one rule — under the raw-remainder reading `library/*` would deny `nginx`, denying the single most common pull on the preset the criterion names. C-004 and C-014 pass the rewritten path; the code comment now states this and says why the alternative loses.

## C-011 — Group resolution

`internal/repo/group.go`: `Resolve(members []MemberState, reference string) Resolution`, pure over already-filtered member state — **no store, no clock, no I/O**, which is exactly what lets C-012 do its permission filtering *before* calling and what makes the whole matrix exhaustively table-testable (ADR 0005 §4). Members are walked in position order: the first that served wins and members after it are never examined (so a lazy caller may leave them unasked, and a required-but-down member behind the winner does not fail the group); a not-found member is passed over silently; a down or malformed one is skipped with a `group.member.skipped` payload recorded for the caller to emit — **unless it is `Required`, which fails the group 503-class** and names it. Malformed and digest-mismatched results are treated as down for the request and never served through. **An empty member list answers exactly like all-not-found**, which is the property that makes C-012's filtering invisible: a subject who cannot read any member gets the same answer as one asking a group that has none. Nesting (`meta.Group` as a member), unknown types, and duplicate positions or names are refused whole before the walk — the schema's uniqueness constraints already prevent the duplicates, so those checks are assertions that keep the determinism property true. `FuzzResolve` ran 4.4M executions asserting determinism under permutation, that a served result names the earliest actually-served member, and that a required failure before any winner always fails the group at the earliest such position.

**Six further decisions the agent flagged, all confirmed:** `MemberState.Type` was added beyond the brief so the no-nesting rule can be refused loudly rather than assumed; the zero `RoutingRules` value means "a proxy with no rules" and allows, identical to compiling an empty set, rather than a fifth fail-closed state; a required member that fails is *not* also listed as skipped, since it stopped the resolution rather than being passed over (the 503 names it instead); duplicate positions are refused rather than tie-broken; the `reference` is opaque to `Resolve` because the tag/digest grammar lives in `internal/registry` and duplicating it would be a second grammar; and a `system/`-prefixed remainder is decidable by `*` or the default but not nameable by a rule, inherited from ADR 0001. **For C-012:** filter members at the query layer before building `[]MemberState`, do not renumber positions after filtering (they are stored ordering and gaps are fine), map `GroupNotFound` to the same 404 an empty group gives, and note that skip payloads carry member names — the event layer must not deliver them to a subscriber that cannot read the named member.

## C-002 — Upstream client interface + contract suite

`internal/proxy` is the first piece of §4's "highest-risk subsystem", and the interface is frozen here for C-004..C-009 to build on: `ResolveTag` (conditional, so an unchanged tag costs no bandwidth), `FetchManifest` and `FetchBlob` (both digest-verified), and `RateLimit()`. The `repository` argument is the **upstream** path — rewriting and routing rules (C-010) happen before the call. **Errors are a total sentinel mapping**, so no caller ever branches on a status code: not-found, unauthorized, rate-limited (`errors.As` to a `*RateLimitedError` that never invents a delay it was not told), digest-mismatch, and unavailable — with every unmapped status folded into unavailable so the set stays total. Three sentinels were added and justified beyond the brief: `ErrRedirectRefused` is deliberately **not** an unavailability, because an SSRF attempt must not hide behind a stale-content warning; `ErrInvalidReference` and `ErrManifestTooLarge` are not retryable, so they are not outages. Digest work reuses `internal/blob` end to end — the mismatch error **is** `blob.ErrDigestMismatch` under a local name, one verification and one error — and `FetchManifest` returns nothing at all on mismatch, so unverified bytes never reach a caller that might cache them.

**The SSRF/redirect policy is a pure function with no I/O** (`redirect.go`), which is what makes it exhaustively table-testable — 40 rows, plus end-to-end coverage through a virtual-host transport that rewrites the dial address while leaving URL and Host intact, since every httptest server is otherwise 127.0.0.1 and host-family behaviour would be untestable. The rules: a 5-hop cap; `https→http` refused judged against **both** the original upstream and the immediate hop, so a chain cannot launder a downgrade; scheme restricted and userinfo refused; a private, loopback, link-local, or unspecified address that is not the upstream itself refused **before** `TrustedHosts` is consulted. The same policy guards the `WWW-Authenticate` realm, which is the detail that matters most — that realm is where the operator's upstream password would be sent, and credentials attach only to the upstream host family plus that policy-checked realm, so a CDN redirect gets none. Documented limitation: the policy is URL-level, so DNS rebinding needs a control dialer, which is a follow-up rather than C-002.

**The contract suite** (`clienttest`, in the metatest/blobtest style) has two halves: `Run` (12 cases any spec-compliant upstream must satisfy, including that an unchanged conditional resolve transfers no body — asserted from recorded response bytes rather than from a mock's say-so) and `RunFaults` (14 faults). It runs against **both** a real `registry:2` testcontainer and the in-process fake, and running the same suite against both is the deliberate part: it makes the fake provably contract-equivalent, so C-004..C-008 can build against the fake without their tests drifting from real registry behaviour. registry:2 proves the client against genuine HEAD/`Docker-Content-Digest`/ETag/404 semantics; httptest covers what a real registry will not do on demand (429s, redirect loops and downgrades, private-address targets, digest mismatches, malformed challenges, stalled and truncated bodies, token-endpoint failures).

**Decisions the ADRs did not settle, all confirmed at reconcile:** "same registry family" was undefined, and is now same host, a subdomain of it, or an explicit `TrustedHosts` entry — strict eTLD+1 would break Docker Hub (`auth.docker.io` plus a `*.docker.com` CDN) while a public-suffix guess would silently trust co-tenants; **C-014's presets will need `TrustedHosts`, and `repo.ProxyConfig` has no field for it yet**. The client neither retries nor sleeps on 429, it only reports state — backoff is C-009's. `RequestTimeout` bounds the header phase of the whole redirect chain and is released once headers arrive, so a large layer streams under the caller's context; C-004 owns the body deadline. A HEAD answering 405/501 falls through to GET (real middleboxes do this) while 404/401/429 are definitive, so a throttled HEAD never becomes a second request. `tagPattern` is duplicated from `internal/registry` because the agent could not touch that package — extracting it to a leaf package beside `internal/reponame` is a noted follow-up. **`clienttest` joined the §9 named-harness exclusion list** — the documented deliberate edit, with its self-test gaining a counter-assertion that `registryclient.go` is still counted; CLAUDE.md §9's list was updated to match, since it names the harnesses explicitly. Coverage 95.7% overall.

## C-003 — Upstream credential storage

The acceptance criterion is a negative one — "no read path returns a credential" — so the work is mostly proving an absence, and the design makes that absence **structural rather than a rule handlers follow**. `server.RepositoryAdminStore`, the consumer-declared slice the admin API writes through, lists the put, status and delete methods and **omits `GetProxyCredential` entirely**: the handler's type has no method that could return a sealed value, so no future edit to a handler can leak one without first widening an interface. Two details reinforce it: the status is a *distinct type* rather than the credential type with the secret blanked (a blanked field is one assignment away from being populated), and the SQL behind the status selects `rotated_at` only, so the ciphertext is never even in a result set. `GetProxyCredential` exists for exactly one caller and its doc comment names it.

**Storage** is migration 0007 in both engines: `proxy_credentials` keyed by entity name, cascading with the repository as `repository_config_history` does. The sealed payload is `{"username","password"}` JSON under `secretbox.ProxyCredential(<repo>)` — **the username is sealed too**, because half a credential in the clear on every backup and replica is precisely the half that names who the token belongs to. JSON inside the ciphertext so rotation can re-seal values it does not interpret and a later field is backwards-compatible; the format is defined in one file that both seals and opens, since a format defined twice is a format that drifts. A missing row is `ErrCredentialUnavailable`, never a silent downgrade to anonymous — that would turn a broken credential into a confusing upstream 404. The JSON unmarshal error is deliberately *dropped* rather than wrapped, because `encoding/json` quotes the input it choked on and that input is a decrypted credential.

**HTTP**: `PUT` and `DELETE` on `/api/v1/repositories/{name}/credentials`, both gated `proxy:credentials` alone — no conjunction, because that verb is implied by nothing (ADR 0002). The repository GET gains `credential: {set, rotated_at}`, present only for a proxy and only behind the same `proxy:read` conjunction that serves `config`, omitted entirely otherwise for the same reason `config` is. There is no GET of the credential at any verb, and the status resource has no field for a value. A route-table walk asserts exactly two `/credentials` routes, both writes, both behind `proxy:credentials`.

**Proving the absence.** Every assertion is `strings.Contains` over the **whole serialized body** — never a named field — for the password, the username, the exact sealed string, and a bare `v1:` prefix. Probed across five subjects including an every-verb administrator, on the entity GET, the listing, the config-update echo, and three refusal bodies (a 403'd write, a rejected body, unparseable JSON), since problem documents are the likeliest place to echo a request back. The probes are proved non-vacuous: each test reaches past the handler, confirms the row exists, and opens it to the exact pair that was written. The **AAD swap test** seals for one repository, writes those bytes directly into another's row, and proves the original still opens while the transplant fails authentication — so the failure is the context binding rather than corruption, and a stolen row is useless elsewhere. `StoredCredentials` builds its context from its own repository field rather than the row's, which is what makes that true. A config-dump scan renders `String()` and `Explain()` with real secrets in every `redact:"true"` field and asserts none survive, plus that the placeholder is present so the test cannot pass by rendering nothing.

**For E-011** (`trove support-bundle`, not yet built): it inherits this obligation verbatim — ADR 0016 names the bundle alongside the config dump, and it must be scanned for `trove_r_`, `trove_p_` and `v1:`. Keyfiles appear as existence and fingerprint only, and if the bundle renders repository config history it must never join `proxy_credentials`; credential *state* may appear as set/rotated-at, never as a value.

**Five ADR 0016 ambiguities the agent flagged, all confirmed:** the username is sealed (the ADR said "credentials" without saying which halves); both halves are required non-empty, which is a mild real restriction since some registries accept any username with a PAT as the password; the set/unset status sits behind `proxy:read` rather than `proxy:credentials`, on the grounds that whether a proxy authenticates is part of how it is configured and an operator debugging an upstream 401 should not need the write verb to see it; `DELETE` of an unset credential is 404 rather than an idempotent 204, consistent with the resource's other deletes; and `trove admin rotate-secrets` (ADR 0016's rotation command) still has no task — when it lands it will need a `ListProxyCredentials`, deliberately absent today because nothing needed one. **Reconcile:** serve now threads the keyring into the admin API, without which the two credential routes answer 500 and log the reason. `proxy:credentials` comes off the §9 pending list, leaving 16.


## C-004 — Blob/manifest fetch-and-cache by digest

The first task that writes cached content, so most of it is the storage family
ADR 0006 named and nothing had built yet: `meta.CachedManifest`,
`CachedManifestRef` and `CachedBlob`, reached only through the new
`CachedContentStore`, over `cached_manifests` / `cached_manifest_refs` /
`cached_blobs` in **migration 0008** (both engines, column for column, with the
`COLLATE "C"` the parity test demands). The rows hold no foreign key to
`repositories` — content is keyed by full name and the row it needs is its
*entity*, exactly as 0004 settled for hosted content — so `DeleteRepository`
sweeps them by name range beside the hosted tables, which is the one operation
that legitimately spans both families because it is deleting the entity that
owns them. `last_access_at` is a column and an index from the start: it is what
C-013 ranks by, and adding the LRU key later would mean a migration over the
largest tables in the deployment.

**Every cached write requires its entity to be a proxy**, not merely to exist.
That is the wall that matters here: cached content is *defined* by being
refillable from an upstream, and a row under a hosted entity would claim
recoverability the deployment cannot deliver — the only copy of those bytes
would be sitting in the cache store, where eviction is free to take it. A
hosted or group entity is `ErrInvalid`, a missing one `ErrNotFound`, and the
contract suite proves both against all three implementations. A second contract
case writes the *same digest* as hosted content and as cached content and shows
each family answers only through its own methods, so a statement in the wrong
package has no row to reach even before it has no type to name. See the
ADR 0009 clarification for why the blob-side `HostedRef`/`CachedRef` newtypes
wait for the first deleting caller instead of landing here.

**The filler** (`internal/proxy/fill.go`) is `Manifest` and `Blob` over a
per-call `Target` — repository, upstream path, remote name, client — rather
than a per-repository object, because one process serves many proxies and only
the cache, the clock and the event sink are shared. Both check the cache first
and both verify through the client rather than re-verifying: the mismatch error
*is* `blob.ErrDigestMismatch` (C-002), and one verification with one error is
what makes a mismatch mean the same thing everywhere. A blob miss streams to
the client and into an upload session at once, and publishes nothing until the
stream ends and the whole of it verified — so a client that disconnects
halfway, an upstream that truncates, and an upstream that lies about its bytes
all leave the cache exactly as it was. The bytes go in before the row, and that
asymmetry is deliberate: a row with no bytes is a miss the read path already
handles, while bytes with no row are invisible to this proxy and wait for the
eviction sweep's orphan pass — leaking recoverable bytes is the cheaper of the
two, and neither loses anything irreplaceable, which is the whole difference
between this path and the hosted one.

**A cache failure is not a pull failure.** The bytes are already correct and
already in hand; refusing to serve them because the disk or the metadata store
would not take a copy turns a degraded cache into an outage. Every cache-write
failure — session refused, write refused, commit refused, row refused, entity
not a proxy — is logged and served through, and both result types carry a flag
saying whether the cache actually holds what was served, so the degraded state
is visible instead of indistinguishable from success. The one exception is a
cache *read* that fails: that is returned, because falling through to the
upstream would turn a broken metadata store into a stampede against somebody
else's registry, which is the failure a pull-through cache exists to prevent.

**Two decisions the ADRs did not settle.** A manifest this registry cannot
parse is refused rather than cached opaquely — it could not be accounted for,
gated, or scanned, and the push path refuses the same media types (R-002) — and
the refusal is `ErrUpstreamUnavailable` through a typed `UnusableContentError`,
so group resolution treats such a member exactly as it treats one that is down
(C-011) and the client's sentinel set stays closed and total. And the access
time is written on fill only: touching on serve is a write on the hot path, so
it belongs with C-013's batched writer, in the shape R-010 already established
for pull statistics.

**Not wired into the serving path.** Nothing constructs a `Filler` in `serve`
yet, because a proxy pull needs a tag to resolve before it needs a digest to
fetch; C-005 brings the lease and the wiring together. `ListContentNames` also
still lists hosted content only — what a proxy's catalog should report is a
decision that belongs with the task that serves proxy pulls, and answering it
here would have settled it by accident. Coverage 96.1% overall, `fill.go` at
100%.

## C-005 — Tag → digest lease with TTL and revalidation

The distinction the whole subsystem turns on, made concrete: content fetched by
digest is cached forever (C-004), and the mapping from a *name* to a digest is
a lease held for a TTL. `tag_leases` is **migration 0009** in both engines,
keyed by repository and tag, swept with the rest of the cached family when its
entity goes.

Three columns needed a decision. `fetched_at` is when the mapping was last
*confirmed* rather than first learned, so an unchanged revalidation moves it
while leaving the digest alone. `ttl_s` records the interval that was in effect
when the row was written and is **not** what expiry is computed from — the
resolver reads the repository's current TTL, because an operator who lowers it
expects the next pull to revalidate, not the pull after every lease happens to
be rewritten. And `stale` is deliberately not "past its TTL", which is
derivable from `fetched_at` and would drift the moment it were stored: it marks
a lease whose last revalidation could not be completed and which was served
anyway, which is a real event nothing else remembers and the flag an operator
reads when asking why a cluster is pulling yesterday's image. ADR 0006 named
the column without saying which of the two it meant; this is the reading that
carries information.

`Filler.ResolveTag` has three outcomes. A lease inside its TTL answers with no
upstream request at all. An expired one is revalidated **conditionally** —
the upstream is told the digest and entity tag we hold, and an unchanged tag
transfers no manifest body, which C-002's contract suite already proves against
both registry:2 and the fake. Unchanged moves the deadline and nothing else;
changed caches the new manifest *from the bytes the resolution already carried*
(re-fetching by digest would pay for them twice) and repoints the lease, while
**the old manifest stays cached** — an image pinned by digest keeps working,
which is why nothing is deleted here. A tag the upstream no longer has drops
its lease and answers not-found, and the manifest it named stays cached for the
same reason.

**Degraded mode covers outages and nothing else.** Unreachability and 429 serve
the expired lease with `cache.stale-served` and a `Stale` flag; `strict` fails
instead. A rejected credential and a refused redirect do *not*: they are a
configuration problem and a security event, and serving stale content through
either would replace a loud failure with a quiet one. The stale path marks the
lease but does **not** move `fetched_at` — refreshing the deadline there would
let one unreachable upstream buy a full TTL of silence before anything tried
again. C-008 refines "unreachable" into dial, DNS, and timeout and wires the
mode through configuration; the decision about which failures qualify does not
change with it.

`TagTTL` and `Offline` live on the per-call `Target` rather than on the Filler,
because they are per-repository configuration and one process serves many
proxies. A zero TTL means revalidate on every pull (Q11), so it is *not* a
missing value the package fills in with the 15-minute default: whoever builds
the Target from configuration applies that, and a zero-value Target is
deliberately the conservative one.

Not in scope, and each absent on purpose: single-flight (C-006 — N concurrent
cold pulls still make N resolutions), negative caching (C-007 — a typo'd tag
reaches the upstream every time), and the serving-path wiring, which lands with
the task that mounts proxy pulls on `/v2/`. Coverage 96.2% overall, `lease.go`
at 100%.
