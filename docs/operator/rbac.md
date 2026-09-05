# Access control

Who can see and do what in trove, how to set it up, and how to work out why
somebody is getting a 404 they did not expect.

> **What exists today.** The model below is real and enforced on every request.
> The repository admin API (`/api/v1/repositories`), password rotation, and
> `trove auth explain` all work now. **The API and CLI for creating subjects,
> roles, and bindings do not exist yet** — they land with U-007. Until then the
> bootstrap administrator is the only subject a fresh install has, and the
> worked setups below describe the bindings you will create rather than the
> commands you will type. The concepts, verbs, scopes, and behaviour are stable;
> only the administration surface is pending.

## Three concepts, kept separate

**A subject** is a user, a robot account, or `anonymous`. Anonymous is a real
subject with real bindings, not a bypass: an unauthenticated request is a
request *by* the anonymous subject, and it walks the same authorization path as
everyone else. There is one code path, so there is one set of rules to get
right.

**A role** is a named set of permissions. Six ship built in; you compose your
own from the same vocabulary. No permission exists that a custom role cannot
hold, and none bypasses a check.

**A binding** grants `(subject or group) → role → scope`. Bindings are what you
actually administer. A subject with no bindings can do nothing; a subject with
three bindings can do the union of all three.

### Bindings are additive. There are no deny rules.

The decision is the union of every binding that matches. This is deliberate and
it is the Kubernetes model: deny rules make effective permissions depend on
evaluation order, which makes them unpredictable in exactly the situations you
most need to predict them.

The practical consequence is a naming discipline. Because you cannot carve an
exception out of a grant, **you express exceptions in the namespace instead**.
If `team-a` should see everything under `team-a/` except one secret repository,
that repository does not live under `team-a/`. Decide this when you name things,
not when you grant them — renaming a repository later means retagging every
image that references it.

## Scopes

A binding's scope is exactly one of four forms:

| Scope | Means |
|---|---|
| `system` | Global, non-repository permissions: user administration, GC, maintenance mode |
| `*` | Every repository |
| `team-a/api` | Exactly that repository |
| `team-a/*` | Every repository under that prefix, at any depth |

The only wildcard is a single trailing `/*`, or a bare `*`. Mid-pattern forms
(`team-*/api`, `*/prod`) are refused: they reintroduce precedence reasoning to a
model that is deliberately additive.

Two details that surprise people:

- **`system` and `*` are disjoint.** A `*` binding reaches every repository and
  grants nothing global; a `system` binding does the reverse. The built-in
  administrator is bound at both, because administering the registry and
  reaching every repository are two different grants.
- **`team-a/*` does not include `team-a` itself.** The prefix form matches what
  is *under* the path. If content lives directly at the entity name, grant that
  name too.

The `system` prefix is reserved: no repository may be named `system` or live
under `system/`. A binding written `admin@system/*` by somebody meaning the
global scope would otherwise grant nothing while looking like it granted
everything.

## The permission vocabulary

Thirty verbs. Some splits exist specifically because collapsing them is a
real incident:

| Split | Why |
|---|---|
| `repo:write` does not imply `repo:delete`, `tag:delete`, or `manifest:delete` | Pushing is not purging |
| `tag:delete` does not imply `manifest:delete` | Untagging abandons an artifact to retention; deleting destroys it and its signatures now |
| `policy:write` does not imply `policy:apply` | Authoring a retention rule is not executing a deletion plan |
| `proxy:write` does not imply `proxy:credentials` | Changing an upstream is not reading its password |
| `gate:override` is implied by nothing | Breaking past a vulnerability block is always deliberate |
| `referrer:read` additionally requires `repo:read` on the subject | A user who cannot pull an image cannot read its SBOM |

The full list: `repo:list` `repo:read` `repo:write` `tag:delete`
`manifest:delete` `referrer:read` `repo:create` `repo:configure` `repo:delete`
`scan:read` `scan:trigger` `policy:read` `policy:write` `policy:apply`
`gate:override` `proxy:read` `proxy:write` `proxy:credentials` `quota:read`
`quota:write` `webhook:read` `webhook:write` `search:read` `user:read`
`user:write` `role:read` `role:write` `audit:read` `gc:run`
`system:maintenance`.

## Built-in roles

Read-only and non-deletable. `admin`, `operator`, and `auditor` are *derived*
from the vocabulary rather than listed, so they cannot fall behind it when a
verb is added.

| Role | Holds |
|---|---|
| `admin` | Every verb |
| `operator` | Every verb except `user:*` and `role:*` — runs the registry without administering its people |
| `publisher` | `repo:list` `repo:read` `repo:write` `tag:delete` `referrer:read` `scan:read` `search:read` |
| `developer` | `repo:list` `repo:read` `referrer:read` `scan:read` `search:read` |
| `auditor` | `repo:list` plus every `:read` verb, including `audit:read`. Writes nothing, anywhere |
| `anonymous-reader` | `repo:list` `repo:read` `referrer:read` |

`anonymous-reader` **ships unbound**. A fresh install is not readable by the
internet because somebody forgot to look; anonymous access begins the moment an
administrator binds that role to the `anonymous` subject, and not before.

> **`auditor` sees everything.** `audit:read` is system-scoped and intentionally
> global — the audit log records actions across every repository, so a subject
> that can read it can see the names of repositories it cannot pull from.
> Granting `auditor` is granting registry-wide visibility. This is the one
> deliberate exception to "unreadable means invisible"; treat the role as
> privileged.

## Worked setups

### A small team: three roles

Most deployments need three grants and nothing more.

| Subject | Role | Scope | Gets |
|---|---|---|---|
| `alice` (you) | `admin` | `system` **and** `*` | Everything |
| `ci` (robot) | `publisher` | `*` | Push and pull everywhere; cannot delete manifests |
| everyone else | `developer` | `*` | Pull everywhere; write nothing |

Both admin bindings are needed — `system` for administration, `*` for content.
The bootstrap administrator is created this way on first run.

### Per-team, roughly twenty people

Bind roles to **groups**, not to people. Adding somebody to a team then means
one group membership rather than one binding per repository they should reach,
and removing them is a single revocation you can actually verify.

| Group | Role | Scope |
|---|---|---|
| `team-a` | `publisher` | `team-a/*` |
| `team-a` | `developer` | `shared/*` |
| `team-b` | `publisher` | `team-b/*` |
| `team-b` | `developer` | `shared/*` |
| `platform` | `operator` | `system` and `*` |

Name repositories `team-a/api`, `team-b/web`, `shared/base-images` and the
scopes write themselves. This is the naming discipline from earlier doing its
job: because grants follow the namespace, the namespace is the access-control
design.

### Robot accounts for CI

Robots get bindings like anyone else — no implicit privilege. Give each pipeline
its own robot rather than sharing one, so revoking a compromised credential does
not stop every build in the organisation.

Scope them to what they publish. A build that pushes `team-a/api` should hold
`publisher` at `team-a/api`, not at `team-a/*` and certainly not at `*`: the
blast radius of a leaked CI token is exactly its scope. Robot credentials carry
a mandatory expiry, and their tokens are re-checked against live bindings on
every request — revoking a binding stops an outstanding token on its next use,
not whenever it would have expired.

### Enabling anonymous pulls

Bind `anonymous-reader` to the `anonymous` subject at the scope you want public
— `*` for a fully public mirror, `public/*` for one namespace. Everything
outside that scope stays invisible rather than forbidden: an anonymous client
sees a 401 with a challenge, and an authenticated one that still lacks access
sees a 404.

To turn anonymous access off again, remove the binding — or disable the
`anonymous` subject, which switches it off wholesale without touching your
bindings.

## Troubleshooting

### "Not found" can mean "no permission"

This is the single most common confusion, and it is deliberate. If a subject
cannot read a repository, it does not appear — not in the catalog, not in a tag
list, not in a search result, and not as a 403. It answers exactly as a
repository that does not exist, byte for byte.

The reasoning: a 403 confirms existence, and confirmed existence is enough to
enumerate an organisation's projects by guessing names. The cost is that a
missing grant and a typo look identical from the outside, which is what the
explainer is for.

The status codes:

| Situation | Answer |
|---|---|
| No credentials presented | `401` with a `WWW-Authenticate` challenge |
| Authenticated, cannot read the resource | `404`, identical to absent |
| Authenticated, can read, lacks the write/delete verb | `403` — readability already disclosed existence, so a helpful error is safe |
| Anonymous, lacks read | `401` + challenge, not `404` — the client may be able to authenticate into visibility |

### `trove auth explain`

The answer to "why can this person not push?" — it runs the same decision
function the request path runs, so it cannot drift from what actually happened.

```
trove auth explain --server https://registry.example.com \
  --subject alice --verb repo:write --repo team-a/api
```

`--verb` is required; `--subject` defaults to the calling subject; `--repo`
defaults to the system scope; `--json` prints the raw response. The server URL
comes from `--server` or `TROVE_SERVER`, and the command authenticates with
`TROVE_TOKEN`.

It reports the decision **and every binding that contributed to it** — the
binding id, the role, the scope, and the group it arrived through when it came
from a group membership. A denial with an empty match list means no binding
applies; a denial with matches means the bindings that matched do not carry the
verb.

It also reports whether the subject is **disabled**, which is worth knowing:
a disabled subject has no effective bindings at all, so its grants are still on
the books while nothing works. That combination produces some of the most
confusing tickets, and it is one line of output away.

Reading somebody else's permissions requires `user:read` at the system scope.
Without it you may still explain your own — and the refusal is identical whether
or not the subject you asked about exists.

### Common causes

| Symptom | Likely cause |
|---|---|
| 404 on a repository that exists | No binding grants `repo:read` at a matching scope |
| Can pull, cannot push | The role is `developer`, not `publisher` |
| Can push, cannot delete | Correct: `repo:write` does not imply deletion. Grant `manifest:delete` or `tag:delete` deliberately |
| Everything fails despite bindings | The subject is disabled, or its password rotation is pending |
| Repository invisible after a grant at `team-a/*` | Content lives at `team-a` itself; the prefix form does not include the bare name |
| A robot's token stopped working immediately | Its binding was revoked — tokens are re-checked against live bindings |

## Administration notes

- **Bootstrap.** First run creates one administrator and prints its password
  once, to stdout, never to the log. Rotation is forced before that account can
  do anything else. There is never a default credential.
- **Last-admin protection.** The final binding granting `role:write` at `system`
  cannot be removed, and the refusal says so. Breadth is not administration: a
  `*`-scoped grant does not count, because the two scopes are disjoint.
- **Role and binding changes are audited** with before-and-after state.
- **External identity** (OIDC, LDAP) is v1.1. External groups will map onto the
  local groups that already carry bindings, so the binding model does not change
  and the setups above survive the upgrade.

## Related

- `docs/operator/configuration.md` — configuration reference
- `docs/adr/0001-rbac-model.md` — the model and its rejected alternatives
- `docs/adr/0002-permission-vocabulary.md` — every verb and why each split exists
- `docs/adr/0003-visibility-disclosure.md` — the disclosure policy behind the 404s
