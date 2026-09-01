# ADR 0003 — Visibility and disclosure policy

- Status: accepted (2026-09-01)
- Task: D-019
- Decisions applied: Q18 (404 on unauthorized reads)

## Context

Existence is information. If a subject cannot read a repository, learning that the
repository *exists* — from a status code, a count, a metric label, or a timing
difference — is already a leak. The policy must be decided once and applied uniformly,
because a single inconsistent surface defeats every other one.

## Decision

### Status-code matrix

| Situation | Response |
|---|---|
| No credentials, endpoint requires auth | `401` + `WWW-Authenticate` challenge (the `docker login` contract) |
| Authenticated, lacks **read** on the resource | `404` with the same spec error a truly absent resource returns (`NAME_UNKNOWN`, `MANIFEST_UNKNOWN`, `BLOB_UNKNOWN`; admin API: `404` problem document) |
| Authenticated, **can read** but lacks the write/delete/admin verb | `403 DENIED` — readability already disclosed existence, so a helpful error is safe and debuggable |
| Anonymous subject lacks read | `401` + challenge, not `404` — the client may be able to authenticate into visibility |

The unauthorized-read `404` body, headers, and (as far as practical) latency are
identical to the genuinely-absent case: same error constructor, same code path.
Golden tests (R-008) assert byte-identical bodies for the two cases.

### Enumerated surfaces that must filter

Every one of these builds from permission-filtered queries (never post-filtering),
and each has a line item in the disclosure suite (Z-018):

1. `/v2/_catalog` and repository listings (UI + admin API)
2. Tag lists and their pagination `Link` headers and counts
3. Referrers listings (also require `repo:read` on the subject artifact)
4. Cross-repo search results, facets, and result counts
5. Event deliveries to webhooks (E-004: filtered by the *owning subject's* readability)
6. Metric label values — no repository name appears as a label the scraper's
   deployment hasn't accepted; `/metrics` exposure is a deployment-level decision
   (E-005), because Prometheus text format cannot be per-subject filtered
7. Group resolution behaviour: unreadable members are removed *before* resolution,
   so neither the served digest nor an error pattern reveals a member (C-012)
8. Effective-permissions endpoint: subjects see only their own permissions unless
   they hold `user:read`
9. Scan results, CVE rollups, policy dry-run plans, quota reports: scoped to
   readable repositories
10. Audit log: `audit:read` is system-scoped and intentionally sees everything —
    it is the one deliberate exception, and granting it is granting global visibility
    (documented in DOC-003)

### Non-goals

- Padding response times artificially. Query-layer filtering makes the absent and
  hidden paths structurally similar; we do not add timing jitter beyond that.
- Hiding *verbs* from authorized readers: a reader who pushes without `repo:write`
  learns nothing new from the `403`.

## Rejected alternatives

- **`403` for unauthorized reads** — conventional and debuggable, but confirms
  existence to any authenticated probe; enumeration of `team-*/`-style names becomes
  trivial. The explainer (Z-013) restores debuggability for legitimate users.
- **Per-repository visibility setting (public/private toggles)** — a second
  visibility mechanism that can disagree with bindings. Anonymous bindings already
  express "public".

## Consequences

- Error constructors live in one package; handlers cannot hand-roll a `404`/`403`.
- Z-018's suite enumerates the ten surfaces above; adding a listing surface without
  extending the suite is a review-blocking omission.
- Docs must tell operators that "not found" can mean "no permission" — and point at
  `trove auth explain`.
