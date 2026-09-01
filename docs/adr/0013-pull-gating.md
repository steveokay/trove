# ADR 0013 — Pull gating and quarantine

- Status: accepted (2026-09-01)
- Task: D-015
- Decisions applied: Q12 (off by default), Q24 (serve on fill; strict mode opt-in),
  Q4 (signature presence, not verification, in v1)

## Context

A gating policy refuses to serve artifacts that violate a security condition.
The design problem is bypass closure: digests, referrers, group members, and child
manifests are all alternate doors to the same bytes.

## Decision

### Policy conditions

A gating policy is scoped by repository pattern (ADR 0001 grammar) and composes:

- `max-severity: <none|low|medium|high|critical>` — block if any non-suppressed
  finding exceeds it; `fixable-only: true` narrows to findings with a fix.
- `unsigned: block` — block subjects lacking at least one signature-type referrer
  (cosign media types). **Presence, not verification** in v1 (Q4).
- `unscanned: block|allow` — block artifacts with no completed scan. Default
  `allow` (must be, for gating-off deployments to upgrade safely).
- `scan-stale: <duration>` — treat scans older than the duration (or older than
  the current CVE DB version) as unscanned.
- `block-until-scanned: true` — the Q24 strict mode: cache fills and fresh pushes
  are held (client receives 404-class `MANIFEST_UNKNOWN` with a gating detail
  message) until the scan completes.

Gating is **off by default** (Q12): no policy, no gate.

### Enforcement point — one door

Gating is enforced in exactly one place: the hosted/proxy **manifest-serving
function**, after authz and after repo/group routing resolve to a concrete
`(repository, manifest)`. Consequences of that placement:

- **Digest pulls** hit the same function — gated identically to tag pulls.
- **Group pulls** resolve to a member first (ADR 0005); the member's serving
  function gates. A group cannot launder a blocked artifact.
- **Child manifests**: a blocked index blocks its children when reached *through*
  the index; a child pulled directly by digest is evaluated on its own findings
  (its own scan), so a clean child of a dirty multi-arch index remains pullable —
  correct, since the child is what actually runs.
- **Blob pulls are not gated** — blobs are reachable only by digest already known
  to the client; gating manifests denies the discovery path while keeping the
  enforcement surface small and fast. (Registry clients always fetch the manifest
  first.)
- **Referrers**: reading an SBOM/scan result of a blocked subject is allowed
  (given `repo:read` + `referrer:read`) — operators need to *inspect* what's
  blocked. Referrer manifests themselves are exempt from gating (they are
  metadata, they don't run), closing the "pull gating bypass via referrers" case
  in the sane direction: the subject stays blocked, its metadata stays readable.

### Failure posture

- Scan-results lookup failing (store error) fails **closed** for repos with a
  gating policy, with a distinct error detail — a gated repo never silently
  degrades to open.
- The block response is `404`-class per ADR 0003? No — gating is not a
  disclosure concern: the subject *can* read the repo. Blocks return
  `403 DENIED` with a structured detail (`policy`, `condition`, `worst-finding`)
  so CI logs are actionable. This is the one deliberate, documented divergence
  between "cannot read" (404) and "read but blocked" (403 + reason).

### Break-glass

- A subject holding `gate:override` may pull a blocked artifact by sending
  `Trove-Gate-Override: <reason>`; the reason is mandatory, and the pull emits
  `policy.violated` (override variant) + an audit record with subject, digest,
  policy, and reason. No configuration disables the audit.
- `gate:override` is granted by no built-in role except `admin` (ADR 0002).

## Rejected alternatives

- **Gating at the tag-resolution layer only** — digest pulls bypass it; this is
  the classic Harbor-class bug the adversarial suite (§9) names.
- **Gating blobs too** — doubles the hot-path cost for no additional enforcement
  (manifest is the discovery path), and breaks blob mounting between repos.
- **On-by-default conservative threshold** — rejected per Q12; a fresh deployment
  with an empty CVE DB would block everything and teach operators to disable
  gating permanently.
- **Signature verification in v1** — rejected per Q4; presence-checking delivers
  the "nothing unsigned in prod" policy without shipping trust-root management.

## Consequences

- S-011's adversarial cases map to the placement argument: bypass via digest, via
  group member, via referrer, via child manifest — each is a test against the
  single enforcement function.
- `internal/policy` evaluates gating from plain inputs (findings summary,
  referrer type list, scan age); the serving path supplies them — evaluation
  stays pure and property-testable like retention.
- The UI shows gate status per tag (S-006 data + policy evaluation), so a blocked
  pull is diagnosable without reading server logs.
