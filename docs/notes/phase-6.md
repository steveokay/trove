# Phase 6 — completion notes

The full completion write-ups for phase 6 tasks, moved out of the `status.md`
acceptance column per the CLAUDE.md §14 convention. One frozen section per
task, in board order.

## P-002 — Retention evaluator as a pure function

`internal/policy`: `Evaluate(inventory, rules, now) → (Plan, error)`, zero I/O, with its own value types mirroring the stored shapes rather than importing `internal/meta`. This is the function an operator's approval of a dry-run plan rests on, and everything below follows from that: an evaluator that can read state can disagree with the snapshot it was handed, and once it can, approving a plan stops meaning that the approved deletions are the ones that happen.

**The selectable-set invariant is the whole design.** `NewInventory` computes exclusions *before any rule exists* — protected tag, immutable tag, index child (Q10), and live subject (ADR 0011's "attached, not orphaned") — and `Evaluate` only ever ranges over what survived. Protection is therefore not a rule that beats other rules; it is a manifest a rule never sees, which is why no priority, count, or ordering can defeat it. Tag status and index-child-ness are *derived* from the graph rather than stored as flags, so they cannot contradict it. The constructor also refuses snapshots it cannot reason about (duplicate digests, one tag on two manifests, zero push time, subject cycles) — a zero `PushedAt` would read as year one and make every age rule select everything.

**The fuzzer found a real hole, and it is the most valuable thing in this task.** `FuzzProtectedContentSurvivesEveryRuleSet` produced an untagged image carrying a **tagged, protected** attestation. An `untagged` rule selected the image entirely legitimately, and the ADR 0011 referrer cascade then deleted the protected manifest along with it — protection defeated through a path no rule ever traversed and no reviewer would have thought to check, because the protected manifest was never *selected*, it was collateral. The fix re-checks exclusions across every cascade member: a member excluded for any reason blocks the whole selection, reported as a `BlockedEntry` naming the exclusion. This generalises ADR 0011's stated multi-arch case to all four exclusion reasons, and was written back into that ADR as a clarification, because it is a property of the referrer lifecycle rather than of this evaluator — any future caller that deletes a subject and its attachments inherits the same obligation. A regression seed is committed.

**Rules and precedence.** A rule is filter-plus-keep-condition; whatever the filter matched and the condition did not save is selected. **Lower priority wins**, following ECR lifecycle policies (the prior art §12 names), and only the strongest tier with an opinion decides. Equal priority with genuine disagreement is a typed `*ConflictError` naming every selecting and every keeping rule for every disputed digest, and produces **no plan at all** — CLAUDE.md §7's "ties are an error, not a coin flip" taken literally, because a half-plan is worse than none. Agreement within a tier is fine, and the deciding rule is recorded as first *by name* rather than by config order, so reordering a policy document cannot change a plan (the same reasoning that made group member `Position` explicit). Regexes are compiled once and anchored; empty patterns, unknown kinds, and fields a kind does not read are compile errors rather than evaluation surprises.

**The plan** partitions the inventory exactly — selected, cascaded, blocked, kept — with `Kept` carrying *why* (by rule, no rule applied, or not selectable with its exclusions), because an operator's first question about a plan that deletes nothing is why not. Five fuzz targets cover selectable-set containment, protection dominance, inventory partitioning, order-independence under both manifest and rule permutation, and weaker-priority monotonicity. `purity_test.go` is a file-scoped import allowlist over the three evaluator files, which is the real guarantee at a granularity archtest cannot express.

**Reconcile notes.** The agent's proposed archtest rule was corrected before landing: it listed stdlib I/O packages under `Transitive`, which no package can satisfy since `fmt` reaches `os`. The rule now covers state-reaching packages only, and its `Reason` explains why the stdlib half lives in the purity test — which also lets P-005's apply path live in this package later without weakening either check. Seven decisions the agent flagged were confirmed: priority direction, name-based tie-break, protection not consuming a keep-last-N slot (protection keeps more, never fewer), an index child freed by the same plan staying excluded until the next evaluation (keeping plans independent of apply order), strictly-after boundary semantics, and zero-value safety on every enum. **For P-004**: the plan-staleness hash should cover the *inventory snapshot*, not the plan output — hashing the plan alone would accept an apply after a new push that made the plan wrong. That is P-004's decision to make, and the reasoning is recorded here so it is not rediscovered.


## P-007 (part 1) — what the sweep may ask the store

P-007 splits into two commits the way C-013 did, because the halves are
independently reviewable: this one is what the metadata store can answer about
reclaimable blobs, and the collector in `internal/gc` follows. Nothing here
deletes anything on a schedule; what it adds is the ability to ask, and one
method that deletes exactly one row under conditions it re-checks itself.

**The mark turned out to be a predicate rather than a snapshot**, which is the
one place this diverges from ADR 0010 and is recorded there as a clarification.
`manifest_refs` already flattens every manifest's edges, and a blob is
referenced only as a `config` or a `layer` — `child-manifest` and `subject`
edges name manifests, whose payloads live in their own rows. So reachability
for the blob store is a `NOT EXISTS` over one table, evaluated inside the
candidate query and again inside the delete. There is no mark set to age out,
`gc_runs` stores none, and a resumed sweep needs no rule beyond "carry on from
the cursor" — which is strictly safer than the ADR's version, since a sweep
running for a week acts on reachability computed a moment ago rather than a
week ago.

**`sweep_before` is a snapshot, and deliberately the other way.** The grace
deadline is stored on the run and reused on resume rather than recomputed:
recomputing would move the window forward and admit blobs that were protected
when the run began, so an interruption would quietly widen what a sweep may
delete. For the one operation that cannot be undone, that is the wrong
direction to drift.

**One WHERE clause, two callers.** `ListSweepCandidates` and
`DeleteBlobIfUnreferenced` share the sweep conditions as a single constant
(SQLite) or a single builder (Postgres, whose placeholders are numbered).
Drift between them is the worst bug this file could have: a listing that
offered what the re-check was meant to protect, or a re-check that refused
everything and stopped the sweep reclaiming while looking healthy.

**Postgres takes the lock the ADR asks for.** `SELECT … FOR UPDATE` on the blob
row before the conditional delete, so a concurrent manifest PUT's existence
check either lands before it — and the re-check sees the reference — or waits
and then fails its own check, which is a re-upload and spec-legal. SQLite's
single writer gives the same guarantee for free; there it is a single
conditional `DELETE`, because there is no "between" for a reference to appear
in.

**A candidate that stopped being one is `(false, nil)`, not an error.** The
re-check refusing is the system working, and a sweep that logged an error every
time somebody pushed would teach an operator to ignore it.

Migration 0011 adds `gc_runs` and two indexes the sweep needs: `manifest_refs
(child_digest, kind)`, because the existing index leads with `repo_name` and
the sweep's question is global (blobs are), and `upload_sessions (digest)`,
because a pin is looked up by digest rather than by session. Both are added now
rather than when the tables are large — the lesson C-004 recorded about
`last_access_at`.

Nine contract cases run against all three engines: referenced blobs are never
offered and become collectable the moment their manifest goes, the grace window
and the upload pin each protect independently, the listing pages by digest with
an exclusive cursor, child-manifest edges protect nothing in the blob store,
the delete re-checks references *and* the deadline, and a run's lifecycle,
resume order, and refusals behave the same everywhere.

**Still to come in P-007:** `internal/gc` — the collector that pages candidates,
deletes rows then bytes, persists the cursor, emits `gc.completed`, and takes
`blob.HostedRef` (the newtype C-013 introduced with its cached twin). P-008's
race matrix follows it.

## P-007 (part 2) — the collector

`internal/gc` is the one place in trove that deletes something nothing can
recreate, and everything about it is arranged so its mistakes fall on the safe
side.

**Rows before bytes, and a leak is the accepted failure.** The metadata row
goes first, in a transaction that re-checks every condition; the bytes follow.
A crash or a storage failure between the two leaves unreferenced bytes on disk,
counted as `Leaked` in the result and logged — reclaimed later by `trove verify`
(P-012). The reverse order would produce a row whose content is missing, which
is the one corruption class this registry refuses to create. The test that pins
this makes the blob store refuse the delete and asserts the row is gone, the
bytes are not, and the sweep returns no error.

**Interrupted and failed are different stops.** A cancelled sweep saves its
cursor and leaves the run *open*, so the next one resumes it; a store failure
closes the run with the reason, so an operator sees that collection is failing
rather than an unfinished row that reads like a shutdown. Restarting after a
failure costs almost nothing — the blobs already deleted are gone from the
candidate set, so a restart re-lists rather than re-deletes. **The tests found
this**: the first implementation closed the run on cancellation too, which made
"resumable" a comment rather than a behaviour, and two cases failed until the
code matched its own doc.

**A resumed sweep keeps its original deadline**, which is the whole reason
resuming is safe. `TestResumeKeepsTheOriginalWindow` uploads a blob *after* a
run begins, advances the clock past the grace window, resumes, and asserts the
blob survives — a fresh run would have collected it, and an interruption must
not silently widen what a sweep may delete.

**The re-check refusing is not an error.** A candidate that something started
referencing between the listing and the delete is counted as `Skipped`. So is
one whose re-check could not be answered at all: an unknown answer is not a
licence to delete. Both leave the blob completely intact, rows and bytes, which
is what the tests assert rather than just checking a counter.

**`blob.HostedRef` found its consumer.** C-013 introduced the newtype pair with
its cached twin and said the first deleting caller on each side would use them;
`gc.reclaim` is that caller, and it is the only function in trove that removes
content from the hosted blob store. A cached digest cannot be converted into a
`HostedRef`, and `internal/cache` cannot import this package at all (archtest).

**ADR 0009's proving test gained its other half.** `test/separation` could
previously only show that a cache sweep cannot reach hosted content; with a
collector to run, it now shows the converse over the same fixture — the same
digests in both families, the hosted layer swept, every cached row and byte
untouched. Neither test could have been written against a shared deletion
engine, which is the argument the ADR makes.

**One event-payload correction.** `event.GCCompletedPayload` had
`manifests_scanned`, written when the design walked manifests to build a mark
set. Nothing walks manifests now — reachability is a predicate — so the field
would have reported a number nothing measures. It is `blobs_scanned`, with the
golden updated; no consumer exists yet (webhooks are E-002+), so the wire
format was still free to be honest.

Coverage: `internal/gc` 100%.
