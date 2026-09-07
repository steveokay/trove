// Package gc reclaims unreferenced hosted blobs by mark-and-sweep. It must
// never reach cached content; see ADR 0009.
//
// This is the one place in trove that deletes something nothing can recreate.
// Everything about it is arranged so that its mistakes fall on the safe side:
//
//   - **Prefer leaking a blob over losing one** (§7). Every failure mode here
//     ends in bytes that are still on disk and no longer referenced, which a
//     later sweep or `trove verify` (P-012) reclaims. None of them ends in a
//     manifest pointing at bytes that are gone.
//   - **Rows before bytes.** The metadata row is deleted first, in a
//     transaction that re-checks every condition; the bytes follow. A crash
//     between the two leaks. The reverse order would create the one corruption
//     class this registry refuses to produce: a row whose content is missing.
//   - **The re-check is the safety property**, not the listing. A candidate is
//     a statement about the past the moment it is returned, so
//     `DeleteBlobIfUnreferenced` evaluates the conditions again inside its own
//     transaction, and a candidate that stopped being one is simply skipped.
//   - **Hosted only.** The collector is constructed with the hosted metadata
//     view and the hosted blob store, it deletes through `blob.HostedRef`, and
//     it cannot import internal/cache (archtest enforces it). Its cached twin
//     is internal/cache's evictor, whose mistakes cost a refill.
//
// A sweep is resumable because it is a cursor over blobs in digest order, with
// the cursor and the counters persisted after each batch. What it resumes is
// the same sweep: the grace deadline is stored on the run and reused, since
// recomputing it would widen the window an interrupted sweep may delete in.
package gc
