// Package cache reclaims proxy cache storage. It must never reach hosted
// content; see ADR 0009.
//
// Everything here acts on the cached-content family and on a blob store rooted
// at the cache, both handed in at construction. There is no argument through
// which the hosted half arrives, no import of internal/gc or internal/policy
// (archtest enforces it), and the one function that deletes bytes takes a
// blob.CachedRef, which a hosted digest cannot be converted into by accident.
// Evicting cached bytes costs a refill; deleting hosted bytes loses them.
//
// Three moving parts, on three schedules:
//
//   - The budget sweep (Evictor.Sweep) ranks cached rows least-recently-used
//     first and removes them until the cache is inside its budget. It runs on
//     the Scheduler's timer and on a breach trigger from whoever fills the
//     cache.
//   - The orphan pass (Evictor.SweepOrphans) reclaims bytes in the cache store
//     that no proxy has a row for. Those exist by design: a fill commits bytes
//     before it writes the row, because a row without bytes is a miss the read
//     path already handles while bytes without a row are merely wasted space
//     (C-004).
//   - The touch batcher (TouchBatcher) feeds last-access times from the serving
//     path into the store in batches, so a pull never waits on the LRU write.
//
// The LRU is deliberately approximate. Touches flush on an interval, so
// content served seconds before a sweep can be ranked as cold and evicted --
// which costs one refill of content that is, by definition, refillable. The
// Scheduler flushes pending touches before it sweeps, which narrows the window
// without pretending to close it.
package cache
