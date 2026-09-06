-- 0009_tag_leases: a proxy's cached answer to "what does this tag point at"
-- (ADR 0008, C-005).
--
-- This is the table that keeps a pull-through cache honest. Digests are
-- immutable, so 0008's content never expires; the mapping from a *name* to one
-- does, and a proxy serving a week-old `:latest` is worse than no proxy at all.
-- A row here is therefore a lease rather than a tag: somebody else's fact,
-- borrowed until `fetched_at + ttl_s`, at which point it is revalidated with a
-- conditional request that costs no bandwidth when nothing moved.
--
-- `fetched_at` is when the mapping was last *confirmed*, not when it was first
-- learned: an unchanged revalidation refreshes it while leaving the digest
-- alone. Freshness is computed from it and never stored, because a stored
-- "fresh" boolean is one clock away from being wrong.
--
-- `ttl_s` records the interval that was in effect when the row was written. It
-- is for the operator and the UI; the resolver reads the repository's *current*
-- TTL, so lowering it takes effect on the next pull rather than after every
-- lease happens to be rewritten. Zero means revalidate on every pull (Q11).
--
-- `stale` is not "past its TTL" -- that is derivable and would drift the moment
-- it were stored. It marks a lease whose last revalidation could not be
-- completed and which was served anyway in degraded mode: a real event that
-- nothing else remembers, and the flag an operator wants to see when asking
-- why a cluster is pulling yesterday's image.
--
-- `etag` is what the upstream returned, sent back as If-None-Match. It is kept
-- beside the digest rather than instead of it because registries differ in
-- whether they answer 304, and the digest comparison works against all of them.
--
-- The row holds no foreign key to `cached_manifests`. A lease is what the
-- upstream said, which is true whether or not the manifest landed; a key would
-- turn the order of two writes into a constraint on a mapping that does not
-- depend on it. It is swept by name range with the rest of the cached family
-- when its entity is deleted.

CREATE TABLE tag_leases (
    repo_name  TEXT NOT NULL,
    tag        TEXT NOT NULL,
    digest     TEXT NOT NULL,
    etag       TEXT NOT NULL,
    fetched_at INTEGER,
    ttl_s      INTEGER NOT NULL,
    stale      INTEGER NOT NULL,
    PRIMARY KEY (repo_name, tag)
);
