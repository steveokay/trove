-- 0010_negative_cache: what the upstream did not have (ADR 0008, C-007).
--
-- A typo'd tag must not become a request per pull against somebody else's
-- registry, and a rate-limited upstream is exactly where a retry loop does the
-- most damage. A row here says "this name was absent at `observed_at`" and is
-- good for `ttl_s` seconds -- 60 by default (Q11), short by design, because the
-- entry exists to absorb a retry loop rather than to remember a decision.
--
-- Nothing keyed by a **digest** is ever recorded here. Digest existence can
-- appear at any moment -- somebody is pushing it -- and caching that absence
-- breaks push-then-pull-through-a-group. The rule lives in the resolver,
-- because this table cannot tell a tag from a digest; what it can do is not
-- invite one, which is why the column is called `reference` and is documented
-- as a name.
--
-- There is no expiry sweep. Entries are overwritten when the same name is
-- missed again and deleted when the upstream finally answers, so the table
-- tracks live mistakes rather than accumulating every one ever made.
--
-- Keyed and swept exactly like the rest of the cached family, by name range
-- when the entity is deleted.

CREATE TABLE negative_cache (
    repo_name   TEXT NOT NULL,
    reference   TEXT NOT NULL,
    observed_at INTEGER,
    ttl_s       INTEGER NOT NULL,
    PRIMARY KEY (repo_name, reference)
);
