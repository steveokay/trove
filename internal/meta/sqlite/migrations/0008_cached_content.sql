-- 0008_cached_content: the cached half of ADR 0006's two content families
-- (C-004). Cached content is what a proxy repository fetched from its upstream
-- and kept; hosted content is what somebody pushed and nobody else has a copy
-- of.
--
-- The families share no table, no key, and no foreign key. That is ADR 0009's
-- fourth wall: a statement in the wrong package has no table to reach, so even
-- a hand-written DELETE in the eviction path cannot name `manifests`. The Go
-- types are separate for the same reason, and either separation alone would
-- have to fail before a cache sweep could touch an irreplaceable blob.
--
-- Rows are keyed by the full content name -- `dockerhub/library/nginx` -- and
-- hold no foreign key to `repositories`, matching what 0004 did to the hosted
-- tables: the row a content name needs is its *entity*, the first path
-- segment, and that check lives in the store rather than in a key that would
-- claim `dockerhub/library/nginx` is itself a repository. DeleteRepository
-- sweeps these tables by name range for the same reason it sweeps the hosted
-- ones.
--
-- `last_access_at` is the LRU key eviction ranks by (Q11, C-013). It is
-- written on fill and refreshed on serve, and it is indexed because the
-- eviction sweep's whole query is "the least recently used rows, oldest
-- first"; without the index that sweep table-scans the cache on every budget
-- breach, which is exactly when the registry is already under pressure.
--
-- There is no negative-cache or lease table here. Those are C-005's and
-- C-007's, and they hold mappings rather than content: a lease is a tag whose
-- value expires, and cached content never does. Putting them in this migration
-- would tie the lifetime of a mapping to the lifetime of the bytes it happens
-- to name.

CREATE TABLE cached_manifests (
    repo_name      TEXT NOT NULL,
    digest         TEXT NOT NULL,
    media_type     TEXT NOT NULL,
    artifact_type  TEXT NOT NULL,
    subject_digest TEXT NOT NULL,
    payload        BLOB NOT NULL,
    size           INTEGER NOT NULL,
    cached_at      INTEGER,
    last_access_at INTEGER,
    PRIMARY KEY (repo_name, digest)
);

-- The referrers query over cached content: subject digest within one
-- repository, the same shape the hosted index has.
CREATE INDEX cached_manifests_subject ON cached_manifests (repo_name, subject_digest);

-- The eviction query: least recently used first, across every proxy, because
-- the budget is global by default (Q11).
CREATE INDEX cached_manifests_last_access ON cached_manifests (last_access_at);

CREATE TABLE cached_manifest_refs (
    repo_name       TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    ordinal         INTEGER NOT NULL,
    child_digest    TEXT NOT NULL,
    kind            TEXT NOT NULL,
    PRIMARY KEY (repo_name, manifest_digest, ordinal),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES cached_manifests (repo_name, digest) ON DELETE CASCADE
);

-- Blobs are per repository, not global as hosted blobs are: one proxy having
-- fetched a layer says nothing about whether another may serve it, and a
-- global row would let a proxy answer for content its own routing rules never
-- admitted. The bytes are content-addressed and stored once in the
-- cache-rooted blob store; these rows are the accounting.
CREATE TABLE cached_blobs (
    repo_name      TEXT NOT NULL,
    digest         TEXT NOT NULL,
    size           INTEGER NOT NULL,
    cached_at      INTEGER,
    last_access_at INTEGER,
    PRIMARY KEY (repo_name, digest)
);

CREATE INDEX cached_blobs_last_access ON cached_blobs (last_access_at);
