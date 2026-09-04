-- 0004_content_names_are_not_entities: content is keyed by the full OCI name,
-- and the repository row it belongs to is its entity (ADR 0005).
--
-- A repository entity is mounted at the first path segment of a name, so the
-- entity `team-a` holds `team-a/api` and `team-a/web`. 0001 was written when a
-- name and an entity were the same string, and gave manifests.repo_name and
-- upload_sessions.repo_name a foreign key to repositories(name): with prefix
-- routing that key refuses every name with a remainder, because no row is ever
-- created for one. The keys go; the store checks the entity instead
-- (reponame.Prefix), and DeleteRepository removes an entity's content over the
-- name prefix in one transaction rather than leaning on a cascade.
--
-- SQLite cannot drop a constraint, so the two tables are rebuilt. Two rules
-- shape the order below:
--
--   * `PRAGMA foreign_keys` is a no-op inside a transaction, and every
--     migration runs in one, so the rebuild has to be correct with enforcement
--     ON rather than switching it off.
--   * DROP TABLE performs an implicit DELETE first. Dropping `manifests` while
--     `tags` and `manifest_refs` still reference it would fire their ON DELETE
--     CASCADE and take every row with it, so their rows are parked in
--     unconstrained tables and put back afterwards.
--
-- The foreign keys from tags and manifest_refs to manifests are deliberately
-- kept: a tag pointing at a manifest that is gone would resolve to nothing,
-- and that cascade is what DeleteRepository still relies on after deleting a
-- manifest row.

-- --- park the children ------------------------------------------------------

CREATE TABLE manifest_refs_parked AS SELECT * FROM manifest_refs;
CREATE TABLE tags_parked AS SELECT * FROM tags;

DROP TABLE manifest_refs;
DROP TABLE tags;

-- --- rebuild manifests without the repositories key -------------------------

CREATE TABLE manifests_rebuilt (
    repo_name      TEXT    NOT NULL,
    digest         TEXT    NOT NULL,
    media_type     TEXT    NOT NULL DEFAULT '',
    artifact_type  TEXT    NOT NULL DEFAULT '',
    subject_digest TEXT    NOT NULL DEFAULT '',
    payload        BLOB,
    size           INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER,
    PRIMARY KEY (repo_name, digest)
);

INSERT INTO manifests_rebuilt
    (repo_name, digest, media_type, artifact_type, subject_digest, payload, size, created_at)
SELECT repo_name, digest, media_type, artifact_type, subject_digest, payload, size, created_at
  FROM manifests;

DROP TABLE manifests;
ALTER TABLE manifests_rebuilt RENAME TO manifests;

CREATE INDEX manifests_subject ON manifests (repo_name, subject_digest);

-- --- put the children back, unchanged ---------------------------------------

CREATE TABLE manifest_refs (
    repo_name       TEXT    NOT NULL,
    manifest_digest TEXT    NOT NULL,
    ordinal         INTEGER NOT NULL,
    child_digest    TEXT    NOT NULL,
    kind            TEXT    NOT NULL CHECK (kind IN ('config', 'layer', 'child-manifest', 'subject')),
    PRIMARY KEY (repo_name, manifest_digest, ordinal),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES manifests (repo_name, digest) ON DELETE CASCADE
);

INSERT INTO manifest_refs (repo_name, manifest_digest, ordinal, child_digest, kind)
SELECT repo_name, manifest_digest, ordinal, child_digest, kind FROM manifest_refs_parked;

DROP TABLE manifest_refs_parked;

CREATE INDEX manifest_refs_child ON manifest_refs (repo_name, child_digest, kind);

CREATE TABLE tags (
    repo_name       TEXT NOT NULL,
    name            TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    created_at      INTEGER,
    updated_at      INTEGER,
    PRIMARY KEY (repo_name, name),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES manifests (repo_name, digest) ON DELETE CASCADE
);

INSERT INTO tags (repo_name, name, manifest_digest, created_at, updated_at)
SELECT repo_name, name, manifest_digest, created_at, updated_at FROM tags_parked;

DROP TABLE tags_parked;

CREATE INDEX tags_manifest ON tags (repo_name, manifest_digest);

-- --- rebuild upload_sessions, which has no children -------------------------

CREATE TABLE upload_sessions_rebuilt (
    id            TEXT    PRIMARY KEY,
    repo_name     TEXT    NOT NULL,
    digest        TEXT    NOT NULL DEFAULT '',
    bytes         INTEGER NOT NULL DEFAULT 0,
    started_at    INTEGER,
    last_chunk_at INTEGER
);

INSERT INTO upload_sessions_rebuilt (id, repo_name, digest, bytes, started_at, last_chunk_at)
SELECT id, repo_name, digest, bytes, started_at, last_chunk_at FROM upload_sessions;

DROP TABLE upload_sessions;
ALTER TABLE upload_sessions_rebuilt RENAME TO upload_sessions;

CREATE INDEX upload_sessions_last_chunk ON upload_sessions (last_chunk_at);

-- Deleting an entity now sweeps its sessions by name prefix rather than
-- through the key that just went, so that sweep gets an index.
CREATE INDEX upload_sessions_repo ON upload_sessions (repo_name);
