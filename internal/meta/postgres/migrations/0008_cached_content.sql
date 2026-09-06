-- 0008_cached_content: the SQLite migration's twin (C-004). Its comment
-- carries the reasoning; this side must say column for column the same thing,
-- because a schema that drifts makes the shared contract suite prove only that
-- two different stores each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives: SQLite compares
-- text byte by byte and has no other option, and these tables are keyed and
-- swept by `repo_name`, so a locale collation here would make the same
-- eviction sweep select different rows depending on which engine an operator
-- chose.

CREATE TABLE cached_manifests (
    repo_name      TEXT COLLATE "C" NOT NULL,
    digest         TEXT COLLATE "C" NOT NULL,
    media_type     TEXT COLLATE "C" NOT NULL,
    artifact_type  TEXT COLLATE "C" NOT NULL,
    subject_digest TEXT COLLATE "C" NOT NULL,
    payload        BYTEA NOT NULL,
    size           BIGINT NOT NULL,
    cached_at      BIGINT,
    last_access_at BIGINT,
    PRIMARY KEY (repo_name, digest)
);

CREATE INDEX cached_manifests_subject ON cached_manifests (repo_name, subject_digest);

CREATE INDEX cached_manifests_last_access ON cached_manifests (last_access_at);

CREATE TABLE cached_manifest_refs (
    repo_name       TEXT COLLATE "C" NOT NULL,
    manifest_digest TEXT COLLATE "C" NOT NULL,
    ordinal         BIGINT NOT NULL,
    child_digest    TEXT COLLATE "C" NOT NULL,
    kind            TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (repo_name, manifest_digest, ordinal),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES cached_manifests (repo_name, digest) ON DELETE CASCADE
);

CREATE TABLE cached_blobs (
    repo_name      TEXT COLLATE "C" NOT NULL,
    digest         TEXT COLLATE "C" NOT NULL,
    size           BIGINT NOT NULL,
    cached_at      BIGINT,
    last_access_at BIGINT,
    PRIMARY KEY (repo_name, digest)
);

CREATE INDEX cached_blobs_last_access ON cached_blobs (last_access_at);
