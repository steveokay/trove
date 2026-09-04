-- 0005_repository_config_history: the SQLite migration's twin. Its comment
-- carries the reasoning; this side must say column for column the same thing,
-- because a schema that drifts makes the shared contract suite prove only that
-- two different stores each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives: SQLite compares
-- text byte by byte and has no other option, and history is ordered by
-- repo_name and version.

CREATE TABLE repository_config_history (
    repo_name TEXT COLLATE "C" NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    version   BIGINT NOT NULL,
    config    BYTEA,
    actor     TEXT COLLATE "C" NOT NULL DEFAULT '',
    at        BIGINT,
    PRIMARY KEY (repo_name, version)
);
