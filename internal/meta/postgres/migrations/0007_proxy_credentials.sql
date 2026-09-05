-- 0007_proxy_credentials: the SQLite migration's twin. Its comment carries the
-- reasoning; this side must say column for column the same thing, because a
-- schema that drifts makes the shared contract suite prove only that two
-- different stores each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives: SQLite compares
-- text byte by byte and has no other option, and this table is keyed and
-- cascaded by `repo_name`.

CREATE TABLE proxy_credentials (
    repo_name  TEXT COLLATE "C" NOT NULL PRIMARY KEY REFERENCES repositories (name) ON DELETE CASCADE,
    sealed     TEXT COLLATE "C" NOT NULL,
    rotated_at BIGINT
);
