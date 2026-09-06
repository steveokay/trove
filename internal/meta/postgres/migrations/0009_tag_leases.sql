-- 0009_tag_leases: the SQLite migration's twin (C-005). Its comment carries the
-- reasoning; this side must say column for column the same thing, because a
-- schema that drifts makes the shared contract suite prove only that two
-- different stores each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives, and `stale` is a
-- BOOLEAN here against SQLite's INTEGER for the reason every other flag in this
-- schema is: SQLite has no boolean type, both hold 0/1, and the parity check
-- maps them to one class deliberately.

CREATE TABLE tag_leases (
    repo_name  TEXT COLLATE "C" NOT NULL,
    tag        TEXT COLLATE "C" NOT NULL,
    digest     TEXT COLLATE "C" NOT NULL,
    etag       TEXT COLLATE "C" NOT NULL,
    fetched_at BIGINT,
    ttl_s      BIGINT NOT NULL,
    stale      BOOLEAN NOT NULL,
    PRIMARY KEY (repo_name, tag)
);
