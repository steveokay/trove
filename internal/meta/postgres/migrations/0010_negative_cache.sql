-- 0010_negative_cache: the SQLite migration's twin (C-007). Its comment carries
-- the reasoning; this side must say column for column the same thing, because a
-- schema that drifts makes the shared contract suite prove only that two
-- different stores each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives.

CREATE TABLE negative_cache (
    repo_name   TEXT COLLATE "C" NOT NULL,
    reference   TEXT COLLATE "C" NOT NULL,
    observed_at BIGINT,
    ttl_s       BIGINT NOT NULL,
    PRIMARY KEY (repo_name, reference)
);
