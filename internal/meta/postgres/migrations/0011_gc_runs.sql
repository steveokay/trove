-- 0011_gc_runs: the SQLite migration's twin (P-007). Its comment carries the
-- reasoning; this side must say column for column the same thing, because a
-- schema that drifts makes the shared contract suite prove only that two
-- different stores each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives. The sweep pages
-- by digest, so the cursor comparison has to order the same way in both
-- engines or a resumed sweep would skip rows on one of them.

CREATE TABLE gc_runs (
    id           TEXT COLLATE "C" PRIMARY KEY,
    started_at   BIGINT,
    finished_at  BIGINT,
    sweep_before BIGINT,
    cursor       TEXT COLLATE "C" NOT NULL DEFAULT '',
    scanned      BIGINT NOT NULL DEFAULT 0,
    deleted      BIGINT NOT NULL DEFAULT 0,
    freed_bytes  BIGINT NOT NULL DEFAULT 0,
    failure      TEXT COLLATE "C" NOT NULL DEFAULT ''
);

CREATE INDEX gc_runs_unfinished ON gc_runs (finished_at, started_at);

CREATE INDEX manifest_refs_child_global ON manifest_refs (child_digest, kind);

CREATE INDEX upload_sessions_digest ON upload_sessions (digest);
