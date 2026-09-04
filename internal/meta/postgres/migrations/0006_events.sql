-- 0006_events: the SQLite migration's twin. Its comment carries the reasoning;
-- this side must say column for column the same thing, because a schema that
-- drifts makes the shared contract suite prove only that two different stores
-- each work.
--
-- COLLATE "C" on the text columns for the reason 0001 gives: SQLite compares
-- text byte by byte and has no other option, and the outbox is ordered and
-- paginated by `id`, whose chronological ordering is byte ordering.

CREATE TABLE events (
    id        TEXT COLLATE "C" NOT NULL PRIMARY KEY,
    type      TEXT COLLATE "C" NOT NULL,
    repo_name TEXT COLLATE "C",
    resource  TEXT COLLATE "C" NOT NULL DEFAULT '',
    actor     TEXT COLLATE "C" NOT NULL DEFAULT '',
    payload   BYTEA,
    at        BIGINT NOT NULL
);

CREATE INDEX events_repo ON events (repo_name, id);
