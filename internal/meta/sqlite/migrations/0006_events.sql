-- 0006_events: the durable outbox (ADR 0006, ADR 0012).
--
-- Webhook delivery, the UI activity feed, and the operational half of the audit
-- trail all read from here. The row is written in the same transaction as the
-- change it announces, so an event exists if and only if that change committed
-- -- which is the whole reason the table exists rather than a channel.
--
-- `id` is a ULID and is the primary key, so ordering by it is chronological
-- ordering under the byte comparison this schema already uses everywhere else,
-- and a cursor is just the last id of a page. It is also the idempotency key a
-- receiver deduplicates on (`Trove-Event-Id`), which is why a repeat is a
-- primary-key conflict rather than a second row.
--
-- There is deliberately no foreign key on `repo_name`. These rows are
-- observations, not references: `artifact.deleted` for a repository that was
-- then deleted must outlive it, or the log would erase exactly the records an
-- operator goes looking for. It is the same reasoning pull_stats carries, and
-- the opposite of repository_config_history, which is state and does cascade.
--
-- `repo_name` is NULL for a system event -- a garbage-collection run, a role
-- change -- and that is load-bearing: the permission-filtered listing returns
-- those only to an unrestricted reader, because there is no repository to check
-- them against.
--
-- `payload` is BLOB rather than a JSON type for the reason the config columns
-- are: it must come back byte for byte. It is the webhook wire body, and a JSON
-- type would reorder keys and rewrite whitespace underneath a signature.

CREATE TABLE events (
    id        TEXT    NOT NULL PRIMARY KEY,
    type      TEXT    NOT NULL,
    repo_name TEXT,
    resource  TEXT    NOT NULL DEFAULT '',
    actor     TEXT    NOT NULL DEFAULT '',
    payload   BLOB,
    at        INTEGER NOT NULL
);

-- The activity feed and the permission-filtered listing both ask "this
-- repository's events, in order", so the repository and the id are the pair
-- they scan on.
CREATE INDEX events_repo ON events (repo_name, id);
