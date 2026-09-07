-- 0011_gc_runs: what a garbage collection sweep remembers (ADR 0010, P-007).
--
-- A sweep over a large registry does not finish in one go, and the thing it is
-- doing -- deleting bytes nothing can recreate -- is the worst thing in this
-- system to get wrong twice. So it keeps a row: where it had got to, what
-- window it was sweeping, and what it has taken so far. An interrupted sweep
-- resumes from the cursor rather than starting over, and a resumed sweep is
-- the same sweep rather than a new one with a wider window.
--
-- `sweep_before` is the grace deadline the run started with, stored rather
-- than recomputed. Recomputing it on resume would move the window forward and
-- admit blobs that were protected when the run began -- an interruption would
-- quietly widen what a sweep may delete, which is precisely backwards for the
-- one operation that cannot be undone.
--
-- There is no mark snapshot here, and that is deliberate: the candidate query
-- computes reachability at the moment it runs, so there is no stale set to age
-- out and no resume rule beyond "carry on from the cursor". See the ADR 0010
-- clarification added with P-007.
--
-- Rows are kept after the run finishes. A sweep is a destructive operation and
-- its history is the answer to "what happened to that blob"; pruning belongs
-- to audit retention (E-013), not here.

CREATE TABLE gc_runs (
    id           TEXT    PRIMARY KEY,
    started_at   INTEGER,
    finished_at  INTEGER,
    sweep_before INTEGER,
    cursor       TEXT    NOT NULL DEFAULT '',
    scanned      INTEGER NOT NULL DEFAULT 0,
    deleted      INTEGER NOT NULL DEFAULT 0,
    freed_bytes  INTEGER NOT NULL DEFAULT 0,
    failure      TEXT    NOT NULL DEFAULT ''
);

-- Finding the run to resume: the most recent unfinished one.
CREATE INDEX gc_runs_unfinished ON gc_runs (finished_at, started_at);

-- The sweep asks "does any live manifest reference these bytes?" about a blob,
-- which is a question across every repository -- blobs are global (ADR 0006).
-- The existing manifest_refs index leads with repo_name and cannot answer it,
-- and adding this index once the table is large is not free (the lesson C-004
-- recorded about last_access_at).
CREATE INDEX manifest_refs_child_global ON manifest_refs (child_digest, kind);

-- The other half of the sweep's condition: an upload session pins its digest,
-- and the pin is looked up by digest rather than by session.
CREATE INDEX upload_sessions_digest ON upload_sessions (digest);
