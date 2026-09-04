-- 0003_pull_stats: last-pulled time and pull counts per reference (ADR 0006).
--
-- Written by a batched writer off the pull path (R-010), never by the pull
-- itself: a count is worth nothing if paying for it slows the thing counted.
--
-- The column is called tag because that is the name the schema was designed
-- with, but it holds the reference as the client asked for it -- a tag or a
-- digest, both of which are pulls. The primary key is the pair, so a flush is
-- one upsert per distinct reference however many pulls it aggregated.
--
-- There is deliberately no foreign key to repositories or tags. These rows are
-- observations, not references: a tag repointed or deleted between the pull and
-- the flush must not fail the write, and retention (§7) joins them against live
-- content when it evaluates rather than trusting them to have been pruned.
CREATE TABLE pull_stats (
    repo_name      TEXT    NOT NULL,
    tag            TEXT    NOT NULL,
    last_pulled_at INTEGER,
    count          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repo_name, tag)
);

-- Retention asks "what in this repository has not been pulled since X", so the
-- repository and the timestamp are the pair it scans on.
CREATE INDEX pull_stats_last_pulled ON pull_stats (repo_name, last_pulled_at);
