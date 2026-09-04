-- 0005_repository_config_history: config changes are versioned in the metadata
-- store so a support bundle can show their lineage (ADR 0005).
--
-- A row here is a *superseded* revision: the document that was stored at
-- `version` until somebody replaced it, who replaced it, and when. The live
-- configuration stays on the repositories row, so a repository's whole lineage
-- is these rows followed by that one -- which is why creating a repository
-- writes nothing here, and why there is always exactly one more version than
-- there are rows.
--
-- The row dies with the repository it belonged to. A name is free once it is
-- deleted, and a repository created at that name afterwards is a different
-- repository: inheriting a predecessor's upstreams and settings would
-- attribute somebody else's configuration to it. The cascade is the same one
-- group_members has had since 0001 -- unlike content, which is keyed by full
-- OCI name and cannot hold a key to an entity row (0004), history is keyed by
-- the entity name itself, so the foreign key is exactly right.
--
-- `config` is BLOB rather than a JSON type for the same reason the
-- repositories column is: it must come back byte for byte, and a JSON type
-- would rewrite key order and whitespace.

CREATE TABLE repository_config_history (
    repo_name TEXT    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    version   INTEGER NOT NULL,
    config    BLOB,
    actor     TEXT    NOT NULL DEFAULT '',
    at        INTEGER,
    PRIMARY KEY (repo_name, version)
);
