-- 0004_content_names_are_not_entities: content is keyed by the full OCI name,
-- and the repository row it belongs to is its entity (ADR 0005).
--
-- The reasoning is in the SQLite copy of this migration, which has to rebuild
-- both tables to say the same thing. Postgres can drop a constraint, so this
-- side is three statements -- but it must say exactly the same thing, because
-- a foreign key surviving on one engine is a registry that accepts a push on
-- one and refuses it on the other.
--
-- The constraint names are the ones Postgres generated for the inline
-- REFERENCES clauses in 0001, spelled out rather than guarded with IF EXISTS:
-- if a name is wrong, the migration must fail loudly here rather than silently
-- leaving the key in place and diverging from SQLite.

ALTER TABLE manifests DROP CONSTRAINT manifests_repo_name_fkey;
ALTER TABLE upload_sessions DROP CONSTRAINT upload_sessions_repo_name_fkey;

-- Deleting an entity now sweeps its sessions by name prefix rather than
-- through the key that just went, so that sweep gets an index.
CREATE INDEX upload_sessions_repo ON upload_sessions (repo_name);
