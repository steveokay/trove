-- 0001_init: the entity groups meta.Store covers today (ADR 0006).
--
-- Conventions:
--   * timestamps are UTC epoch milliseconds; NULL means "unset", which keeps
--     the zero time distinguishable from the epoch.
--   * booleans are 0/1 integers.
--   * hosted content and cached content are separate table families. Only the
--     hosted family exists here; the cached family arrives with the proxy work
--     and must never share a row or a foreign key with these (ADR 0009).

-- --- repositories -----------------------------------------------------------

CREATE TABLE repositories (
    name           TEXT    PRIMARY KEY,
    type           TEXT    NOT NULL CHECK (type IN ('hosted', 'proxy', 'group')),
    config         BLOB,
    config_version INTEGER NOT NULL DEFAULT 1,
    created_at     INTEGER,
    updated_at     INTEGER
);

-- A member row dies with either end of it: with the group it belongs to, and
-- with the repository it points at, so a group can never resolve to something
-- that no longer exists.
CREATE TABLE group_members (
    group_name   TEXT    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    member_name  TEXT    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    position     INTEGER NOT NULL,
    required     INTEGER NOT NULL DEFAULT 0,
    write_target INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_name, member_name),
    UNIQUE (group_name, position)
);

CREATE INDEX group_members_member ON group_members (member_name);

-- --- hosted content ---------------------------------------------------------

CREATE TABLE manifests (
    repo_name      TEXT    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    digest         TEXT    NOT NULL,
    media_type     TEXT    NOT NULL DEFAULT '',
    artifact_type  TEXT    NOT NULL DEFAULT '',
    subject_digest TEXT    NOT NULL DEFAULT '',
    payload        BLOB,
    size           INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER,
    PRIMARY KEY (repo_name, digest)
);

-- The referrers API is one indexed query, not a scan (ADR 0006).
CREATE INDEX manifests_subject ON manifests (repo_name, subject_digest);

-- The edge set garbage collection walks. Ordinal preserves the order the edges
-- were written in, so a manifest's layers come back as they were listed.
CREATE TABLE manifest_refs (
    repo_name       TEXT    NOT NULL,
    manifest_digest TEXT    NOT NULL,
    ordinal         INTEGER NOT NULL,
    child_digest    TEXT    NOT NULL,
    kind            TEXT    NOT NULL CHECK (kind IN ('config', 'layer', 'child-manifest', 'subject')),
    PRIMARY KEY (repo_name, manifest_digest, ordinal),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES manifests (repo_name, digest) ON DELETE CASCADE
);

-- The Q10 check -- "is this manifest a child of a live index?" -- is this index.
CREATE INDEX manifest_refs_child ON manifest_refs (repo_name, child_digest, kind);

-- A tag pointing at a deleted manifest would resolve to nothing, so it goes
-- with the manifest.
CREATE TABLE tags (
    repo_name       TEXT NOT NULL,
    name            TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    created_at      INTEGER,
    updated_at      INTEGER,
    PRIMARY KEY (repo_name, name),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES manifests (repo_name, digest) ON DELETE CASCADE
);

CREATE INDEX tags_manifest ON tags (repo_name, manifest_digest);

-- Hosted blob presence. The bytes live in the blob store (ADR 0007); this is
-- the metadata half, and it is not shared with cached content.
CREATE TABLE blobs (
    digest     TEXT    PRIMARY KEY,
    size       INTEGER NOT NULL,
    created_at INTEGER
);

-- An upload session pins its digest against garbage collection, so it is
-- stored rather than held in memory (ADR 0010).
CREATE TABLE upload_sessions (
    id            TEXT    PRIMARY KEY,
    repo_name     TEXT    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    digest        TEXT    NOT NULL DEFAULT '',
    bytes         INTEGER NOT NULL DEFAULT 0,
    started_at    INTEGER,
    last_chunk_at INTEGER
);

CREATE INDEX upload_sessions_last_chunk ON upload_sessions (last_chunk_at);

-- --- identity and authorization ---------------------------------------------

CREATE TABLE subjects (
    id         TEXT    NOT NULL UNIQUE,
    name       TEXT    PRIMARY KEY,
    kind       TEXT    NOT NULL CHECK (kind IN ('user', 'robot', 'anonymous')),
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER
);

CREATE TABLE subject_groups (
    id         TEXT NOT NULL UNIQUE,
    name       TEXT PRIMARY KEY,
    created_at INTEGER
);

CREATE TABLE group_subjects (
    group_name   TEXT NOT NULL REFERENCES subject_groups (name) ON DELETE CASCADE,
    subject_name TEXT NOT NULL REFERENCES subjects (name) ON DELETE CASCADE,
    PRIMARY KEY (group_name, subject_name)
);

CREATE INDEX group_subjects_subject ON group_subjects (subject_name);

CREATE TABLE roles (
    name    TEXT    PRIMARY KEY,
    builtin INTEGER NOT NULL DEFAULT 0
);

-- Verbs are stored expanded and explicit, never as wildcards (ADR 0002).
CREATE TABLE role_verbs (
    role_name TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    verb      TEXT NOT NULL,
    PRIMARY KEY (role_name, verb)
);

-- principal_id names a subject id or a group id, so it carries no foreign key;
-- the two deletion paths remove the matching bindings explicitly. The unique
-- grant keeps duplicates out of the effective-permission explainer.
CREATE TABLE bindings (
    id             TEXT NOT NULL PRIMARY KEY,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('subject', 'group')),
    principal_id   TEXT NOT NULL,
    role_name      TEXT NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    scope          TEXT NOT NULL,
    created_at     INTEGER,
    UNIQUE (principal_kind, principal_id, role_name, scope)
);

CREATE INDEX bindings_principal ON bindings (principal_kind, principal_id);

-- --- credentials ------------------------------------------------------------
--
-- Every secret column holds a hash. A credential outliving its subject would
-- be a usable secret belonging to nobody, so all four cascade.

CREATE TABLE user_credentials (
    subject_name TEXT    PRIMARY KEY REFERENCES subjects (name) ON DELETE CASCADE,
    hash         TEXT    NOT NULL,
    must_rotate  INTEGER NOT NULL DEFAULT 0,
    rotated_at   INTEGER
);

CREATE TABLE robot_credentials (
    subject_name TEXT    PRIMARY KEY REFERENCES subjects (name) ON DELETE CASCADE,
    secret_hash  BLOB    NOT NULL,
    expires_at   INTEGER NOT NULL,
    rotated_at   INTEGER
);

CREATE TABLE access_tokens (
    id           TEXT NOT NULL PRIMARY KEY,
    subject_name TEXT NOT NULL REFERENCES subjects (name) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    token_hash   BLOB NOT NULL UNIQUE,
    created_at   INTEGER,
    expires_at   INTEGER,
    last_used_at INTEGER
);

CREATE INDEX access_tokens_subject ON access_tokens (subject_name, name);

CREATE TABLE sessions (
    id                  TEXT    NOT NULL PRIMARY KEY,
    subject_name        TEXT    NOT NULL REFERENCES subjects (name) ON DELETE CASCADE,
    csrf_token          TEXT    NOT NULL,
    created_at          INTEGER,
    idle_expires_at     INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL
);

CREATE INDEX sessions_subject ON sessions (subject_name);
