-- 0001_init: the entity groups meta.Store covers today (ADR 0006).
--
-- This is the SQLite schema's twin. The two are held to column-for-column
-- parity by a test, because two engines that drift apart make the shared
-- contract suite meaningless: it would be proving that two different things
-- each work, rather than that they are substitutable.
--
-- Conventions, matching the other engine:
--   * timestamps are UTC epoch milliseconds in BIGINT columns, so neither
--     engine's time zone handling can enter the picture. NULL means "unset",
--     which keeps the zero time distinguishable from the epoch.
--   * every TEXT column is COLLATE "C". SQLite compares text byte by byte and
--     has no other option; Postgres would otherwise use the database's locale,
--     where punctuation can sort differently. Listings are ordered and paginated
--     by these columns, so a different collation would mean the two engines
--     returned the same page in a different order -- and a cursor handed to one
--     could not be reasoned about with the other.
--   * repository config and manifest payloads are BYTEA, not JSONB. They are
--     opaque to this layer and must come back byte for byte; JSONB would
--     rewrite key order and whitespace, making the round-trip lossy and the
--     two engines disagree about what was stored.
--   * hosted content and cached content are separate table families. Only the
--     hosted family exists here; the cached family arrives with the proxy work
--     and must never share a row or a foreign key with these (ADR 0009).

-- --- repositories -----------------------------------------------------------

CREATE TABLE repositories (
    name           TEXT COLLATE "C"   PRIMARY KEY,
    type           TEXT COLLATE "C"   NOT NULL CHECK (type IN ('hosted', 'proxy', 'group')),
    config         BYTEA,
    config_version BIGINT NOT NULL DEFAULT 1,
    created_at     BIGINT,
    updated_at     BIGINT
);

-- A member row dies with either end of it: with the group it belongs to, and
-- with the repository it points at, so a group can never resolve to something
-- that no longer exists.
CREATE TABLE group_members (
    group_name   TEXT COLLATE "C"    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    member_name  TEXT COLLATE "C"    NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    position     INTEGER NOT NULL,
    required     BOOLEAN NOT NULL DEFAULT FALSE,
    write_target BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (group_name, member_name),
    UNIQUE (group_name, position)
);

CREATE INDEX group_members_member ON group_members (member_name);

-- --- hosted content ---------------------------------------------------------

CREATE TABLE manifests (
    repo_name      TEXT COLLATE "C"   NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    digest         TEXT COLLATE "C"   NOT NULL,
    media_type     TEXT COLLATE "C"   NOT NULL DEFAULT '',
    artifact_type  TEXT COLLATE "C"   NOT NULL DEFAULT '',
    subject_digest TEXT COLLATE "C"   NOT NULL DEFAULT '',
    payload        BYTEA,
    size           BIGINT NOT NULL DEFAULT 0,
    created_at     BIGINT,
    PRIMARY KEY (repo_name, digest)
);

-- The referrers API is one indexed query, not a scan (ADR 0006).
CREATE INDEX manifests_subject ON manifests (repo_name, subject_digest);

-- The edge set garbage collection walks. Ordinal preserves the order the edges
-- were written in, so a manifest's layers come back as they were listed.
CREATE TABLE manifest_refs (
    repo_name       TEXT COLLATE "C"    NOT NULL,
    manifest_digest TEXT COLLATE "C"    NOT NULL,
    ordinal         INTEGER NOT NULL,
    child_digest    TEXT COLLATE "C"    NOT NULL,
    kind            TEXT COLLATE "C"    NOT NULL CHECK (kind IN ('config', 'layer', 'child-manifest', 'subject')),
    PRIMARY KEY (repo_name, manifest_digest, ordinal),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES manifests (repo_name, digest) ON DELETE CASCADE
);

-- The Q10 check -- "is this manifest a child of a live index?" -- is this index.
CREATE INDEX manifest_refs_child ON manifest_refs (repo_name, child_digest, kind);

-- A tag pointing at a deleted manifest would resolve to nothing, so it goes
-- with the manifest.
CREATE TABLE tags (
    repo_name       TEXT COLLATE "C" NOT NULL,
    name            TEXT COLLATE "C" NOT NULL,
    manifest_digest TEXT COLLATE "C" NOT NULL,
    created_at      BIGINT,
    updated_at      BIGINT,
    PRIMARY KEY (repo_name, name),
    FOREIGN KEY (repo_name, manifest_digest)
        REFERENCES manifests (repo_name, digest) ON DELETE CASCADE
);

CREATE INDEX tags_manifest ON tags (repo_name, manifest_digest);

-- Hosted blob presence. The bytes live in the blob store (ADR 0007); this is
-- the metadata half, and it is not shared with cached content.
CREATE TABLE blobs (
    digest     TEXT COLLATE "C"   PRIMARY KEY,
    size       BIGINT NOT NULL,
    created_at BIGINT
);

-- An upload session pins its digest against garbage collection, so it is
-- stored rather than held in memory (ADR 0010).
CREATE TABLE upload_sessions (
    id            TEXT COLLATE "C"   PRIMARY KEY,
    repo_name     TEXT COLLATE "C"   NOT NULL REFERENCES repositories (name) ON DELETE CASCADE,
    digest        TEXT COLLATE "C"   NOT NULL DEFAULT '',
    bytes         BIGINT NOT NULL DEFAULT 0,
    started_at    BIGINT,
    last_chunk_at BIGINT
);

CREATE INDEX upload_sessions_last_chunk ON upload_sessions (last_chunk_at);

-- --- identity and authorization ---------------------------------------------

CREATE TABLE subjects (
    id         TEXT COLLATE "C"    NOT NULL UNIQUE,
    name       TEXT COLLATE "C"    PRIMARY KEY,
    kind       TEXT COLLATE "C"    NOT NULL CHECK (kind IN ('user', 'robot', 'anonymous')),
    disabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT
);

CREATE TABLE subject_groups (
    id         TEXT COLLATE "C" NOT NULL UNIQUE,
    name       TEXT COLLATE "C" PRIMARY KEY,
    created_at BIGINT
);

CREATE TABLE group_subjects (
    group_name   TEXT COLLATE "C" NOT NULL REFERENCES subject_groups (name) ON DELETE CASCADE,
    subject_name TEXT COLLATE "C" NOT NULL REFERENCES subjects (name) ON DELETE CASCADE,
    PRIMARY KEY (group_name, subject_name)
);

CREATE INDEX group_subjects_subject ON group_subjects (subject_name);

CREATE TABLE roles (
    name    TEXT COLLATE "C"    PRIMARY KEY,
    builtin BOOLEAN NOT NULL DEFAULT FALSE
);

-- Verbs are stored expanded and explicit, never as wildcards (ADR 0002).
CREATE TABLE role_verbs (
    role_name TEXT COLLATE "C" NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    verb      TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (role_name, verb)
);

-- principal_id names a subject id or a group id, so it carries no foreign key;
-- the two deletion paths remove the matching bindings explicitly. The unique
-- grant keeps duplicates out of the effective-permission explainer.
CREATE TABLE bindings (
    id             TEXT COLLATE "C" NOT NULL PRIMARY KEY,
    principal_kind TEXT COLLATE "C" NOT NULL CHECK (principal_kind IN ('subject', 'group')),
    principal_id   TEXT COLLATE "C" NOT NULL,
    role_name      TEXT COLLATE "C" NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    scope          TEXT COLLATE "C" NOT NULL,
    created_at     BIGINT,
    UNIQUE (principal_kind, principal_id, role_name, scope)
);

CREATE INDEX bindings_principal ON bindings (principal_kind, principal_id);

-- --- credentials ------------------------------------------------------------
--
-- Every secret column holds a hash. A credential outliving its subject would
-- be a usable secret belonging to nobody, so all four cascade.

CREATE TABLE user_credentials (
    subject_name TEXT COLLATE "C"    PRIMARY KEY REFERENCES subjects (name) ON DELETE CASCADE,
    hash         TEXT COLLATE "C"    NOT NULL,
    must_rotate  BOOLEAN NOT NULL DEFAULT FALSE,
    rotated_at   BIGINT
);

CREATE TABLE robot_credentials (
    subject_name TEXT COLLATE "C"   PRIMARY KEY REFERENCES subjects (name) ON DELETE CASCADE,
    secret_hash  BYTEA  NOT NULL,
    expires_at   BIGINT NOT NULL,
    rotated_at   BIGINT
);

CREATE TABLE access_tokens (
    id           TEXT COLLATE "C"  NOT NULL PRIMARY KEY,
    subject_name TEXT COLLATE "C"  NOT NULL REFERENCES subjects (name) ON DELETE CASCADE,
    name         TEXT COLLATE "C"  NOT NULL DEFAULT '',
    token_hash   BYTEA NOT NULL UNIQUE,
    created_at   BIGINT,
    expires_at   BIGINT,
    last_used_at BIGINT
);

CREATE INDEX access_tokens_subject ON access_tokens (subject_name, name);

CREATE TABLE sessions (
    id                  TEXT COLLATE "C"   NOT NULL PRIMARY KEY,
    subject_name        TEXT COLLATE "C"   NOT NULL REFERENCES subjects (name) ON DELETE CASCADE,
    csrf_token          TEXT COLLATE "C"   NOT NULL,
    created_at          BIGINT,
    idle_expires_at     BIGINT NOT NULL,
    absolute_expires_at BIGINT NOT NULL
);

CREATE INDEX sessions_subject ON sessions (subject_name);
