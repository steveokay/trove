-- 0007_proxy_credentials: one encrypted upstream credential per proxy
-- repository (ADR 0016, C-003).
--
-- `sealed` is a complete secretbox value -- "v1:<key-id>:<base64(nonce ‖
-- ciphertext)>" -- produced under the associated data
-- `proxy-credential:<repo-name>`. Nothing in the storage layer encrypts or
-- decrypts: the column holds a string this schema cannot read, and the key
-- lives outside the database entirely, so a stolen database yields ciphertext
-- and a stolen row yields ciphertext bound to a repository it is not in.
--
-- There is deliberately no username column. Storing the account beside the
-- ciphertext would put half the credential in the clear for every read path,
-- backup, and replica -- and the half that names the identity is the half an
-- attacker most wants when the other half is a token. Both fields go inside
-- the sealed blob together.
--
-- The row dies with the repository, the cascade group_members has had since
-- 0001 and repository_config_history since 0005. A name is free once it is
-- deleted, and a proxy created at that name afterwards points at whatever
-- upstream its own operator chose; inheriting a predecessor's credential would
-- send somebody else's password there.
--
-- One row per repository, so the name is the primary key: a proxy has one
-- upstream (ADR 0005) and therefore one credential, and rotation is a
-- replacement rather than a second row nothing would choose between.

CREATE TABLE proxy_credentials (
    repo_name  TEXT NOT NULL PRIMARY KEY REFERENCES repositories (name) ON DELETE CASCADE,
    sealed     TEXT NOT NULL,
    rotated_at INTEGER
);
