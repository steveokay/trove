# ADR 0007 — Blob storage layout and digest verification

- Status: accepted (2026-09-01)
- Task: D-007
- Decisions applied: Q13 (encryption delegated to the storage layer)

## Context

Content-addressed blob storage with a filesystem driver (default) and an
S3-compatible driver, one `blob.Store` interface, one contract suite. Hosted and
cached content must be physically separate (§4), and digests are verified on both
write and read (§11).

## Decision

### Interface shape

Two instances of the same interface, constructed over disjoint roots — the caller
chooses at wiring time, so cache code *cannot name* hosted storage:

```
type Store interface {
    Put(ctx, expectedDigest, io.Reader) error      // verifies while streaming; atomic
    Get(ctx, digest) (VerifiedReader, error)        // stream-verifies; see below
    Stat(ctx, digest) (Descriptor, error)
    Delete(ctx, digest) error
    Walk(ctx, fn) error                             // for GC sweep and trove verify
}
```

Upload sessions (chunked/resumable) are a separate `UploadSession` type that only
ever commits into the hosted instance via `Put` semantics.

### Filesystem layout

```
<data>/
  hosted/blobs/sha256/<first-2>/<digest>          # committed, immutable
  hosted/uploads/<session-ulid>                    # staging; fsync then rename
  cache/blobs/sha256/<first-2>/<digest>
  keys/                                            # secrets + signing keys (ADR 0016)
```

- Two-level fan-out keeps directories small on ext4/NTFS alike.
- Writes stage under `uploads/`, are hash-verified as bytes stream in, then
  `fsync` + `rename(2)` into place — a blob path either doesn't exist or is
  complete and verified. Committed files are read-only (0444).
- Digest algorithm: `sha256` required; the layout namespaces the algorithm so
  `sha512` can be added without migration.

### S3-compatible layout

- Keys mirror the fs layout: `hosted/blobs/sha256/<digest>`, `cache/blobs/...`
  under a configurable prefix; separate buckets optionally.
- Multipart upload for large blobs; the digest is verified by streaming hash during
  upload, and the object is aborted (never completed) on mismatch.
- Reads may be served as redirects to presigned URLs *only* when
  `s3.redirect: true` (default false): a redirect bypasses our read-verification,
  so the default keeps trove in the data path. Operators who enable it accept
  S3's integrity guarantees explicitly.

### Verification semantics

- **Write**: always fully verified before commit — a mismatched Put leaves nothing
  behind and returns `DIGEST_INVALID`. This includes proxy cache fills: upstream
  bytes are hashed against the digest *we requested*, and a mismatch is rejected
  and not cached (C-004).
- **Read**: `Get` returns a reader that hashes as it streams; on completion
  mismatch it (a) truncates the response before the final byte so clients fail
  digest-check cleanly, (b) quarantines the blob (renames into
  `<root>/quarantine/`), (c) emits `blob.corrupt` + audit. Clients verify digests
  themselves per OCI, so the failure mode is a failed pull, never silent corruption.
- `trove verify` (P-012) walks both stores re-hashing at rest and reconciling
  against `blobs`/`cached_blobs` rows.

### Encryption at rest

Delegated to the layer below (Q13): LUKS/dm-crypt/ZFS for the filesystem driver,
SSE for S3 — documented in DOC-002 with worked examples. trove itself encrypts only
small secrets (ADR 0016), never blob payloads.

## Rejected alternatives

- **Sharing one root with a `kind` column/flag** — same argument as the schema
  (ADR 0006): separation by construction beats separation by discipline.
- **App-level blob encryption** — kills range requests and S3 redirect, adds key
  loss as a total-data-loss mode, duplicates what LUKS/SSE do better (Q13).
- **Trusting upstream/storage integrity on read** — a bit-flipped layer served
  silently is the worst failure a registry can have; streaming hash on read is
  cheap relative to network I/O.
- **docker/distribution's deep path scheme** (`/docker/registry/v2/...`) — carries
  historical baggage (link files, algorithm dirs per repo) we don't need; our
  references live in the metadata store.

## Consequences

- The contract suite (F-008) covers: digest mismatch on write, truncated stream,
  resume, concurrent Put of the same digest (first commit wins, second is a no-op),
  Walk consistency during writes, and path-traversal attempts via digest strings
  (rejected by the digest parser before any path is built).
- Blob bytes are engine-agnostic: migrating fs → S3 is a copy of two trees plus a
  config change, and `trove verify` validates the result.
- `internal/cache` receives only the cache-rooted Store instance; `internal/gc`
  only the hosted one — the type-level separation test (§4) asserts exactly this
  wiring.
