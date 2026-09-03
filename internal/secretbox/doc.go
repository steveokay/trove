// Package secretbox encrypts the small secrets trove must keep across restarts
// but must never reveal: proxy upstream credentials (C-003) and webhook signing
// secrets (ADR 0012).
//
// It is deliberately the only package in the tree that imports an AEAD
// primitive, which is what makes the cryptography auditable in one place; an
// import-boundary test enforces that (ADR 0016). Blob payloads are explicitly
// out of scope (Q13) — encrypting those is the filesystem's or the object
// store's job.
//
// The shape of the package follows from two operational requirements. Rotation
// must be possible without downtime, so a Keyring holds several keys: the first
// encrypts, the rest only decrypt, and every sealed value names the key that
// produced it. And a ciphertext must be useless outside the row it came from,
// so every Seal and Open takes a Context — associated data that binds the value
// to its column and its owner. There is no default context, because a default
// is a thing a caller can forget to override.
package secretbox
