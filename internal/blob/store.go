// Package blob is content-addressed blob storage: the interface, the digest
// parser that guards it, and the verification both drivers share.
//
// Two rules shape everything here.
//
// Digests are verified on write and on read (ADR 0007). A Put that does not
// hash to the digest it was given leaves nothing behind, and a Get that finds
// the bytes have changed underneath it fails the read rather than serving
// them. Silently returning a corrupted layer is the worst thing a registry can
// do, and it is cheap to prevent relative to the network cost of the transfer.
//
// Hosted and cached content are separate instances of this interface over
// disjoint roots, chosen at wiring time (ADR 0009). There is no "kind"
// argument and no way to ask a store for the other one's content: the cache
// eviction path is handed the cache store and physically cannot name a hosted
// blob. Deleting a cached blob is always recoverable; deleting a hosted one is
// not, and separation by construction beats separation by discipline.
package blob

import (
	"context"
	"io"
)

// Descriptor is what the store knows about a blob without opening it.
type Descriptor struct {
	Digest Digest
	Size   int64
}

// Store is content-addressed blob storage.
//
// Every method takes a Digest and validates it before touching storage, so an
// unparseable digest is an error rather than a path.
type Store interface {
	// Put stores the reader's bytes under the expected digest, hashing as they
	// stream. On mismatch it returns ErrDigestMismatch and leaves nothing
	// behind -- a partially written blob must never become visible, because
	// nothing downstream re-checks.
	//
	// Storing a digest that is already present is not an error: blobs are
	// content-addressed and identical by definition, so two pushes of the same
	// layer both succeed and the first one stored wins.
	Put(ctx context.Context, expected Digest, r io.Reader) error

	// Get opens a blob. The returned reader verifies as it streams and fails
	// before its final byte if the content no longer matches (ADR 0007), so a
	// client's own digest check cannot pass over corrupt bytes.
	Get(ctx context.Context, digest Digest) (VerifiedReader, error)

	// Stat returns a descriptor without opening the content.
	Stat(ctx context.Context, digest Digest) (Descriptor, error)

	// Delete removes a blob. Garbage collection calls it only after
	// re-checking reachability (ADR 0010); the store enforces nothing about
	// references because it does not know about them.
	Delete(ctx context.Context, digest Digest) error

	// Walk calls fn for every blob currently stored, in no defined order. It
	// is what garbage collection sweeps with and what `trove verify` scrubs.
	// A blob mid-write is not visible to Walk: only committed content is.
	//
	// If fn returns an error, Walk stops and returns it.
	Walk(ctx context.Context, fn func(Descriptor) error) error
}

// VerifiedReader streams a blob and verifies it as it goes.
//
// The last byte is withheld until the hash checks out. A client that trusted a
// clean EOF would otherwise have to be told separately that what it just read
// was wrong; instead the stream ends short and the read returns
// ErrDigestMismatch, which every OCI client already handles as a failed pull.
type VerifiedReader interface {
	io.ReadCloser

	// Descriptor describes the blob being read.
	Descriptor() Descriptor
}

// Uploader opens resumable upload sessions. A driver implements it alongside
// Store when it can hold partial content; the registry's chunked upload
// endpoints need it, and a Put of a complete body does not.
type Uploader interface {
	// CreateUpload starts a session under the caller's identifier. Identifiers
	// come from the caller so that they can be recorded in the metadata store
	// in the same transaction that starts the upload (ADR 0010).
	CreateUpload(ctx context.Context, id string) (UploadSession, error)

	// OpenUpload resumes a session, or returns ErrNotFound. Resuming is what a
	// client does after a dropped connection, and what makes an interrupted
	// push of a large layer survivable.
	OpenUpload(ctx context.Context, id string) (UploadSession, error)
}

// UploadSession accumulates a blob across requests.
//
// A session's bytes are not a blob: they are unverified, they have no digest
// yet, and nothing outside the session can see them. Only Commit turns them
// into content, and only after verifying the whole of what was accumulated.
type UploadSession interface {
	// ID is the identifier the session was created with.
	ID() string

	// Offset is how many bytes the session holds. A resumed session reports
	// what survived, which is what a client's Range header is answered from.
	Offset() int64

	// Write appends the reader's bytes and returns the new offset.
	Write(ctx context.Context, r io.Reader) (int64, error)

	// Commit verifies everything the session holds against expected and
	// publishes it as a blob. On mismatch the session's bytes are discarded
	// and nothing is published: a caller that could retry into a
	// half-committed session would be able to smuggle content past the check.
	Commit(ctx context.Context, expected Digest) (Descriptor, error)

	// Cancel discards the session. It is safe to call on a session that was
	// already committed or cancelled -- an abandoned upload is reaped later
	// (R-011) and the reaper should not have to care who got there first.
	Cancel(ctx context.Context) error
}

// CorruptHook is called when a read finds a blob whose bytes no longer hash to
// its digest. A driver quarantines the content and then calls the hook, which
// is where the blob.corrupt event and the audit record come from (§8).
//
// It is a plain function rather than an event-bus dependency so that the blob
// packages stay free of one: storage does not import the event system, the
// wiring passes the hook in.
type CorruptHook func(ctx context.Context, desc Descriptor, err error)
