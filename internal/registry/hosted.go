package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/meta"
)

// Serving hosted content through the delegate contract (C-019).
//
// A group member can be hosted or a proxy, and group resolution asks both the
// same question: "can you serve this reference?". A proxy answers through
// internal/proxyserve; this is the hosted answer, so the group server holds one
// interface rather than a type switch over two.
//
// **The handlers do not route through it, and that is deliberate.** Rewiring
// them looked tidy until the cost showed itself: a hosted blob HEAD answers
// today from the metadata row alone, and asking it through ContentServer.Blob
// would open the file on every existence check -- which is what `docker push`
// does for every layer it might be able to mount, and what a pull does before
// it fetches. The seam is the right shape for a group member, which has to
// *produce* content to prove it has it, and the wrong shape for an existence
// check that already has a cheaper answer.
//
// What is shared instead is the part where duplication would actually hurt:
// resolveHostedManifest below is the one reader of a hosted manifest, used by
// the handler with an HTTP error mapping and by the adapter with a sentinel
// one. Two mappings of one read, rather than two reads.

// HostedManifestStore is what reading a hosted manifest needs. Declared here
// so the adapter can be built with less than a handler's worth of store.
type HostedManifestStore interface {
	GetTag(ctx context.Context, repo, name string) (meta.Tag, error)
	GetManifest(ctx context.Context, repo string, digest meta.Digest) (meta.Manifest, error)
	GetBlob(ctx context.Context, digest meta.Digest) (meta.Blob, error)
}

// errManifestDrift reports storage that disagrees with itself: a tag pointing
// at a manifest that is not there, or a payload that does not hash to the
// digest it is filed under.
//
// It is deliberately not one of the delegate sentinels. Drift is not "content
// unknown" -- the store promised this row exists -- and reporting it as such
// would let a client cache a not-found for content the registry still believes
// it has. It renders as an internal error, which is what it is, and `trove
// verify` (P-012) is what finds them in bulk.
var errManifestDrift = errors.New("registry: stored manifest does not match its record")

// errUnparseableDigest reports a reference that is digest-shaped and is not a
// digest.
//
// It is separate from ErrContentUnknown because the two are different answers
// to different questions. "sha256:short" is not a name this registry could
// ever hold, so saying DIGEST_INVALID discloses nothing about what exists --
// and it tells a client with a broken reference what is actually wrong, which
// a 404 would not. The delegated path collapses it to unknown instead, because
// a group member cannot serve an unparseable reference either way.
var errUnparseableDigest = errors.New("registry: reference is not a digest")

// resolveHostedManifest reads a hosted manifest by tag or digest.
//
// The reference is taken as the client wrote it. A tag that cannot be a tag is
// reported as unknown rather than as invalid, so probing with garbage looks
// exactly like probing with a plausible name (ADR 0003).
func resolveHostedManifest(ctx context.Context, store HostedManifestStore, name, reference string) (meta.Manifest, error) {
	var digest meta.Digest
	byDigest := isDigestReference(reference)

	switch {
	case byDigest:
		parsed, err := blob.ParseDigest(reference)
		if err != nil {
			return meta.Manifest{}, fmt.Errorf("%w: %s", errUnparseableDigest, err)
		}
		digest = meta.Digest(parsed)
	case !tagPattern.MatchString(reference):
		return meta.Manifest{}, ErrContentUnknown
	default:
		tag, err := store.GetTag(ctx, name, reference)
		switch {
		case errors.Is(err, meta.ErrNotFound):
			return meta.Manifest{}, ErrContentUnknown
		case err != nil:
			return meta.Manifest{}, fmt.Errorf("resolve tag %q in %q: %w", reference, name, err)
		}
		digest = tag.Digest
	}

	record, err := store.GetManifest(ctx, name, digest)
	switch {
	case errors.Is(err, meta.ErrNotFound) && byDigest:
		return meta.Manifest{}, ErrContentUnknown
	case errors.Is(err, meta.ErrNotFound):
		// A tag pointing at a manifest that is not there. The store guarantees
		// that edge, so this is drift rather than a miss.
		return meta.Manifest{}, fmt.Errorf("%w: tag %q in %q names a manifest that is not stored",
			errManifestDrift, reference, name)
	case err != nil:
		return meta.Manifest{}, fmt.Errorf("read manifest %s in %q: %w", digest, name, err)
	}

	// Re-hashed on every read: the bytes are what the client verifies, and
	// serving a payload that does not match the digest it is filed under would
	// be the registry telling a lie its client is equipped to catch.
	stored, err := blob.ParseDigest(string(record.Digest))
	if err != nil || blob.FromBytes(stored.Algorithm(), record.Payload) != stored {
		return meta.Manifest{}, fmt.Errorf("%w: %s in %q", errManifestDrift, record.Digest, name)
	}
	return record, nil
}

// HostedContent serves a hosted repository's reads through the delegate
// contract, so group resolution can ask a hosted member and a proxy member the
// same question (C-019).
type HostedContent struct {
	// Meta reads manifests, tags, and blob rows.
	Meta HostedManifestStore
	// Store holds the bytes.
	Store blob.Store
}

// Manifest returns a hosted manifest by tag or digest.
func (h *HostedContent) Manifest(ctx context.Context, name, reference string) (ServedManifest, error) {
	record, err := resolveHostedManifest(ctx, h.Meta, name, reference)
	switch {
	case errors.Is(err, errUnparseableDigest):
		// A member cannot serve a reference that is not one. The delegate
		// contract has three answers and this is the closest true one: not
		// here, and never could be.
		return ServedManifest{}, ErrContentUnknown
	case err != nil:
		return ServedManifest{}, err
	}
	return ServedManifest{
		Digest:    blob.Digest(record.Digest),
		MediaType: record.MediaType,
		Payload:   record.Payload,
	}, nil
}

// Blob opens a hosted blob.
//
// The row is consulted before the bytes for the reason the hosted handler
// consults it: the row is what says this registry has the blob, and opening
// bytes that no row claims would serve content the registry does not consider
// itself to hold.
func (h *HostedContent) Blob(ctx context.Context, _ string, digest blob.Digest) (ServedBlob, error) {
	record, err := h.Meta.GetBlob(ctx, meta.Digest(digest))
	switch {
	case errors.Is(err, meta.ErrNotFound):
		return ServedBlob{}, ErrContentUnknown
	case err != nil:
		return ServedBlob{}, fmt.Errorf("read blob row %s: %w", digest, err)
	}

	reader, err := h.Store.Get(ctx, digest)
	if err != nil {
		// A row without bytes is drift, never "unknown": the row is a promise
		// this registry made (P-012 finds these in bulk).
		return ServedBlob{}, fmt.Errorf("open hosted blob %s: %w", digest, err)
	}
	return ServedBlob{Content: reader, Size: record.Size, Digest: digest}, nil
}

// HostedContent implements the delegate contract.
var _ ContentServer = (*HostedContent)(nil)
