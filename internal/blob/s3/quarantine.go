package s3

import (
	"context"
	"errors"
	"fmt"

	"github.com/minio/minio-go/v7"

	"github.com/steveokay/trove/internal/blob"
)

// quarantiningReader moves an object out of the served keyspace once a read
// proves its bytes no longer hash to its digest.
//
// As on the filesystem, the move happens on Close: the inner reader still has
// the object open at detection, and the operator's hook is called after the
// move so "corrupt" and "quarantined" are one event that is already true.
type quarantiningReader struct {
	blob.VerifiedReader

	store *Store
	desc  blob.Descriptor
	ctx   context.Context

	corrupt error
}

// detected records the mismatch. It is the CorruptHook the shared verified
// reader calls, and it does nothing that could fail mid-read.
func (r *quarantiningReader) detected(_ context.Context, _ blob.Descriptor, err error) {
	r.corrupt = err
}

// Close releases the object and, if the content turned out to be corrupt,
// quarantines it and reports it.
func (r *quarantiningReader) Close() error {
	err := r.VerifiedReader.Close()
	if r.corrupt == nil {
		return err
	}

	quarantineErr := r.store.quarantine(r.ctx, r.desc.Digest)
	if r.store.onCorrupt != nil {
		// The hook is called whether or not the move worked: an operator needs
		// to hear about corrupt content even when it could not be isolated,
		// and that case is the more urgent of the two.
		r.store.onCorrupt(r.ctx, r.desc, errors.Join(r.corrupt, quarantineErr))
	}
	return errors.Join(err, quarantineErr)
}

// quarantine copies a blob into the quarantine keyspace and removes the
// original.
//
// Keeping the bytes is the point: they are evidence of whether a layer was
// truncated, flipped, or replaced, and `trove verify` reconciles what is left
// against the metadata store. An object store has no rename, so this is a
// server-side copy followed by a delete -- and in that order, because losing
// the evidence is worse than briefly holding two copies.
func (s *Store) quarantine(ctx context.Context, digest blob.Digest) error {
	source, err := s.blobKey(digest)
	if err != nil {
		return err
	}
	target, err := s.quarantineKey(digest)
	if err != nil {
		return err
	}

	_, err = s.client.CopyObject(ctx,
		minio.CopyDestOptions{Bucket: s.bucket, Object: target},
		minio.CopySrcOptions{Bucket: s.bucket, Object: source})
	if err != nil {
		if notFound(err) {
			// Something else already moved it: a concurrent reader hitting the
			// same corruption, or a sweep. Either way the bad content is no
			// longer being served, which is the goal.
			return nil
		}
		return fmt.Errorf("copy to quarantine: %w", err)
	}

	if err := s.client.RemoveObject(ctx, s.bucket, source, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("remove quarantined object: %w", err)
	}
	return nil
}
