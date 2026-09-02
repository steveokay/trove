package fs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/steveokay/trove/internal/blob"
)

// quarantiningReader moves a blob out of the way once a read proves its bytes
// no longer hash to its digest.
//
// The move happens on Close rather than at detection, because a file cannot be
// renamed while it is open on Windows and the inner reader still holds it. The
// operator's hook is called after the move, so "corrupt" and "quarantined" are
// reported as one event that is already true rather than an intention.
//
// On Windows the move can still fail while another reader holds the same blob,
// and then the hook carries that failure alongside the mismatch. Nothing
// unsafe follows from it: no reader will serve the content, because each one
// verifies for itself, and the next Close after the last handle closes moves
// it. The correctness target for the layout is ext4 (Q25).
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

// Close releases the file and, if the content turned out to be corrupt,
// quarantines it and reports it.
func (r *quarantiningReader) Close() error {
	err := r.VerifiedReader.Close()
	if r.corrupt == nil {
		return err
	}

	quarantineErr := r.store.quarantine(r.desc.Digest)
	if r.store.onCorrupt != nil {
		// The hook is called whether or not the move worked: an operator needs
		// to hear about corrupt content even when it could not be isolated,
		// and that case is the more urgent of the two.
		r.store.onCorrupt(r.ctx, r.desc, errors.Join(r.corrupt, quarantineErr))
	}
	return errors.Join(err, quarantineErr)
}

// quarantine moves a blob out of the served tree.
//
// Moving rather than deleting is the point: the bytes are evidence. An
// operator wants to know whether a layer was truncated, flipped by a failing
// disk, or replaced, and `trove verify` reconciles what is left against the
// metadata store. A blob that is gone answers none of that.
func (s *Store) quarantine(digest blob.Digest) error {
	source, err := s.blobPath(digest)
	if err != nil {
		return err
	}
	target, err := s.quarantinePath(digest)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
		return fmt.Errorf("create quarantine directory: %w", err)
	}
	// Committed blobs are read-only, and Windows refuses to replace a
	// read-only file. Removing an earlier copy of the same corrupt content
	// loses nothing: it is the same digest and the same failure.
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear quarantine slot: %w", err)
	}
	if err := os.Rename(source, target); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Something else already moved or deleted it -- a concurrent
			// reader hitting the same corruption, or a sweep. Either way the
			// bad content is no longer being served, which is the goal.
			return nil
		}
		return fmt.Errorf("quarantine blob: %w", err)
	}
	return syncDir(filepath.Dir(target))
}
