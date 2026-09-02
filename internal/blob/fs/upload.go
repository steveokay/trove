package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"

	"github.com/steveokay/trove/internal/blob"
)

// uploadPath returns the staging file for a session.
func (s *Store) uploadPath(id string) (string, error) {
	if err := blob.ValidateUploadID(id); err != nil {
		return "", err
	}
	return s.confine(uploadsDir, id)
}

// CreateUpload starts an upload session.
func (s *Store) CreateUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.uploadPath(id)
	if err != nil {
		return nil, err
	}

	// O_EXCL is the whole check: two clients cannot end up appending to one
	// file because one of them created it first.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stagingMode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, blob.Invalid("id", "upload session already exists")
		}
		return nil, fmt.Errorf("create upload session: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("create upload session: %w", err)
	}
	return &session{store: s, id: id, path: path}, nil
}

// OpenUpload resumes an existing session.
func (s *Store) OpenUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.uploadPath(id)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, blob.NotFound("upload", id)
		}
		return nil, fmt.Errorf("open upload session: %w", err)
	}
	// The offset comes from the file rather than from memory, so a session
	// survives a restart: what is on disk is what the client is told it can
	// resume from.
	return &session{store: s, id: id, path: path, offset: info.Size()}, nil
}

// session is one in-progress upload, backed by a staging file.
//
// Its state lives on disk: the file's presence is the session's existence, and
// its size is the offset. Two handles on the same identifier therefore agree,
// and a restart loses nothing.
type session struct {
	store *Store
	id    string
	path  string

	mu     sync.Mutex
	offset int64
}

// ID is the identifier the session was created with.
func (u *session) ID() string { return u.id }

// Offset is how many bytes the session holds.
func (u *session) Offset() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.offset
}

// Write appends the reader's bytes and returns the new offset.
func (u *session) Write(ctx context.Context, r io.Reader) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	file, err := os.OpenFile(u.path, os.O_WRONLY|os.O_APPEND, stagingMode)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, blob.NotFound("upload", u.id)
		}
		return u.offset, fmt.Errorf("open upload session: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Whatever arrived is kept, even when the copy fails part way: a client
	// that lost its connection resumes from the offset it is told about, and
	// discarding the chunk would make a large push unresumable on exactly the
	// links that drop.
	written, copyErr := io.Copy(file, r)
	u.offset += written

	if err := file.Sync(); err != nil && copyErr == nil {
		copyErr = fmt.Errorf("sync upload session: %w", err)
	}
	return u.offset, copyErr
}

// Commit verifies everything the session holds and publishes it.
func (u *session) Commit(ctx context.Context, expected blob.Digest) (blob.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return blob.Descriptor{}, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	target, err := u.store.blobPath(expected)
	if err != nil {
		return blob.Descriptor{}, err
	}

	file, err := os.Open(u.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return blob.Descriptor{}, blob.NotFound("upload", u.id)
		}
		return blob.Descriptor{}, fmt.Errorf("open upload session: %w", err)
	}

	// Re-read rather than trusting a hash carried across requests: the session
	// may have been resumed by another process, and the bytes on disk are the
	// only thing that can be verified.
	size, verifyErr := blob.Copy(io.Discard, file, expected)
	if closeErr := file.Close(); closeErr != nil && verifyErr == nil {
		verifyErr = fmt.Errorf("close upload session: %w", closeErr)
	}
	if verifyErr != nil {
		// The session goes with the failure. Leaving it open would let a
		// caller retry the commit against bytes that have already been
		// rejected, one chunk at a time, until something matched.
		_ = os.Remove(u.path)
		return blob.Descriptor{}, verifyErr
	}

	if err := u.store.commit(u.path, target); err != nil {
		return blob.Descriptor{}, err
	}
	// commit renames the staging file when the blob is new and leaves it when
	// the blob already existed, so the session is cleared either way.
	_ = os.Remove(u.path)
	u.offset = 0
	return blob.Descriptor{Digest: expected, Size: size}, nil
}

// Cancel discards the session. It is safe to call more than once.
func (u *session) Cancel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if err := os.Remove(u.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cancel upload session: %w", err)
	}
	u.offset = 0
	return nil
}
