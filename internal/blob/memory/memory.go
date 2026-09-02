// Package memory is an in-memory blob.Store. It is the reference
// implementation: it defines the behaviour the contract suite pins down, and it
// lets packages above the storage layer be tested without a filesystem or an
// object store.
//
// It is not a production store. Nothing is persisted and every blob is held in
// memory, so it is only sensible for tests and for a throwaway instance.
package memory

import (
	"bytes"
	"context"
	"io"
	"sync"

	"github.com/steveokay/trove/internal/blob"
)

// Options configure a store.
type Options struct {
	// OnCorrupt is called when a read finds content that no longer matches its
	// digest. In memory that can only happen if something reached past the
	// store and changed it, which is exactly what a test does to exercise the
	// path a disk driver hits for real.
	OnCorrupt blob.CorruptHook
}

// Store is an in-memory blob.Store.
type Store struct {
	mu      sync.RWMutex
	blobs   map[blob.Digest][]byte
	uploads map[string]*session

	onCorrupt blob.CorruptHook
}

// assert the interfaces are satisfied at compile time.
var (
	_ blob.Store    = (*Store)(nil)
	_ blob.Uploader = (*Store)(nil)
)

// New returns an empty store.
func New(opts Options) *Store {
	return &Store{
		blobs:     make(map[blob.Digest][]byte),
		uploads:   make(map[string]*session),
		onCorrupt: opts.OnCorrupt,
	}
}

// Put stores the reader's bytes under the expected digest.
func (s *Store) Put(ctx context.Context, expected blob.Digest, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return err
	}

	// Buffered before the lock is taken and before anything is published: a
	// mismatch must leave nothing behind, so nothing is stored until the whole
	// content has been verified.
	var buf bytes.Buffer
	if _, err := blob.Copy(&buf, r, expected); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.blobs[expected]; exists {
		// Content-addressed: identical by definition, so the first write wins
		// and the second is a no-op rather than a conflict.
		return nil
	}
	s.blobs[expected] = buf.Bytes()
	return nil
}

// Get opens a blob for reading, verified as it streams.
func (s *Store) Get(ctx context.Context, digest blob.Digest) (blob.VerifiedReader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := digest.Validate(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	data, ok := s.blobs[digest]
	s.mu.RUnlock()
	if !ok {
		return nil, blob.NotFound("blob", string(digest))
	}

	desc := blob.Descriptor{Digest: digest, Size: int64(len(data))}
	return blob.NewVerifiedReader(ctx, io.NopCloser(bytes.NewReader(data)), desc, s.onCorrupt)
}

// Stat returns a descriptor without opening the content.
func (s *Store) Stat(ctx context.Context, digest blob.Digest) (blob.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return blob.Descriptor{}, err
	}
	if err := digest.Validate(); err != nil {
		return blob.Descriptor{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blobs[digest]
	if !ok {
		return blob.Descriptor{}, blob.NotFound("blob", string(digest))
	}
	return blob.Descriptor{Digest: digest, Size: int64(len(data))}, nil
}

// Delete removes a blob.
func (s *Store) Delete(ctx context.Context, digest blob.Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := digest.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blobs[digest]; !ok {
		return blob.NotFound("blob", string(digest))
	}
	delete(s.blobs, digest)
	return nil
}

// Walk calls fn for every stored blob.
func (s *Store) Walk(ctx context.Context, fn func(blob.Descriptor) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// The snapshot is taken under the lock and walked outside it: fn is the
	// caller's code, and calling it with the store locked would let a garbage
	// collector deadlock itself against a concurrent push.
	s.mu.RLock()
	descriptors := make([]blob.Descriptor, 0, len(s.blobs))
	for digest, data := range s.blobs {
		descriptors = append(descriptors, blob.Descriptor{Digest: digest, Size: int64(len(data))})
	}
	s.mu.RUnlock()

	for _, desc := range descriptors {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(desc); err != nil {
			return err
		}
	}
	return nil
}

// CreateUpload starts an upload session.
func (s *Store) CreateUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, blob.Invalid("id", "must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.uploads[id]; exists {
		return nil, blob.Invalid("id", "upload session already exists")
	}
	upload := &session{store: s, id: id}
	s.uploads[id] = upload
	return upload, nil
}

// OpenUpload resumes an existing session.
func (s *Store) OpenUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	upload, ok := s.uploads[id]
	if !ok {
		return nil, blob.NotFound("upload", id)
	}
	return upload, nil
}

// session is one in-progress upload. Its bytes are not a blob: nothing outside
// the session can see them, and only Commit turns them into content.
type session struct {
	store *Store
	id    string

	mu     sync.Mutex
	buf    []byte
	closed bool
}

// ID is the identifier the session was created with.
func (u *session) ID() string { return u.id }

// Offset is how many bytes the session holds.
func (u *session) Offset() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return int64(len(u.buf))
}

// Write appends the reader's bytes and returns the new offset.
func (u *session) Write(ctx context.Context, r io.Reader) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, blob.NotFound("upload", u.id)
	}

	// Copied rather than read whole, so the bytes that did arrive are kept: a
	// client that lost its connection mid-chunk resumes from the offset it is
	// told about, and discarding them would make a large push unresumable on
	// exactly the links that drop.
	var chunk bytes.Buffer
	_, err := io.Copy(&chunk, r)
	u.buf = append(u.buf, chunk.Bytes()...)
	return int64(len(u.buf)), err
}

// Commit verifies everything the session holds and publishes it.
func (u *session) Commit(ctx context.Context, expected blob.Digest) (blob.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return blob.Descriptor{}, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return blob.Descriptor{}, blob.NotFound("upload", u.id)
	}

	// NewVerifier validates the digest, so an unparseable one is refused here
	// rather than becoming a key.
	verifier, err := blob.NewVerifier(expected)
	if err != nil {
		return blob.Descriptor{}, err
	}
	_, _ = verifier.Write(u.buf)
	if err := verifier.Verify(); err != nil {
		// The session goes with the failure. Leaving it open would let a
		// caller retry the commit against bytes that have already been
		// rejected, one chunk at a time, until something matched.
		u.discard()
		return blob.Descriptor{}, err
	}

	desc := blob.Descriptor{Digest: expected, Size: int64(len(u.buf))}
	u.store.mu.Lock()
	if _, exists := u.store.blobs[expected]; !exists {
		u.store.blobs[expected] = u.buf
	}
	delete(u.store.uploads, u.id)
	u.store.mu.Unlock()

	u.closed = true
	u.buf = nil
	return desc, nil
}

// Cancel discards the session. It is safe to call more than once.
func (u *session) Cancel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	u.discard()
	return nil
}

// discard drops the session's bytes and its registration. Callers hold the
// session lock.
func (u *session) discard() {
	u.store.mu.Lock()
	delete(u.store.uploads, u.id)
	u.store.mu.Unlock()

	u.closed = true
	u.buf = nil
}
