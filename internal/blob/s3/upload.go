package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7"

	"github.com/steveokay/trove/internal/blob"
)

// An object store has no append, so a session is a set of chunk objects under
// one key prefix rather than a single growing file:
//
//	<prefix>uploads/<id>/session      a zero-length marker
//	<prefix>uploads/<id>/000001       one PATCH's bytes
//
// The marker is what makes an empty session exist. Everything else about the
// session is derived from the objects themselves -- the offset is the sum of
// the chunk sizes -- so two handles agree and a restart loses nothing, exactly
// as the filesystem driver derives its state from one file.
//
// A multipart upload would avoid the extra round trip at commit, but its parts
// cannot be smaller than 5 MiB except the last, and a client is entitled to
// PATCH a kilobyte at a time. Buffering to reach the minimum would mean
// holding a client's bytes in memory across requests, which is worse.

// sessionMarker is the object that says a session exists.
const sessionMarker = "session"

// chunkDigits pads a sequence number so lexical listing order is numeric
// order. Six digits allows a million chunks, far past what any client sends.
const chunkDigits = 6

// uploadPrefixFor returns the key prefix holding one session's objects.
func (s *Store) uploadPrefixFor(id string) (string, error) {
	if err := blob.ValidateUploadID(id); err != nil {
		return "", err
	}
	return s.prefix + uploadsPrefix + "/" + id + "/", nil
}

// CreateUpload starts an upload session.
func (s *Store) CreateUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix, err := s.uploadPrefixFor(id)
	if err != nil {
		return nil, err
	}

	// Reusing an identifier would let one client write into another's session,
	// so an existing marker is a refusal rather than a fresh start.
	_, err = s.client.StatObject(ctx, s.bucket, prefix+sessionMarker, minio.StatObjectOptions{})
	switch {
	case err == nil:
		return nil, blob.Invalid("id", "upload session already exists")
	case !notFound(err):
		return nil, fmt.Errorf("check upload session: %w", err)
	}

	if _, err := s.client.PutObject(ctx, s.bucket, prefix+sessionMarker,
		strings.NewReader(""), 0, minio.PutObjectOptions{}); err != nil {
		return nil, fmt.Errorf("create upload session: %w", err)
	}
	return &session{store: s, id: id, prefix: prefix}, nil
}

// OpenUpload resumes an existing session.
func (s *Store) OpenUpload(ctx context.Context, id string) (blob.UploadSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix, err := s.uploadPrefixFor(id)
	if err != nil {
		return nil, err
	}

	if _, err := s.client.StatObject(ctx, s.bucket, prefix+sessionMarker, minio.StatObjectOptions{}); err != nil {
		if notFound(err) {
			return nil, blob.NotFound("upload", id)
		}
		return nil, fmt.Errorf("open upload session: %w", err)
	}

	chunks, err := s.listChunks(ctx, prefix)
	if err != nil {
		return nil, err
	}
	// The offset comes from the objects rather than from memory, so what the
	// client is told it can resume from is what is actually stored.
	var offset int64
	for _, chunk := range chunks {
		offset += chunk.size
	}
	return &session{store: s, id: id, prefix: prefix, offset: offset, next: len(chunks) + 1}, nil
}

// chunk is one stored piece of a session.
type chunk struct {
	key  string
	size int64
}

// listChunks returns a session's chunks in the order they were written.
func (s *Store) listChunks(ctx context.Context, prefix string) ([]chunk, error) {
	var chunks []chunk
	err := s.forEachObject(ctx, minio.ListObjectsOptions{Prefix: prefix, Recursive: true},
		func(object minio.ObjectInfo) error {
			name := strings.TrimPrefix(object.Key, prefix)
			if name == sessionMarker {
				return nil
			}
			if _, err := strconv.Atoi(name); err != nil {
				// Not something this driver wrote; leaving it alone beats
				// folding unknown bytes into a client's upload.
				return nil
			}
			chunks = append(chunks, chunk{key: object.Key, size: object.Size})
			return nil
		})
	if err != nil {
		return nil, err
	}
	// Listings are lexical, and the names are zero-padded, so this is already
	// numeric order -- but the sort makes that a property of this code rather
	// than of the service.
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].key < chunks[j].key })
	return chunks, nil
}

// session is one in-progress upload, backed by chunk objects.
type session struct {
	store  *Store
	id     string
	prefix string

	mu     sync.Mutex
	offset int64
	next   int
}

// ID is the identifier the session was created with.
func (u *session) ID() string { return u.id }

// Offset is how many bytes the session holds.
func (u *session) Offset() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.offset
}

// Write appends the reader's bytes as a new chunk and returns the new offset.
func (u *session) Write(ctx context.Context, r io.Reader) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if _, err := u.store.client.StatObject(ctx, u.store.bucket, u.prefix+sessionMarker, minio.StatObjectOptions{}); err != nil {
		if notFound(err) {
			return 0, blob.NotFound("upload", u.id)
		}
		return u.offset, fmt.Errorf("check upload session: %w", err)
	}

	if u.next == 0 {
		u.next = 1
	}
	key := fmt.Sprintf("%s%0*d", u.prefix, chunkDigits, u.next)

	// A read failure part way through is presented to the client library as a
	// clean end, so the bytes that did arrive are stored and the error is
	// returned afterwards. Discarding them would make a large push
	// unresumable on exactly the links that drop.
	source := &haltingReader{src: r}
	info, err := u.store.client.PutObject(ctx, u.store.bucket, key, source, -1, minio.PutObjectOptions{})
	if err != nil {
		return u.offset, fmt.Errorf("write upload chunk: %w", err)
	}
	if info.Size > 0 {
		u.offset += info.Size
		u.next++
	} else {
		// An empty chunk would list as a gap in the sequence for no reason.
		_ = u.store.client.RemoveObject(ctx, u.store.bucket, key, minio.RemoveObjectOptions{})
	}
	return u.offset, source.err
}

// haltingReader turns a source failure into an end of stream, remembering the
// error for the caller to report once what arrived has been stored.
type haltingReader struct {
	src io.Reader
	err error
}

func (r *haltingReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, io.EOF
	}
	n, err := r.src.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		r.err = err
		return n, io.EOF
	}
	return n, err
}

// Commit verifies everything the session holds and publishes it.
func (u *session) Commit(ctx context.Context, expected blob.Digest) (blob.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return blob.Descriptor{}, err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	key, err := u.store.blobKey(expected)
	if err != nil {
		return blob.Descriptor{}, err
	}
	if _, err := u.store.client.StatObject(ctx, u.store.bucket, u.prefix+sessionMarker, minio.StatObjectOptions{}); err != nil {
		if notFound(err) {
			return blob.Descriptor{}, blob.NotFound("upload", u.id)
		}
		return blob.Descriptor{}, fmt.Errorf("check upload session: %w", err)
	}

	chunks, err := u.store.listChunks(ctx, u.prefix)
	if err != nil {
		return blob.Descriptor{}, err
	}

	// Re-read rather than trusting a hash carried across requests: the session
	// may have been resumed by another process, and what is stored is the only
	// thing that can be verified.
	source := &chunkReader{ctx: ctx, store: u.store, chunks: chunks}
	size, err := u.store.upload(ctx, key, source, expected)
	if closeErr := source.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		// The session goes with the failure. Leaving it open would let a
		// caller retry the commit against bytes that have already been
		// rejected, one chunk at a time, until something matched. A failure to
		// clean up is not reported over the rejection itself: the leftovers
		// are invisible to everything but the reaper (R-011).
		_ = u.discard(ctx)
		return blob.Descriptor{}, err
	}

	// The blob is published, so a failure to clear the session leaves waste
	// rather than anything unsafe -- and reporting it would tell the client
	// its push failed when it did not.
	_ = u.discard(ctx)
	return blob.Descriptor{Digest: expected, Size: size}, nil
}

// Cancel discards the session. It is safe to call more than once.
func (u *session) Cancel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	return u.discard(ctx)
}

// discard removes every object belonging to the session. Callers hold the
// session lock.
func (u *session) discard(ctx context.Context) error {
	chunks, err := u.store.listChunks(ctx, u.prefix)
	if err != nil {
		return err
	}
	for _, c := range chunks {
		if err := u.store.client.RemoveObject(ctx, u.store.bucket, c.key, minio.RemoveObjectOptions{}); err != nil {
			return fmt.Errorf("discard upload chunk: %w", err)
		}
	}
	if err := u.store.client.RemoveObject(ctx, u.store.bucket, u.prefix+sessionMarker,
		minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("discard upload session: %w", err)
	}
	u.offset = 0
	u.next = 1
	return nil
}

// chunkReader streams a session's chunks in order as one continuous reader,
// opening each object only when it is reached.
type chunkReader struct {
	ctx    context.Context
	store  *Store
	chunks []chunk

	current io.ReadCloser
	index   int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for {
		if r.current == nil {
			if r.index >= len(r.chunks) {
				return 0, io.EOF
			}
			object, err := r.store.client.GetObject(r.ctx, r.store.bucket, r.chunks[r.index].key,
				minio.GetObjectOptions{})
			if err != nil {
				return 0, fmt.Errorf("read upload chunk: %w", err)
			}
			r.current = object
			r.index++
		}

		n, err := r.current.Read(p)
		if n > 0 {
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			if closeErr := r.current.Close(); closeErr != nil {
				return 0, closeErr
			}
			r.current = nil
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (r *chunkReader) Close() error {
	if r.current == nil {
		return nil
	}
	err := r.current.Close()
	r.current = nil
	return err
}
