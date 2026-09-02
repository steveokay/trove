// Package blobtest is the contract suite for blob.Store. Every driver runs the
// same suite unmodified: the filesystem driver, the S3 driver, and the
// in-memory reference implementation. A behaviour that is not asserted here is
// not part of the contract, and a driver that passes here is substitutable for
// any other.
package blobtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/steveokay/trove/internal/blob"
)

// Factory builds a fresh, empty store for one test.
type Factory func(t *testing.T) blob.Store

// UploaderFactory builds a store that also supports upload sessions. A driver
// that cannot hold partial content passes nil to RunUploads and the session
// cases are skipped -- but every driver the registry writes through needs one,
// because chunked upload is in the distribution spec.
type UploaderFactory func(t *testing.T) UploadStore

// UploadStore is a store that supports resumable uploads.
type UploadStore interface {
	blob.Store
	blob.Uploader
}

type suiteCase struct {
	name string
	run  func(t *testing.T, s blob.Store)
}

// Run executes the whole contract suite against the store built by f.
func Run(t *testing.T, f Factory) {
	t.Helper()

	tests := []suiteCase{
		{"PutGetStat", testPutGetStat},
		{"PutIsIdempotent", testPutIsIdempotent},
		{"PutRejectsAMismatch", testPutRejectsAMismatch},
		{"PutRejectsATruncatedStream", testPutRejectsATruncatedStream},
		{"PutPropagatesAReadFailure", testPutPropagatesAReadFailure},
		{"EmptyBlob", testEmptyBlob},
		{"LargeBlob", testLargeBlob},
		{"ConcurrentPutOfTheSameDigest", testConcurrentPutOfTheSameDigest},
		{"MissingBlob", testMissingBlob},
		{"Delete", testDelete},
		{"Walk", testWalk},
		{"WalkStopsOnError", testWalkStopsOnError},
		{"WalkStopsWhenCancelled", testWalkStopsWhenCancelled},
		{"WalkSeesOnlyCommittedContent", testWalkSeesOnlyCommittedContent},
		{"InvalidDigestsAreRejected", testInvalidDigestsAreRejected},
		{"ContextCancellation", testContextCancellation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, f(t))
		})
	}
}

// RunUploads executes the upload-session half of the contract.
func RunUploads(t *testing.T, f UploaderFactory) {
	t.Helper()

	tests := []struct {
		name string
		run  func(t *testing.T, s UploadStore)
	}{
		{"UploadInChunks", testUploadInChunks},
		{"UploadResumes", testUploadResumes},
		{"UploadCommitRejectsAMismatch", testUploadCommitRejectsAMismatch},
		{"UploadCommitRejectsAnInvalidDigest", testUploadCommitRejectsAnInvalidDigest},
		{"UploadKeepsWhatArrivedOnAFailedWrite", testUploadKeepsWhatArrivedOnAFailedWrite},
		{"UploadCancel", testUploadCancel},
		{"UploadIdentifiers", testUploadIdentifiers},
		{"UploadContextCancellation", testUploadContextCancellation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, f(t))
		})
	}
}

// --- helpers ---

func ctx() context.Context { return context.Background() }

// content builds deterministic bytes and the digest they hash to, so a test
// never has to hard-code a hash.
func content(seed string) ([]byte, blob.Digest) {
	data := []byte("blob content: " + seed)
	return data, blob.FromBytes(blob.SHA256, data)
}

func mustPut(t *testing.T, s blob.Store, data []byte, digest blob.Digest) {
	t.Helper()

	if err := s.Put(ctx(), digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put(%s): %v", digest, err)
	}
}

// readAll drains a verified reader and closes it.
func readAll(t *testing.T, r blob.VerifiedReader) ([]byte, error) {
	t.Helper()

	data, err := io.ReadAll(r)
	if closeErr := r.Close(); closeErr != nil {
		t.Errorf("Close: %v", closeErr)
	}
	return data, err
}

func mustGet(t *testing.T, s blob.Store, digest blob.Digest) []byte {
	t.Helper()

	reader, err := s.Get(ctx(), digest)
	if err != nil {
		t.Fatalf("Get(%s): %v", digest, err)
	}
	data, err := readAll(t, reader)
	if err != nil {
		t.Fatalf("read %s: %v", digest, err)
	}
	return data
}

func requireErrIs(t *testing.T, err, target error, what string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s: got nil error, want %v", what, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want errors.Is(err, %v)", what, err, target)
	}
}

// failingReader yields some bytes and then fails, standing in for a client
// that disconnects mid-push.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// --- content ---

func testPutGetStat(t *testing.T, s blob.Store) {
	data, digest := content("round trip")
	mustPut(t, s, data, digest)

	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("Get returned %q, want %q", got, data)
	}

	desc, err := s.Stat(ctx(), digest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if desc.Digest != digest {
		t.Errorf("descriptor digest = %s, want %s", desc.Digest, digest)
	}
	if desc.Size != int64(len(data)) {
		t.Errorf("descriptor size = %d, want %d", desc.Size, len(data))
	}

	// The reader describes what it is serving, so a caller streaming a blob
	// does not have to Stat it separately to learn its size.
	reader, err := s.Get(ctx(), digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reader.Descriptor() != desc {
		t.Errorf("reader descriptor = %+v, want %+v", reader.Descriptor(), desc)
	}
	if _, err := readAll(t, reader); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func testPutIsIdempotent(t *testing.T, s blob.Store) {
	data, digest := content("idempotent")

	// Two pushes of the same layer must both succeed: blobs are
	// content-addressed, so the second is not a conflict, it is the same blob.
	mustPut(t, s, data, digest)
	mustPut(t, s, data, digest)

	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("content = %q after a repeat Put, want %q", got, data)
	}
}

func testPutRejectsAMismatch(t *testing.T, s blob.Store) {
	data, digest := content("honest")
	_, other := content("different")

	err := s.Put(ctx(), other, bytes.NewReader(data))
	requireErrIs(t, err, blob.ErrDigestMismatch, "Put under the wrong digest")

	// The error names both digests, which is how an operator tells a corrupt
	// upstream from a client bug.
	var mismatch *blob.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error type = %T, want *blob.MismatchError", err)
	}
	if mismatch.Expected != other || mismatch.Actual != digest {
		t.Errorf("mismatch = %+v, want expected %s and actual %s", mismatch, other, digest)
	}

	// Nothing may survive a failed write. A partially stored blob would be
	// served to the next client that asked for that digest.
	_, err = s.Stat(ctx(), other)
	requireErrIs(t, err, blob.ErrNotFound, "Stat after a rejected Put")
	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat of the content's real digest after a rejected Put")
}

func testPutRejectsATruncatedStream(t *testing.T, s blob.Store) {
	data, digest := content("truncated")

	// A short stream hashes to something else, which is the same failure as
	// corruption and must be treated the same way.
	err := s.Put(ctx(), digest, bytes.NewReader(data[:len(data)-1]))
	requireErrIs(t, err, blob.ErrDigestMismatch, "Put of a truncated stream")

	var mismatch *blob.MismatchError
	if errors.As(err, &mismatch) && mismatch.Size != int64(len(data)-1) {
		t.Errorf("mismatch size = %d, want the %d bytes that arrived", mismatch.Size, len(data)-1)
	}

	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat after a truncated Put")
}

func testPutPropagatesAReadFailure(t *testing.T, s blob.Store) {
	data, digest := content("dropped connection")
	failure := errors.New("connection reset")

	err := s.Put(ctx(), digest, &failingReader{data: data[:4], err: failure})
	if !errors.Is(err, failure) {
		t.Errorf("Put with a failing reader = %v, want the reader's error", err)
	}

	// A dropped push leaves nothing, exactly like a mismatch.
	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat after a failed Put")
}

func testEmptyBlob(t *testing.T, s blob.Store) {
	// The empty blob is real: an OCI config can be empty, and its digest is
	// pushed and pulled like any other.
	data := []byte{}
	digest := blob.FromBytes(blob.SHA256, data)

	mustPut(t, s, data, digest)
	if got := mustGet(t, s, digest); len(got) != 0 {
		t.Errorf("empty blob read back %d bytes", len(got))
	}

	desc, err := s.Stat(ctx(), digest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if desc.Size != 0 {
		t.Errorf("size = %d, want 0", desc.Size)
	}
}

func testLargeBlob(t *testing.T, s blob.Store) {
	// Big enough to cross buffer boundaries in any reasonable driver, which is
	// where an off-by-one in a streaming verifier hides.
	data := bytes.Repeat([]byte("0123456789abcdef"), 64*1024)
	digest := blob.FromBytes(blob.SHA256, data)

	mustPut(t, s, data, digest)
	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("large blob did not round-trip: got %d bytes, want %d", len(got), len(data))
	}
}

func testConcurrentPutOfTheSameDigest(t *testing.T, s blob.Store) {
	data, digest := content("contested")

	// Two clients pushing the same layer at once is ordinary, not exceptional:
	// both must succeed and the content must be intact afterwards.
	const writers = 8
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			if err := s.Put(ctx(), digest, bytes.NewReader(data)); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("concurrent Put of the same digest failed: %v", errs)
	}
	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("content = %q after concurrent writes, want %q", got, data)
	}
}

func testMissingBlob(t *testing.T, s blob.Store) {
	_, digest := content("never stored")

	_, err := s.Get(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Get of a missing blob")
	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat of a missing blob")
	requireErrIs(t, s.Delete(ctx(), digest), blob.ErrNotFound, "Delete of a missing blob")
}

func testDelete(t *testing.T, s blob.Store) {
	data, digest := content("doomed")
	mustPut(t, s, data, digest)

	if err := s.Delete(ctx(), digest); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat after delete")
	requireErrIs(t, s.Delete(ctx(), digest), blob.ErrNotFound, "Delete twice")

	// Deleting one blob leaves the others alone. Obvious, and worth pinning:
	// a driver that shares a directory prefix could get this wrong.
	otherData, otherDigest := content("survivor")
	mustPut(t, s, otherData, otherDigest)
	mustPut(t, s, data, digest)
	if err := s.Delete(ctx(), digest); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := mustGet(t, s, otherDigest); !bytes.Equal(got, otherData) {
		t.Errorf("deleting one blob disturbed another")
	}
}

func testWalk(t *testing.T, s blob.Store) {
	stored := make(map[blob.Digest]int64)
	for i := 0; i < 5; i++ {
		data, digest := content(fmt.Sprintf("walk-%d", i))
		mustPut(t, s, data, digest)
		stored[digest] = int64(len(data))
	}

	seen := make(map[blob.Digest]int64)
	if err := s.Walk(ctx(), func(desc blob.Descriptor) error {
		if _, dup := seen[desc.Digest]; dup {
			t.Errorf("Walk yielded %s twice", desc.Digest)
		}
		seen[desc.Digest] = desc.Size
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(seen) != len(stored) {
		t.Fatalf("Walk yielded %d blobs, want %d", len(seen), len(stored))
	}
	for digest, size := range stored {
		got, ok := seen[digest]
		if !ok {
			t.Errorf("Walk missed %s -- garbage collection would treat it as unreachable", digest)
			continue
		}
		if got != size {
			t.Errorf("Walk reported %s as %d bytes, want %d", digest, got, size)
		}
	}

	// An empty store walks to nothing rather than failing.
	empty := 0
	if err := s.Walk(ctx(), func(blob.Descriptor) error { empty++; return nil }); err != nil {
		t.Fatalf("Walk: %v", err)
	}
}

func testWalkStopsOnError(t *testing.T, s blob.Store) {
	for i := 0; i < 3; i++ {
		data, digest := content(fmt.Sprintf("stop-%d", i))
		mustPut(t, s, data, digest)
	}

	// A sweep that hit an error and kept going would report success over a
	// partial walk, and a garbage collector would then delete what it had not
	// looked at.
	stop := errors.New("stop walking")
	calls := 0
	err := s.Walk(ctx(), func(blob.Descriptor) error {
		calls++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Errorf("Walk = %v, want the callback's error", err)
	}
	if calls != 1 {
		t.Errorf("callback ran %d times after returning an error, want 1", calls)
	}
}

// A sweep that outlived its caller would keep reading -- and, in a garbage
// collector, keep deciding -- after the run was abandoned.
func testWalkStopsWhenCancelled(t *testing.T, s blob.Store) {
	for i := 0; i < 4; i++ {
		data, digest := content(fmt.Sprintf("cancel-walk-%d", i))
		mustPut(t, s, data, digest)
	}

	cancellable, cancel := context.WithCancel(context.Background())
	calls := 0
	err := s.Walk(cancellable, func(blob.Descriptor) error {
		calls++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Walk after cancellation = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("callback ran %d times after the context was cancelled, want 1", calls)
	}
}

func testWalkSeesOnlyCommittedContent(t *testing.T, s blob.Store) {
	existing, existingDigest := content("already here")
	mustPut(t, s, existing, existingDigest)

	// A blob being written is not a blob. If a sweep could see partial
	// content, garbage collection would either delete a live upload or count
	// bytes that are not yet real.
	data, digest := content("in flight")
	release := make(chan struct{})
	written := make(chan error, 1)
	go func() {
		written <- s.Put(ctx(), digest, &blockingReader{data: data, release: release})
	}()

	var seen []blob.Digest
	if err := s.Walk(ctx(), func(desc blob.Descriptor) error {
		seen = append(seen, desc.Digest)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, got := range seen {
		if got == digest {
			t.Error("Walk yielded a blob that was still being written")
		}
	}

	close(release)
	if err := <-written; err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Once committed it is visible, so the exclusion above is about timing
	// rather than the blob never arriving.
	found := false
	if err := s.Walk(ctx(), func(desc blob.Descriptor) error {
		if desc.Digest == digest {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !found {
		t.Error("Walk did not yield the blob after it was committed")
	}
}

// blockingReader hands over its bytes and then waits, so a test can hold a
// write open while it looks at the store.
type blockingReader struct {
	data    []byte
	release chan struct{}
	drained bool
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if r.drained {
		<-r.release
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.drained = true
	}
	return n, nil
}

// --- the digest gate ---

// Every method takes a digest, and every digest goes through the parser before
// anything is built from it. These strings are what an attacker sends when the
// parser is the only thing between them and a path.
func testInvalidDigestsAreRejected(t *testing.T, s blob.Store) {
	invalid := []string{
		"",
		"sha256",
		"sha256:",
		":deadbeef",
		"sha256:../../../../etc/passwd",
		"sha256:..",
		"../../etc/passwd",
		"sha256:" + strings.Repeat("a", 63), // one short
		"sha256:" + strings.Repeat("a", 65), // one long
		"sha256:" + strings.Repeat("A", 64), // uppercase is a second address
		"sha256:" + strings.Repeat("g", 64), // not hex
		"md5:" + strings.Repeat("a", 32),    // not in the allowlist
		"sha256:" + strings.Repeat("a", 63) + "/",
		"sha256:" + strings.Repeat("a", 63) + "\x00",
		"sha256:" + strings.Repeat("a", 63) + "\\",
	}

	for _, candidate := range invalid {
		t.Run(fmt.Sprintf("%q", candidate), func(t *testing.T) {
			digest := blob.Digest(candidate)

			requireErrIs(t, s.Put(ctx(), digest, strings.NewReader("x")),
				blob.ErrInvalidDigest, "Put")
			_, err := s.Get(ctx(), digest)
			requireErrIs(t, err, blob.ErrInvalidDigest, "Get")
			_, err = s.Stat(ctx(), digest)
			requireErrIs(t, err, blob.ErrInvalidDigest, "Stat")
			requireErrIs(t, s.Delete(ctx(), digest), blob.ErrInvalidDigest, "Delete")
		})
	}
}

// --- cancellation ---

// Every method must observe context cancellation. A store that ignores it
// keeps working after its caller has given up, which is how a shutdown hangs
// and how a cancelled push still writes.
func testContextCancellation(t *testing.T, s blob.Store) {
	data, digest := content("cancelled")
	mustPut(t, s, data, digest)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	calls := []struct {
		name string
		fn   func() error
	}{
		{"Put", func() error { return s.Put(cancelled, digest, bytes.NewReader(data)) }},
		{"Get", func() error { _, err := s.Get(cancelled, digest); return err }},
		{"Stat", func() error { _, err := s.Stat(cancelled, digest); return err }},
		{"Delete", func() error { return s.Delete(cancelled, digest) }},
		{"Walk", func() error { return s.Walk(cancelled, func(blob.Descriptor) error { return nil }) }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); !errors.Is(err, context.Canceled) {
				t.Errorf("%s with a cancelled context = %v, want context.Canceled", c.name, err)
			}
		})
	}
}

// --- upload sessions ---

func testUploadInChunks(t *testing.T, s UploadStore) {
	data, digest := content("chunked upload")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if session.ID() != "upload-1" {
		t.Errorf("ID = %q, want upload-1", session.ID())
	}
	if session.Offset() != 0 {
		t.Errorf("a new session holds %d bytes, want 0", session.Offset())
	}

	half := len(data) / 2
	offset, err := session.Write(ctx(), bytes.NewReader(data[:half]))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if offset != int64(half) {
		t.Errorf("offset = %d after the first chunk, want %d", offset, half)
	}
	if _, err := session.Write(ctx(), bytes.NewReader(data[half:])); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if session.Offset() != int64(len(data)) {
		t.Errorf("offset = %d, want %d", session.Offset(), len(data))
	}

	// Nothing is a blob until it is committed.
	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat before commit")

	desc, err := session.Commit(ctx(), digest)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if desc.Digest != digest || desc.Size != int64(len(data)) {
		t.Errorf("descriptor = %+v, want %s at %d bytes", desc, digest, len(data))
	}
	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("committed content = %q, want %q", got, data)
	}

	// The session is spent. Committing again must not republish anything.
	_, err = session.Commit(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Commit twice")
	_, err = s.OpenUpload(ctx(), "upload-1")
	requireErrIs(t, err, blob.ErrNotFound, "OpenUpload after commit")
}

func testUploadResumes(t *testing.T, s UploadStore) {
	data, digest := content("resumed upload")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	half := len(data) / 2
	if _, err := session.Write(ctx(), bytes.NewReader(data[:half])); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// A client that lost its connection comes back and asks where it got to.
	// Answering wrongly corrupts the blob; answering "start again" makes a
	// large push impossible on a poor link.
	resumed, err := s.OpenUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("OpenUpload: %v", err)
	}
	if resumed.Offset() != int64(half) {
		t.Fatalf("resumed offset = %d, want %d", resumed.Offset(), half)
	}
	if resumed.ID() != "upload-1" {
		t.Errorf("resumed ID = %q, want upload-1", resumed.ID())
	}

	if _, err := resumed.Write(ctx(), bytes.NewReader(data[half:])); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := resumed.Commit(ctx(), digest); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("resumed content = %q, want %q", got, data)
	}

	_, err = s.OpenUpload(ctx(), "never-created")
	requireErrIs(t, err, blob.ErrNotFound, "OpenUpload of a missing session")
}

func testUploadCommitRejectsAMismatch(t *testing.T, s UploadStore) {
	data, digest := content("honest upload")
	_, other := content("some other content")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx(), bytes.NewReader(data)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_, err = session.Commit(ctx(), other)
	requireErrIs(t, err, blob.ErrDigestMismatch, "Commit under the wrong digest")

	// Neither digest may exist afterwards, and the session must be gone: a
	// caller able to retry into a rejected session could append a byte at a
	// time until something matched.
	_, err = s.Stat(ctx(), other)
	requireErrIs(t, err, blob.ErrNotFound, "Stat of the claimed digest")
	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat of the real digest")
	_, err = s.OpenUpload(ctx(), "upload-1")
	requireErrIs(t, err, blob.ErrNotFound, "OpenUpload after a rejected commit")
}

func testUploadCommitRejectsAnInvalidDigest(t *testing.T, s UploadStore) {
	data, _ := content("bad commit digest")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx(), bytes.NewReader(data)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// The digest a client sends on the final PUT is untrusted input like any
	// other, and it must be refused before it can become a key or a path.
	_, err = session.Commit(ctx(), blob.Digest("sha256:../../etc/passwd"))
	requireErrIs(t, err, blob.ErrInvalidDigest, "Commit with an unparseable digest")
}

func testUploadKeepsWhatArrivedOnAFailedWrite(t *testing.T, s UploadStore) {
	data, digest := content("interrupted chunk")
	failure := errors.New("connection reset")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	half := len(data) / 2
	if _, err := session.Write(ctx(), &failingReader{data: data[:half], err: failure}); !errors.Is(err, failure) {
		t.Fatalf("Write = %v, want the reader's error", err)
	}

	// What arrived survives. Discarding the session on a dropped connection
	// would make a large push unresumable on exactly the links that need it.
	if session.Offset() != int64(half) {
		t.Errorf("offset = %d after an interrupted chunk, want %d", session.Offset(), half)
	}
	if _, err := session.Write(ctx(), bytes.NewReader(data[half:])); err != nil {
		t.Fatalf("Write after a failure: %v", err)
	}
	if _, err := session.Commit(ctx(), digest); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if got := mustGet(t, s, digest); !bytes.Equal(got, data) {
		t.Errorf("content = %q, want %q", got, data)
	}
}

func testUploadCancel(t *testing.T, s UploadStore) {
	data, digest := content("abandoned")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx(), bytes.NewReader(data)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := session.Cancel(ctx()); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// Cancelling twice is fine: the reaper that sweeps abandoned uploads
	// (R-011) should not have to care whether the client got there first.
	if err := session.Cancel(ctx()); err != nil {
		t.Errorf("Cancel twice: %v", err)
	}

	_, err = s.OpenUpload(ctx(), "upload-1")
	requireErrIs(t, err, blob.ErrNotFound, "OpenUpload after cancel")
	_, err = s.Stat(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Stat after cancel")
	_, err = session.Commit(ctx(), digest)
	requireErrIs(t, err, blob.ErrNotFound, "Commit after cancel")
	_, err = session.Write(ctx(), bytes.NewReader(data))
	requireErrIs(t, err, blob.ErrNotFound, "Write after cancel")
}

func testUploadIdentifiers(t *testing.T, s UploadStore) {
	_, err := s.CreateUpload(ctx(), "")
	requireErrIs(t, err, blob.ErrInvalid, "CreateUpload with no id")

	if _, err := s.CreateUpload(ctx(), "upload-1"); err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	// Reusing an identifier would let one client write into another's session.
	_, err = s.CreateUpload(ctx(), "upload-1")
	requireErrIs(t, err, blob.ErrInvalid, "CreateUpload with a taken id")

	// Sessions are independent: two uploads in flight must not see each
	// other's bytes.
	second, err := s.CreateUpload(ctx(), "upload-2")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := second.Write(ctx(), strings.NewReader("second")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	first, err := s.OpenUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("OpenUpload: %v", err)
	}
	if first.Offset() != 0 {
		t.Errorf("upload-1 holds %d bytes after writing to upload-2", first.Offset())
	}
}

func testUploadContextCancellation(t *testing.T, s UploadStore) {
	data, digest := content("cancelled upload")

	session, err := s.CreateUpload(ctx(), "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	calls := []struct {
		name string
		fn   func() error
	}{
		{"CreateUpload", func() error { _, err := s.CreateUpload(cancelled, "upload-2"); return err }},
		{"OpenUpload", func() error { _, err := s.OpenUpload(cancelled, "upload-1"); return err }},
		{"Write", func() error { _, err := session.Write(cancelled, bytes.NewReader(data)); return err }},
		{"Commit", func() error { _, err := session.Commit(cancelled, digest); return err }},
		{"Cancel", func() error { return session.Cancel(cancelled) }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); !errors.Is(err, context.Canceled) {
				t.Errorf("%s with a cancelled context = %v, want context.Canceled", c.name, err)
			}
		})
	}
}
