package fs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/blob/blobtest"
	"github.com/steveokay/trove/internal/blob/fs"
)

func newStore(t *testing.T, opts ...func(*fs.Options)) *fs.Store {
	t.Helper()

	options := fs.Options{Root: t.TempDir()}
	for _, apply := range opts {
		apply(&options)
	}
	store, err := fs.New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

// The filesystem driver must satisfy the same contract as the in-memory
// reference, unmodified.
func TestContract(t *testing.T) {
	t.Parallel()

	blobtest.Run(t, func(t *testing.T) blob.Store {
		t.Helper()
		return newStore(t)
	})
}

func TestUploadContract(t *testing.T) {
	t.Parallel()

	blobtest.RunUploads(t, func(t *testing.T) blobtest.UploadStore {
		t.Helper()
		return newStore(t)
	})
}

// Behaviour specific to this driver, which the shared contract does not cover.

func TestNewRequiresARoot(t *testing.T) {
	t.Parallel()

	if _, err := fs.New(fs.Options{}); !errors.Is(err, blob.ErrInvalid) {
		t.Errorf("New without a root = %v, want ErrInvalid", err)
	}
}

func TestNewFailsOnAnUnusableRoot(t *testing.T) {
	t.Parallel()

	// A file where the root should be: refusing to start beats starting with
	// nowhere to write.
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := fs.New(fs.Options{Root: path}); err == nil {
		t.Error("New over a file succeeded, want an error")
	}
}

func TestLayout(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })

	data := []byte("laid out on disk")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(context.Background(), digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The path is the contract with `trove verify`, with backup procedures,
	// and with an operator reading the directory: two-level fan-out under the
	// algorithm, keyed by hex with no colon (which Windows would refuse).
	hex := digest.Hex()
	want := filepath.Join(root, "blobs", "sha256", hex[:2], hex)
	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("blob is not at %s: %v", want, err)
	}
	if info.Size() != int64(len(data)) {
		t.Errorf("stored %d bytes, want %d", info.Size(), len(data))
	}

	// Nothing is left in the staging area once a write completes.
	entries, err := os.ReadDir(filepath.Join(root, "uploads"))
	if err != nil {
		t.Fatalf("read uploads: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("uploads holds %d entries after a completed Put, want none", len(entries))
	}
}

// Committed blobs are immutable, and the mode says so. Windows has no
// equivalent of a POSIX mode bit, so the assertion is skipped there (Q25) --
// the correctness target is ext4.
func TestCommittedBlobsAreReadOnly(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })

	data := []byte("immutable")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(context.Background(), digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	hex := digest.Hex()
	info, err := os.Stat(filepath.Join(root, "blobs", "sha256", hex[:2], hex))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o444 {
		t.Errorf("mode = %o, want 0444: a committed blob must not be writable", perm)
	}
}

// Deleting must work even though committed blobs are read-only. Windows
// refuses to unlink a read-only file without clearing the attribute first, so
// this is the case that would break the garbage collector there.
func TestDeleteRemovesAReadOnlyBlob(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	data := []byte("deletable")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, digest); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Stat(ctx, digest); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("Stat after delete = %v, want ErrNotFound", err)
	}
}

// A crash between fsync and rename leaves a staging file and no blob. The
// store must be unbothered by it: the blob is absent, and writing it again
// succeeds.
func TestStagingLeftoverIsHarmless(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("interrupted between fsync and rename")
	digest := blob.FromBytes(blob.SHA256, data)

	// Exactly what the moment before the rename looks like: complete,
	// verified content under a staging name.
	leftover := filepath.Join(root, "uploads", "staging-deadbeef")
	if err := os.WriteFile(leftover, data, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := store.Stat(ctx, digest); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("a staging file made the blob visible: %v", err)
	}
	found := false
	if err := store.Walk(ctx, func(blob.Descriptor) error { found = true; return nil }); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if found {
		t.Error("Walk yielded a staging file: garbage collection would count bytes that are not a blob")
	}

	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put after a leftover staging file: %v", err)
	}
	if _, err := store.Stat(ctx, digest); err != nil {
		t.Errorf("Stat: %v", err)
	}
	// The leftover is still there -- this driver does not reap it, R-011 does
	// -- but it did not get in the way.
	if _, err := os.Stat(leftover); err != nil {
		t.Errorf("the leftover was disturbed: %v", err)
	}
}

// The read path is the last line of defence against a disk that has started
// lying. A corrupted blob must fail the read, move out of the served tree, and
// tell the operator.
func TestCorruptBlobIsQuarantined(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	var (
		hookCalls int
		hookDesc  blob.Descriptor
		hookErr   error
	)
	store := newStore(t, func(o *fs.Options) {
		o.Root = root
		o.OnCorrupt = func(_ context.Context, desc blob.Descriptor, err error) {
			hookCalls++
			hookDesc, hookErr = desc, err
		}
	})
	ctx := context.Background()

	data := []byte("content that will rot on disk")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Flip a byte behind the store's back, which is what a failing disk or a
	// careless operator does.
	hex := digest.Hex()
	path := filepath.Join(root, "blobs", "sha256", hex[:2], hex)
	corrupted := append([]byte(nil), data...)
	corrupted[0] ^= 0xff
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.WriteFile(path, corrupted, 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	reader, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(reader)
	if !errors.Is(err, blob.ErrDigestMismatch) {
		t.Fatalf("read = %v, want ErrDigestMismatch", err)
	}
	if len(got) != len(data)-1 {
		t.Errorf("read %d bytes, want %d: the last byte must be withheld", len(got), len(data)-1)
	}
	if err := reader.Close(); !errors.Is(err, blob.ErrDigestMismatch) && err != nil {
		t.Errorf("Close = %v", err)
	}

	// The blob is out of the served tree, so the next pull is a clean miss
	// rather than a second corrupt transfer.
	if _, err := store.Stat(ctx, digest); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("Stat after quarantine = %v, want ErrNotFound", err)
	}
	quarantined := filepath.Join(root, "quarantine", "sha256", hex[:2], hex)
	kept, err := os.ReadFile(quarantined)
	if err != nil {
		t.Fatalf("the corrupt bytes were not kept as evidence: %v", err)
	}
	if !bytes.Equal(kept, corrupted) {
		t.Error("quarantined content is not what was on disk")
	}

	// The hook is what becomes the blob.corrupt event and the audit record.
	if hookCalls != 1 {
		t.Fatalf("corrupt hook called %d times, want 1", hookCalls)
	}
	if hookDesc.Digest != digest {
		t.Errorf("hook received %s, want %s", hookDesc.Digest, digest)
	}
	if !errors.Is(hookErr, blob.ErrDigestMismatch) {
		t.Errorf("hook received %v, want ErrDigestMismatch", hookErr)
	}
}

// Quarantining twice must not fail: two readers can hit the same rotten blob
// at once, and the second one finding it already gone is success, not an error.
func TestQuarantineIsIdempotent(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		// Windows refuses to rename a file another handle has open, so the
		// first reader cannot move the blob out while the second still holds
		// it. The read still fails safely on both -- nothing corrupt is
		// served -- and the quarantine happens once the last reader lets go.
		// The correctness target is ext4 (Q25).
		t.Skip("a held file cannot be renamed on Windows")
	}

	root := t.TempDir()
	corrupted := 0
	store := newStore(t, func(o *fs.Options) {
		o.Root = root
		o.OnCorrupt = func(context.Context, blob.Descriptor, error) { corrupted++ }
	})
	ctx := context.Background()

	data := []byte("rotten twice")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	hex := digest.Hex()
	path := filepath.Join(root, "blobs", "sha256", hex[:2], hex)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.WriteFile(path, []byte("entirely different content!!!"), 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	// Two readers opened before either finishes, both holding the same file.
	first, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	second, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, reader := range []blob.VerifiedReader{first, second} {
		if _, err := io.ReadAll(reader); !errors.Is(err, blob.ErrDigestMismatch) {
			t.Errorf("read = %v, want ErrDigestMismatch", err)
		}
		if err := reader.Close(); err != nil && !errors.Is(err, blob.ErrDigestMismatch) {
			t.Errorf("Close = %v, want no quarantine failure", err)
		}
	}
	if corrupted != 2 {
		t.Errorf("hook called %d times, want one per reader", corrupted)
	}
}

// Walk yields blobs and ignores anything else. An operator's stray file, or a
// directory that is not part of the layout, must not become a descriptor a
// garbage collector would act on.
func TestWalkIgnoresForeignFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("a real blob")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	hex := digest.Hex()
	foreign := []string{
		filepath.Join(root, "blobs", "README"),                         // too shallow
		filepath.Join(root, "blobs", "sha256", "zz", "not-a-digest"),   // not hex
		filepath.Join(root, "blobs", "sha256", "ff", hex),              // wrong fan-out
		filepath.Join(root, "blobs", "md5", hex[:2], hex),              // unknown algorithm
		filepath.Join(root, "blobs", "sha256", hex[:2], hex, "nested"), // a directory named like a blob
	}
	for _, path := range foreign {
		// Best effort: the last case deliberately tries to write under an
		// existing blob, which is a file and not a directory. What matters is
		// what Walk does with whatever ends up on disk.
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			continue
		}
		_ = os.WriteFile(path, []byte("junk"), 0o644)
	}

	var seen []blob.Digest
	if err := store.Walk(ctx, func(desc blob.Descriptor) error {
		seen = append(seen, desc.Digest)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(seen) != 1 || seen[0] != digest {
		t.Errorf("Walk yielded %v, want only the real blob", seen)
	}
}

// The digest parser rejects traversal before a path is built, and the driver
// checks again on the way out. This is the second wall (ADR 0009): it exists
// for the caller who one day forgets the first.
func TestUploadIdentifiersAreGated(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	rejected := []string{
		"",
		".",
		"..",
		"../escape",
		"sub/dir",
		`sub\dir`,
		"has space",
		"null\x00byte",
		"tilde~",
		string(make([]byte, 129)),
	}
	for _, id := range rejected {
		t.Run(id, func(t *testing.T) {
			_, err := store.CreateUpload(ctx, id)
			if !errors.Is(err, blob.ErrInvalid) {
				t.Errorf("CreateUpload(%q) = %v, want ErrInvalid", id, err)
			}
			_, err = store.OpenUpload(ctx, id)
			if !errors.Is(err, blob.ErrInvalid) {
				t.Errorf("OpenUpload(%q) = %v, want ErrInvalid", id, err)
			}
		})
	}

	// A ULID is what the registry will actually pass, so it must be accepted.
	if _, err := store.CreateUpload(ctx, "01JQ8Z5K9X7YQF3M2N4P6R8T0V"); err != nil {
		t.Errorf("CreateUpload with a ULID: %v", err)
	}
}

// A session's state is on disk, so it survives the process that started it.
func TestUploadSurvivesAReopenedStore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	first := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("uploaded across two processes")
	digest := blob.FromBytes(blob.SHA256, data)
	half := len(data) / 2

	session, err := first.CreateUpload(ctx, "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx, bytes.NewReader(data[:half])); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// A restart: a new store over the same root, as a redeployed process would
	// have. The client's next PATCH must continue where it left off.
	second := newStore(t, func(o *fs.Options) { o.Root = root })
	resumed, err := second.OpenUpload(ctx, "upload-1")
	if err != nil {
		t.Fatalf("OpenUpload after restart: %v", err)
	}
	if resumed.Offset() != int64(half) {
		t.Fatalf("offset = %d after restart, want %d", resumed.Offset(), half)
	}
	if _, err := resumed.Write(ctx, bytes.NewReader(data[half:])); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := resumed.Commit(ctx, digest); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	reader, err := second.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = reader.Close() }()
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("content = %q, %v; want %q", got, err, data)
	}
}

// Committing content that is already stored is a no-op that still clears the
// session: two clients pushing the same layer must both come away happy.
func TestCommitOfAnExistingBlob(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	data := []byte("pushed twice")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	session, err := store.CreateUpload(ctx, "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx, bytes.NewReader(data)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	desc, err := session.Commit(ctx, digest)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if desc.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", desc.Size, len(data))
	}
	if _, err := store.OpenUpload(ctx, "upload-1"); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("the session survived a no-op commit: %v", err)
	}
}

func TestRootIsReported(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })

	// The wiring compares roots to prove the hosted and cache stores are
	// disjoint (ADR 0009), so the value has to be the resolved one.
	want, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if store.Root() != want {
		t.Errorf("Root() = %q, want %q", store.Root(), want)
	}
}
