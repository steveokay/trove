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
	"github.com/steveokay/trove/internal/blob/fs"
)

// A storage driver's error paths are the ones that matter when a disk fills,
// a mount goes read-only, or a directory is removed underneath it. Returning a
// zero value and a nil error there would read as "no such blob", which is how
// a failing disk turns into a garbage collector deleting live content.
//
// The injection is permission bits, so these cases need a Unix filesystem and
// a user those bits apply to. Root ignores them, and Windows does not enforce
// them on directories; both skip, and Linux CI is the authoritative gate (Q25).
func requirePermissionEnforcement(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses permission bits")
	}
}

// unwritable makes a directory refuse new entries for the rest of the test.
func unwritable(t *testing.T, dir string) {
	t.Helper()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	// Restored so the temporary directory can be cleaned up afterwards.
	t.Cleanup(func() { _ = os.Chmod(dir, info.Mode().Perm()) })
}

func TestPutReportsAStagingFailure(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	unwritable(t, filepath.Join(root, "uploads"))

	data := []byte("nowhere to stage")
	digest := blob.FromBytes(blob.SHA256, data)

	err := store.Put(context.Background(), digest, bytes.NewReader(data))
	if err == nil {
		t.Fatal("Put with an unwritable staging directory succeeded")
	}
	// A failed write must not look like a stored blob.
	if _, statErr := store.Stat(context.Background(), digest); !errors.Is(statErr, blob.ErrNotFound) {
		t.Errorf("Stat after a failed Put = %v, want ErrNotFound", statErr)
	}
}

func TestPutReportsACommitFailure(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	unwritable(t, filepath.Join(root, "blobs"))

	data := []byte("nowhere to commit")
	digest := blob.FromBytes(blob.SHA256, data)

	if err := store.Put(context.Background(), digest, bytes.NewReader(data)); err == nil {
		t.Fatal("Put with an unwritable blob directory succeeded")
	}

	// The staging file is cleaned up even though the commit failed, so a
	// failing mount does not fill the disk with orphans.
	entries, err := os.ReadDir(filepath.Join(root, "uploads"))
	if err != nil {
		t.Fatalf("read uploads: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("uploads holds %d entries after a failed commit, want none", len(entries))
	}
}

func TestDeleteReportsAFailure(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("undeletable")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	hex := digest.Hex()
	unwritable(t, filepath.Join(root, "blobs", "sha256", hex[:2]))

	err := store.Delete(ctx, digest)
	if err == nil {
		t.Fatal("Delete from an unwritable directory succeeded")
	}
	// "Cannot delete" must not be reported as "already gone": a garbage
	// collector would record the blob as reclaimed and stop tracking it.
	if errors.Is(err, blob.ErrNotFound) {
		t.Errorf("Delete = %v, want a failure rather than ErrNotFound", err)
	}
}

func TestStatReportsAFailure(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("unstatable")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A directory that cannot be traversed: the blob is there, but the store
	// cannot tell, and it must not answer "absent".
	hex := digest.Hex()
	dir := filepath.Join(root, "blobs", "sha256", hex[:2])
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, info.Mode().Perm()) })

	if _, err := store.Stat(ctx, digest); err == nil || errors.Is(err, blob.ErrNotFound) {
		t.Errorf("Stat = %v, want a failure rather than nil or ErrNotFound", err)
	}
	if _, err := store.Get(ctx, digest); err == nil || errors.Is(err, blob.ErrNotFound) {
		t.Errorf("Get = %v, want a failure rather than nil or ErrNotFound", err)
	}
}

func TestWalkReportsAFailure(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("unwalkable")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	dir := filepath.Join(root, "blobs", "sha256")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, info.Mode().Perm()) })

	// A sweep that reported success over a directory it could not read would
	// tell garbage collection that everything under it is unreachable.
	if err := store.Walk(ctx, func(blob.Descriptor) error { return nil }); err == nil {
		t.Error("Walk over an unreadable directory succeeded")
	}
}

func TestQuarantineFailureReachesTheOperator(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	var hookErr error
	hookCalls := 0
	store := newStore(t, func(o *fs.Options) {
		o.Root = root
		o.OnCorrupt = func(_ context.Context, _ blob.Descriptor, err error) {
			hookCalls++
			hookErr = err
		}
	})
	ctx := context.Background()

	data := []byte("corrupt and unmovable")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	hex := digest.Hex()
	path := filepath.Join(root, "blobs", "sha256", hex[:2], hex)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := os.WriteFile(path, []byte("something else entirely!!"), 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	// The blob cannot be moved out of a directory that refuses writes.
	unwritable(t, filepath.Join(root, "blobs", "sha256", hex[:2]))

	reader, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, blob.ErrDigestMismatch) {
		t.Errorf("read = %v, want ErrDigestMismatch", err)
	}
	if err := reader.Close(); err == nil {
		t.Error("Close reported success although the blob could not be quarantined")
	}

	// The operator hears about it either way, and the more urgent half is
	// that the corrupt content could not be isolated.
	if hookCalls != 1 {
		t.Fatalf("hook called %d times, want 1", hookCalls)
	}
	if !errors.Is(hookErr, blob.ErrDigestMismatch) {
		t.Errorf("hook error = %v, want it to carry the mismatch", hookErr)
	}
	if hookErr.Error() == blob.Mismatch(digest, digest, 0).Error() {
		t.Error("hook error does not mention the quarantine failure")
	}
}

func TestUploadReportsFailures(t *testing.T) {
	t.Parallel()
	requirePermissionEnforcement(t)

	root := t.TempDir()
	store := newStore(t, func(o *fs.Options) { o.Root = root })
	ctx := context.Background()

	data := []byte("upload that cannot land")
	digest := blob.FromBytes(blob.SHA256, data)

	session, err := store.CreateUpload(ctx, "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx, bytes.NewReader(data)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// The content verifies, but there is nowhere to publish it.
	unwritable(t, filepath.Join(root, "blobs"))
	if _, err := session.Commit(ctx, digest); err == nil {
		t.Error("Commit with an unwritable blob directory succeeded")
	}

	// Starting a session at all fails when the staging directory does.
	unwritable(t, filepath.Join(root, "uploads"))
	if _, err := store.CreateUpload(ctx, "upload-2"); err == nil {
		t.Error("CreateUpload with an unwritable uploads directory succeeded")
	}
}
