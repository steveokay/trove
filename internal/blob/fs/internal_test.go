package fs

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/blob"
)

// confine is the second wall (ADR 0009). The digest parser and the upload-id
// check stop traversal before a path is built; this catches whatever a future
// caller forgets to validate, so it is tested directly rather than only
// through the callers that currently cannot reach it.
func TestConfine(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	store := &Store{root: root}

	allowed := [][]string{
		{"blobs", "sha256", "ab", strings.Repeat("a", 64)},
		{"uploads", "01JQ8Z5K9X7YQF3M2N4P6R8T0V"},
		{"quarantine"},
	}
	for _, parts := range allowed {
		path, err := store.confine(parts...)
		if err != nil {
			t.Errorf("confine(%v) = %v, want a path", parts, err)
			continue
		}
		if !strings.HasPrefix(path, root) {
			t.Errorf("confine(%v) = %q, which is outside %q", parts, path, root)
		}
	}

	escapes := [][]string{
		{".."},
		{"..", "..", "etc", "passwd"},
		{"blobs", "..", "..", "outside"},
		{filepath.Join("..", "sibling")},
	}
	for _, parts := range escapes {
		if _, err := store.confine(parts...); !errors.Is(err, blob.ErrInvalid) {
			t.Errorf("confine(%v) = %v, want ErrInvalid: it resolves outside the root", parts, err)
		}
	}
}

// An absolute path passed as a component would replace the root entirely if
// filepath.Join were trusted on its own.
func TestConfineRefusesAnAbsoluteComponent(t *testing.T) {
	t.Parallel()

	store := &Store{root: t.TempDir()}

	// filepath.Join treats this as a relative component and keeps it under the
	// root, which is the safe outcome; the assertion is that it never escapes.
	path, err := store.confine("/etc/passwd")
	if err != nil {
		return
	}
	if !strings.HasPrefix(path, store.root) {
		t.Errorf("confine produced %q, outside %q", path, store.root)
	}
}

func TestDigestFromPath(t *testing.T) {
	t.Parallel()

	const hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	root := filepath.Join("store", "blobs")

	tests := []struct {
		name string
		path string
		want blob.Digest
	}{
		{
			name: "well formed",
			path: filepath.Join(root, "sha256", hex[:2], hex),
			want: blob.Digest("sha256:" + hex),
		},
		{
			name: "too shallow",
			path: filepath.Join(root, "README"),
		},
		{
			name: "too deep",
			path: filepath.Join(root, "sha256", hex[:2], hex, "nested"),
		},
		{
			name: "unknown algorithm",
			path: filepath.Join(root, "md5", hex[:2], hex),
		},
		{
			name: "not hex",
			path: filepath.Join(root, "sha256", "zz", strings.Repeat("z", 64)),
		},
		{
			// A blob under the wrong fan-out directory is not where this
			// driver would have put it, so it is not one of its blobs.
			name: "wrong fan-out",
			path: filepath.Join(root, "sha256", "ff", hex),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := digestFromPath(root, tt.path)
			if tt.want == "" {
				if ok {
					t.Errorf("digestFromPath(%q) = %s, want it ignored", tt.path, got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("digestFromPath(%q) = %s, %v; want %s", tt.path, got, ok, tt.want)
			}
		})
	}
}

// A rename is only durable once its directory entry is flushed, so a failure
// to do that must be reported rather than swallowed.
func TestSyncDirReportsFailure(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("directories cannot be opened for synchronisation on Windows")
	}
	if err := syncDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("syncDir on a missing directory succeeded, want an error")
	}
}

func TestSyncDirIsSkippedOnWindows(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "windows" {
		t.Skip("only meaningful on Windows")
	}
	if err := syncDir(filepath.Join(t.TempDir(), "does-not-exist")); err != nil {
		t.Errorf("syncDir = %v, want nil: there is nothing to flush on Windows", err)
	}
}

func TestUploadIDValidation(t *testing.T) {
	t.Parallel()

	valid := []string{
		"01JQ8Z5K9X7YQF3M2N4P6R8T0V",
		"upload-1",
		"a",
		"with.dots_and-dashes",
		strings.Repeat("a", maxUploadIDLength),
	}
	for _, id := range valid {
		if err := validUploadID(id); err != nil {
			t.Errorf("validUploadID(%q) = %v, want nil", id, err)
		}
	}

	invalid := []string{
		"",
		".",
		"..",
		"../escape",
		"a/b",
		`a\b`,
		"a b",
		"a\x00b",
		"a:b",
		"a~b",
		strings.Repeat("a", maxUploadIDLength+1),
	}
	for _, id := range invalid {
		if err := validUploadID(id); !errors.Is(err, blob.ErrInvalid) {
			t.Errorf("validUploadID(%q) = %v, want ErrInvalid", id, err)
		}
	}
}
