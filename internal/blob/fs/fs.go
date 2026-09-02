// Package fs is the default blob driver: content-addressed files on local
// disk, laid out per ADR 0007.
//
//	<root>/blobs/<algorithm>/<first-2>/<hex>   committed, immutable, 0444
//	<root>/uploads/<id>                        in-progress sessions and staging
//	<root>/quarantine/<algorithm>/<first-2>/<hex>
//
// A store owns one root, and hosted and cached content are two stores over two
// roots (ADR 0009). Nothing here can name the other one's files.
//
// The write path is staging, fsync, rename. A blob path therefore either does
// not exist or holds complete, verified content: there is no window in which a
// half-written file is visible, because nothing downstream re-checks what it
// reads out of the blob directory.
package fs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/steveokay/trove/internal/blob"
)

// Directory names under the store root.
const (
	blobsDir      = "blobs"
	uploadsDir    = "uploads"
	quarantineDir = "quarantine"
)

// File modes. Committed blobs are read-only: they are immutable by definition,
// and a mode that says so turns an accidental write into an error rather than
// silent corruption.
const (
	dirMode       fs.FileMode = 0o755
	stagingMode   fs.FileMode = 0o644
	committedMode fs.FileMode = 0o444
)

// Options configure a store.
type Options struct {
	// Root is the directory the store owns. Required. It is created if it does
	// not exist.
	Root string

	// OnCorrupt is called when a read finds a blob whose bytes no longer hash
	// to its digest, after the content has been quarantined. It is where the
	// blob.corrupt event and the audit record come from (§8).
	OnCorrupt blob.CorruptHook
}

// Store is a filesystem blob.Store.
type Store struct {
	root      string
	onCorrupt blob.CorruptHook
}

// assert the interfaces are satisfied at compile time.
var (
	_ blob.Store    = (*Store)(nil)
	_ blob.Uploader = (*Store)(nil)
)

// New opens or creates a store at the given root.
func New(opts Options) (*Store, error) {
	if opts.Root == "" {
		return nil, blob.Invalid("root", "must not be empty")
	}
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve root %q: %w", opts.Root, err)
	}

	for _, dir := range []string{blobsDir, uploadsDir, quarantineDir} {
		if err := os.MkdirAll(filepath.Join(root, dir), dirMode); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return &Store{root: root, onCorrupt: opts.OnCorrupt}, nil
}

// Root is the directory the store owns. It is what the wiring uses to prove
// the hosted and cache stores are disjoint (ADR 0009).
func (s *Store) Root() string { return s.root }

// blobPath returns the committed path for a digest.
//
// The digest has already been through the parser, so the components cannot
// contain a separator. Resolving through confine anyway is deliberate: it is
// the second wall, and it costs one string comparison per operation.
func (s *Store) blobPath(digest blob.Digest) (string, error) {
	return s.pathFor(blobsDir, digest)
}

func (s *Store) quarantinePath(digest blob.Digest) (string, error) {
	return s.pathFor(quarantineDir, digest)
}

func (s *Store) pathFor(base string, digest blob.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}
	hex := digest.Hex()
	// Two-level fan-out: a flat directory of a million blobs is slow to read
	// on every filesystem worth supporting.
	return s.confine(base, string(digest.Algorithm()), hex[:2], hex)
}

// confine joins parts to the root and refuses anything that escapes it. It is
// the last line rather than the first: the digest parser and the upload-id
// check reject traversal before it gets here, and this catches whatever a
// future caller forgets to validate.
func (s *Store) confine(parts ...string) (string, error) {
	path := filepath.Join(append([]string{s.root}, parts...)...)

	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return "", blob.Invalid("path", fmt.Sprintf("cannot be resolved against the store root: %v", err))
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", blob.Invalid("path", "resolves outside the store root")
	}
	return path, nil
}

// Put stores the reader's bytes under the expected digest.
func (s *Store) Put(ctx context.Context, expected blob.Digest, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := s.blobPath(expected)
	if err != nil {
		return err
	}

	staging, err := s.stage(r, expected)
	if err != nil {
		return err
	}
	// Whatever happens next, the staging file must not survive. A leftover is
	// harmless -- nothing reads that directory expecting blobs -- but it is
	// wasted space that nothing else would ever clean up.
	defer func() { _ = os.Remove(staging) }()

	return s.commit(staging, target)
}

// stage writes the reader to a temporary file, verifying as it streams, and
// returns the file's path. The content is never written under its final name
// before it has been verified.
func (s *Store) stage(r io.Reader, expected blob.Digest) (string, error) {
	name, err := randomName()
	if err != nil {
		return "", err
	}
	path, err := s.confine(uploadsDir, name)
	if err != nil {
		return "", err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stagingMode)
	if err != nil {
		return "", fmt.Errorf("create staging file: %w", err)
	}

	if _, err := blob.Copy(file, r, expected); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	// Durable before the rename: a rename that survives a crash while its
	// content does not would publish a truncated blob.
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("sync staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close staging file: %w", err)
	}
	return path, nil
}

// commit moves verified staging content into its final place.
func (s *Store) commit(staging, target string) error {
	if _, err := os.Stat(target); err == nil {
		// Content-addressed: whatever is already there is this content, so the
		// first writer wins and this one is a no-op. Replacing it would mean
		// unlinking a file another reader may have open, for no gain.
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat target: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
		return fmt.Errorf("create blob directory: %w", err)
	}
	if err := os.Chmod(staging, committedMode); err != nil {
		return fmt.Errorf("set blob mode: %w", err)
	}
	if err := os.Rename(staging, target); err != nil {
		// Losing a race with another writer of the same digest is not a
		// failure: the content is there either way.
		if _, statErr := os.Stat(target); statErr == nil {
			return nil
		}
		return fmt.Errorf("commit blob: %w", err)
	}
	return syncDir(filepath.Dir(target))
}

// syncDir flushes a directory entry so a rename survives a crash. Windows has
// no equivalent -- a directory cannot be opened for synchronisation -- and the
// correctness target is ext4 (Q25), so it is skipped there.
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer func() { _ = dir.Close() }()

	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

// randomName returns an unguessable staging filename. Randomness rather than a
// counter or a timestamp, so two processes over one root cannot collide.
func randomName() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate staging name: %w", err)
	}
	return "staging-" + hex.EncodeToString(raw[:]), nil
}

// Get opens a blob, verified as it streams.
func (s *Store) Get(ctx context.Context, digest blob.Digest) (blob.VerifiedReader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.blobPath(digest)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, blob.NotFound("blob", string(digest))
		}
		return nil, fmt.Errorf("open blob: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat blob: %w", err)
	}

	desc := blob.Descriptor{Digest: digest, Size: info.Size()}
	reader := &quarantiningReader{store: s, desc: desc, ctx: ctx}
	verified, err := blob.NewVerifiedReader(ctx, file, desc, reader.detected)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	reader.VerifiedReader = verified
	return reader, nil
}

// Stat returns a descriptor without opening the content.
func (s *Store) Stat(ctx context.Context, digest blob.Digest) (blob.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return blob.Descriptor{}, err
	}
	path, err := s.blobPath(digest)
	if err != nil {
		return blob.Descriptor{}, err
	}

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return blob.Descriptor{}, blob.NotFound("blob", string(digest))
		}
		return blob.Descriptor{}, fmt.Errorf("stat blob: %w", err)
	}
	return blob.Descriptor{Digest: digest, Size: info.Size()}, nil
}

// Delete removes a blob.
func (s *Store) Delete(ctx context.Context, digest blob.Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.blobPath(digest)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return blob.NotFound("blob", string(digest))
		}
		return fmt.Errorf("delete blob: %w", err)
	}
	return nil
}

// Walk calls fn for every committed blob.
//
// Only files whose path reconstructs to a valid digest are yielded. Anything
// else under the blob directory was not put there by this driver, and a
// garbage collector must not be handed a descriptor it cannot verify;
// reporting such drift is `trove verify`'s job (P-012), not the sweep's.
func (s *Store) Walk(ctx context.Context, fn func(blob.Descriptor) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root := filepath.Join(s.root, blobsDir)

	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		digest, ok := digestFromPath(root, path)
		if !ok {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Deleted between the listing and the stat: it is not there to
				// be swept, which is the same as never having seen it.
				return nil
			}
			return fmt.Errorf("stat %s: %w", digest, err)
		}
		return fn(blob.Descriptor{Digest: digest, Size: info.Size()})
	})
}

// digestFromPath reverses the layout: <algorithm>/<first-2>/<hex>.
func digestFromPath(root, path string) (blob.Digest, bool) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 {
		return "", false
	}
	algorithm, prefix, name := parts[0], parts[1], parts[2]

	digest, err := blob.ParseDigest(algorithm + ":" + name)
	if err != nil {
		return "", false
	}
	// The fan-out directory has to agree with the digest, or the file is not
	// where this driver would have put it.
	if prefix != name[:2] {
		return "", false
	}
	return digest, true
}
