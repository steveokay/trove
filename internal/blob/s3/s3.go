// Package s3 is the optional blob driver: content-addressed objects in an
// S3-compatible bucket, keyed per ADR 0007.
//
//	<prefix>blobs/<algorithm>/<hex>
//	<prefix>uploads/<id>/<sequence>
//	<prefix>quarantine/<algorithm>/<hex>
//
// The prefix is what makes hosted and cached content disjoint (ADR 0009): two
// stores over two prefixes, or two buckets entirely, chosen at wiring time.
// There is no fan-out directory here as there is on a filesystem, because an
// object store has no directories to keep small.
//
// Writes go through a multipart upload that is completed only after the digest
// verifies. That is the object-store equivalent of the filesystem's
// stage-then-rename: an aborted multipart upload never becomes an object, so a
// mismatched Put leaves nothing behind rather than something a later delete
// has to clean up.
package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/steveokay/trove/internal/blob"
)

// Key components under the store's prefix.
const (
	blobsPrefix      = "blobs"
	uploadsPrefix    = "uploads"
	quarantinePrefix = "quarantine"
)

// DefaultPartSize is how much of a blob is buffered before a multipart part is
// sent. S3 requires at least 5 MiB for every part but the last; 16 MiB keeps
// the part count low for large layers without holding much memory.
const DefaultPartSize = 16 << 20

// minimumPartSize is the floor S3 imposes on every part but the last.
const minimumPartSize = 5 << 20

// Options configure a store.
type Options struct {
	// Endpoint is the host:port of the S3-compatible service. Required.
	Endpoint string
	// Bucket must already exist. Creating it is an operator decision, not a
	// side effect of starting the registry.
	Bucket string
	// Prefix namespaces the store within the bucket, and is what keeps hosted
	// and cached content apart when they share one.
	Prefix string
	// Region is the bucket's region; empty lets the client discover it.
	Region string

	AccessKeyID     string
	SecretAccessKey string
	// UseSSL should be true anywhere but a test.
	UseSSL bool

	// Redirect serves reads as a redirect to a presigned URL instead of
	// streaming through trove. It is off by default and must stay that way:
	// a redirect takes trove out of the data path, so nothing verifies the
	// bytes the client receives (ADR 0007).
	Redirect bool
	// RedirectExpiry bounds a presigned URL's lifetime. Zero means
	// DefaultRedirectExpiry.
	RedirectExpiry time.Duration

	// PartSize overrides DefaultPartSize.
	PartSize int64

	// OnCorrupt is called when a read finds an object whose bytes no longer
	// hash to its digest, after it has been quarantined.
	OnCorrupt blob.CorruptHook
}

// DefaultRedirectExpiry is how long a presigned URL stays valid. Long enough
// for a slow client to start a large pull, short enough that a leaked URL is
// not a lasting grant.
const DefaultRedirectExpiry = 15 * time.Minute

// Store is an S3-backed blob.Store.
type Store struct {
	// client is the ordinary object API; core is the multipart one. minio's
	// Core embeds a Client and shadows several of its methods with lower-level
	// versions, so the two are held separately rather than reached through one
	// another.
	client *minio.Client
	core   *minio.Core

	bucket string
	prefix string

	partSize       int64
	redirect       bool
	redirectExpiry time.Duration
	onCorrupt      blob.CorruptHook
}

// assert the interfaces are satisfied at compile time.
var (
	_ blob.Store      = (*Store)(nil)
	_ blob.Uploader   = (*Store)(nil)
	_ blob.Redirector = (*Store)(nil)
)

// New connects to the bucket and returns a store over it.
func New(ctx context.Context, opts Options) (*Store, error) {
	switch {
	case opts.Endpoint == "":
		return nil, blob.Invalid("endpoint", "must not be empty")
	case opts.Bucket == "":
		return nil, blob.Invalid("bucket", "must not be empty")
	}
	prefix, err := normalisePrefix(opts.Prefix)
	if err != nil {
		return nil, err
	}
	partSize := opts.PartSize
	if partSize <= 0 {
		partSize = DefaultPartSize
	}
	if partSize < minimumPartSize {
		return nil, blob.Invalid("part_size", fmt.Sprintf("must be at least %d bytes", minimumPartSize))
	}
	expiry := opts.RedirectExpiry
	if expiry <= 0 {
		expiry = DefaultRedirectExpiry
	}

	core, err := minio.NewCore(opts.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(opts.AccessKeyID, opts.SecretAccessKey, ""),
		Secure: opts.UseSSL,
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", opts.Endpoint, err)
	}

	// Checked at startup rather than on the first push: a missing bucket is a
	// configuration mistake, and finding out during a pull is too late.
	exists, err := core.Client.BucketExists(ctx, opts.Bucket)
	if err != nil {
		return nil, fmt.Errorf("check bucket %q: %w", opts.Bucket, err)
	}
	if !exists {
		return nil, fmt.Errorf("bucket %q does not exist", opts.Bucket)
	}

	return &Store{
		client:         core.Client,
		core:           core,
		bucket:         opts.Bucket,
		prefix:         prefix,
		partSize:       partSize,
		redirect:       opts.Redirect,
		redirectExpiry: expiry,
		onCorrupt:      opts.OnCorrupt,
	}, nil
}

// normalisePrefix trims a prefix to its canonical form and refuses one that
// could reach outside the store's namespace. The prefix is operator
// configuration rather than user input, but two stores sharing a bucket depend
// on it being what it says (ADR 0009).
func normalisePrefix(prefix string) (string, error) {
	trimmed := strings.Trim(prefix, "/")
	if trimmed == "" {
		return "", nil
	}
	cleaned := path.Clean(trimmed)
	if cleaned != trimmed || strings.HasPrefix(cleaned, "..") {
		return "", blob.Invalid("prefix", "must be a plain key prefix")
	}
	return cleaned + "/", nil
}

// blobKey returns the object key for a digest.
func (s *Store) blobKey(digest blob.Digest) (string, error) {
	return s.keyFor(blobsPrefix, digest)
}

func (s *Store) quarantineKey(digest blob.Digest) (string, error) {
	return s.keyFor(quarantinePrefix, digest)
}

func (s *Store) keyFor(base string, digest blob.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}
	return s.prefix + base + "/" + string(digest.Algorithm()) + "/" + digest.Hex(), nil
}

// notFound reports whether an S3 error means the object is absent.
//
// A missing bucket is deliberately not in the list. It means the store's
// configuration is wrong or someone removed it, and reporting that as "no such
// blob" would tell a garbage collector every blob had already been reclaimed.
// A broken store must read as broken.
func notFound(err error) bool {
	switch minio.ToErrorResponse(err).Code {
	case "NoSuchKey", "NotFound":
		return true
	default:
		return false
	}
}

// Put stores the reader's bytes under the expected digest.
func (s *Store) Put(ctx context.Context, expected blob.Digest, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := s.blobKey(expected)
	if err != nil {
		return err
	}
	_, err = s.upload(ctx, key, r, expected)
	return err
}

// Get opens a blob, verified as it streams.
func (s *Store) Get(ctx context.Context, digest blob.Digest) (blob.VerifiedReader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	desc, err := s.Stat(ctx, digest)
	if err != nil {
		return nil, err
	}
	key, err := s.blobKey(digest)
	if err != nil {
		return nil, err
	}

	object, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		if notFound(err) {
			return nil, blob.NotFound("blob", string(digest))
		}
		return nil, fmt.Errorf("get object: %w", err)
	}

	reader := &quarantiningReader{store: s, desc: desc, ctx: ctx}
	verified, err := blob.NewVerifiedReader(ctx, object, desc, reader.detected)
	if err != nil {
		_ = object.Close()
		return nil, err
	}
	reader.VerifiedReader = verified
	return reader, nil
}

// Stat returns a descriptor without fetching the content.
func (s *Store) Stat(ctx context.Context, digest blob.Digest) (blob.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return blob.Descriptor{}, err
	}
	key, err := s.blobKey(digest)
	if err != nil {
		return blob.Descriptor{}, err
	}

	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if notFound(err) {
			return blob.Descriptor{}, blob.NotFound("blob", string(digest))
		}
		return blob.Descriptor{}, fmt.Errorf("stat object: %w", err)
	}
	return blob.Descriptor{Digest: digest, Size: info.Size}, nil
}

// Delete removes a blob.
func (s *Store) Delete(ctx context.Context, digest blob.Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// S3 deletes are idempotent and report success for a key that was never
	// there, so absence is established first: a garbage collector that could
	// not tell "removed" from "never existed" would report reclaiming bytes it
	// never held.
	if _, err := s.Stat(ctx, digest); err != nil {
		return err
	}
	key, err := s.blobKey(digest)
	if err != nil {
		return err
	}

	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete object: %w", err)
	}
	return nil
}

// Walk calls fn for every committed blob.
//
// Only keys that reconstruct to a valid digest are yielded: anything else
// under the prefix was not put there by this driver, and a sweep must not hand
// garbage collection a descriptor it cannot verify.
func (s *Store) Walk(ctx context.Context, fn func(blob.Descriptor) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	prefix := s.prefix + blobsPrefix + "/"
	return s.forEachObject(ctx, minio.ListObjectsOptions{Prefix: prefix, Recursive: true},
		func(object minio.ObjectInfo) error {
			digest, ok := digestFromKey(prefix, object.Key)
			if !ok {
				return nil
			}
			return fn(blob.Descriptor{Digest: digest, Size: object.Size})
		})
}

// forEachObject lists objects and calls fn for each, draining the listing to
// the end whatever happens.
//
// Draining is not tidiness. minio's listing goroutine reacts to a cancelled
// context by sending one last error object, and that send has no receiver if
// the caller simply stops reading: the goroutine blocks forever holding an
// HTTP connection, and enough of those exhaust the transport's pool and hang
// every later request. A sweep that stops early -- which garbage collection
// does on any error -- would otherwise poison the client it shares.
func (s *Store) forEachObject(ctx context.Context, opts minio.ListObjectsOptions, fn func(minio.ObjectInfo) error) error {
	listing, cancel := context.WithCancel(ctx)
	defer cancel()

	var stop error
	for object := range s.client.ListObjects(listing, s.bucket, opts) {
		if stop != nil {
			// Already finished; keep receiving so the sender can exit.
			continue
		}
		switch {
		case object.Err != nil:
			stop = fmt.Errorf("list objects: %w", object.Err)
		case ctx.Err() != nil:
			// Checked before each call rather than only between pages: a
			// caller that cancels from inside fn -- which is what a sweep
			// abandoning its run looks like -- must not see fn called again
			// with an object that was already in flight.
			stop = ctx.Err()
		default:
			stop = fn(object)
		}
		if stop != nil {
			cancel()
		}
	}
	return stop
}

// digestFromKey reverses the key scheme: <algorithm>/<hex>.
func digestFromKey(prefix, key string) (blob.Digest, bool) {
	rest, found := strings.CutPrefix(key, prefix)
	if !found {
		return "", false
	}
	algorithm, hex, found := strings.Cut(rest, "/")
	if !found || strings.Contains(hex, "/") {
		return "", false
	}
	digest, err := blob.ParseDigest(algorithm + ":" + hex)
	if err != nil {
		return "", false
	}
	return digest, true
}

// RedirectURL returns a presigned URL for a blob, or ErrNoRedirect when the
// mode is off.
//
// A redirect takes trove out of the data path: nothing verifies what the
// client receives, and the object store's integrity guarantees are all that is
// left. That is a trade an operator may make deliberately -- it is why the
// option exists -- but never by default (ADR 0007).
func (s *Store) RedirectURL(ctx context.Context, digest blob.Digest) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !s.redirect {
		return "", blob.ErrNoRedirect
	}
	// Existence is established first so a redirect never sends a client to a
	// URL that will 404 after the registry already answered.
	if _, err := s.Stat(ctx, digest); err != nil {
		return "", err
	}
	key, err := s.blobKey(digest)
	if err != nil {
		return "", err
	}

	presigned, err := s.client.PresignedGetObject(ctx, s.bucket, key, s.redirectExpiry, url.Values{})
	if err != nil {
		return "", fmt.Errorf("presign object: %w", err)
	}
	return presigned.String(), nil
}

// upload streams src into key through a multipart upload, completing it only
// once the content verifies. It returns the number of bytes stored.
func (s *Store) upload(ctx context.Context, key string, src io.Reader, expected blob.Digest) (int64, error) {
	verifier, err := blob.NewVerifier(expected)
	if err != nil {
		return 0, err
	}

	uploadID, err := s.core.NewMultipartUpload(ctx, s.bucket, key, minio.PutObjectOptions{})
	if err != nil {
		return 0, fmt.Errorf("start multipart upload: %w", err)
	}

	parts, size, err := s.sendParts(ctx, key, uploadID, src, verifier)
	if err == nil {
		err = verifier.Verify()
	}
	if err != nil {
		// Abandoning the upload is what keeps a rejected push invisible: an
		// aborted multipart upload never becomes an object, so there is
		// nothing for a later sweep to find and nothing a reader can see.
		if abortErr := s.core.AbortMultipartUpload(ctx, s.bucket, key, uploadID); abortErr != nil {
			return size, errors.Join(err, fmt.Errorf("abort multipart upload: %w", abortErr))
		}
		return size, err
	}

	if _, err := s.core.CompleteMultipartUpload(ctx, s.bucket, key, uploadID, parts, minio.PutObjectOptions{}); err != nil {
		return size, fmt.Errorf("complete multipart upload: %w", err)
	}
	return size, nil
}

// sendParts uploads src one part at a time, hashing as it goes.
func (s *Store) sendParts(ctx context.Context, key, uploadID string, src io.Reader, verifier *blob.Verifier) ([]minio.CompletePart, int64, error) {
	var (
		parts []minio.CompletePart
		size  int64
		buf   = make([]byte, s.partSize)
	)
	for number := 1; ; number++ {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			_, _ = verifier.Write(buf[:n])
			part, partErr := s.core.PutObjectPart(ctx, s.bucket, key, uploadID, number,
				bytes.NewReader(buf[:n]), int64(n), minio.PutObjectPartOptions{})
			if partErr != nil {
				return nil, size, fmt.Errorf("upload part %d: %w", number, partErr)
			}
			parts = append(parts, minio.CompletePart{PartNumber: part.PartNumber, ETag: part.ETag})
			size += int64(n)
		}
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			// A zero-length blob still needs one part: S3 refuses to complete
			// a multipart upload with none.
			if len(parts) == 0 {
				part, partErr := s.core.PutObjectPart(ctx, s.bucket, key, uploadID, 1,
					bytes.NewReader(nil), 0, minio.PutObjectPartOptions{})
				if partErr != nil {
					return nil, size, fmt.Errorf("upload empty part: %w", partErr)
				}
				parts = append(parts, minio.CompletePart{PartNumber: part.PartNumber, ETag: part.ETag})
			}
			return parts, size, nil
		case err != nil:
			return nil, size, err
		}
	}
}
