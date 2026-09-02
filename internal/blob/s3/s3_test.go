package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/blob/blobtest"
)

// newStore builds a store over a fresh bucket.
func newStore(t *testing.T, opts ...func(*Options)) *Store {
	t.Helper()

	host, bucket := requireBucket(t)
	options := Options{
		Endpoint:        host,
		Bucket:          bucket,
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		// Smaller than the default so a test can cross a part boundary
		// without moving 16 MiB; this is the S3 minimum.
		PartSize: minimumPartSize,
	}
	for _, apply := range opts {
		apply(&options)
	}

	store, err := New(context.Background(), options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

// rawClient talks to the same bucket without going through the store, so a
// test can look at what is actually stored and interfere with it.
func rawClient(t *testing.T, store *Store) *minio.Client {
	t.Helper()

	client, err := minio.New(store.client.EndpointURL().Host, &minio.Options{
		Creds: credentials.NewStaticV4(accessKey, secretKey, ""),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return client
}

// The S3 driver must satisfy the same contract as the filesystem driver and
// the in-memory reference, unmodified.
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

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts Options
		want error
	}{
		{"no endpoint", Options{Bucket: "b"}, blob.ErrInvalid},
		{"no bucket", Options{Endpoint: "localhost:9000"}, blob.ErrInvalid},
		{
			name: "part below the S3 minimum",
			opts: Options{Endpoint: "localhost:9000", Bucket: "b", PartSize: 1024},
			want: blob.ErrInvalid,
		},
		{
			name: "prefix that is not a plain key prefix",
			opts: Options{Endpoint: "localhost:9000", Bucket: "b", Prefix: "../elsewhere"},
			want: blob.ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(context.Background(), tt.opts)
			if !errors.Is(err, tt.want) {
				t.Errorf("New = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewRequiresAnExistingBucket(t *testing.T) {
	t.Parallel()

	host, _ := requireBucket(t)
	_, err := New(context.Background(), Options{
		Endpoint:        host,
		Bucket:          "never-created",
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	})
	if err == nil {
		t.Fatal("New over a missing bucket succeeded")
	}
	// Creating the bucket is an operator decision; starting anyway and failing
	// on the first push would be worse than refusing now.
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %v, want it to say the bucket is missing", err)
	}
}

func TestNewRejectsAnUnreachableEndpoint(t *testing.T) {
	t.Parallel()

	_, err := New(context.Background(), Options{
		Endpoint:        "127.0.0.1:1",
		Bucket:          "b",
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	})
	if err == nil {
		t.Error("New against an unreachable endpoint succeeded")
	}
}

// The key scheme is the contract with `trove verify`, with an operator reading
// the bucket, and with anything that migrates content between drivers.
func TestKeyLayout(t *testing.T) {
	t.Parallel()

	store := newStore(t, func(o *Options) { o.Prefix = "hosted" })
	ctx := context.Background()

	data := []byte("keyed by content")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	want := "hosted/blobs/sha256/" + digest.Hex()
	client := rawClient(t, store)
	var keys []string
	for object := range client.ListObjects(ctx, store.bucket, minio.ListObjectsOptions{Recursive: true}) {
		if object.Err != nil {
			t.Fatalf("list: %v", object.Err)
		}
		keys = append(keys, object.Key)
	}
	if len(keys) != 1 || keys[0] != want {
		t.Errorf("bucket holds %v, want exactly %q", keys, want)
	}
}

// Hosted and cached content share a bucket only through their prefixes, and
// that separation is what stops an eviction reaching a hosted blob (ADR 0009).
func TestPrefixesAreDisjoint(t *testing.T) {
	t.Parallel()

	host, bucket := requireBucket(t)
	ctx := context.Background()

	build := func(prefix string) *Store {
		store, err := New(ctx, Options{
			Endpoint: host, Bucket: bucket, Prefix: prefix,
			AccessKeyID: accessKey, SecretAccessKey: secretKey,
		})
		if err != nil {
			t.Fatalf("New(%s): %v", prefix, err)
		}
		return store
	}
	hosted, cache := build("hosted"), build("cache")

	data := []byte("hosted only")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := hosted.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := cache.Stat(ctx, digest); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("the cache store can see hosted content: %v", err)
	}
	seen := 0
	if err := cache.Walk(ctx, func(blob.Descriptor) error { seen++; return nil }); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if seen != 0 {
		t.Errorf("the cache store walked %d hosted blobs", seen)
	}

	// Evicting from the cache cannot reach the hosted object, even for content
	// that exists in both.
	if err := cache.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := cache.Delete(ctx, digest); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := hosted.Stat(ctx, digest); err != nil {
		t.Errorf("deleting from the cache removed hosted content: %v", err)
	}
}

// A mismatched push must leave nothing at all: the multipart upload is
// abandoned rather than completed, so no object ever appears.
func TestMismatchLeavesNoObject(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	data := []byte("honest content")
	claimed := blob.FromBytes(blob.SHA256, []byte("something else"))

	if err := store.Put(ctx, claimed, bytes.NewReader(data)); !errors.Is(err, blob.ErrDigestMismatch) {
		t.Fatalf("Put = %v, want ErrDigestMismatch", err)
	}

	client := rawClient(t, store)
	for object := range client.ListObjects(ctx, store.bucket, minio.ListObjectsOptions{Recursive: true}) {
		if object.Err != nil {
			t.Fatalf("list: %v", object.Err)
		}
		t.Errorf("a rejected push left %q behind", object.Key)
	}
}

// Content larger than one part exercises the multipart path that every real
// layer takes.
func TestMultipartBlob(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	// Two and a bit parts, so there is a full part, another full part, and a
	// short final one.
	data := bytes.Repeat([]byte("0123456789abcdef"), (minimumPartSize*2+1024)/16)
	digest := blob.FromBytes(blob.SHA256, data)

	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	desc, err := store.Stat(ctx, digest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if desc.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", desc.Size, len(data))
	}

	reader, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = reader.Close() }()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("multipart blob did not round-trip: got %d bytes, want %d", len(got), len(data))
	}
}

// The read path is the last line of defence against an object store that has
// started lying, or an operator who edited a key by hand.
func TestCorruptObjectIsQuarantined(t *testing.T) {
	t.Parallel()

	var (
		hookCalls int
		hookDesc  blob.Descriptor
		hookErr   error
	)
	store := newStore(t, func(o *Options) {
		o.OnCorrupt = func(_ context.Context, desc blob.Descriptor, err error) {
			hookCalls++
			hookDesc, hookErr = desc, err
		}
	})
	ctx := context.Background()

	data := []byte("content that will be tampered with")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Overwrite the object behind the store's back.
	corrupted := append([]byte(nil), data...)
	corrupted[0] ^= 0xff
	key := "blobs/sha256/" + digest.Hex()
	client := rawClient(t, store)
	if _, err := client.PutObject(ctx, store.bucket, key,
		bytes.NewReader(corrupted), int64(len(corrupted)), minio.PutObjectOptions{}); err != nil {
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
	if err := reader.Close(); err != nil && !errors.Is(err, blob.ErrDigestMismatch) {
		t.Errorf("Close: %v", err)
	}

	// Out of the served keyspace, so the next pull is a clean miss rather than
	// a second corrupt transfer.
	if _, err := store.Stat(ctx, digest); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("Stat after quarantine = %v, want ErrNotFound", err)
	}
	// The bytes are kept as evidence.
	object, err := client.GetObject(ctx, store.bucket, "quarantine/sha256/"+digest.Hex(),
		minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("open quarantined object: %v", err)
	}
	defer func() { _ = object.Close() }()
	kept, err := io.ReadAll(object)
	if err != nil {
		t.Fatalf("read quarantined object: %v", err)
	}
	if !bytes.Equal(kept, corrupted) {
		t.Error("quarantined content is not what was stored")
	}

	if hookCalls != 1 {
		t.Fatalf("corrupt hook called %d times, want 1", hookCalls)
	}
	if hookDesc.Digest != digest || !errors.Is(hookErr, blob.ErrDigestMismatch) {
		t.Errorf("hook received %+v / %v", hookDesc, hookErr)
	}
}

// Redirects are off unless an operator turns them on, because a redirect takes
// trove out of the data path and nothing then verifies what the client gets.
func TestRedirectIsOffByDefault(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	data := []byte("streamed, not redirected")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := store.RedirectURL(ctx, digest); !errors.Is(err, blob.ErrNoRedirect) {
		t.Errorf("RedirectURL = %v, want ErrNoRedirect", err)
	}
}

func TestRedirectWhenEnabled(t *testing.T) {
	t.Parallel()

	store := newStore(t, func(o *Options) {
		o.Redirect = true
		o.RedirectExpiry = time.Minute
	})
	ctx := context.Background()

	data := []byte("fetched straight from the object store")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	url, err := store.RedirectURL(ctx, digest)
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}

	// The URL has to actually work, or the registry would hand clients a 403.
	response, err := http.Get(url) //nolint:gosec // the URL is one the test just minted
	if err != nil {
		t.Fatalf("fetch presigned URL: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("presigned URL returned %s", response.Status)
	}
	got, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read presigned response: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("presigned URL served %q, want %q", got, data)
	}

	// A redirect for content that is not there would send the client to a
	// URL that 404s after the registry already answered.
	missing := blob.FromBytes(blob.SHA256, []byte("never stored"))
	if _, err := store.RedirectURL(ctx, missing); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("RedirectURL for a missing blob = %v, want ErrNotFound", err)
	}
}

// A session's state lives in the bucket, so it survives the process that
// started it.
func TestUploadSurvivesANewStore(t *testing.T) {
	t.Parallel()

	host, bucket := requireBucket(t)
	ctx := context.Background()
	build := func() *Store {
		store, err := New(ctx, Options{
			Endpoint: host, Bucket: bucket,
			AccessKeyID: accessKey, SecretAccessKey: secretKey,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return store
	}

	data := []byte("uploaded across two processes")
	digest := blob.FromBytes(blob.SHA256, data)
	half := len(data) / 2

	first := build()
	session, err := first.CreateUpload(ctx, "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx, bytes.NewReader(data[:half])); err != nil {
		t.Fatalf("Write: %v", err)
	}

	second := build()
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

// A committed session leaves nothing behind: its chunks and its marker go
// with it, or every push would leak a copy of the layer it just stored.
func TestCommitClearsTheSessionObjects(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	data := []byte("committed and cleaned up")
	digest := blob.FromBytes(blob.SHA256, data)

	session, err := store.CreateUpload(ctx, "upload-1")
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if _, err := session.Write(ctx, bytes.NewReader(data)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := session.Commit(ctx, digest); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	client := rawClient(t, store)
	for object := range client.ListObjects(ctx, store.bucket, minio.ListObjectsOptions{
		Prefix: "uploads/", Recursive: true,
	}) {
		if object.Err != nil {
			t.Fatalf("list: %v", object.Err)
		}
		t.Errorf("the session left %q behind", object.Key)
	}
}

// Walk yields blobs and ignores anything else, so a stray object cannot become
// a descriptor a garbage collector would act on.
func TestWalkIgnoresForeignObjects(t *testing.T) {
	t.Parallel()

	store := newStore(t)
	ctx := context.Background()

	data := []byte("a real blob")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	client := rawClient(t, store)
	foreign := []string{
		"blobs/README",
		"blobs/sha256/not-a-digest",
		"blobs/md5/" + digest.Hex(),
		"blobs/sha256/" + digest.Hex() + "/nested",
	}
	for _, key := range foreign {
		if _, err := client.PutObject(ctx, store.bucket, key,
			strings.NewReader("junk"), 4, minio.PutObjectOptions{}); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
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

func TestNormalisePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
		bad  bool
	}{
		{in: "", want: ""},
		{in: "/", want: ""},
		{in: "hosted", want: "hosted/"},
		{in: "/hosted/", want: "hosted/"},
		{in: "team/hosted", want: "team/hosted/"},
		{in: "../escape", bad: true},
		{in: "hosted/../cache", bad: true},
		{in: "hosted//double", bad: true},
		{in: "./hosted", bad: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			got, err := normalisePrefix(tt.in)
			if tt.bad {
				if !errors.Is(err, blob.ErrInvalid) {
					t.Errorf("normalisePrefix(%q) = %q, %v; want ErrInvalid", tt.in, got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("normalisePrefix(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestDigestFromKey(t *testing.T) {
	t.Parallel()

	const hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	prefix := "hosted/blobs/"

	tests := []struct {
		name string
		key  string
		want blob.Digest
	}{
		{"well formed", prefix + "sha256/" + hex, blob.Digest("sha256:" + hex)},
		{"outside the prefix", "other/blobs/sha256/" + hex, ""},
		{"no algorithm", prefix + hex, ""},
		{"nested", prefix + "sha256/" + hex + "/part", ""},
		{"unknown algorithm", prefix + "md5/" + hex, ""},
		{"not hex", prefix + "sha256/" + strings.Repeat("z", 64), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := digestFromKey(prefix, tt.key)
			if tt.want == "" {
				if ok {
					t.Errorf("digestFromKey(%q) = %s, want it ignored", tt.key, got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("digestFromKey(%q) = %s, %v; want %s", tt.key, got, ok, tt.want)
			}
		})
	}
}
