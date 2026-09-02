package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"

	"github.com/steveokay/trove/internal/blob"
)

// An upload interrupted part way through must leave nothing an operator or a
// garbage collector can see. That is the whole reason writes go through a
// multipart upload that is completed last: parts already sent are not an
// object, and an upload that never completes never becomes one.
//
// This case gets its own container because it stops the service mid-write, so
// it cannot share one with the rest of the suite.
func TestInterruptedUploadLeavesNothingVisible(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	container, err := tcminio.Run(ctx, minioImage,
		tcminio.WithUsername(accessKey),
		tcminio.WithPassword(secretKey),
	)
	if err != nil {
		if _, set := os.LookupEnv("CI"); set {
			t.Fatalf("MinIO container unavailable in CI: %v", err)
		}
		t.Skipf("MinIO container unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Errorf("terminate: %v", err)
		}
	})

	host, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	const bucket = "interrupted"
	client, err := minio.New(host, &minio.Options{
		Creds: credentials.NewStaticV4(accessKey, secretKey, ""),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	store, err := New(ctx, Options{
		Endpoint: host, Bucket: bucket,
		AccessKeyID: accessKey, SecretAccessKey: secretKey,
		PartSize: minimumPartSize,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Three parts, with the source pausing after the first so the service can
	// be stopped while the upload is genuinely in progress.
	data := bytes.Repeat([]byte("0123456789abcdef"), (minimumPartSize*3)/16)
	digest := blob.FromBytes(blob.SHA256, data)

	sent := make(chan struct{})
	release := make(chan struct{})
	source := &pausingReader{data: data, after: minimumPartSize, sent: sent, release: release}

	// The upload runs under a deadline. A driver call inherits its caller's
	// context and imposes no timeout of its own, so without one here a client
	// waiting on a service that has stopped answering waits forever -- which
	// is what a request deadline exists to prevent in the server.
	putCtx, cancelPut := context.WithTimeout(ctx, 30*time.Second)
	defer cancelPut()

	failed := make(chan error, 1)
	go func() { failed <- store.Put(putCtx, digest, source) }()

	select {
	case <-sent:
	case <-time.After(30 * time.Second):
		t.Fatal("the upload never reached its first part")
	}

	timeout := 10 * time.Second
	if err := container.Stop(ctx, &timeout); err != nil {
		t.Fatalf("stop container: %v", err)
	}
	close(release)

	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("Put succeeded although the service went away mid-upload")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Put never returned after the service went away")
	}

	// Bring it back and look: the parts that did arrive must not have become
	// an object, and nothing must be visible under the blob keyspace.
	if err := container.Start(ctx); err != nil {
		t.Fatalf("restart container: %v", err)
	}
	restarted, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string after restart: %v", err)
	}
	after, err := New(ctx, Options{
		Endpoint: restarted, Bucket: bucket,
		AccessKeyID: accessKey, SecretAccessKey: secretKey,
	})
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}

	if _, err := after.Stat(ctx, digest); err == nil {
		t.Error("an interrupted upload became a visible blob")
	}
	seen := 0
	if err := after.Walk(ctx, func(desc blob.Descriptor) error {
		seen++
		t.Errorf("Walk yielded %s after an interrupted upload", desc.Digest)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if seen != 0 {
		t.Errorf("the store holds %d blobs, want none", seen)
	}
}

// pausingReader hands over the first `after` bytes, then blocks until it is
// released, so a test can interfere while an upload is in flight.
type pausingReader struct {
	data    []byte
	after   int
	offset  int
	sent    chan struct{}
	release chan struct{}
	paused  bool
}

func (r *pausingReader) Read(p []byte) (int, error) {
	if r.offset >= r.after && !r.paused {
		r.paused = true
		close(r.sent)
		<-r.release
	}
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// Every method must report a broken store as broken. Answering "no such blob"
// when the bucket has gone would tell a garbage collector that everything was
// already reclaimed, and tell a client that a layer it just pushed is missing.
func TestMissingBucketIsNotMistakenForMissingContent(t *testing.T) {
	t.Parallel()

	host, bucket := requireBucket(t)
	ctx := context.Background()
	store, err := New(ctx, Options{
		Endpoint: host, Bucket: bucket,
		AccessKeyID: accessKey, SecretAccessKey: secretKey,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := []byte("here until the bucket is not")
	digest := blob.FromBytes(blob.SHA256, data)
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	client, err := minio.New(host, &minio.Options{
		Creds: credentials.NewStaticV4(accessKey, secretKey, ""),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := client.RemoveObject(ctx, bucket, "blobs/sha256/"+digest.Hex(),
		minio.RemoveObjectOptions{}); err != nil {
		t.Fatalf("empty bucket: %v", err)
	}
	if err := client.RemoveBucket(ctx, bucket); err != nil {
		t.Fatalf("remove bucket: %v", err)
	}

	// The removal is done through a second client, so wait until the store's
	// own client agrees the bucket has gone before asserting anything about
	// what it reports. Establishing the precondition beats assuming it: the
	// alternative is a test that passes or fails on timing.
	deadline := time.Now().Add(10 * time.Second)
	for {
		exists, err := store.client.BucketExists(ctx, bucket)
		if err == nil && !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the bucket is still visible to the store: exists=%v err=%v", exists, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	calls := []struct {
		name string
		fn   func() error
	}{
		{"Put", func() error { return store.Put(ctx, digest, bytes.NewReader(data)) }},
		{"Get", func() error { _, err := store.Get(ctx, digest); return err }},
		{"Stat", func() error { _, err := store.Stat(ctx, digest); return err }},
		{"Delete", func() error { return store.Delete(ctx, digest) }},
		{"Walk", func() error { return store.Walk(ctx, func(blob.Descriptor) error { return nil }) }},
		{"CreateUpload", func() error { _, err := store.CreateUpload(ctx, "upload-1"); return err }},
		{"OpenUpload", func() error { _, err := store.OpenUpload(ctx, "upload-1"); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn()
			if err == nil {
				t.Fatalf("%s succeeded against a bucket that is gone", c.name)
			}
			if errors.Is(err, blob.ErrNotFound) {
				t.Errorf("%s = %v, want a failure rather than ErrNotFound", c.name, err)
			}
		})
	}
}
