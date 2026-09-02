package s3

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

// The S3 driver is tested against a real object store, not a fake: most of
// what this driver has to get right is what the service does with it --
// multipart lifecycle, listing order, delete semantics, presigned URLs.
//
// One container is shared by the package and each test gets its own bucket,
// which keeps the suite honest without paying for a container per case.

const (
	minioImage = "minio/minio:RELEASE.2025-04-22T22-12-26Z"
	accessKey  = "trove"
	secretKey  = "trovetrove"
)

var (
	sharedOnce     sync.Once
	sharedEndpoint string
	sharedErr      error
	bucketCounter  counter
)

type counter struct {
	mu sync.Mutex
	n  int
}

func (c *counter) next() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.n
}

// endpoint starts the shared container on first use.
func endpoint(ctx context.Context) (string, error) {
	sharedOnce.Do(func() {
		container, err := tcminio.Run(ctx, minioImage,
			tcminio.WithUsername(accessKey),
			tcminio.WithPassword(secretKey),
		)
		if err != nil {
			sharedErr = fmt.Errorf("start %s: %w", minioImage, err)
			return
		}
		sharedEndpoint, sharedErr = container.ConnectionString(ctx)
	})
	return sharedEndpoint, sharedErr
}

// requireBucket returns the endpoint and a fresh bucket, skipping the test
// when Docker is not available at all.
func requireBucket(t *testing.T) (string, string) {
	t.Helper()

	ctx := context.Background()
	host, err := endpoint(ctx)
	if err != nil {
		if _, set := os.LookupEnv("CI"); set {
			t.Fatalf("MinIO container unavailable in CI: %v", err)
		}
		t.Skipf("MinIO container unavailable: %v", err)
	}

	client, err := minio.New(host, &minio.Options{
		Creds: credentials.NewStaticV4(accessKey, secretKey, ""),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	bucket := fmt.Sprintf("trove-test-%d", bucketCounter.next())
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatalf("create bucket %s: %v", bucket, err)
	}
	return host, bucket
}

func TestContainerStarts(t *testing.T) {
	host, bucket := requireBucket(t)

	store, err := New(context.Background(), Options{
		Endpoint:        host,
		Bucket:          bucket,
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if store == nil {
		t.Fatal("New returned no store")
	}
}
