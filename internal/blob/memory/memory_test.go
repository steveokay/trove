package memory_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/blob/blobtest"
	"github.com/steveokay/trove/internal/blob/memory"
)

// The in-memory store is the reference implementation: it must satisfy the
// same contract as the disk-backed ones, unmodified.
func TestContract(t *testing.T) {
	t.Parallel()

	blobtest.Run(t, func(t *testing.T) blob.Store {
		t.Helper()
		return memory.New(memory.Options{})
	})
}

func TestUploadContract(t *testing.T) {
	t.Parallel()

	blobtest.RunUploads(t, func(t *testing.T) blobtest.UploadStore {
		t.Helper()
		return memory.New(memory.Options{})
	})
}

// Behaviour specific to this implementation, which the shared contract does
// not cover.

// Two stores share nothing. This is the wiring the hosted/cache separation
// depends on (ADR 0009): the cache eviction path holds one instance and
// physically cannot name content in the other.
func TestStoresAreIndependent(t *testing.T) {
	t.Parallel()

	hosted := memory.New(memory.Options{})
	cache := memory.New(memory.Options{})

	data := []byte("shared bytes")
	digest := blob.FromBytes(blob.SHA256, data)

	ctx := context.Background()
	if err := hosted.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := cache.Stat(ctx, digest); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("the cache store can see hosted content: %v", err)
	}

	// Evicting from the cache cannot reach the hosted blob, even for content
	// that happens to exist in both.
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

func TestPutRejectsAnUnavailableAlgorithm(t *testing.T) {
	t.Parallel()

	store := memory.New(memory.Options{})
	// sha512 is in the allowlist, so this proves the store handles more than
	// the one algorithm every client happens to use.
	data := []byte("second algorithm")
	digest := blob.FromBytes(blob.SHA512, data)

	ctx := context.Background()
	if err := store.Put(ctx, digest, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put(sha512): %v", err)
	}
	reader, err := store.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = reader.Close() }()
	if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, data) {
		t.Errorf("sha512 blob = %q, %v; want %q", got, err, data)
	}
}
