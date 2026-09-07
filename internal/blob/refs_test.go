package blob_test

import (
	"errors"
	"testing"

	"github.com/steveokay/trove/internal/blob"
)

func TestRefsCarryTheirDigest(t *testing.T) {
	t.Parallel()

	digest := blob.FromBytes(blob.SHA256, []byte("layer"))

	cached, err := blob.NewCachedRef(digest)
	if err != nil {
		t.Fatalf("NewCachedRef: %v", err)
	}
	hosted, err := blob.NewHostedRef(digest)
	if err != nil {
		t.Fatalf("NewHostedRef: %v", err)
	}

	if cached.Digest() != digest {
		t.Errorf("CachedRef.Digest() = %s, want %s", cached.Digest(), digest)
	}
	if hosted.Digest() != digest {
		t.Errorf("HostedRef.Digest() = %s, want %s", hosted.Digest(), digest)
	}
	if cached.String() != digest.String() {
		t.Errorf("CachedRef.String() = %s, want %s", cached, digest)
	}
	if hosted.String() != digest.String() {
		t.Errorf("HostedRef.String() = %s, want %s", hosted, digest)
	}
}

func TestRefsRefuseAnUnparseableDigest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		digest blob.Digest
	}{
		{name: "empty", digest: ""},
		{name: "no algorithm", digest: "deadbeef"},
		{name: "unknown algorithm", digest: "md5:d41d8cd98f00b204e9800998ecf8427e"},
		{name: "traversal", digest: "sha256:../../etc/passwd"},
		{name: "short hex", digest: "sha256:abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A ref that exists has been validated, so the check cannot be
			// skipped at the delete -- which is the one call site where
			// getting it wrong reaches a filesystem path.
			if _, err := blob.NewCachedRef(tc.digest); !errors.Is(err, blob.ErrInvalidDigest) {
				t.Errorf("NewCachedRef(%q) error = %v, want ErrInvalidDigest", tc.digest, err)
			}
			if _, err := blob.NewHostedRef(tc.digest); !errors.Is(err, blob.ErrInvalidDigest) {
				t.Errorf("NewHostedRef(%q) error = %v, want ErrInvalidDigest", tc.digest, err)
			}
		})
	}
}

// TestZeroRefsNameNothing pins the zero value: it carries no digest, so a ref
// somebody declared and forgot to fill in reaches a store as an empty digest
// and is refused there rather than naming content by accident.
func TestZeroRefsNameNothing(t *testing.T) {
	t.Parallel()

	var cached blob.CachedRef
	var hosted blob.HostedRef

	if got := cached.Digest(); got != "" {
		t.Errorf("zero CachedRef.Digest() = %q, want empty", got)
	}
	if got := hosted.Digest(); got != "" {
		t.Errorf("zero HostedRef.Digest() = %q, want empty", got)
	}
	if err := cached.Digest().Validate(); err == nil {
		t.Error("zero CachedRef's digest validated; want an error")
	}
}
