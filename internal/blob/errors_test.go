package blob_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/blob"
)

// The messages are what an operator reads in a log line, so they have to name
// the thing that went wrong. The sentinels are what callers match on, and
// mixing the two up -- matching on text -- is what §11 forbids.
func TestErrorMessagesAndSentinels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		sentinel error
		contains []string
	}{
		{
			name:     "not found",
			err:      blob.NotFound("blob", "sha256:abc"),
			sentinel: blob.ErrNotFound,
			contains: []string{"blob", "sha256:abc", "not found"},
		},
		{
			name:     "invalid digest",
			err:      blob.InvalidDigest("sha256:..", "hex must be lowercase 0-9a-f"),
			sentinel: blob.ErrInvalidDigest,
			contains: []string{"sha256:..", "lowercase"},
		},
		{
			name:     "mismatch",
			err:      blob.Mismatch("sha256:expected", "sha256:actual", 42),
			sentinel: blob.ErrDigestMismatch,
			contains: []string{"sha256:expected", "sha256:actual", "42"},
		},
		{
			name:     "invalid argument",
			err:      blob.Invalid("id", "must not be empty"),
			sentinel: blob.ErrInvalid,
			contains: []string{"id", "must not be empty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("%v does not match its sentinel %v", tt.err, tt.sentinel)
			}
			// The sentinels are distinct: a caller checking for one must not
			// accidentally catch another.
			for _, other := range []error{
				blob.ErrNotFound, blob.ErrInvalidDigest, blob.ErrDigestMismatch, blob.ErrInvalid,
			} {
				if other != tt.sentinel && errors.Is(tt.err, other) {
					t.Errorf("%v also matches %v", tt.err, other)
				}
			}

			message := tt.err.Error()
			for _, want := range tt.contains {
				if !strings.Contains(message, want) {
					t.Errorf("message %q does not mention %q", message, want)
				}
			}
		})
	}
}
