package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/meta/metatest"
)

// The in-memory store is the reference implementation: it must satisfy the
// same contract as the database-backed ones, unmodified.
func TestContract(t *testing.T) {
	t.Parallel()

	metatest.Run(t, func(t *testing.T) meta.Store {
		t.Helper()
		return memory.New()
	})
}

// Behaviour specific to this implementation, which the shared contract does
// not cover.

// A closed store must refuse every method rather than serving stale state or
// panicking on a half-torn-down handle.
func TestClosedStoreRefusesEveryMethod(t *testing.T) {
	t.Parallel()

	s := memory.New()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	calls := metatest.Calls(context.Background(), s)
	if len(calls) != len(metatest.MethodNames()) {
		t.Fatalf("got %d calls, want one per store method", len(calls))
	}

	for _, c := range calls {
		t.Run(c.Name, func(t *testing.T) {
			if err := c.Fn(); !errors.Is(err, meta.ErrInvalid) {
				t.Errorf("%s on a closed store = %v, want ErrInvalid", c.Name, err)
			}
		})
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	t.Parallel()

	s := memory.New()
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	if _, err := s.CreateRepository(ctx, meta.Repository{Name: "repo", Type: meta.Hosted}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	// The reference implementation is used by tests across the codebase, some
	// of which run in parallel; the race detector must stay quiet.
	const workers = 8
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			d := meta.Digest("sha256:" + string(rune('a'+i)))
			if err := s.PutBlob(ctx, meta.Blob{Digest: d, Size: int64(i)}); err != nil {
				t.Errorf("PutBlob: %v", err)
			}
			if _, err := s.GetBlob(ctx, d); err != nil {
				t.Errorf("GetBlob: %v", err)
			}
			if _, err := s.ListRepositories(ctx, meta.ListOptions{Visibility: meta.Unrestricted()}); err != nil {
				t.Errorf("ListRepositories: %v", err)
			}
		}(i)
	}
	wg.Wait()
}
