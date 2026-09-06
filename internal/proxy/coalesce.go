package proxy

import (
	"context"
	"fmt"

	"golang.org/x/sync/singleflight"

	"github.com/steveokay/trove/internal/blob"
)

// Single-flight (C-006).
//
// Fifty pods starting at once pull the same tag at once. Without coalescing
// that is fifty resolutions and fifty manifest fetches against an upstream that
// counts them -- Docker Hub's rate limit is a primary reason operators deploy a
// pull-through cache (§4), and a cache that stampedes on a cold start spends
// the quota it exists to protect.
//
// The mechanism is behind an interface because ADR 0018 says v1 is single-node
// and v2 may not be: coalescing across processes needs the metadata store, and
// the seam is the concession to that future rather than an implementation of
// it. The v1 form is an in-process group, which is exactly right for one
// process owning its data directory.

// Coalescer collapses concurrent identical work into one execution.
//
// Do runs fn when no call for the key is in flight, and otherwise waits for the
// one that is; every caller receives the same value and the same error. The
// bool reports whether the result was shared with another caller, which is what
// makes the coalescing observable to a test and to metrics.
//
// Two obligations an implementation must keep:
//
//   - A caller's own context bounds its wait. A waiter whose client has gone
//     must not be held by work somebody else started, and cancelling one caller
//     must not fail the others.
//   - fn's result is handed to every waiter. Anything that must not be shared
//     between them -- a stream, a mutable buffer -- is the caller's problem to
//     copy, which is why the fill path coalesces values and never readers.
type Coalescer interface {
	Do(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, bool, error)
}

// SingleFlight is the v1 Coalescer: one process, one group, no coordination.
type SingleFlight struct {
	group singleflight.Group
}

// NewSingleFlight returns an in-process Coalescer.
func NewSingleFlight() *SingleFlight { return &SingleFlight{} }

// Do runs fn once per key across concurrent callers.
//
// The work runs under a context detached from cancellation, and each caller
// waits under its own. That combination is deliberate: the leader is not
// special, so its client disconnecting must not fail the fifty waiters behind
// it, and a waiter that goes away must not be made to wait for work it no
// longer needs. What bounds the detached work is the client's own request
// timeout (C-002), which every upstream call already carries.
//
// The values on the detached context are the leader's -- its logger and request
// id travel with the fill -- which is the honest description of a shared fetch:
// one of them paid for it.
func (s *SingleFlight) Do(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, bool, error) {
	detached := context.WithoutCancel(ctx)
	result := s.group.DoChan(key, func() (any, error) { return fn(detached) })

	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case out := <-result:
		return out.Val, out.Shared, out.Err
	}
}

// coalesce runs typed work through a Coalescer.
//
// It exists because a Coalescer cannot be generic -- a method with a type
// parameter is not expressible in Go -- and every caller would otherwise repeat
// the same assertion. A result of the wrong type is an error rather than a
// panic: the interface is an extension point (ADR 0018), and a third
// implementation getting it wrong should fail the request that hit it rather
// than the process.
func coalesce[T any](ctx context.Context, c Coalescer, key string, fn func(context.Context) (T, error)) (T, error) {
	var zero T

	value, _, err := c.Do(ctx, key, func(ctx context.Context) (any, error) { return fn(ctx) })
	if err != nil {
		return zero, err
	}
	typed, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("%w: coalescer returned %T, want %T", ErrUpstreamUnavailable, value, zero)
	}
	return typed, nil
}

// The key space. Repository names and tags may both contain almost anything the
// grammar allows, so the parts are separated by a NUL, which neither can hold:
// `dockerhub/a` + `b:c` and `dockerhub/a:b` + `c` must not collide into one
// fetch of the wrong thing.
const keySeparator = "\x00"

func manifestKey(repo string, digest blob.Digest) string {
	return "manifest" + keySeparator + repo + keySeparator + digest.String()
}

func tagKey(repo, tag string) string {
	return "tag" + keySeparator + repo + keySeparator + tag
}
