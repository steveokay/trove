package authn_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
)

// loginFixture is a store with one user, "alice", whose password is "sesame".
func loginFixture(t *testing.T, hasher authn.Hasher) *memory.Store {
	t.Helper()

	ctx := context.Background()
	store := newBootStore(t)
	if err := store.CreateSubject(ctx, meta.Subject{ID: "u-alice", Kind: meta.User, Name: "alice"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	hash, err := hasher.Hash("sesame")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.PutUserCredential(ctx, meta.UserCredential{
		Subject: "alice", Hash: hash, MustRotate: true,
	}); err != nil {
		t.Fatalf("PutUserCredential: %v", err)
	}
	return store
}

// weakHasher hashes at the lowest cost Validate accepts, standing in for a
// deployment whose stored hashes predate a parameter raise.
func weakHasher(t *testing.T) authn.Hasher {
	t.Helper()
	h := authn.Hasher{Params: authn.Params{
		Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}}
	if err := h.Params.Validate(); err != nil {
		t.Fatalf("the weak parameters are supposed to be valid: %v", err)
	}
	return h
}

func TestPasswordLogin(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := loginFixture(t, authn.NewHasher())
	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	tests := []struct {
		name     string
		user     string
		password string
		wantErr  error
	}{
		{"correct password", "alice", "sesame", nil},
		{"wrong password", "alice", "open barley", authn.ErrBadCredentials},
		// Unknown user and wrong password are the same answer: the
		// difference is an account-enumeration oracle (ADR 0003's logic
		// applied to people).
		{"unknown user", "bob", "sesame", authn.ErrBadCredentials},
		{"empty password", "alice", "", authn.ErrBadCredentials},
		{"empty username", "", "sesame", authn.ErrBadCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := login.Authenticate(ctx, tt.user, tt.password, "203.0.113.7")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Authenticate = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// A corrupt stored hash is a server problem, never "wrong password": the
// distinction decides between a 401 the user can fix and a 500 somebody must.
func TestPasswordLoginSurfacesACorruptHash(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)
	if err := store.CreateSubject(ctx, meta.Subject{ID: "u-eve", Kind: meta.User, Name: "eve"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := store.PutUserCredential(ctx, meta.UserCredential{Subject: "eve", Hash: "not-a-phc-string"}); err != nil {
		t.Fatalf("PutUserCredential: %v", err)
	}

	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}
	got := login.Authenticate(ctx, "eve", "anything", "")
	if !errors.Is(got, authn.ErrInvalidHash) {
		t.Errorf("Authenticate = %v, want ErrInvalidHash", got)
	}
	if errors.Is(got, authn.ErrBadCredentials) {
		t.Error("a corrupt row must not read as a wrong password")
	}
}

func TestPasswordLoginRateLimits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := loginFixture(t, authn.NewHasher())

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	limiter, err := authn.NewAttemptLimiter(
		authn.LimiterConfig{Burst: 2, Refill: 10 * time.Second, MaxKeys: 16},
		authn.LimiterConfig{Burst: 100, Refill: time.Second, MaxKeys: 16},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := login.Authenticate(ctx, "alice", "wrong", "203.0.113.7"); !errors.Is(err, authn.ErrBadCredentials) {
			t.Fatalf("attempt %d = %v, want bad credentials", i, err)
		}
	}

	// The burst is spent; the next attempt is refused with a truthful wait --
	// even with the correct password, because the limiter cannot know that
	// without doing the work it exists to bound.
	var limited *authn.RateLimitedError
	err = login.Authenticate(ctx, "alice", "sesame", "203.0.113.7")
	if !errors.As(err, &limited) {
		t.Fatalf("Authenticate = %v, want a rate-limited error", err)
	}
	if limited.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want a positive wait", limited.RetryAfter)
	}

	// The error explains itself: it is what ends up in the log.
	if msg := limited.Error(); !strings.Contains(msg, "retry after") {
		t.Errorf("Error() = %q, want it to name the wait", msg)
	}

	// After the wait, the door opens again.
	now = now.Add(limited.RetryAfter)
	if err := login.Authenticate(ctx, "alice", "sesame", "203.0.113.7"); err != nil {
		t.Errorf("Authenticate after the wait: %v", err)
	}
}

// A login path with unusable hashing parameters must refuse to build: the
// decoy verifier is part of its contract, and starting without one would turn
// the unknown-user branch into a timing oracle.
func TestNewPasswordLoginRefusesBadParams(t *testing.T) {
	t.Parallel()

	store := newBootStore(t)
	if _, err := authn.NewPasswordLogin(store, nil, authn.Hasher{}); err == nil {
		t.Fatal("NewPasswordLogin accepted zero-valued parameters")
	}
}

// A successful login is the one moment the plaintext is in hand, so it is
// when a hash stored at yesterday's cost is upgraded to today's (Z-002).
func TestPasswordLoginUpgradesWeakHashes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := loginFixture(t, weakHasher(t))
	before, err := store.GetUserCredential(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}

	login, err := authn.NewPasswordLogin(store, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}
	if err := login.Authenticate(ctx, "alice", "sesame", ""); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	after, err := store.GetUserCredential(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if after.Hash == before.Hash {
		t.Fatal("the weak hash was not upgraded")
	}
	if err := authn.Verify(after.Hash, "sesame"); err != nil {
		t.Fatalf("the upgraded hash does not verify: %v", err)
	}
	if !after.MustRotate {
		t.Error("the upgrade dropped MustRotate")
	}
	needs, err := authn.NeedsRehash(after.Hash, authn.DefaultParams)
	if err != nil || needs {
		t.Errorf("NeedsRehash after upgrade = %v, %v; want done", needs, err)
	}

	// A wrong password upgrades nothing.
	if err := login.Authenticate(ctx, "alice", "wrong", ""); !errors.Is(err, authn.ErrBadCredentials) {
		t.Fatalf("Authenticate = %v", err)
	}
}

// failingCredentialWriter lets reads through and refuses writes, standing in
// for a store that has gone read-only mid-flight.
type failingCredentialWriter struct {
	*memory.Store
}

func (f *failingCredentialWriter) PutUserCredential(context.Context, meta.UserCredential) error {
	return errors.New("read-only filesystem")
}

// The upgrade is best-effort: a login must not fail because the write-back of
// a better hash did, or a degraded store turns into a full outage.
func TestPasswordLoginToleratesAFailedUpgrade(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := loginFixture(t, weakHasher(t))
	login, err := authn.NewPasswordLogin(&failingCredentialWriter{Store: store}, nil, authn.NewHasher())
	if err != nil {
		t.Fatalf("NewPasswordLogin: %v", err)
	}

	if err := login.Authenticate(ctx, "alice", "sesame", ""); err != nil {
		t.Fatalf("Authenticate = %v, want success despite the failed upgrade", err)
	}
}
