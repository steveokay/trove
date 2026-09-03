package token_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/steveokay/trove/internal/authn/token"
	"github.com/steveokay/trove/internal/authz"
)

var mintTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// fixedSigner is deterministic: fixed seed, fixed clock, zeroed randomness.
// Ed25519 signatures are themselves deterministic, so its tokens are golden-
// able bytes.
func fixedSigner(t *testing.T, ttl time.Duration) *token.Signer {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	clock := mintTime
	signer, err := token.NewSigner(key, ttl, func() time.Time { return clock }, zeroReader{})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestSignerRoundTrip(t *testing.T) {
	t.Parallel()

	signer := fixedSigner(t, 5*time.Minute)
	access := []token.ResourceActions{{Type: "repository", Name: "library/nginx", Actions: []string{"pull"}}}

	minted, err := signer.Mint("alice", access)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if minted.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300", minted.ExpiresIn)
	}
	if !minted.IssuedAt.Equal(mintTime) {
		t.Errorf("IssuedAt = %v, want the injected clock", minted.IssuedAt)
	}

	claims, err := signer.Verify(minted.JWT)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", claims.Subject)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "library/nginx" ||
		len(claims.Access[0].Actions) != 1 || claims.Access[0].Actions[0] != "pull" {
		t.Errorf("Access = %+v, want the minted scope back", claims.Access)
	}
}

// The token is a wire contract with docker and with future trove versions; a
// pinned golden catches an accidental claims or header change.
func TestSignerPinnedGolden(t *testing.T) {
	t.Parallel()

	signer := fixedSigner(t, 5*time.Minute)
	minted, err := signer.Mint("alice", []token.ResourceActions{
		{Type: "repository", Name: "library/nginx", Actions: []string{"pull"}},
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const want = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0cm92ZSIsInN1YiI6ImFsaWNlIiwiYXVkIjpbInRyb3ZlIl0sImV4cCI6MTc4ODQzNzEwMCwibmJmIjoxNzg4NDM2ODAwLCJpYXQiOjE3ODg0MzY4MDAsImp0aSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiYWNjZXNzIjpbeyJ0eXBlIjoicmVwb3NpdG9yeSIsIm5hbWUiOiJsaWJyYXJ5L25naW54IiwiYWN0aW9ucyI6WyJwdWxsIl19XX0.i3yB3rtjP5r7pEv8af4rcQkMAsnuMt86Plo1Iz5oZ4n2fKZ_XUU71eJy6vOtj4D0uTpnnGIL7hZTLJ5X9FUeBw"
	if minted.JWT != want {
		t.Errorf("JWT =\n%s\nwant the pinned\n%s", minted.JWT, want)
	}
}

func TestSignerRejectsForgeries(t *testing.T) {
	t.Parallel()

	signer := fixedSigner(t, 5*time.Minute)
	minted, err := signer.Mint("alice", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)).Public().(ed25519.PublicKey)

	// The classic algorithm-confusion forgery: an HMAC token whose secret is
	// the verifier's own public key. Only EdDSA may verify.
	confused := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"iss": "trove", "aud": "trove", "sub": "admin",
		"exp": mintTime.Add(time.Hour).Unix(),
	})
	confusedString, err := confused.SignedString([]byte(public))
	if err != nil {
		t.Fatalf("signing the forgery: %v", err)
	}

	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	foreign := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, jwtlib.MapClaims{
		"iss": "trove", "aud": "trove", "sub": "admin",
		"exp": mintTime.Add(time.Hour).Unix(),
	})
	foreignString, err := foreign.SignedString(otherKey)
	if err != nil {
		t.Fatalf("signing with the wrong key: %v", err)
	}

	tampered := minted.JWT[:strings.LastIndex(minted.JWT, ".")+1] + "AAAA"

	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"trove","aud":"trove","sub":"admin"}`)) + "."

	for name, raw := range map[string]string{
		"alg confusion":  confusedString,
		"foreign key":    foreignString,
		"tampered":       tampered,
		"alg none":       unsigned,
		"garbage":        "not.a.token",
		"empty":          "",
		"wrong issuer":   mintWith(t, "evil", "trove"),
		"wrong audience": mintWith(t, "trove", "evil"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := signer.Verify(raw); err == nil {
				t.Errorf("Verify accepted a forgery")
			}
		})
	}
}

// mintWith signs with the right key but the wrong identity claims.
func mintWith(t *testing.T, issuer, audience string) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	raw, err := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, jwtlib.MapClaims{
		"iss": issuer, "aud": audience, "sub": "admin",
		"exp": mintTime.Add(time.Hour).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return raw
}

func TestSignerRejectsAnExpiredToken(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	clock := mintTime
	signer, err := token.NewSigner(key, time.Minute, func() time.Time { return clock }, zeroReader{})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	minted, err := signer.Mint("alice", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	clock = mintTime.Add(2 * time.Minute)
	if _, err := signer.Verify(minted.JWT); err == nil {
		t.Fatal("Verify accepted an expired token")
	}
}

// The TTL is clamped, not trusted: ADR 0004 bounds it to [1m, 60m] and zero
// means the 5-minute default.
func TestSignerClampsTheTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ttl  time.Duration
		want int64
	}{
		{0, 300},
		{time.Second, 60},
		{24 * time.Hour, 3600},
		{10 * time.Minute, 600},
	}
	for _, tt := range tests {
		signer := fixedSigner(t, tt.ttl)
		minted, err := signer.Mint("alice", nil)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if minted.ExpiresIn != tt.want {
			t.Errorf("ttl %v: ExpiresIn = %d, want %d", tt.ttl, minted.ExpiresIn, tt.want)
		}
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keys", "token-signing.key")
	first, err := token.LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}

	// The file holds a base64 seed and nothing else.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("keyfile content = %q: not a base64 seed (%v)", raw, err)
	}

	// A second load returns the same key: a restart must not invalidate every
	// outstanding token by silently regenerating.
	second, err := token.LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey (again): %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("two loads returned different keys")
	}

	// A corrupt keyfile is fatal, never regenerated over.
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := token.LoadOrCreateKey(path); err == nil {
		t.Fatal("LoadOrCreateKey accepted a corrupt keyfile")
	}
}

func TestLoadOrCreateKeyRefusals(t *testing.T) {
	t.Parallel()

	t.Run("a seed of the wrong size", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token.key")
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(make([]byte, 16))+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := token.LoadOrCreateKey(path); err == nil {
			t.Fatal("accepted a 16-byte seed")
		}
	})

	t.Run("group-readable keyfile", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" {
			t.Skip("no POSIX modes on windows (Q25); linux CI runs this")
		}
		path := filepath.Join(t.TempDir(), "token.key")
		if _, err := token.LoadOrCreateKey(path); err != nil {
			t.Fatalf("LoadOrCreateKey: %v", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if _, err := token.LoadOrCreateKey(path); err == nil {
			t.Fatal("accepted a keyfile anyone can read: anyone who reads it can mint tokens")
		}
	})
}

func TestNewSignerRefusesABadKey(t *testing.T) {
	t.Parallel()

	if _, err := token.NewSigner(make([]byte, 5), 0, nil, nil); err == nil {
		t.Fatal("NewSigner accepted a five-byte key")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

func TestMintSurfacesARandomnessFailure(t *testing.T) {
	t.Parallel()

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signer, err := token.NewSigner(key, 0, nil, failingReader{})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := signer.Mint("alice", nil); err == nil {
		t.Fatal("Mint succeeded without a token id")
	}
}

func TestParseScopes(t *testing.T) {
	t.Parallel()

	requests := token.ParseScopes([]string{
		"repository:library/nginx:pull,push",
		// Space-joined values arrive from some clients as one parameter.
		"repository:team-a/api:pull repository:team-a/web:push",
		// Unknown types, malformed entries, and illegal names grant nothing
		// but must not fail the mint: the token just carries less.
		"registry:catalog:*",
		"repository:../etc:pull",
		"repository:short",
		"",
		"repository:library/nginx:*",
	})

	type flat struct {
		name    string
		actions string
	}
	var got []flat
	for _, r := range requests {
		got = append(got, flat{r.Name, strings.Join(r.Actions, ",")})
	}
	want := []flat{
		{"library/nginx", "pull,push"},
		{"team-a/api", "pull"},
		{"team-a/web", "push"},
		{"library/nginx", "delete,pull,push"},
	}
	if len(got) != len(want) {
		t.Fatalf("requests = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("requests[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// The intersection is the mint-time half of enforcement (ADR 0004): the token
// carries only what the subject's bindings grant right now, and the handlers
// re-decide on every request anyway.
func TestGrant(t *testing.T) {
	t.Parallel()

	bindings := []authz.Binding{
		{ID: "b1", Role: "developer", Scope: "library/*", Verbs: []authz.Verb{authz.RepoRead}},
		{ID: "b2", Role: "publisher", Scope: "team-a/api", Verbs: []authz.Verb{authz.RepoRead, authz.RepoWrite}},
	}

	granted := token.Grant(bindings, token.ParseScopes([]string{
		// Wide request, narrow grant: push is not held on library/*.
		"repository:library/nginx:pull,push",
		"repository:team-a/api:pull,push",
		// Nothing held here at all: the scope vanishes from the token.
		"repository:secret/repo:pull",
	}))

	if len(granted) != 2 {
		t.Fatalf("granted = %+v, want two entries", granted)
	}
	if granted[0].Name != "library/nginx" || strings.Join(granted[0].Actions, ",") != "pull" {
		t.Errorf("granted[0] = %+v, want library/nginx pull only", granted[0])
	}
	if granted[1].Name != "team-a/api" || strings.Join(granted[1].Actions, ",") != "pull,push" {
		t.Errorf("granted[1] = %+v, want team-a/api pull,push", granted[1])
	}

	if got := token.Grant(nil, token.ParseScopes([]string{"repository:library/nginx:pull"})); len(got) != 0 {
		t.Errorf("no bindings granted %+v, want nothing", got)
	}

	// A hand-built request with an illegal name grants nothing: Grant is
	// exported and must not trust its caller to have gone through ParseScopes.
	if got := token.Grant(bindings, []token.ResourceActions{
		{Type: "repository", Name: "../etc", Actions: []string{"pull"}},
	}); len(got) != 0 {
		t.Errorf("an illegal name granted %+v", got)
	}
}
