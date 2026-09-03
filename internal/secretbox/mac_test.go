package secretbox_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/steveokay/trove/internal/secretbox"
)

func macKeyring(t *testing.T, lines ...string) *secretbox.Keyring {
	t.Helper()

	keys := make([]secretbox.Key, len(lines))
	for i, line := range lines {
		key, err := secretbox.DecodeKey(line)
		if err != nil {
			t.Fatalf("DecodeKey: %v", err)
		}
		keys[i] = key
	}
	ring, err := secretbox.NewKeyring(keys...)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return ring
}

// A fixed key for the pinned digest below.
var macTestKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, secretbox.KeySize))

func TestMACRoundTrip(t *testing.T) {
	t.Parallel()

	ring := macKeyring(t, macTestKey)
	ctx := secretbox.RobotSecret("robot-1")

	digest, err := ring.MAC([]byte("trove_r_robot-1_secret"), ctx)
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if !ring.VerifyMAC([]byte("trove_r_robot-1_secret"), ctx, digest) {
		t.Fatal("a digest this keyring just produced did not verify")
	}

	tests := []struct {
		name   string
		value  []byte
		ctx    secretbox.Context
		digest []byte
	}{
		{"different value", []byte("trove_r_robot-1_other"), ctx, digest},
		// The context is the row binding: a digest lifted from one robot's
		// row must not verify another's secret.
		{"different context", []byte("trove_r_robot-1_secret"), secretbox.RobotSecret("robot-2"), digest},
		{"tampered digest", []byte("trove_r_robot-1_secret"), ctx, flipLastBit(digest)},
		{"truncated digest", []byte("trove_r_robot-1_secret"), ctx, digest[:len(digest)-1]},
		{"empty digest", []byte("trove_r_robot-1_secret"), ctx, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if ring.VerifyMAC(tt.value, tt.ctx, tt.digest) {
				t.Error("VerifyMAC accepted what it must refuse")
			}
		})
	}
}

func flipLastBit(digest []byte) []byte {
	out := append([]byte(nil), digest...)
	out[len(out)-1] ^= 1
	return out
}

// The digest format is at-rest data: a build that changes it strands every
// robot secret in the database. Same discipline as Seal's pinned golden.
func TestMACPinnedGolden(t *testing.T) {
	t.Parallel()

	ring := macKeyring(t, macTestKey)
	digest, err := ring.MAC([]byte("pinned-value"), secretbox.RobotSecret("pinned-robot"))
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}

	const want = "34323565643465348f09013102e36a8dfdc071cefda1b442b2705f31a5195e0f0eae59142b7eb8dc"
	if got := hex.EncodeToString(digest); got != want {
		t.Errorf("digest = %s, want the pinned %s\n(a format change strands every stored robot secret)", got, want)
	}
}

// Rotation must not invalidate stored digests: the new key signs, retired
// keys still verify, exactly as retired keys still open sealed values.
func TestMACSurvivesRotation(t *testing.T) {
	t.Parallel()

	old := macKeyring(t, macTestKey)
	ctx := secretbox.RobotSecret("robot-1")
	digest, err := old.MAC([]byte("secret"), ctx)
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}

	fresh, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rotated, err := old.Rotate(fresh)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if !rotated.VerifyMAC([]byte("secret"), ctx, digest) {
		t.Fatal("rotation invalidated an existing digest")
	}

	// New digests carry the new key, and a ring that dropped the old key
	// cannot verify the old digest -- same rule as ErrUnknownKey on Open.
	newDigest, err := rotated.MAC([]byte("secret"), ctx)
	if err != nil {
		t.Fatalf("MAC after rotation: %v", err)
	}
	newOnly, err := secretbox.NewKeyring(fresh)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if !newOnly.VerifyMAC([]byte("secret"), ctx, newDigest) {
		t.Fatal("the new key's own digest did not verify")
	}
	if newOnly.VerifyMAC([]byte("secret"), ctx, digest) {
		t.Fatal("a ring without the old key verified the old digest")
	}
}

func TestMACRefusesAnInvalidContext(t *testing.T) {
	t.Parallel()

	ring := macKeyring(t, macTestKey)
	if _, err := ring.MAC([]byte("v"), secretbox.Context("")); err == nil {
		t.Fatal("MAC accepted an empty context")
	}
	if ring.VerifyMAC([]byte("v"), secretbox.Context(""), []byte("x")) {
		t.Fatal("VerifyMAC accepted an empty context")
	}
}

// Two contexts that concatenate identically must not collide: the encoding is
// length-prefixed, not glued.
func TestMACContextValueBoundaryIsUnambiguous(t *testing.T) {
	t.Parallel()

	ring := macKeyring(t, macTestKey)
	a, err := ring.MAC([]byte("bsecret"), secretbox.Context("robot-secret:a"))
	if err != nil {
		t.Fatalf("MAC: %v", err)
	}
	if ring.VerifyMAC([]byte("secret"), secretbox.Context("robot-secret:ab"), a) {
		t.Fatal("shifting bytes across the context/value boundary produced the same digest")
	}
}
