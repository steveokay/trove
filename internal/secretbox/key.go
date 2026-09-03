package secretbox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// KeySize is the length in bytes of a secrets key. AES-256 is not negotiable
// (ADR 0016), so this is the only length the package accepts.
const KeySize = 32

// KeyIDLength is the number of hex characters in a key identifier.
const KeyIDLength = 8

// Key is 32 bytes of key material together with the identifier derived from
// it.
//
// The identifier is public: it is stored in the clear beside every sealed
// value, which is what lets rotation tell which key opens which row without
// trying them all. The material is not, so String renders only the identifier
// — a stray %v in a log line cannot spill a key.
type Key struct {
	material [KeySize]byte
	id       string
}

// NewKey adopts existing key material, for an operator mounting a key from
// their platform or for a test that needs a fixed one.
func NewKey(material []byte) (Key, error) {
	if len(material) != KeySize {
		return Key{}, &InvalidKeyError{
			Reason: fmt.Sprintf("must be %d bytes, got %d", KeySize, len(material)),
		}
	}
	k := Key{id: keyID(material)}
	copy(k.material[:], material)
	return k, nil
}

// GenerateKey returns a new key read from the system entropy source.
func GenerateKey() (Key, error) { return generateKey(rand.Reader) }

// generateKey is the injectable form. The entropy source is a parameter so the
// failure path is reachable in a test rather than merely believed.
func generateKey(random io.Reader) (Key, error) {
	var material [KeySize]byte
	if _, err := io.ReadFull(random, material[:]); err != nil {
		return Key{}, fmt.Errorf("generate secrets key: %w", err)
	}
	return NewKey(material[:])
}

// DecodeKey parses one keyfile line: a standard-base64 encoding of 32 bytes.
func DecodeKey(line string) (Key, error) {
	material, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		return Key{}, &InvalidKeyError{Reason: "must be standard base64 of 32 bytes"}
	}
	return NewKey(material)
}

// ID returns the key's identifier: the first KeyIDLength hex characters of
// SHA-256 over the key (ADR 0016). It is empty for a zero Key.
func (k Key) ID() string { return k.id }

// Encode renders the key as the keyfile line DecodeKey reads back. It is the
// one method that exposes key material, and it exists only so a keyfile can be
// written; nothing else in the codebase should call it.
func (k Key) Encode() string { return base64.StdEncoding.EncodeToString(k.material[:]) }

// String renders the key by identifier alone, so that formatting a Key — or a
// struct holding one — can never print the material.
func (k Key) String() string { return "secretbox.Key(" + k.id + ")" }

// keyID derives the public identifier. Truncating to eight hex characters is
// safe because the identifier authenticates nothing; it only selects which key
// to try. Two keys that collide there are rejected when the keyring is built,
// so a collision is a loud error and never a silent wrong lookup.
func keyID(material []byte) string {
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:])[:KeyIDLength]
}

// isKeyID reports whether s is shaped like an identifier this package emits.
// Checking before a map lookup keeps an arbitrary attacker-supplied string
// from reaching anything that might one day index by it.
func isKeyID(s string) bool {
	if len(s) != KeyIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
