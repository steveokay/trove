package secretbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// RobotSecret names the context for a robot account's secret digest
// (ADR 0004, Z-003b). The robot id must be non-empty. It binds by id rather
// than name, so renaming a robot does not orphan its credential.
func RobotSecret(robotID string) Context { return Context("robot-secret:" + robotID) }

// macSize is the HMAC-SHA-256 digest length.
const macSize = sha256.Size

// MACSize is the length of a digest MAC produces: the signing key's id
// followed by the HMAC itself.
const MACSize = KeyIDLength + macSize

// MAC computes a keyed digest of value bound to ctx, under the active key.
//
// This is how credentials that must be *checked* rather than recovered --
// robot secrets, personal access tokens -- are stored: a database copy yields
// digests, not credentials (ADR 0004). Keying lives here, beside Seal, so the
// secrets key never leaves this package and rotation covers both uses at once
// (ADR 0016): the digest records which key signed it, retired keys keep
// verifying, and NeedsReseal's analogue is a digest naming a retired key.
func (r *Keyring) MAC(value []byte, ctx Context) ([]byte, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if r == nil || len(r.entries) == 0 {
		return nil, fmt.Errorf("mac: %w", ErrNoKey)
	}

	active := r.entries[0].key
	out := make([]byte, 0, MACSize)
	out = append(out, active.id...)
	return append(out, computeMAC(active, ctx, value)...), nil
}

// VerifyMAC reports whether digest is a MAC of value under ctx by any key
// this keyring holds. Anything else -- tampering, another row's digest, a
// retired key no longer in the ring, garbage -- is false, indistinguishably,
// like Open's ErrAuthentication.
func (r *Keyring) VerifyMAC(value []byte, ctx Context, digest []byte) bool {
	if ctx.Validate() != nil || r == nil {
		return false
	}
	if len(digest) != MACSize {
		return false
	}
	index, ok := r.byID[string(digest[:KeyIDLength])]
	if !ok {
		return false
	}
	want := computeMAC(r.entries[index].key, ctx, value)
	return hmac.Equal(digest[KeyIDLength:], want)
}

// computeMAC binds the context and the value unambiguously: the context is
// length-prefixed, so bytes cannot migrate across the boundary and produce
// the same digest for a different (context, value) pair.
func computeMAC(key Key, ctx Context, value []byte) []byte {
	mac := hmac.New(sha256.New, key.material[:])
	var length [binary.MaxVarintLen64]byte
	mac.Write(length[:binary.PutUvarint(length[:], uint64(len(ctx)))])
	mac.Write([]byte(ctx))
	mac.Write(value)
	return mac.Sum(nil)
}
