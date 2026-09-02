package blob

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
)

// Algorithm names a digest algorithm. The set is closed: an algorithm that is
// not listed here cannot be parsed, which is what keeps an attacker-supplied
// string from reaching a path or a bucket key.
type Algorithm string

// The algorithms trove accepts. sha256 is what every client uses and what the
// distribution spec requires; sha512 is registered by the spec too, and the
// storage layout namespaces the algorithm so accepting it costs nothing.
const (
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

// algorithms is the allowlist. Anything absent is not a digest as far as this
// package is concerned.
var algorithms = map[Algorithm]struct {
	hexLength int
	newHash   func() hash.Hash
}{
	SHA256: {hexLength: 64, newHash: func() hash.Hash { return sha256.New() }},
	SHA512: {hexLength: 128, newHash: func() hash.Hash { return sha512.New() }},
}

// Available reports whether the algorithm is one trove accepts.
func (a Algorithm) Available() bool {
	_, ok := algorithms[a]
	return ok
}

// HexLength is the number of hex characters a digest of this algorithm has.
// It is zero for an unavailable algorithm.
func (a Algorithm) HexLength() int { return algorithms[a].hexLength }

// New returns a hash for the algorithm, or nil if it is not available.
func (a Algorithm) New() hash.Hash {
	entry, ok := algorithms[a]
	if !ok {
		return nil
	}
	return entry.newHash()
}

// Digest is a content address in "algorithm:hex" form.
//
// A Digest that exists has been through ParseDigest, and every driver builds
// its paths and keys from one. That is deliberate and it is the whole traversal
// story: the parser accepts nothing but an allowlisted algorithm, a colon, and
// exactly the right number of lowercase hex characters, so "..", "/", "\", a
// null byte, or a Windows device name cannot survive to reach a filesystem.
// Rejecting these at the edge beats sanitising them later, because sanitising
// is something a future code path can forget to do.
type Digest string

// ParseDigest validates a digest string and returns it.
func ParseDigest(s string) (Digest, error) {
	algorithm, hex, found := strings.Cut(s, ":")
	if !found {
		return "", InvalidDigest(s, "want algorithm:hex")
	}

	algo := Algorithm(algorithm)
	entry, ok := algorithms[algo]
	if !ok {
		return "", InvalidDigest(s, fmt.Sprintf("unsupported algorithm %q", algorithm))
	}
	if len(hex) != entry.hexLength {
		return "", InvalidDigest(s, fmt.Sprintf("%s digests are %d hex characters, got %d",
			algo, entry.hexLength, len(hex)))
	}
	for i := 0; i < len(hex); i++ {
		if !isLowerHex(hex[i]) {
			// Uppercase is rejected along with everything else: one blob must
			// have exactly one address, or it would have two paths and two
			// cache entries.
			return "", InvalidDigest(s, "hex must be lowercase 0-9a-f")
		}
	}
	return Digest(s), nil
}

func isLowerHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// Validate reports whether the digest is well formed. Methods that take a
// Digest call it rather than trusting the type: a Digest can be produced by
// conversion as well as by parsing.
func (d Digest) Validate() error {
	_, err := ParseDigest(string(d))
	return err
}

// Algorithm returns the digest's algorithm, or the empty string if it is not
// well formed.
func (d Digest) Algorithm() Algorithm {
	algorithm, _, found := strings.Cut(string(d), ":")
	if !found {
		return ""
	}
	return Algorithm(algorithm)
}

// Hex returns the digest's hex portion, or the empty string if it is not well
// formed.
func (d Digest) Hex() string {
	_, hex, found := strings.Cut(string(d), ":")
	if !found {
		return ""
	}
	return hex
}

// String renders the digest.
func (d Digest) String() string { return string(d) }

// FromBytes computes the digest of a byte slice. It panics on an unavailable
// algorithm, which can only be a programming error: callers pass a constant.
func FromBytes(algo Algorithm, data []byte) Digest {
	h := algo.New()
	if h == nil {
		panic("blob: digest algorithm " + string(algo) + " is not available")
	}
	h.Write(data)
	return digestOf(algo, h)
}

// digestOf renders a finished hash as a Digest.
func digestOf(algo Algorithm, h hash.Hash) Digest {
	return Digest(fmt.Sprintf("%s:%x", algo, h.Sum(nil)))
}
