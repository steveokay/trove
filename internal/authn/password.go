package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id is the password hash (ADR 0004). It is the current OWASP first
// choice, and its pure-Go implementation keeps CGO_ENABLED=0.
//
// Every hash carries its own salt and its own cost parameters, encoded in the
// standard PHC string:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>
//
// That format is why parameters can be raised later without a migration and
// without invalidating a single existing password: verification uses the
// parameters the hash was made with, and NeedsRehash reports afterwards that
// the credential should be re-hashed at the new cost the next time the plain
// password is in hand -- which is exactly once, at login.
//
// Storing parameters per hash also means a deployment that was tuned on a
// small VM and later moved to a large one converges on the new cost as people
// log in, rather than being stuck at whatever the original bootstrap measured.

// Params are the Argon2id cost parameters.
type Params struct {
	// Memory is the memory cost in KiB. It is the parameter that matters most
	// against GPU attack, and the one to raise first.
	Memory uint32
	// Iterations is the time cost: passes over memory.
	Iterations uint32
	// Parallelism is the number of lanes.
	Parallelism uint8
	// SaltLength is how many random bytes each hash gets.
	SaltLength uint32
	// KeyLength is the digest length in bytes.
	KeyLength uint32
}

// DefaultParams are OWASP's interactive recommendation for Argon2id: 19 MiB of
// memory, two passes, one lane.
//
// They are deliberately not the heaviest possible. A login is on the request
// path -- for the UI, for `docker login`, and for every token mint -- so a cost
// that makes an attacker's life hard and a user's life slow is a denial of
// service somebody will eventually "fix" by lowering it in a hurry.
var DefaultParams = Params{
	Memory:      19456,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Ceilings on what a hash may ask for.
//
// These exist because Verify's parameters come out of the stored hash, and the
// stored hash is data. A row reading m=1000002100 asks for 954 GiB of memory
// before a password is ever compared -- so a single corrupt or planted
// verifier would take the process down, and every login attempt against it
// would do so again. A fuzzer found exactly that.
//
// A finite ceiling is not enough on its own: the fuzzer's second find asked
// for just under a gigabyte and twenty passes, each of which is individually
// unremarkable and which together are twenty seconds of grinding per attempt.
// So the product is bounded too -- that is the quantity that is actually
// spent.
//
// The limits are far above any sane configuration: the default asks for 19 MiB
// and two passes, which is a seventieth of the work budget. Anything beyond
// these is a broken row, not a strong password policy.
const (
	// MaxMemory is the largest memory cost a hash may declare, in KiB. It
	// bounds the allocation a single attempt can make.
	MaxMemory = 1 << 18 // 256 MiB
	// MaxIterations is the largest time cost a hash may declare.
	MaxIterations = 16
	// MaxWork bounds memory times iterations, in KiB-passes: how much a single
	// verification may actually cost, whichever way the two are traded off.
	MaxWork = 1 << 19 // 512 MiB-passes
	// MaxLength bounds the declared salt and digest lengths.
	MaxLength = 1024
)

// Validate reports whether the parameters can produce a usable hash.
//
// The floors are deliberately low: they refuse values that are broken rather
// than values that are merely weak, because an operator with an unusual
// machine has better information about their own hardware than a constant here
// does. What they do stop is a zero-valued Params silently hashing with no
// memory and no salt at all -- and, at the other end, a hash whose declared
// cost would exhaust the machine before anything is compared.
func (p Params) Validate() error {
	switch {
	case p.Memory < 8:
		// Argon2 requires at least 8 KiB per lane, and the library panics
		// below it. A panic in the login path is not an error message.
		return fmt.Errorf("%w: memory %d KiB is below the 8 KiB minimum", ErrInvalidParams, p.Memory)
	case p.Parallelism == 0:
		return fmt.Errorf("%w: parallelism must be at least 1", ErrInvalidParams)
	case uint32(p.Parallelism) > p.Memory/8:
		return fmt.Errorf("%w: %d lanes need at least %d KiB of memory, have %d",
			ErrInvalidParams, p.Parallelism, uint32(p.Parallelism)*8, p.Memory)
	case p.Iterations == 0:
		return fmt.Errorf("%w: iterations must be at least 1", ErrInvalidParams)
	case p.SaltLength < 8:
		// Below this a salt stops doing its job: identical passwords start
		// colliding across accounts, which is what a salt exists to prevent.
		return fmt.Errorf("%w: salt length %d is below the 8-byte minimum", ErrInvalidParams, p.SaltLength)
	case p.KeyLength < 16:
		return fmt.Errorf("%w: key length %d is below the 16-byte minimum", ErrInvalidParams, p.KeyLength)
	case p.Memory > MaxMemory:
		return fmt.Errorf("%w: memory %d KiB exceeds the %d KiB maximum", ErrInvalidParams, p.Memory, MaxMemory)
	case p.Iterations > MaxIterations:
		return fmt.Errorf("%w: %d iterations exceed the maximum of %d", ErrInvalidParams, p.Iterations, MaxIterations)
	case uint64(p.Memory)*uint64(p.Iterations) > MaxWork:
		return fmt.Errorf("%w: %d KiB over %d passes is %d KiB-passes of work, above the maximum of %d",
			ErrInvalidParams, p.Memory, p.Iterations,
			uint64(p.Memory)*uint64(p.Iterations), uint64(MaxWork))
	case p.SaltLength > MaxLength:
		return fmt.Errorf("%w: salt length %d exceeds the maximum of %d", ErrInvalidParams, p.SaltLength, MaxLength)
	case p.KeyLength > MaxLength:
		return fmt.Errorf("%w: key length %d exceeds the maximum of %d", ErrInvalidParams, p.KeyLength, MaxLength)
	}
	return nil
}

// Errors from hashing and verification. Callers assert with errors.Is.
var (
	// ErrPasswordMismatch reports a password that does not match the hash. It
	// is the only answer a caller gets for a wrong password: nothing
	// distinguishes "wrong password" from "no such user" above this layer,
	// because the difference is an account enumeration oracle.
	ErrPasswordMismatch = errors.New("password does not match")
	// ErrInvalidHash reports a stored verifier that cannot be parsed. It means
	// the row is corrupt or was written by something else -- never that the
	// password was wrong, and the two must not be conflated.
	ErrInvalidHash = errors.New("invalid password hash")
	// ErrInvalidParams reports unusable cost parameters.
	ErrInvalidParams = errors.New("invalid Argon2id parameters")
	// ErrEmptyPassword reports an attempt to hash nothing. An empty password
	// is not a credential, and hashing one would produce a verifier that looks
	// exactly like a real one.
	ErrEmptyPassword = errors.New("password is empty")
)

// Hasher produces password verifiers.
//
// It is a value rather than a package-level function so the parameters and the
// randomness are both injected: the parameters because they are configuration
// that rises over time, and the randomness because a test that cannot fix the
// salt cannot pin the encoding.
type Hasher struct {
	// Params are the cost parameters new hashes are made with.
	Params Params
	// Rand supplies salt bytes. Nil means crypto/rand.
	Rand io.Reader
}

// NewHasher returns a hasher at the default cost.
func NewHasher() Hasher { return Hasher{Params: DefaultParams} }

// Hash returns the encoded verifier for a password.
//
// Argon2 has no input length limit, so unlike bcrypt there is no silent
// truncation to design around: a long passphrase is hashed whole.
func (h Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	if err := h.Params.Validate(); err != nil {
		return "", err
	}

	salt := make([]byte, h.Params.SaltLength)
	source := h.Rand
	if source == nil {
		source = rand.Reader
	}
	if _, err := io.ReadFull(source, salt); err != nil {
		// Without randomness there is no salt, and a fixed salt is worse than
		// no hash at all because it looks like one.
		return "", fmt.Errorf("reading salt: %w", err)
	}

	return encode(h.Params, salt, derive(password, salt, h.Params)), nil
}

// Verify reports whether a password matches an encoded verifier.
//
// The comparison is constant-time. The parse is not, and does not need to be:
// it reads the stored hash, which the client did not supply and cannot vary.
func Verify(encoded, password string) error {
	params, salt, want, err := decode(encoded)
	if err != nil {
		return err
	}

	got := derive(password, salt, params)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// NeedsRehash reports whether a verifier was made at a lower cost than want.
//
// This is the upgrade path, and it only ever moves in one direction: a hash
// made at or above the target cost is left alone, so lowering the configured
// parameters does not quietly downgrade every stored password at next login.
// Call it after a successful Verify, which is the one moment the plain
// password is available to re-hash.
func NeedsRehash(encoded string, want Params) (bool, error) {
	// decode has already bounded the salt and recorded its length, so the
	// comparison uses that rather than re-measuring the slice.
	have, _, _, err := decode(encoded)
	if err != nil {
		return false, err
	}
	return have.Memory < want.Memory ||
		have.Iterations < want.Iterations ||
		have.Parallelism < want.Parallelism ||
		have.SaltLength < want.SaltLength, nil
}

// derive runs Argon2id. It is the only call site of the primitive, so the
// mapping from our parameters to the library's argument order is written once.
func derive(password string, salt []byte, p Params) []byte {
	return argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

// The PHC string's fixed parts. Version 19 is 0x13, the only Argon2 version
// this understands; a hash claiming another one is refused rather than
// verified with the wrong algorithm.
const (
	phcAlgorithm = "argon2id"
	phcVersion   = argon2.Version
)

// phcEncoding is unpadded standard base64, as the PHC format specifies.
var phcEncoding = base64.RawStdEncoding

// encode renders a hash in the PHC string format.
func encode(p Params, salt, digest []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		phcAlgorithm, phcVersion, p.Memory, p.Iterations, p.Parallelism,
		phcEncoding.EncodeToString(salt), phcEncoding.EncodeToString(digest))
}

// decode parses a PHC string strictly.
//
// Strictly means one spelling per hash. Go's base64 decoder accepts embedded
// newlines and non-zero padding bits, and strconv accepts leading zeros, so a
// lenient parser would let one verifier have many encodings -- which turns a
// stored-hash comparison into something that depends on how the row was
// written. The check is a round-trip: whatever we parsed must re-encode to
// exactly what we were given.
func decode(encoded string) (Params, []byte, []byte, error) {
	fail := func(detail string) (Params, []byte, []byte, error) {
		return Params{}, nil, nil, fmt.Errorf("%w: %s", ErrInvalidHash, detail)
	}

	fields := strings.Split(encoded, "$")
	// A leading "$" makes the first field empty: "", alg, version, params,
	// salt, digest.
	if len(fields) != 6 || fields[0] != "" {
		return fail("expected 5 $-separated fields")
	}
	if fields[1] != phcAlgorithm {
		return fail(fmt.Sprintf("algorithm %q is not %s", fields[1], phcAlgorithm))
	}

	if !strings.HasPrefix(fields[2], "v=") {
		return fail(fmt.Sprintf("unreadable version %q", fields[2]))
	}
	version, err := parseUint(strings.TrimPrefix(fields[2], "v="), 32)
	if err != nil {
		return fail(fmt.Sprintf("unreadable version %q", fields[2]))
	}
	if version != phcVersion {
		return fail(fmt.Sprintf("version %d is not %d", version, phcVersion))
	}

	var params Params
	costs := strings.Split(fields[3], ",")
	if len(costs) != 3 {
		return fail(fmt.Sprintf("unreadable cost parameters %q", fields[3]))
	}
	for i, cost := range costs {
		prefix := [...]string{"m=", "t=", "p="}[i]
		if !strings.HasPrefix(cost, prefix) {
			return fail(fmt.Sprintf("expected %q in %q", prefix, cost))
		}
		bits := 32
		if prefix == "p=" {
			bits = 8
		}
		value, err := parseUint(strings.TrimPrefix(cost, prefix), bits)
		if err != nil {
			return fail(fmt.Sprintf("unreadable cost %q", cost))
		}
		// parseUint bounded each value to the width it is stored in, which is
		// what the bits argument above is for.
		switch prefix {
		case "m=":
			params.Memory = uint32(value) // #nosec G115
		case "t=":
			params.Iterations = uint32(value) // #nosec G115
		case "p=":
			params.Parallelism = uint8(value) // #nosec G115
		}
	}

	salt, err := phcEncoding.DecodeString(fields[4])
	if err != nil {
		return fail("salt is not base64")
	}
	digest, err := phcEncoding.DecodeString(fields[5])
	if err != nil {
		return fail("digest is not base64")
	}
	// Bounded before conversion, so an enormous field is refused as data
	// rather than becoming a length nothing downstream expected.
	if len(salt) > MaxLength {
		return fail(fmt.Sprintf("salt longer than the %d-byte maximum", MaxLength))
	}
	if len(digest) > MaxLength {
		return fail(fmt.Sprintf("digest longer than the %d-byte maximum", MaxLength))
	}
	params.SaltLength = uint32(len(salt))  // #nosec G115 -- bounded by MaxLength above
	params.KeyLength = uint32(len(digest)) // #nosec G115 -- bounded by MaxLength above

	if err := params.Validate(); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}
	// The round trip is what makes the parse strict: anything the lenient
	// decoders tolerated shows up here as a difference.
	if canonical := encode(params, salt, digest); canonical != encoded {
		return fail("is not canonically encoded")
	}

	return params, salt, digest, nil
}

// parseUint accepts only plain decimal digits. strconv already refuses a sign,
// but it accepts leading zeros, and "m=0019456" would parse to the same
// parameters while being a second spelling of one hash.
func parseUint(s string, bits int) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, strconv.ErrSyntax
	}
	return strconv.ParseUint(s, 10, bits)
}
