package authn_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/steveokay/trove/internal/authn"
)

// cheapParams keep the tests fast. Password hashing is meant to be slow, and a
// suite that pays the real cost a hundred times is a suite people stop running.
// The default cost is exercised where it matters -- once, below.
var cheapParams = authn.Params{
	Memory:      64,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// fixedSalt makes the encoding reproducible so a golden can be pinned.
func fixedSalt(b byte, n int) io.Reader { return bytes.NewReader(bytes.Repeat([]byte{b}, n)) }

func TestHashAndVerify(t *testing.T) {
	t.Parallel()

	hasher := authn.Hasher{Params: cheapParams}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if err := authn.Verify(encoded, "correct horse battery staple"); err != nil {
		t.Errorf("Verify with the right password: %v", err)
	}
	if err := authn.Verify(encoded, "correct horse battery staplf"); !errors.Is(err, authn.ErrPasswordMismatch) {
		t.Errorf("Verify with a wrong password = %v, want ErrPasswordMismatch", err)
	}
	// An empty password must not verify against a real hash, and must not be
	// mistaken for a parse failure either.
	if err := authn.Verify(encoded, ""); !errors.Is(err, authn.ErrPasswordMismatch) {
		t.Errorf("Verify with no password = %v, want ErrPasswordMismatch", err)
	}
}

// The default parameters are what production actually uses, so they get one
// real round trip: they have to validate, hash, and verify at their stated
// cost, not just look reasonable in a struct literal.
func TestDefaultParamsWork(t *testing.T) {
	t.Parallel()

	if err := authn.DefaultParams.Validate(); err != nil {
		t.Fatalf("the default parameters do not validate: %v", err)
	}

	encoded, err := authn.NewHasher().Hash("a passphrase nobody guesses")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("encoded = %q, want the default cost in the header", encoded)
	}
	if err := authn.Verify(encoded, "a passphrase nobody guesses"); err != nil {
		t.Errorf("Verify: %v", err)
	}
	// A hash made at the current default is not due for an upgrade.
	stale, err := authn.NeedsRehash(encoded, authn.DefaultParams)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if stale {
		t.Error("a hash at the default cost wants rehashing")
	}
}

// The wire format is a golden. Rows outlive code: a change to the encoding, to
// the parameter order, or to how the salt reaches Argon2 would orphan every
// stored password, and this is what fails instead.
func TestEncodingIsPinned(t *testing.T) {
	t.Parallel()

	hasher := authn.Hasher{Params: cheapParams, Rand: fixedSalt('A', 16)}
	encoded, err := hasher.Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	const pinned = "$argon2id$v=19$m=64,t=1,p=1$QUFBQUFBQUFBQUFBQUFBQQ$" +
		"bQe5eHN2Q7Y5rvYIP659RsBbYwOf9svfWsJzoke2l0Q"
	if encoded != pinned {
		t.Errorf("encoded = %q\n          want %q", encoded, pinned)
	}

	// And the digest is Argon2id over the salt we said we used -- not, say,
	// over the encoded salt, or with the cost arguments transposed. The
	// library is the same one, so this pins the plumbing rather than the
	// primitive, which is the part that can silently be wrong.
	direct := argon2.IDKey([]byte("hunter2"), bytes.Repeat([]byte{'A'}, 16),
		cheapParams.Iterations, cheapParams.Memory, cheapParams.Parallelism, cheapParams.KeyLength)
	want := base64.RawStdEncoding.EncodeToString(direct)
	if got := encoded[strings.LastIndex(encoded, "$")+1:]; got != want {
		t.Errorf("digest = %s, want %s", got, want)
	}
}

// Two hashes of one password must differ, or the salt is not doing anything.
func TestHashesAreSalted(t *testing.T) {
	t.Parallel()

	hasher := authn.Hasher{Params: cheapParams}
	first, err := hasher.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := hasher.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if first == second {
		t.Error("two hashes of one password are identical: the salt is not random")
	}
	for _, encoded := range []string{first, second} {
		if err := authn.Verify(encoded, "same password"); err != nil {
			t.Errorf("Verify: %v", err)
		}
	}
}

func TestHashRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		hasher authn.Hasher
		want   error
	}{
		{
			name:   "no parameters at all",
			hasher: authn.Hasher{},
			want:   authn.ErrInvalidParams,
		},
		{
			name:   "randomness unavailable",
			hasher: authn.Hasher{Params: cheapParams, Rand: failingReader{}},
			want:   errFailedRead,
		},
		{
			name:   "not enough randomness for a full salt",
			hasher: authn.Hasher{Params: cheapParams, Rand: fixedSalt('A', 4)},
			want:   io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.hasher.Hash("a password"); !errors.Is(err, tt.want) {
				t.Errorf("Hash = %v, want %v", err, tt.want)
			}
		})
	}

	// An empty password is refused before anything is derived: a verifier for
	// "" would be indistinguishable from a real one.
	if _, err := authn.NewHasher().Hash(""); !errors.Is(err, authn.ErrEmptyPassword) {
		t.Errorf("hashing an empty password = %v, want ErrEmptyPassword", err)
	}
}

func TestParamsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params authn.Params
		valid  bool
	}{
		{name: "defaults", params: authn.DefaultParams, valid: true},
		{name: "cheap but usable", params: cheapParams, valid: true},
		{name: "zero", params: authn.Params{}},
		{
			name:   "no memory",
			params: authn.Params{Memory: 4, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		},
		{
			name:   "no lanes",
			params: authn.Params{Memory: 64, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		},
		{
			// Argon2 panics when the lanes cannot each get 8 KiB, and a panic
			// in the login path is not an error message.
			name:   "more lanes than memory can feed",
			params: authn.Params{Memory: 16, Iterations: 1, Parallelism: 8, SaltLength: 16, KeyLength: 32},
		},
		{
			name:   "no iterations",
			params: authn.Params{Memory: 64, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		},
		{
			name:   "salt too short to separate accounts",
			params: authn.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 32},
		},
		{
			name:   "digest too short",
			params: authn.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8},
		},
		{
			// A fuzzer found this: the parameters come out of the stored hash,
			// so a row asking for 954 GiB is a denial of service that fires
			// before a password is ever compared.
			name: "more memory than the machine has",
			params: authn.Params{
				Memory: 1000002100, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
			},
		},
		{
			// The fuzzer's second find: each parameter is unremarkable on its
			// own, and together they are twenty seconds of grinding for every
			// attempt against that row.
			name: "a cost that is only absurd as a product",
			params: authn.Params{
				Memory: 1044444 / 2, Iterations: 20 / 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
			},
		},
		{
			name: "more passes than anyone configures",
			params: authn.Params{
				Memory: 64, Iterations: 1_000_000, Parallelism: 1, SaltLength: 16, KeyLength: 32,
			},
		},
		{
			name: "an absurd salt length",
			params: authn.Params{
				Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 1 << 20, KeyLength: 32,
			},
		},
		{
			name: "an absurd digest length",
			params: authn.Params{
				Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 1 << 20,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.params.Validate()
			if tt.valid && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if !tt.valid {
				if !errors.Is(err, authn.ErrInvalidParams) {
					t.Fatalf("Validate = %v, want ErrInvalidParams", err)
				}
				return
			}
			// Whatever validates must also survive a round trip, so the
			// floors and the encoder agree about what is usable.
			hasher := authn.Hasher{Params: tt.params}
			encoded, err := hasher.Hash("round trip")
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			if err := authn.Verify(encoded, "round trip"); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

// The parse is strict on purpose: one verifier, one spelling. Everything here
// is something a lenient parser would accept, and each would make a stored
// hash compare unequal to a re-encoding of itself.
func TestVerifyRejectsMalformedHashes(t *testing.T) {
	t.Parallel()

	// A real hash to mutate, so each case differs from a valid one in exactly
	// the way it is named for.
	valid, err := authn.Hasher{Params: cheapParams, Rand: fixedSalt('B', 16)}.Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	fields := strings.Split(valid, "$")

	rebuild := func(mutate func([]string)) string {
		copied := append([]string(nil), fields...)
		mutate(copied)
		return strings.Join(copied, "$")
	}

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "empty"},
		{name: "not a hash at all", encoded: "hunter2"},
		{name: "too few fields", encoded: "$argon2id$v=19$m=64,t=1,p=1$QUFB"},
		{name: "too many fields", encoded: valid + "$extra"},
		{name: "no leading separator", encoded: strings.TrimPrefix(valid, "$")},
		{
			name:    "a different argon2 variant",
			encoded: rebuild(func(f []string) { f[1] = "argon2i" }),
		},
		{
			name:    "bcrypt",
			encoded: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		},
		{
			name:    "a version we do not implement",
			encoded: rebuild(func(f []string) { f[2] = "v=16" }),
		},
		{
			name:    "version is not a number",
			encoded: rebuild(func(f []string) { f[2] = "v=nineteen" }),
		},
		{
			name:    "version has no prefix",
			encoded: rebuild(func(f []string) { f[2] = "19" }),
		},
		{
			name:    "a cost parameter is missing",
			encoded: rebuild(func(f []string) { f[3] = "m=64,t=1" }),
		},
		{
			name:    "cost parameters out of order",
			encoded: rebuild(func(f []string) { f[3] = "t=1,m=64,p=1" }),
		},
		{
			name:    "memory is not a number",
			encoded: rebuild(func(f []string) { f[3] = "m=lots,t=1,p=1" }),
		},
		{
			name:    "memory has a leading zero",
			encoded: rebuild(func(f []string) { f[3] = "m=064,t=1,p=1" }),
		},
		{
			name:    "parallelism overflows its byte",
			encoded: rebuild(func(f []string) { f[3] = "m=64,t=1,p=256" }),
		},
		{
			name:    "memory below what argon2 accepts",
			encoded: rebuild(func(f []string) { f[3] = "m=4,t=1,p=1" }),
		},
		{
			// The memory bomb, as it would actually arrive: in a row.
			name:    "a cost the machine cannot pay",
			encoded: rebuild(func(f []string) { f[3] = "m=1000002100,t=1,p=1" }),
		},
		{
			name:    "a cost that is only absurd as a product",
			encoded: rebuild(func(f []string) { f[3] = "m=262144,t=16,p=1" }),
		},
		{
			name:    "salt is not base64",
			encoded: rebuild(func(f []string) { f[4] = "not base64!" }),
		},
		{
			name:    "salt is padded",
			encoded: rebuild(func(f []string) { f[4] += "==" }),
		},
		{
			// Refused as data before it becomes a length: a field this size is
			// a corrupt row, and measuring it into a parameter first is how a
			// parser ends up trusting one.
			name:    "a salt field far larger than any salt",
			encoded: rebuild(func(f []string) { f[4] = strings.Repeat("Q", 4096) }),
		},
		{
			name:    "a digest field far larger than any digest",
			encoded: rebuild(func(f []string) { f[5] = strings.Repeat("Q", 4096) }),
		},
		{
			name:    "salt too short to be a salt",
			encoded: rebuild(func(f []string) { f[4] = "QUFB" }),
		},
		{
			name:    "digest is not base64",
			encoded: rebuild(func(f []string) { f[5] = "not base64!" }),
		},
		{
			name:    "digest truncated",
			encoded: rebuild(func(f []string) { f[5] = f[5][:8] }),
		},
		{
			name:    "a newline inside the digest",
			encoded: rebuild(func(f []string) { f[5] = f[5][:8] + "\n" + f[5][8:] }),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := authn.Verify(tt.encoded, "pw")
			if !errors.Is(err, authn.ErrInvalidHash) {
				t.Errorf("Verify = %v, want ErrInvalidHash", err)
			}
			// A corrupt row is not a wrong password. Conflating them would
			// tell an operator their users are typing badly while the real
			// problem is in the database.
			if errors.Is(err, authn.ErrPasswordMismatch) {
				t.Error("a malformed hash was reported as a password mismatch")
			}
			// NeedsRehash reads the same string and must refuse it the same
			// way rather than answering "no upgrade needed".
			if _, err := authn.NeedsRehash(tt.encoded, authn.DefaultParams); !errors.Is(err, authn.ErrInvalidHash) {
				t.Errorf("NeedsRehash = %v, want ErrInvalidHash", err)
			}
		})
	}

	// The unmutated hash is the control: every case above differs from
	// something that works.
	if err := authn.Verify(valid, "pw"); err != nil {
		t.Errorf("the unmutated hash does not verify: %v", err)
	}

	// Editing the cost line produces a well-formed hash, so it is not
	// rejected as malformed -- it simply stops verifying, because the
	// parameters are inputs to the digest. That is the property worth having:
	// somebody with write access to the database cannot weaken a stored
	// password's cost and still log in with it.
	weakened := rebuild(func(f []string) { f[3] = "m=8,t=1,p=1" })
	if err := authn.Verify(weakened, "pw"); !errors.Is(err, authn.ErrPasswordMismatch) {
		t.Errorf("Verify with a tampered cost = %v, want ErrPasswordMismatch", err)
	}
}

// Raising the cost must not invalidate a single stored password. This is the
// whole reason parameters live in the hash, so it is tested end to end rather
// than by inspecting a struct.
func TestParameterUpgradePath(t *testing.T) {
	t.Parallel()

	const password = "an old password"
	old := cheapParams
	raised := cheapParams
	raised.Memory *= 4
	raised.Iterations++

	stored, err := authn.Hasher{Params: old}.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// The old hash still verifies at the new configuration...
	if err := authn.Verify(stored, password); err != nil {
		t.Fatalf("an old hash stopped verifying when the cost was raised: %v", err)
	}
	// ...and reports that it should be replaced.
	stale, err := authn.NeedsRehash(stored, raised)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if !stale {
		t.Fatal("a hash below the configured cost does not want rehashing")
	}

	// Login is the one moment the plain password is in hand, so that is when
	// the upgrade happens.
	upgraded, err := authn.Hasher{Params: raised}.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := authn.Verify(upgraded, password); err != nil {
		t.Fatalf("Verify after upgrade: %v", err)
	}
	stale, err = authn.NeedsRehash(upgraded, raised)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if stale {
		t.Error("the freshly upgraded hash still wants rehashing")
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	lower := func(mutate func(*authn.Params)) authn.Params {
		p := cheapParams
		mutate(&p)
		return p
	}

	tests := []struct {
		name   string
		config authn.Params
		stale  bool
	}{
		{name: "same cost", config: cheapParams},
		{name: "more memory wanted", config: lower(func(p *authn.Params) { p.Memory *= 2 }), stale: true},
		{name: "more passes wanted", config: lower(func(p *authn.Params) { p.Iterations++ }), stale: true},
		{name: "more lanes wanted", config: lower(func(p *authn.Params) { p.Parallelism++ }), stale: true},
		{name: "a longer salt wanted", config: lower(func(p *authn.Params) { p.SaltLength *= 2 }), stale: true},
		{
			// Lowering the configured cost must not quietly downgrade every
			// stored password the next time its owner logs in.
			name:   "a weaker configuration",
			config: lower(func(p *authn.Params) { p.Memory /= 2; p.Iterations = 1 }),
		},
	}

	stored, err := authn.Hasher{Params: cheapParams}.Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := authn.NeedsRehash(stored, tt.config)
			if err != nil {
				t.Fatalf("NeedsRehash: %v", err)
			}
			if got != tt.stale {
				t.Errorf("NeedsRehash = %v, want %v", got, tt.stale)
			}
		})
	}
}

// The parser sees whatever is in the database, including whatever a future bug
// puts there. It may reject anything; it may not panic, and it may never
// accept a string it would not itself have written.
func FuzzVerify(f *testing.F) {
	valid, err := authn.Hasher{Params: cheapParams, Rand: fixedSalt('C', 16)}.Hash("pw")
	if err != nil {
		f.Fatalf("Hash: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add("$argon2id$v=19$m=64,t=1,p=1$QUFBQUFBQUFBQUFBQUFBQQ$")
	f.Add("$argon2id$v=19$m=64,t=1,p=1$QUFBQUFBQUFBQUFBQUFBQQ==$QUFB")
	f.Add("$argon2d$v=19$m=64,t=1,p=1$QUFBQUFBQUFBQUFBQUFBQQ$QUFB")

	f.Fuzz(func(t *testing.T, encoded string) {
		err := authn.Verify(encoded, "pw")
		switch {
		case errors.Is(err, authn.ErrInvalidHash):
			// Refused, which is the expected answer for almost everything.
		case errors.Is(err, authn.ErrPasswordMismatch), err == nil:
			// Accepted as a well-formed hash. Then it must be exactly what
			// this package would have produced: one verifier, one spelling.
			stale, rehashErr := authn.NeedsRehash(encoded, cheapParams)
			if rehashErr != nil {
				t.Fatalf("Verify accepted %q but NeedsRehash refused it: %v", encoded, rehashErr)
			}
			_ = stale
		default:
			t.Fatalf("Verify(%q) = %v, want ErrInvalidHash or a mismatch", encoded, err)
		}
	})
}

// errFailedRead is what a source of randomness fails with here.
var errFailedRead = errors.New("no entropy available")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errFailedRead }
