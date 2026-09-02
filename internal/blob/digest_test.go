package blob_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/blob"
)

// The parser is the traversal gate: every path and every object key in the
// storage layer is built from something that came through it, so what it
// accepts is a security boundary rather than a convenience.
func TestParseDigest(t *testing.T) {
	t.Parallel()

	const (
		sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		sha512Hex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
			"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	)

	valid := []struct {
		name   string
		input  string
		algo   blob.Algorithm
		hexOut string
	}{
		{"sha256", "sha256:" + sha256Hex, blob.SHA256, sha256Hex},
		{"sha512", "sha512:" + sha512Hex, blob.SHA512, sha512Hex},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			digest, err := blob.ParseDigest(tt.input)
			if err != nil {
				t.Fatalf("ParseDigest(%q): %v", tt.input, err)
			}
			if string(digest) != tt.input {
				t.Errorf("digest = %q, want it unchanged", digest)
			}
			if digest.Algorithm() != tt.algo {
				t.Errorf("algorithm = %q, want %q", digest.Algorithm(), tt.algo)
			}
			if digest.Hex() != tt.hexOut {
				t.Errorf("hex = %q, want %q", digest.Hex(), tt.hexOut)
			}
			if digest.String() != tt.input {
				t.Errorf("String() = %q, want %q", digest, tt.input)
			}
			if err := digest.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}

	invalid := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"no separator", "sha256"},
		{"no hex", "sha256:"},
		{"no algorithm", ":" + sha256Hex},
		{"unknown algorithm", "md5:" + strings.Repeat("a", 32)},
		{"algorithm case", "SHA256:" + sha256Hex},
		{"too short", "sha256:" + strings.Repeat("a", 63)},
		{"too long", "sha256:" + strings.Repeat("a", 65)},
		{"uppercase hex", "sha256:" + strings.ToUpper(sha256Hex)},
		{"non hex", "sha256:" + strings.Repeat("g", 64)},
		{"sha512 length under sha256", "sha256:" + sha512Hex},
		{"traversal", "sha256:../../../../etc/passwd"},
		{"dot dot", "sha256:.."},
		{"path", "../../etc/passwd"},
		{"separator in hex", "sha256:" + strings.Repeat("a", 63) + "/"},
		{"backslash in hex", "sha256:" + strings.Repeat("a", 63) + `\`},
		{"null in hex", "sha256:" + strings.Repeat("a", 63) + "\x00"},
		{"space in hex", "sha256:" + strings.Repeat("a", 63) + " "},
		{"second separator", "sha256:sha256:" + sha256Hex},
		{"windows device", "sha256:" + strings.Repeat("a", 60) + "/con"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := blob.ParseDigest(tt.input)
			if !errors.Is(err, blob.ErrInvalidDigest) {
				t.Fatalf("ParseDigest(%q) = %v, want ErrInvalidDigest", tt.input, err)
			}

			// The error names what was rejected, which is what makes a
			// rejected pull diagnosable.
			var invalidErr *blob.InvalidDigestError
			if !errors.As(err, &invalidErr) {
				t.Fatalf("error type = %T, want *blob.InvalidDigestError", err)
			}
			if invalidErr.Digest != tt.input {
				t.Errorf("error carries %q, want %q", invalidErr.Digest, tt.input)
			}
			if invalidErr.Reason == "" {
				t.Error("error carries no reason")
			}

			// A Digest can be produced by conversion as well as by parsing, so
			// Validate has to be just as strict.
			if err := blob.Digest(tt.input).Validate(); !errors.Is(err, blob.ErrInvalidDigest) {
				t.Errorf("Digest(%q).Validate() = %v, want ErrInvalidDigest", tt.input, err)
			}
		})
	}
}

// A malformed digest has no algorithm and no hex rather than half of one:
// callers that log those fields must not print a fragment of an attack string
// as though it were meaningful.
func TestMalformedDigestHasNoParts(t *testing.T) {
	t.Parallel()

	malformed := blob.Digest("not-a-digest")
	if got := malformed.Algorithm(); got != "" {
		t.Errorf("Algorithm() = %q, want empty", got)
	}
	if got := malformed.Hex(); got != "" {
		t.Errorf("Hex() = %q, want empty", got)
	}
}

func TestAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algo      blob.Algorithm
		available bool
		hexLength int
	}{
		{blob.SHA256, true, 64},
		{blob.SHA512, true, 128},
		{blob.Algorithm("md5"), false, 0},
		{blob.Algorithm(""), false, 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			t.Parallel()

			if got := tt.algo.Available(); got != tt.available {
				t.Errorf("Available() = %v, want %v", got, tt.available)
			}
			if got := tt.algo.HexLength(); got != tt.hexLength {
				t.Errorf("HexLength() = %d, want %d", got, tt.hexLength)
			}
			h := tt.algo.New()
			if tt.available && h == nil {
				t.Error("New() = nil for an available algorithm")
			}
			if !tt.available && h != nil {
				t.Error("New() returned a hash for an unavailable algorithm")
			}
		})
	}
}

func TestFromBytes(t *testing.T) {
	t.Parallel()

	// Known vectors: the empty digest is the one that shows up in real
	// registries, as an empty config blob.
	tests := []struct {
		algo blob.Algorithm
		data []byte
		want blob.Digest
	}{
		{
			algo: blob.SHA256,
			data: nil,
			want: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			algo: blob.SHA256,
			data: []byte("abc"),
			want: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			algo: blob.SHA512,
			data: []byte("abc"),
			want: "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
				"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		},
	}
	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			t.Parallel()

			got := blob.FromBytes(tt.algo, tt.data)
			if got != tt.want {
				t.Errorf("FromBytes = %s, want %s", got, tt.want)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("a computed digest does not parse: %v", err)
			}
		})
	}
}

func TestFromBytesPanicsOnAnUnavailableAlgorithm(t *testing.T) {
	t.Parallel()

	// Callers pass a constant, so reaching this is a programming error rather
	// than anything an input can cause.
	defer func() {
		if recover() == nil {
			t.Error("FromBytes with an unknown algorithm did not panic")
		}
	}()
	blob.FromBytes(blob.Algorithm("md5"), []byte("x"))
}

// FuzzParseDigest asserts the property the storage layer relies on: anything
// the parser accepts is safe to build a path from. No traversal, no separators,
// no case ambiguity, nothing but an allowlisted algorithm and fixed-length
// lowercase hex.
func FuzzParseDigest(f *testing.F) {
	seeds := []string{
		"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sha512:" + strings.Repeat("f", 128),
		"sha256:../../../../etc/passwd",
		"sha256:",
		"",
		":",
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 64) + ":extra",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		digest, err := blob.ParseDigest(input)
		if err != nil {
			if !errors.Is(err, blob.ErrInvalidDigest) {
				t.Fatalf("ParseDigest(%q) failed with %v, want ErrInvalidDigest", input, err)
			}
			return
		}

		if string(digest) != input {
			t.Fatalf("ParseDigest(%q) returned %q: a digest must not be rewritten", input, digest)
		}

		algorithm, hex, found := strings.Cut(input, ":")
		if !found {
			t.Fatalf("accepted %q with no separator", input)
		}
		algo := blob.Algorithm(algorithm)
		if !algo.Available() {
			t.Fatalf("accepted unavailable algorithm %q", algorithm)
		}
		if len(hex) != algo.HexLength() {
			t.Fatalf("accepted %d hex characters for %s, want %d", len(hex), algo, algo.HexLength())
		}
		for i := 0; i < len(hex); i++ {
			c := hex[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("accepted %q in the hex portion of %q", c, input)
			}
		}
		// The properties above already exclude these, but assert them
		// directly: this is the list a reviewer actually cares about.
		for _, forbidden := range []string{"/", `\`, "..", "\x00", ":", " "} {
			if strings.Contains(hex, forbidden) {
				t.Fatalf("accepted %q containing %q", input, forbidden)
			}
		}
		if err := digest.Validate(); err != nil {
			t.Fatalf("a parsed digest failed Validate: %v", err)
		}
	})
}
