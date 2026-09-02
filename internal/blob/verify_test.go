package blob_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/blob"
)

func TestVerifier(t *testing.T) {
	t.Parallel()

	data := []byte("verified content")
	digest := blob.FromBytes(blob.SHA256, data)

	verifier, err := blob.NewVerifier(digest)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// Written in pieces, because that is how bytes actually arrive.
	for _, chunk := range [][]byte{data[:4], data[4:9], data[9:]} {
		n, err := verifier.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(chunk))
		}
	}

	if verifier.Size() != int64(len(data)) {
		t.Errorf("Size() = %d, want %d", verifier.Size(), len(data))
	}
	if verifier.Digest() != digest {
		t.Errorf("Digest() = %s, want %s", verifier.Digest(), digest)
	}
	if err := verifier.Verify(); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifierRejectsAMismatch(t *testing.T) {
	t.Parallel()

	data := []byte("what arrived")
	claimed := blob.FromBytes(blob.SHA256, []byte("what was promised"))

	verifier, err := blob.NewVerifier(claimed)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verifier.Write(data)

	err = verifier.Verify()
	if !errors.Is(err, blob.ErrDigestMismatch) {
		t.Fatalf("Verify = %v, want ErrDigestMismatch", err)
	}

	var mismatch *blob.MismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error type = %T, want *blob.MismatchError", err)
	}
	if mismatch.Expected != claimed {
		t.Errorf("expected = %s, want %s", mismatch.Expected, claimed)
	}
	if mismatch.Actual != blob.FromBytes(blob.SHA256, data) {
		t.Errorf("actual = %s, want the digest of what arrived", mismatch.Actual)
	}
	// The byte count is what separates a truncated transfer from content that
	// is the right length and wrong.
	if mismatch.Size != int64(len(data)) {
		t.Errorf("size = %d, want %d", mismatch.Size, len(data))
	}
	if !strings.Contains(err.Error(), string(claimed)) {
		t.Errorf("message %q does not name the expected digest", err)
	}
}

func TestNewVerifierRejectsAnInvalidDigest(t *testing.T) {
	t.Parallel()

	// A driver must not start writing under a digest it will not be able to
	// check, so this fails before any bytes move.
	_, err := blob.NewVerifier(blob.Digest("sha256:nope"))
	if !errors.Is(err, blob.ErrInvalidDigest) {
		t.Errorf("NewVerifier = %v, want ErrInvalidDigest", err)
	}
}

func TestCopy(t *testing.T) {
	t.Parallel()

	data := []byte("copied through")
	digest := blob.FromBytes(blob.SHA256, data)

	var dst bytes.Buffer
	n, err := blob.Copy(&dst, bytes.NewReader(data), digest)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if n != int64(len(data)) || !bytes.Equal(dst.Bytes(), data) {
		t.Errorf("Copy wrote %d bytes %q, want %d bytes %q", n, dst.Bytes(), len(data), data)
	}
}

func TestCopyFailures(t *testing.T) {
	t.Parallel()

	data := []byte("honest bytes")
	digest := blob.FromBytes(blob.SHA256, data)
	readFailure := errors.New("connection reset")

	tests := []struct {
		name     string
		src      io.Reader
		expected blob.Digest
		want     error
	}{
		{
			name:     "invalid digest",
			src:      bytes.NewReader(data),
			expected: blob.Digest("not-a-digest"),
			want:     blob.ErrInvalidDigest,
		},
		{
			name:     "mismatch",
			src:      bytes.NewReader([]byte("different bytes")),
			expected: digest,
			want:     blob.ErrDigestMismatch,
		},
		{
			name:     "truncated",
			src:      bytes.NewReader(data[:len(data)-1]),
			expected: digest,
			want:     blob.ErrDigestMismatch,
		},
		{
			name:     "source failure",
			src:      &failingReader{data: data[:3], err: readFailure},
			expected: digest,
			want:     readFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var dst bytes.Buffer
			_, err := blob.Copy(&dst, tt.src, tt.expected)
			if !errors.Is(err, tt.want) {
				t.Errorf("Copy = %v, want %v", err, tt.want)
			}
		})
	}
}

// failingReader yields some bytes and then fails, standing in for a client
// that disconnects mid-transfer.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func (r *failingReader) Close() error { return nil }

// The verified reader runs one byte behind its source. Every buffer size has
// to produce exactly the same bytes, because a caller chooses that size and
// none of them may see a different blob.
func TestVerifiedReaderStreamsExactly(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 1, 2, 3, 15, 16, 17, 1024} {
		data := bytes.Repeat([]byte("abcdefgh"), size)
		digest := blob.FromBytes(blob.SHA256, data)
		desc := blob.Descriptor{Digest: digest, Size: int64(len(data))}

		for _, bufSize := range []int{1, 2, 3, 7, 64, 4096} {
			t.Run(fmt.Sprintf("content=%d/buffer=%d", len(data), bufSize), func(t *testing.T) {
				t.Parallel()

				reader, err := blob.NewVerifiedReader(context.Background(),
					io.NopCloser(bytes.NewReader(data)), desc, nil)
				if err != nil {
					t.Fatalf("NewVerifiedReader: %v", err)
				}

				var got []byte
				buf := make([]byte, bufSize)
				for {
					n, err := reader.Read(buf)
					got = append(got, buf[:n]...)
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatalf("Read: %v", err)
					}
				}
				if !bytes.Equal(got, data) {
					t.Fatalf("read %d bytes, want %d", len(got), len(data))
				}

				// Reading past the end keeps reporting EOF rather than
				// restarting or blocking.
				if n, err := reader.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("Read after EOF = %d, %v; want 0, EOF", n, err)
				}
				if err := reader.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
		}
	}
}

func TestVerifiedReaderDescribesItsBlob(t *testing.T) {
	t.Parallel()

	data := []byte("described")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}

	reader, err := blob.NewVerifiedReader(context.Background(),
		io.NopCloser(bytes.NewReader(data)), desc, nil)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if reader.Descriptor() != desc {
		t.Errorf("Descriptor() = %+v, want %+v", reader.Descriptor(), desc)
	}
	// A zero-length read is a no-op, not an early EOF.
	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = %d, %v; want 0, nil", n, err)
	}
}

// This is the case the held byte exists for. The stored bytes no longer hash
// to the digest they are filed under; the reader must fail the read and stop
// one byte short, so a client that checks the digest itself -- as every OCI
// client does -- sees a failed pull rather than a corrupt layer.
func TestVerifiedReaderFailsShortOnCorruption(t *testing.T) {
	t.Parallel()

	good := []byte("the original content")
	corrupted := []byte("the corrupted conten")
	if len(good) != len(corrupted) {
		t.Fatalf("the test's own fixtures differ in length: %d and %d", len(good), len(corrupted))
	}
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, good), Size: int64(len(good))}

	var (
		hookCalls int
		hookDesc  blob.Descriptor
		hookErr   error
	)
	hook := func(_ context.Context, d blob.Descriptor, err error) {
		hookCalls++
		hookDesc, hookErr = d, err
	}

	reader, err := blob.NewVerifiedReader(context.Background(),
		io.NopCloser(bytes.NewReader(corrupted)), desc, hook)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := io.ReadAll(reader)
	if !errors.Is(err, blob.ErrDigestMismatch) {
		t.Fatalf("read = %v, want ErrDigestMismatch", err)
	}
	if len(got) != len(corrupted)-1 {
		t.Errorf("read %d bytes, want %d: the last byte must be withheld",
			len(got), len(corrupted)-1)
	}
	if !bytes.Equal(got, corrupted[:len(corrupted)-1]) {
		t.Errorf("read %q, want the corrupt bytes minus the last one", got)
	}

	// The hook is what turns a corrupt blob into a quarantine, an event, and
	// an audit record. It fires once, with the blob's identity and the reason.
	if hookCalls != 1 {
		t.Fatalf("corrupt hook called %d times, want 1", hookCalls)
	}
	if hookDesc != desc {
		t.Errorf("hook received %+v, want %+v", hookDesc, desc)
	}
	if !errors.Is(hookErr, blob.ErrDigestMismatch) {
		t.Errorf("hook received %v, want ErrDigestMismatch", hookErr)
	}

	// The failure sticks: a caller that reads again gets the same error rather
	// than an EOF that looks like success.
	if n, err := reader.Read(make([]byte, 8)); n != 0 || !errors.Is(err, blob.ErrDigestMismatch) {
		t.Errorf("Read after a mismatch = %d, %v; want 0, ErrDigestMismatch", n, err)
	}
}

// The caller picks the buffer size, and a one-byte buffer takes a different
// path through the reader than a large one. Every size must withhold the last
// byte, or a client reading byte by byte would get the whole corrupt blob and
// only then an error it might not check.
func TestVerifiedReaderWithholdsTheLastByteAtEverySize(t *testing.T) {
	t.Parallel()

	good := []byte("the original content")
	corrupted := []byte("the corrupted conten")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, good), Size: int64(len(good))}

	for _, bufSize := range []int{1, 2, 3, 19, 20, 21, 512} {
		t.Run(fmt.Sprintf("buffer=%d", bufSize), func(t *testing.T) {
			t.Parallel()

			reader, err := blob.NewVerifiedReader(context.Background(),
				io.NopCloser(bytes.NewReader(corrupted)), desc, nil)
			if err != nil {
				t.Fatalf("NewVerifiedReader: %v", err)
			}
			defer func() { _ = reader.Close() }()

			var (
				got []byte
				buf = make([]byte, bufSize)
			)
			for {
				n, err := reader.Read(buf)
				got = append(got, buf[:n]...)
				if err != nil {
					if !errors.Is(err, blob.ErrDigestMismatch) {
						t.Fatalf("Read = %v, want ErrDigestMismatch", err)
					}
					break
				}
			}
			if len(got) != len(corrupted)-1 {
				t.Errorf("read %d bytes, want %d", len(got), len(corrupted)-1)
			}
		})
	}
}

func TestVerifiedReaderTruncatedSource(t *testing.T) {
	t.Parallel()

	data := []byte("content that gets cut off")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}

	// A short read hashes to something else, so it fails the same way
	// corruption does. This is what a truncated file on disk looks like.
	reader, err := blob.NewVerifiedReader(context.Background(),
		io.NopCloser(bytes.NewReader(data[:10])), desc, nil)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if _, err := io.ReadAll(reader); !errors.Is(err, blob.ErrDigestMismatch) {
		t.Errorf("read of a truncated source = %v, want ErrDigestMismatch", err)
	}
}

func TestVerifiedReaderPropagatesSourceErrors(t *testing.T) {
	t.Parallel()

	data := []byte("interrupted")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}
	failure := errors.New("disk read failed")

	reader, err := blob.NewVerifiedReader(context.Background(),
		&failingReader{data: data[:4], err: failure}, desc, nil)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if _, err := io.ReadAll(reader); !errors.Is(err, failure) {
		t.Errorf("read = %v, want the source's error", err)
	}
	// The error is remembered rather than retried: a half-read blob does not
	// become valid by asking again.
	if _, err := reader.Read(make([]byte, 4)); !errors.Is(err, failure) {
		t.Errorf("Read after a failure = %v, want the source's error", err)
	}
}

// A source is allowed to return (0, nil), and a reader that treated that as
// end of stream would verify a partial blob and call it good.
func TestVerifiedReaderToleratesEmptyReads(t *testing.T) {
	t.Parallel()

	data := []byte("stuttering source")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}

	for _, bufSize := range []int{1, 4, 512} {
		t.Run(fmt.Sprintf("buffer=%d", bufSize), func(t *testing.T) {
			t.Parallel()

			reader, err := blob.NewVerifiedReader(context.Background(),
				&stutteringReader{data: data}, desc, nil)
			if err != nil {
				t.Fatalf("NewVerifiedReader: %v", err)
			}
			defer func() { _ = reader.Close() }()

			var got []byte
			buf := make([]byte, bufSize)
			for {
				n, err := reader.Read(buf)
				got = append(got, buf[:n]...)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
			}
			if !bytes.Equal(got, data) {
				t.Errorf("read %q, want %q", got, data)
			}
		})
	}
}

// stutteringReader hands over one byte at a time and returns (0, nil) between
// each, which io.Reader permits.
type stutteringReader struct {
	data  []byte
	stall bool
}

func (r *stutteringReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if r.stall = !r.stall; !r.stall {
		return 0, nil
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func (r *stutteringReader) Close() error { return nil }

// A one-byte buffer takes its own path through the reader, so a source failure
// has to be reported there too rather than looking like a clean end.
func TestVerifiedReaderPropagatesSourceErrorsByteByByte(t *testing.T) {
	t.Parallel()

	data := []byte("interrupted byte by byte")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}
	failure := errors.New("disk read failed")

	reader, err := blob.NewVerifiedReader(context.Background(),
		&failingReader{data: data[:4], err: failure}, desc, nil)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	buf := make([]byte, 1)
	var readErr error
	for range len(data) + 2 {
		if _, readErr = reader.Read(buf); readErr != nil {
			break
		}
	}
	if !errors.Is(readErr, failure) {
		t.Errorf("Read = %v, want the source's error", readErr)
	}
}

func TestNewVerifiedReaderRejectsAnInvalidDescriptor(t *testing.T) {
	t.Parallel()

	_, err := blob.NewVerifiedReader(context.Background(),
		io.NopCloser(strings.NewReader("x")),
		blob.Descriptor{Digest: "sha256:short", Size: 1}, nil)
	if !errors.Is(err, blob.ErrInvalidDigest) {
		t.Errorf("NewVerifiedReader = %v, want ErrInvalidDigest", err)
	}
}

// A source that returns its last bytes together with io.EOF is legal, and some
// readers do exactly that. The held byte must still come out.
func TestVerifiedReaderHandlesDataWithEOF(t *testing.T) {
	t.Parallel()

	data := []byte("data and EOF together")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}

	reader, err := blob.NewVerifiedReader(context.Background(),
		&eagerEOFReader{data: data}, desc, nil)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %q, want %q", got, data)
	}
}

// eagerEOFReader returns everything it has along with io.EOF in one call.
type eagerEOFReader struct {
	data []byte
}

func (r *eagerEOFReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (r *eagerEOFReader) Close() error { return nil }

func TestVerifiedReaderCloseReachesTheSource(t *testing.T) {
	t.Parallel()

	data := []byte("closed")
	desc := blob.Descriptor{Digest: blob.FromBytes(blob.SHA256, data), Size: int64(len(data))}
	src := &closeTracker{Reader: bytes.NewReader(data)}

	reader, err := blob.NewVerifiedReader(context.Background(), src, desc, nil)
	if err != nil {
		t.Fatalf("NewVerifiedReader: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !src.closed {
		t.Error("closing the verified reader did not close the source: a driver would leak a file handle")
	}
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error {
	c.closed = true
	return nil
}
