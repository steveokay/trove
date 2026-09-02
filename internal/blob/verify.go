package blob

import (
	"context"
	"errors"
	"hash"
	"io"
)

// Verifier hashes bytes as they are written and reports whether they matched
// the digest they were supposed to. Drivers write through it on the way to
// staging, so verification costs one pass rather than a re-read.
type Verifier struct {
	expected Digest
	hash     hash.Hash
	size     int64
}

// NewVerifier returns a Verifier for the expected digest, or an error if the
// digest is not one this package accepts. Validating here means a driver
// cannot start writing under a digest it will not be able to check.
func NewVerifier(expected Digest) (*Verifier, error) {
	if err := expected.Validate(); err != nil {
		return nil, err
	}
	return &Verifier{expected: expected, hash: expected.Algorithm().New()}, nil
}

// Write hashes p. It never fails, which is what makes it safe to place in an
// io.MultiWriter beside the real destination.
func (v *Verifier) Write(p []byte) (int, error) {
	v.hash.Write(p)
	v.size += int64(len(p))
	return len(p), nil
}

// Size is how many bytes have been hashed.
func (v *Verifier) Size() int64 { return v.size }

// Digest is what the bytes actually hashed to.
func (v *Verifier) Digest() Digest { return digestOf(v.expected.Algorithm(), v.hash) }

// Verify reports whether the bytes matched. A truncated stream fails here for
// the same reason corrupt content does -- it hashes to something else -- and
// the error carries the byte count so the two are distinguishable afterwards.
func (v *Verifier) Verify() error {
	if actual := v.Digest(); actual != v.expected {
		return Mismatch(v.expected, actual, v.size)
	}
	return nil
}

// Copy streams src into dst while verifying it against expected. It is what a
// driver's Put is built from: one pass, and an error that leaves the caller to
// discard whatever dst was.
func Copy(dst io.Writer, src io.Reader, expected Digest) (int64, error) {
	verifier, err := NewVerifier(expected)
	if err != nil {
		return 0, err
	}
	written, err := io.Copy(io.MultiWriter(dst, verifier), src)
	if err != nil {
		return written, err
	}
	if err := verifier.Verify(); err != nil {
		return written, err
	}
	return written, nil
}

// verifiedReader streams a blob, hashing as it goes, and withholds the final
// byte until the hash checks out.
//
// Holding a byte back is the whole trick. A client that read every byte and
// then hit an error would have to be careful to discard what it had already
// buffered; a client whose stream ends one byte short fails its own digest
// check, which every OCI client already does. The failure mode is a failed
// pull rather than silent corruption, and it needs no cooperation from the
// client to be safe.
type verifiedReader struct {
	src      io.ReadCloser
	desc     Descriptor
	verifier *Verifier

	held    byte
	hasHeld bool
	done    bool
	err     error

	onCorrupt CorruptHook
	ctx       context.Context
}

// NewVerifiedReader wraps src so that it verifies against desc as it streams.
// onCorrupt may be nil; when it is not, it is called once if the content turns
// out not to match, after which the driver quarantines it.
//
// The context is held for the hook alone: Read does not take one, because
// io.Reader does not, and cancelling a read is the caller closing it.
func NewVerifiedReader(ctx context.Context, src io.ReadCloser, desc Descriptor, onCorrupt CorruptHook) (VerifiedReader, error) {
	verifier, err := NewVerifier(desc.Digest)
	if err != nil {
		return nil, err
	}
	return &verifiedReader{
		src:       src,
		desc:      desc,
		verifier:  verifier,
		onCorrupt: onCorrupt,
		ctx:       ctx,
	}, nil
}

// Descriptor describes the blob being read.
func (r *verifiedReader) Descriptor() Descriptor { return r.desc }

// Read fills p, running one byte behind the underlying stream.
func (r *verifiedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if r.done {
			return 0, r.err
		}

		// The held byte is only safe to emit once more bytes have arrived
		// behind it: until then it may be the blob's last, and the last byte
		// is the one being withheld. So the source is read first, and the held
		// byte goes out in front of whatever came back.
		if r.hasHeld && len(p) == 1 {
			// No room to do both in one buffer. Read the next byte aside, so
			// the held one can be released without waiting for a bigger p.
			var scratch [1]byte
			n, err := r.src.Read(scratch[:])
			if n > 0 {
				_, _ = r.verifier.Write(scratch[:1])
				p[0] = r.held
				r.held = scratch[0]
				return 1, nil
			}
			switch {
			case errors.Is(err, io.EOF):
				return r.finish(p, 0)
			case err != nil:
				r.done, r.err = true, err
				return 0, err
			}
			continue
		}

		offset := 0
		if r.hasHeld {
			offset = 1
		}
		n, err := r.src.Read(p[offset:])

		written := 0
		if n > 0 {
			_, _ = r.verifier.Write(p[offset : offset+n])
			if r.hasHeld {
				// Now known not to be the last byte, so it is owed to the
				// caller and sits immediately before what just arrived.
				p[0] = r.held
				r.hasHeld = false
				written = 1
			}
			// Hold the last byte read: it may or may not be the blob's final
			// one, and there is no way to know until EOF.
			r.held = p[offset+n-1]
			r.hasHeld = true
			written += n - 1
		}

		switch {
		case errors.Is(err, io.EOF):
			return r.finish(p, written)
		case err != nil:
			r.done, r.err = true, err
			return written, err
		case written > 0:
			return written, nil
		}
		// Nothing to hand over yet -- a single-byte read that is now held.
		// Going round again beats returning (0, nil), which some callers read
		// as a stalled stream.
	}
}

// finish verifies at end of stream and decides what the caller sees.
func (r *verifiedReader) finish(p []byte, written int) (int, error) {
	if err := r.verifier.Verify(); err != nil {
		// The held byte is dropped on purpose: the stream ends one byte short,
		// which is what makes the client's own digest check fail rather than
		// leaving it to notice an error it might not check.
		r.done, r.err = true, err
		r.hasHeld = false
		if r.onCorrupt != nil {
			r.onCorrupt(r.ctx, r.desc, err)
		}
		return written, err
	}

	// The content is good, so the byte held back is owed to the caller, and
	// there is always room for it. Read emits the held byte before reading
	// more, and then holds one of what it read, so it accounts for at most
	// len(p)-1 bytes before reaching here: either it started empty and kept
	// one of at most len(p), or it emitted one and kept one of at most
	// len(p)-1.
	if r.hasHeld {
		p[written] = r.held
		r.hasHeld = false
		written++
	}
	r.done, r.err = true, io.EOF
	return written, io.EOF
}

// Close releases the underlying reader.
func (r *verifiedReader) Close() error { return r.src.Close() }
