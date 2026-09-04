package event

import (
	"crypto/rand"
	"io"
	"sync"
	"time"
)

// IDLength is how many characters a ULID renders to. Every event id is exactly
// this long, which is what lets a cursor be compared as a plain string.
const IDLength = 26

// crockford is Crockford's base32 alphabet: the digits and the upper-case
// letters, minus I, L, O and U. Excluding those is the point of it -- an
// operator copying an event id out of a log cannot turn a 1 into an I.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// IDSource mints ULIDs: a 48-bit millisecond timestamp followed by 80 bits of
// randomness, rendered as 26 base32 characters.
//
// The format is chosen for one property the registry depends on everywhere:
// lexical order is chronological order. That is what makes the outbox's primary
// key its sort key, what makes a page cursor the last id of the page, and what
// lets an operator eyeball a log and know which of two events came first.
//
// Ids minted in the same millisecond stay ordered. The randomness is
// incremented rather than redrawn, which is the standard monotonic ULID rule:
// two events published in the same tick still sort in the order they were
// published, so a push and the scan it triggered never read as simultaneous.
//
// A source is safe for concurrent use. The entropy reader is injectable so a
// test gets the same ids every run (§9); production leaves it nil and gets
// crypto/rand.
type IDSource struct {
	mu      sync.Mutex
	entropy io.Reader
	lastMS  int64
	last    [10]byte
	started bool
}

// NewIDSource returns a source drawing randomness from entropy. A nil reader
// means crypto/rand.
func NewIDSource(entropy io.Reader) *IDSource {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &IDSource{entropy: entropy}
}

// New returns the ULID for an instant.
//
// It cannot fail. A ULID is an identifier, not a secret: nothing about the
// registry's security rests on it being unpredictable, so a randomness source
// that refuses to answer is met by incrementing the previous value rather than
// by handing the caller an error it has no useful response to. This is the same
// call the request-id middleware makes, for the same reason.
func (s *IDSource) New(at time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ms := at.UTC().UnixMilli()
	switch {
	case s.started && ms == s.lastMS:
		// The same tick: keep the ordering by stepping the entropy. An
		// overflow -- 2^80 ids inside one millisecond -- cannot happen, but if
		// the reader were the thing that had failed it would look like this,
		// so it falls through to a fresh draw rather than repeating a value.
		if !increment(s.last[:]) {
			s.draw()
		}
	case s.started && ms < s.lastMS:
		// Time went backwards: a clock correction, or a caller stamping an
		// event with when it happened rather than with now. Ids must stay
		// increasing regardless, so the earlier instant is not honoured.
		ms = s.lastMS
		if !increment(s.last[:]) {
			s.draw()
		}
	default:
		s.draw()
	}
	s.lastMS = ms
	s.started = true

	var raw [16]byte
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	copy(raw[6:], s.last[:])
	return encodeCrockford(raw)
}

// draw refills the entropy. A reader that fails leaves the previous value and
// steps it, which keeps ids unique and ordered without pretending to be random.
func (s *IDSource) draw() {
	if _, err := io.ReadFull(s.entropy, s.last[:]); err != nil {
		increment(s.last[:])
	}
}

// increment adds one to a big-endian counter, reporting false if it wrapped.
func increment(b []byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return true
		}
	}
	return false
}

// encodeCrockford renders 128 bits as 26 base32 digits, most significant first.
// The leading digit carries only three bits: 26 digits hold 130, and the value
// is left-padded with two zeroes, which is what the ULID specification says.
func encodeCrockford(raw [16]byte) string {
	out := make([]byte, IDLength)
	for i := range out {
		shift := 5 * (IDLength - 1 - i)
		var digit uint
		for bit := 4; bit >= 0; bit-- {
			digit = digit<<1 | bitAt(raw, shift+bit)
		}
		out[i] = crockford[digit]
	}
	return string(out)
}

// bitAt returns bit n of the 128-bit big-endian value, counting from the least
// significant. Bits past the end are the padding, and are zero.
func bitAt(raw [16]byte, n int) uint {
	if n >= 128 {
		return 0
	}
	return uint(raw[15-n/8]>>(n%8)) & 1
}
