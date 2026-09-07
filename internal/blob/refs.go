package blob

// CachedRef and HostedRef are the two ways a digest can name bytes this
// registry holds, distinguished at the type level because one of them is
// recoverable and the other is not (ADR 0009 wall 1).
//
// They exist for exactly one purpose: a function whose job is deletion must say
// in its signature which kind of bytes it deletes, so that handing an eviction
// path a hosted digest is a compile error rather than an incident. Everything
// that merely reads or writes content takes a plain Digest -- adding a
// distinction to paths where both answers are correct would be noise, and noise
// is what makes a real distinction easy to miss.
//
// The wrapper is a struct with an unexported field rather than a named Digest
// type, so the conversion `CachedRef(hosted)` does not exist. Crossing from one
// to the other requires naming the digest and building the other ref from it,
// which is a visible, greppable act that a reviewer can ask about. The zero
// value carries an empty digest, which every store rejects.
//
// ADR 0009 deferred this pair to the first deleting caller, on the argument
// that a newtype nothing consumes is a convention rather than a wall. The
// caller is internal/cache's eviction (C-013); internal/gc's sweep (P-007) is
// the other half and takes HostedRef.

// CachedRef names bytes in the proxy cache: content fetched from an upstream
// that can always be fetched again. Deleting it costs a refill.
type CachedRef struct{ digest Digest }

// HostedRef names bytes this registry is the origin of. Deleting it is
// irreversible: nothing upstream can supply them again.
type HostedRef struct{ digest Digest }

// NewCachedRef validates a digest and wraps it as cache content. The
// validation is here rather than at the delete because a ref that exists has
// been checked, which is the same contract Digest itself carries.
func NewCachedRef(digest Digest) (CachedRef, error) {
	if err := digest.Validate(); err != nil {
		return CachedRef{}, err
	}
	return CachedRef{digest: digest}, nil
}

// NewHostedRef validates a digest and wraps it as hosted content.
func NewHostedRef(digest Digest) (HostedRef, error) {
	if err := digest.Validate(); err != nil {
		return HostedRef{}, err
	}
	return HostedRef{digest: digest}, nil
}

// Digest returns the digest the ref names. It is what a store method is
// called with, at the one point where the kind has already been decided.
func (r CachedRef) Digest() Digest { return r.digest }

// Digest returns the digest the ref names.
func (r HostedRef) Digest() Digest { return r.digest }

// String renders the ref as its digest, so a log line reads the same as one
// written from a plain Digest.
func (r CachedRef) String() string { return r.digest.String() }

// String renders the ref as its digest.
func (r HostedRef) String() string { return r.digest.String() }
