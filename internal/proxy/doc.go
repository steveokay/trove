// Package proxy implements upstream clients and pull-through cache semantics:
// leases, revalidation, and backoff.
//
// The upstream client (client.go) is the seam every other part of the proxy
// subsystem is built on, and it is deliberately dumb: it speaks the
// distribution API to one configured upstream, verifies what comes back, and
// classifies failures. It caches nothing, retries nothing, and sleeps never.
// Leases (C-005), single-flight (C-006), negative caching (C-007), degraded
// mode (C-008), and backoff (C-009) are all callers, which is what keeps each
// of them a pure decision over an injected clock rather than a thing that has
// to be tested against a network.
//
// Three rules shape the client (§4, ADR 0008):
//
// Digests are verified here, by internal/blob, on everything that arrives. A
// manifest fetched by digest that does not hash to it is discarded, not
// returned; a blob streams through blob.VerifiedReader so a corrupt body ends
// the stream one byte short instead of arriving clean. Verification is never
// reimplemented in this package -- an upstream is exactly the untrusted source
// that ADR 0007's helpers exist for.
//
// Tags are leases, not content. ResolveTag revalidates conditionally, so an
// unchanged tag costs no bandwidth, and it reports the digest it computed
// itself rather than the one the upstream claimed.
//
// A Location header and a WWW-Authenticate realm are attacker-influenced
// input. Both go through the same RedirectPolicy (redirect.go) before the
// client sends anything to them, and credentials are never carried outside the
// upstream's own host family.
package proxy
