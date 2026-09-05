// Package scan is the seam between trove and whatever finds vulnerabilities
// for it: the Scanner interface, the normalised report every scanner must
// produce, and (from S-003) the queue that runs them.
//
// The seam exists because of one rule (CLAUDE.md section 6, ADR 0017): a
// vendor's output is never the system of record. Exactly one package --
// internal/scan/trivy -- may name the vendor, and an import-boundary rule in
// internal/archtest proves it. Everything else in the registry reads the types
// defined here, so swapping the engine in v1.x cannot ripple past the adapter,
// and a Report loaded from the database ten releases later still means what it
// meant when it was written.
//
// Three consequences shape the types:
//
//   - Severity is a closed, ordered enum with comparison as a method. ADR 0013
//     gates on "worse than this threshold", and a threshold comparison every
//     caller reimplements is a threshold every caller eventually disagrees
//     about.
//   - A report distinguishes "scanned, found nothing" from "could not scan".
//     Gating treats those as opposites -- one is clean, the other fails closed
//     -- so a failure that decays into an empty finding list is a gate that
//     opens when the scanner breaks.
//   - Nothing here does I/O or reads a clock. Rollups, staleness, and worst-
//     severity are pure functions of a report plus an injected now, which is
//     what lets the policy engine evaluate them without a scanner present.
package scan
