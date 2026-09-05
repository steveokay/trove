package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/steveokay/trove/internal/reponame"
)

// ErrInvalidTarget reports a target that does not name a scannable artifact.
// Callers assert with errors.Is; no caller matches on message text (section 11).
var ErrInvalidTarget = errors.New("invalid scan target")

// ErrInvalidReport reports a report whose fields contradict each other -- a
// failure carrying findings, a finish before its start, a severity outside the
// enum. It is returned by Report.Validate and by anything that persists one.
var ErrInvalidReport = errors.New("invalid scan report")

// ErrInvalidSeverity reports a severity string outside the closed enum.
var ErrInvalidSeverity = errors.New("invalid severity")

// ErrInvalidStatus reports a status string outside the closed enum.
var ErrInvalidStatus = errors.New("invalid scan status")

// ErrScanFailed reports a scan that produced no answer. Every Scanner wraps its
// operational failures in it, which is what lets the queue tell "this artifact
// has no vulnerabilities" from "we do not know whether this artifact has
// vulnerabilities" without inspecting a vendor's error type. Gating treats the
// second as unscanned and, for a repository with a policy, fails closed
// (ADR 0013).
var ErrScanFailed = errors.New("scan failed")

// ErrDatabaseUnavailable reports a scanner with no usable CVE database: a fresh
// air-gapped install before the first `trove db import` (Q6), or an update that
// left the database unreadable. It is distinct from ErrScanFailed because the
// operator action is different and /readyz reports it separately (ADR 0017).
var ErrDatabaseUnavailable = errors.New("scanner database unavailable")

// Target names the artifact a scan runs against: a repository, and the digest
// of a manifest in it.
//
// Two strings and nothing else, deliberately. A target that carried a store
// handle, a manifest row, or a byte reader would make every consumer of this
// package -- the queue, the rescan pass, the gating evaluator, the fake -- a
// consumer of storage as well, and the point of the seam is that they are not.
// Whichever implementation dereferences the digest is the one that knows how.
type Target struct {
	// Repository is the local repository the manifest lives in. It is trove's
	// own name for it, never an upstream's: a cached proxy artifact is scanned
	// under the repository that cached it (section 4).
	Repository string

	// Digest is the manifest digest, in "algorithm:hex" form.
	Digest string
}

// String renders the target in the canonical "repository@digest" form, which is
// what error messages, audit records, and the fake's scripting key all use.
func (t Target) String() string { return t.Repository + "@" + t.Digest }

// Validate reports whether the target names something scannable.
//
// The repository name is held to the one grammar the whole registry uses
// (internal/reponame), because a scan target reaches a blob path and a metadata
// row. The digest is checked for shape only -- non-empty, one colon, and no
// character that could become a path or a query -- and not for the algorithm
// allowlist: parsing and verifying a digest belongs to the layer that
// dereferences it (ADR 0007, and the same stance internal/meta takes). A second
// copy of the digest grammar here would be a second answer to what a digest is.
func (t Target) Validate() error {
	if err := reponame.Validate(t.Repository); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	if t.Digest == "" {
		return fmt.Errorf("%w: %s has no digest", ErrInvalidTarget, t.Repository)
	}
	algorithm, hex, ok := strings.Cut(t.Digest, ":")
	if !ok || algorithm == "" || hex == "" {
		return fmt.Errorf("%w: digest %q is not in algorithm:hex form", ErrInvalidTarget, t.Digest)
	}
	if strings.ContainsFunc(t.Digest, disallowedInDigest) {
		return fmt.Errorf("%w: digest %q contains a character no digest has", ErrInvalidTarget, t.Digest)
	}
	return nil
}

// disallowedInDigest reports whether r may not appear in a digest. The allowed
// set is the one every registered algorithm and encoding uses; anything else --
// a slash, a dot-dot, a backslash, a space, a NUL -- is refused before it can
// reach a path or a key.
func disallowedInDigest(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	case r == ':', r == '.', r == '-', r == '_', r == '+', r == '=':
		return false
	default:
		return true
	}
}

// DatabaseVersion identifies the vulnerability database a scan was made
// against.
//
// A finding is only interpretable against the data that found it, so this
// travels on every report and into every scan.completed event. It is also what
// the rescan pass compares (S-005): an image that was clean under yesterday's
// database is not a claim about today's.
type DatabaseVersion struct {
	// ID is the database's own version identifier, opaque to trove. Empty means
	// no database is installed.
	ID string

	// UpdatedAt is when the database was built or imported. It is reported to
	// operators -- an air-gapped deployment's staleness is the number they care
	// about (Q6) -- and is never what a rescan decision keys off.
	UpdatedAt time.Time
}

// IsZero reports whether no database is identified.
func (v DatabaseVersion) IsZero() bool { return v == DatabaseVersion{} }

// String renders the identifier, empty when no database is installed.
func (v DatabaseVersion) String() string { return v.ID }

// Changed reports whether v names a different database than other.
//
// Only the ID is compared. Two records of the same database written at
// different times are the same database, and a rescan keyed on the timestamp
// would re-enqueue every manifest in the registry after a restart that merely
// re-read the file.
func (v DatabaseVersion) Changed(other DatabaseVersion) bool { return v.ID != other.ID }

// DatabaseSource says where a database update should come from.
//
// Empty means the upstream the adapter is configured with; a path means a local
// archive. Both exist because air-gapped operation is a v1 requirement and not
// an afterthought (Q6): `trove db import` is the same code path as the
// scheduled update, with the source swapped.
type DatabaseSource struct {
	// ArchivePath is a database archive on local disk. Empty means fetch from
	// the configured remote.
	ArchivePath string
}

// Offline reports whether the source is a local archive, needing no network.
func (s DatabaseSource) Offline() bool { return s.ArchivePath != "" }

// Scanner analyses one artifact and reports what it found, in trove's model
// rather than its own.
//
// The contract, frozen for phase 5:
//
//   - Scan returns a Report with StatusSucceeded and a nil error when it
//     produced an answer. An answer with no findings is a clean artifact, and
//     that is the only thing that may be read as clean.
//   - Scan returns a non-nil error wrapping ErrScanFailed when it did not, and
//     alongside it a Report with StatusFailed describing the attempt, so a
//     caller can record the failure without reconstructing one. A caller that
//     sees an error must never treat the report's empty finding list as clean.
//   - Scan honours context cancellation and returns the context's error.
//   - Name and Version identify the engine; they take no context because they
//     answer from memory. They are recorded on every report, because a finding
//     that nobody can attribute to an engine version is a finding nobody can
//     reproduce.
//   - DatabaseVersion does take a context: the answer comes from the installed
//     database, which an import can replace underneath it.
type Scanner interface {
	// Name is the engine's stable identifier, recorded on every report and
	// emitted in scan.completed.
	Name() string

	// Version is the engine's own version, which the golden corpus pins the
	// adapter's output against (ADR 0017).
	Version() string

	// DatabaseVersion reports the vulnerability database currently installed.
	// It returns ErrDatabaseUnavailable when there is none.
	DatabaseVersion(ctx context.Context) (DatabaseVersion, error)

	// Scan analyses the target and returns a normalised report.
	Scan(ctx context.Context, target Target) (Report, error)
}

// DatabaseUpdater installs a vulnerability database, online or from an archive.
//
// It is separate from Scanner because almost nothing needs it: the queue, the
// rescan pass, and the gating evaluator only scan, and a fake they had to teach
// about database updates would be a fake with untested branches in it. ADR 0017
// sketches the two as one interface; Engine is that interface, and the adapter
// satisfies it. The split is which callers must depend on what, not what an
// implementation provides.
type DatabaseUpdater interface {
	// UpdateDB installs a database from source, replacing whatever is
	// installed. It is expected to be atomic from a reader's point of view: a
	// scan running concurrently uses the old database or the new one, never
	// half of each.
	UpdateDB(ctx context.Context, source DatabaseSource) error
}

// Engine is ADR 0017's full scanner surface: an engine that both scans and
// owns its database lifecycle. `trove db import` and the scheduled update take
// one of these; everything else takes a Scanner.
type Engine interface {
	Scanner
	DatabaseUpdater
}
