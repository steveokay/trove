package scan

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Severity is how bad one finding is, in trove's vocabulary rather than a
// vendor's.
//
// The set is closed and ordered, and the order is load-bearing: ADR 0013's
// `max-severity` threshold is a comparison against it, and so is the worst-
// severity badge the UI shows. Comparison is a method for that reason -- a
// severity ranking that each caller reimplements is a ranking the callers
// eventually disagree about, and the disagreement shows up as an artifact that
// one screen calls blocked and another serves.
type Severity string

// The severities, from least to most severe.
const (
	// SeverityUnknown is a finding whose severity nobody has rated. It exists
	// because the rollup an operator sees has a bucket for it (ADR 0012's
	// SeverityCounts) and because a finding is never dropped for lacking a
	// rating. Adapters map a vendor's "unknown" up to SeverityLow rather than
	// leaving it here (ADR 0017), so a conforming scan does not produce one;
	// data imported from elsewhere still can, and it is still counted.
	SeverityUnknown Severity = "unknown"

	// SeverityLow is a finding worth recording and not worth waking anyone.
	SeverityLow Severity = "low"

	// SeverityMedium is the default threshold operators reach for first.
	SeverityMedium Severity = "medium"

	// SeverityHigh is a finding most gating policies block on.
	SeverityHigh Severity = "high"

	// SeverityCritical is the top of the scale.
	SeverityCritical Severity = "critical"
)

// severities is the closed set in ascending order. Rank is the index, so the
// order documented above is the order compared, with no second table to drift
// from it.
var severities = []Severity{
	SeverityUnknown,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// Severities returns the closed severity set, least severe first. Callers that
// must handle every severity -- the rollup, the policy validator, the UI's
// filter list -- enumerate it rather than repeating it.
func Severities() []Severity { return slices.Clone(severities) }

// Valid reports whether s is in the closed set.
func (s Severity) Valid() bool { return slices.Contains(severities, s) }

// String returns the stored and displayed name.
func (s Severity) String() string { return string(s) }

// rank orders the severity. An invalid severity ranks below every valid one, so
// comparison is total and no caller can be surprised by a panic; Valid is the
// check that catches the mistake.
func (s Severity) rank() int { return slices.Index(severities, s) }

// Compare orders two severities: negative when s is less severe than other,
// zero when they are equal, positive when s is worse. It has the signature the
// standard library's cmp functions take, so sorting findings is one line.
func (s Severity) Compare(other Severity) int { return s.rank() - other.rank() }

// AtLeast reports whether s is at least as severe as other. It is the shape a
// gating threshold reads in: a finding blocks when it is AtLeast the policy's
// `max-severity` bound (ADR 0013).
func (s Severity) AtLeast(other Severity) bool { return s.Compare(other) >= 0 }

// ParseSeverity reads a stored or configured severity, tolerating case and
// surrounding space because it parses operator-written policy as well as
// database columns. Anything outside the closed set is an error, never a
// silent SeverityUnknown: a policy that says `max-severity: hihg` must be
// refused at load, not quietly loosened to nothing.
func ParseSeverity(s string) (Severity, error) {
	candidate := Severity(strings.ToLower(strings.TrimSpace(s)))
	if !candidate.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidSeverity, s)
	}
	return candidate, nil
}

// Status says whether a scan produced an answer.
//
// The distinction is the whole reason this is not a boolean on the finding
// list: an empty finding list means "clean" under StatusSucceeded and means
// nothing at all under StatusFailed, and a gate that cannot tell them apart
// opens exactly when the scanner is broken (ADR 0013's fail-closed rule).
type Status string

// The scan statuses.
const (
	// StatusSucceeded is a scan that ran to completion. Its findings are the
	// complete answer, and no findings means the artifact is clean.
	StatusSucceeded Status = "succeeded"

	// StatusFailed is a scan that produced no answer. Its findings are empty
	// and must never be read as clean; for a repository with a gating policy
	// the artifact counts as unscanned.
	StatusFailed Status = "failed"
)

// statuses is the closed set, in the order Statuses reports it.
var statuses = []Status{StatusSucceeded, StatusFailed}

// Statuses returns the closed status set.
func Statuses() []Status { return slices.Clone(statuses) }

// Valid reports whether s is in the closed set.
func (s Status) Valid() bool { return slices.Contains(statuses, s) }

// String returns the stored name.
func (s Status) String() string { return string(s) }

// ParseStatus reads a stored status. Anything outside the set is an error.
func ParseStatus(s string) (Status, error) {
	candidate := Status(strings.ToLower(strings.TrimSpace(s)))
	if !candidate.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidStatus, s)
	}
	return candidate, nil
}

// Finding is one vulnerability in one package, in trove's model.
//
// The fields are exactly ADR 0006's `findings` columns, so what a scan produces
// and what the database stores do not need a translation nobody maintains. The
// vendor's own record -- its JSON, its identifiers, its extra fields -- is
// discarded once an adapter has built one of these (section 6): it is not the
// system of record, and anything that must survive belongs in a column here.
type Finding struct {
	// CVE is the advisory identifier: a CVE number, or another feed's
	// identifier (GHSA, ALAS) when that is all the advisory has.
	CVE string

	// Package is the affected package's name in its ecosystem.
	Package string

	// InstalledVersion is the version the artifact actually contains.
	InstalledVersion string

	// FixedVersion is the first version that resolves the advisory, empty when
	// no fix is published. Empty is a real answer and a common one: "twelve
	// criticals" and "twelve criticals, none fixable" call for different
	// responses, which is why ADR 0013 lets a policy narrow to fixable findings.
	FixedVersion string

	// Severity is the finding's rating in trove's enum.
	Severity Severity

	// Source names where the advisory came from: the OS or language ecosystem
	// the package belongs to ("alpine", "debian", "npm", "go").
	Source string
}

// Fixable reports whether a fixed version is known. It is the split ADR 0013's
// `fixable-only` gates on and the one the rollup counts.
func (f Finding) Fixable() bool { return f.FixedVersion != "" }

// Validate reports whether the finding is complete enough to store.
func (f Finding) Validate() error {
	switch {
	case f.CVE == "":
		return fmt.Errorf("%w: a finding has no advisory identifier", ErrInvalidReport)
	case f.Package == "":
		return fmt.Errorf("%w: finding %s names no package", ErrInvalidReport, f.CVE)
	case f.InstalledVersion == "":
		return fmt.Errorf("%w: finding %s on %s has no installed version", ErrInvalidReport, f.CVE, f.Package)
	case !f.Severity.Valid():
		return fmt.Errorf("%w: finding %s has severity %q", ErrInvalidReport, f.CVE, f.Severity)
	default:
		return nil
	}
}

// Rollup is a set of findings counted by severity, with the fixable subset
// split out.
//
// The fields and their JSON names are ADR 0012's SeverityCounts, field for
// field, because this is what a scan.completed and a scan.regressed payload
// carry and what ADR 0013's policies evaluate. One shape, not two: a test in
// this package compares the two structs by reflection and fails if either side
// grows a field the other does not have.
type Rollup struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`

	// Fixable is how many of the counted findings have a published fix. It cuts
	// across the severity buckets rather than adding to them, so it is never
	// part of Total.
	Fixable int `json:"fixable"`
}

// Count returns the number of findings at one severity, and zero for a severity
// outside the enum.
func (r Rollup) Count(s Severity) int {
	switch s {
	case SeverityCritical:
		return r.Critical
	case SeverityHigh:
		return r.High
	case SeverityMedium:
		return r.Medium
	case SeverityLow:
		return r.Low
	case SeverityUnknown:
		return r.Unknown
	default:
		return 0
	}
}

// Total is how many findings the rollup counts, across every severity. Fixable
// is a subset of these and is not added in.
func (r Rollup) Total() int {
	return r.Critical + r.High + r.Medium + r.Low + r.Unknown
}

// Empty reports whether nothing was counted.
func (r Rollup) Empty() bool { return r.Total() == 0 }

// Worst returns the most severe non-empty bucket. The second result is false
// when the rollup is empty, which is the case a caller must handle rather than
// receive a zero value for: "no findings" is not a severity, and a gate that
// compared one against a threshold would be comparing against a value trove
// never assigned.
func (r Rollup) Worst() (Severity, bool) {
	for i := len(severities) - 1; i >= 0; i-- {
		if r.Count(severities[i]) > 0 {
			return severities[i], true
		}
	}
	return "", false
}

// Add counts one finding into a copy of the rollup. A finding whose severity is
// outside the enum is not counted in any bucket -- Report.Validate is what
// refuses it, and silently inventing a bucket for it here would hide that.
func (r Rollup) Add(f Finding) Rollup {
	switch f.Severity {
	case SeverityCritical:
		r.Critical++
	case SeverityHigh:
		r.High++
	case SeverityMedium:
		r.Medium++
	case SeverityLow:
		r.Low++
	case SeverityUnknown:
		r.Unknown++
	default:
		return r
	}
	if f.Fixable() {
		r.Fixable++
	}
	return r
}

// Merge adds another rollup into a copy of this one. It is how a per-repository
// or per-index total is built from its parts (S-006) without re-walking every
// finding.
func (r Rollup) Merge(other Rollup) Rollup {
	r.Critical += other.Critical
	r.High += other.High
	r.Medium += other.Medium
	r.Low += other.Low
	r.Unknown += other.Unknown
	r.Fixable += other.Fixable
	return r
}

// Report is the result of one scan, in trove's model: what ADR 0006's `scans`
// row and its `findings` rows hold, and the only form in which a scan result
// enters the rest of the system.
type Report struct {
	// Target is what was scanned.
	Target Target

	// Scanner and ScannerVersion identify the engine that produced the report.
	Scanner        string
	ScannerVersion string

	// Database is the vulnerability database the scan was made against.
	Database DatabaseVersion

	// Status says whether the scan produced an answer at all.
	Status Status

	// Error is why it did not, empty unless Status is StatusFailed. It is a
	// message for an operator, not a value to branch on: callers branch on
	// Status, and on the error Scan returned alongside the report.
	Error string

	// StartedAt and FinishedAt bound the scan. They come from an injected
	// clock; nothing in this package reads the wall clock.
	StartedAt  time.Time
	FinishedAt time.Time

	// Findings is what was found, empty for a clean artifact and always empty
	// for a failure.
	Findings []Finding
}

// Succeeded reports whether the scan produced an answer.
func (r Report) Succeeded() bool { return r.Status == StatusSucceeded }

// Clean reports whether the scan produced an answer and that answer was no
// findings. It is deliberately the only way to ask: `len(Findings) == 0` is
// true of a failed scan too, and that is the shape of a gate that opens when
// the scanner breaks.
func (r Report) Clean() bool { return r.Succeeded() && len(r.Findings) == 0 }

// Duration is how long the scan took.
func (r Report) Duration() time.Duration { return r.FinishedAt.Sub(r.StartedAt) }

// Age is how old the report is at now. A report finished in the future -- a
// clock that moved backwards between the scan and the question -- has age zero
// rather than a negative one, so a staleness comparison cannot be defeated by
// skew.
func (r Report) Age(now time.Time) time.Duration {
	age := now.Sub(r.FinishedAt)
	if age < 0 {
		return 0
	}
	return age
}

// Stale reports whether the report is older than maxAge at now, which is
// ADR 0013's `scan-stale` condition. A non-positive maxAge means the policy
// sets no age bound and nothing is stale.
func (r Report) Stale(now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 {
		return false
	}
	return r.Age(now) > maxAge
}

// Rollup counts every finding in the report. A failed report rolls up empty,
// which is correct and is also why Status must be consulted first: an empty
// rollup means "nothing found" only for a report that found things.
func (r Report) Rollup() Rollup { return rollup(r.Findings, false) }

// FixableRollup counts only the findings with a published fix. It is the input
// ADR 0013's `fixable-only: true` evaluates, kept as a rollup of the same type
// so a policy picks one or the other and the comparison afterwards is identical.
func (r Report) FixableRollup() Rollup { return rollup(r.Findings, true) }

// rollup counts findings, optionally only the fixable ones.
func rollup(findings []Finding, fixableOnly bool) Rollup {
	var out Rollup
	for _, f := range findings {
		if fixableOnly && !f.Fixable() {
			continue
		}
		out = out.Add(f)
	}
	return out
}

// Worst returns the most severe finding's severity, with false when there are
// none.
func (r Report) Worst() (Severity, bool) { return r.Rollup().Worst() }

// Failed returns a copy of the report marked as a failure: the status set, the
// cause recorded, and the findings cleared.
//
// Clearing is the point. A scanner that got halfway and then lost its database
// holds a partial finding list, and a partial list stored as a result is a
// clean bill of health for everything it did not reach.
func (r Report) Failed(cause error) Report {
	r.Status = StatusFailed
	r.Findings = nil
	if cause == nil {
		r.Error = ErrScanFailed.Error()
		return r
	}
	r.Error = cause.Error()
	return r
}

// Validate reports whether the report is internally consistent. It is what
// anything persisting a report calls, so a contradiction is refused at the
// boundary rather than stored and puzzled over later.
func (r Report) Validate() error {
	if err := r.Target.Validate(); err != nil {
		return err
	}
	switch {
	case r.Scanner == "":
		return fmt.Errorf("%w: %s names no scanner", ErrInvalidReport, r.Target)
	case !r.Status.Valid():
		return fmt.Errorf("%w: %s has status %q", ErrInvalidReport, r.Target, r.Status)
	case r.StartedAt.IsZero():
		return fmt.Errorf("%w: %s has no start time", ErrInvalidReport, r.Target)
	case r.FinishedAt.IsZero():
		return fmt.Errorf("%w: %s has no finish time", ErrInvalidReport, r.Target)
	case r.FinishedAt.Before(r.StartedAt):
		return fmt.Errorf("%w: %s finished before it started", ErrInvalidReport, r.Target)
	}
	if r.Status == StatusFailed {
		switch {
		case r.Error == "":
			return fmt.Errorf("%w: %s failed without a reason", ErrInvalidReport, r.Target)
		case len(r.Findings) > 0:
			return fmt.Errorf("%w: %s failed but carries %d findings", ErrInvalidReport, r.Target, len(r.Findings))
		}
		return nil
	}
	if r.Error != "" {
		return fmt.Errorf("%w: %s succeeded but carries the error %q", ErrInvalidReport, r.Target, r.Error)
	}
	for _, f := range r.Findings {
		if err := f.Validate(); err != nil {
			return err
		}
	}
	return nil
}
