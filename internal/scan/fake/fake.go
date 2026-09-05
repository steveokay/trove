// Package fake is the scriptable scanner every non-adapter test in phase 5
// runs against, and the one ADR 0013's gating tests run against too.
//
// It is built around one rule: the fake never invents an outcome. A digest
// nobody scripted is answered with ErrNotScripted, not with a clean report --
// because a gating test that passes because the fake said "clean" by default is
// a test that would pass with the gate deleted, and that is precisely the
// confidence-for-a-number trade CLAUDE.md section 9 forbids. The same rule
// applies to database updates. A test that genuinely wants a blanket answer
// says so with Options.Fallback, which is a deliberate line in the test rather
// than a default nobody notices.
//
// Nothing here sleeps. Latency is recorded in the report -- so a test can
// assert what a scan claimed to cost -- and, for the tests that need a scan to
// actually still be running while they look at something else, delegated to an
// injectable Options.Wait. Time comes from an injectable clock whose default is
// deterministic, so two runs of the same test produce the same timestamps.
package fake

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/steveokay/trove/internal/scan"
)

// ErrNotScripted reports a call the test did not script. It deliberately does
// not wrap scan.ErrScanFailed: a scanner that broke and a test that forgot a
// line are different problems, and a test asserting on the first must not be
// satisfied by the second.
var ErrNotScripted = errors.New("fake scanner: nothing scripted")

// ErrInvalidScript reports a scripted result that no real scanner could
// produce -- a finding with no CVE, a severity outside the enum. The fake
// refuses it rather than handing back a report the adapter's contract forbids,
// because a downstream test tuned against an impossible report is tuned against
// nothing.
var ErrInvalidScript = errors.New("fake scanner: invalid script")

// epoch is the default clock's zero. It is a fixed instant so that a test that
// does not care about time still gets the same timestamps on every run.
var epoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// tick is how far the default clock advances between scans, so two scans of
// the same digest do not claim to have started at the same instant.
const tick = time.Millisecond

// Result is what the fake answers for one scan.
//
// Findings and Err are exclusive by construction: a Result with an Err is a
// failure and its findings are never returned, which is the same rule
// scan.Report.Failed enforces on real scanners.
type Result struct {
	// Findings are what a successful scan reports. Empty means the artifact
	// scanned clean.
	Findings []scan.Finding

	// Err, when set, injects a failure: Scan returns it wrapped in
	// scan.ErrScanFailed, together with a report in scan.StatusFailed.
	Err error

	// Latency is how long the scan claims to have taken. It sets the report's
	// finish time and, when Options.Wait is set, is what the wait is asked for.
	Latency time.Duration
}

// Options configures a fake scanner. The zero value is usable: it yields a
// scanner named "fake" with a deterministic clock and nothing scripted.
type Options struct {
	// Name and Version identify the engine on every report. They default to
	// "fake" and "0.0.0".
	Name    string
	Version string

	// Database is the database version reported and recorded until an update
	// changes it. It defaults to a fixed non-empty version, because a scanner
	// with no database is a state tests should have to ask for.
	Database scan.DatabaseVersion

	// DatabaseErr, when set, is what DatabaseVersion returns instead of a
	// version -- the air-gapped install before its first import, or a database
	// that went unreadable.
	DatabaseErr error

	// Now is the clock. The default is deterministic and advances by each
	// scan's latency, so successive reports do not overlap.
	Now func() time.Time

	// Wait is how a scan spends its latency. The default does not spend it at
	// all: it returns immediately, which is what keeps unit tests free of
	// sleeps. A test that needs a scan to still be in flight -- strict
	// block-until-scanned (S-009), queue concurrency (S-003) -- supplies one
	// that blocks on a channel it controls.
	Wait func(ctx context.Context, d time.Duration) error

	// Fallback, when set, answers any digest with no script of its own. It
	// exists for tests about volume rather than about findings, such as the
	// queue's backlog benchmark; leaving it nil is the safe default and every
	// test that asserts on gating should.
	Fallback *Result
}

// Call is one recorded Scan.
type Call struct {
	// Target is what was asked for, including targets the fake refused.
	Target scan.Target
	// At is when the scan started, by the fake's clock.
	At time.Time
	// Err is what the scan returned, nil for a successful one.
	Err error
}

// Scanner is a scriptable scan.Engine. It is safe for concurrent use: the
// queue runs workers in parallel under the race detector, and a fake that
// needed a lock held outside it would be a fake that shaped the test.
type Scanner struct {
	name    string
	version string

	wait func(context.Context, time.Duration) error
	now  func() time.Time

	fallback *Result

	mu sync.Mutex
	// elapsed drives the default clock. It is unused when a clock is injected.
	elapsed time.Duration
	// scripts holds the queued results per digest. The last entry repeats.
	scripts map[string][]Result
	// updates holds the queued UpdateDB outcomes. The last entry repeats.
	updates []updateResult
	// database is the currently installed version.
	database scan.DatabaseVersion
	// databaseErr is what DatabaseVersion answers instead of a version.
	databaseErr error

	calls   []Call
	sources []scan.DatabaseSource
}

// updateResult is one scripted UpdateDB outcome.
type updateResult struct {
	version scan.DatabaseVersion
	err     error
}

// Compile-time proof the fake is substitutable for the real thing, in both the
// narrow and the full form.
var (
	_ scan.Scanner = (*Scanner)(nil)
	_ scan.Engine  = (*Scanner)(nil)
)

// New builds a fake scanner.
func New(opts Options) *Scanner {
	s := &Scanner{
		name:        opts.Name,
		version:     opts.Version,
		wait:        opts.Wait,
		now:         opts.Now,
		scripts:     make(map[string][]Result),
		database:    opts.Database,
		databaseErr: opts.DatabaseErr,
	}
	if s.name == "" {
		s.name = "fake"
	}
	if s.version == "" {
		s.version = "0.0.0"
	}
	if s.database.IsZero() && opts.DatabaseErr == nil {
		s.database = scan.DatabaseVersion{ID: "fake-db-1", UpdatedAt: epoch}
	}
	if opts.Fallback != nil {
		fallback := cloneResults([]Result{*opts.Fallback})[0]
		s.fallback = &fallback
	}
	return s
}

// Name reports the engine name.
func (s *Scanner) Name() string { return s.name }

// Version reports the engine version.
func (s *Scanner) Version() string { return s.version }

// DatabaseVersion reports the installed database, or the scripted error.
func (s *Scanner) DatabaseVersion(ctx context.Context) (scan.DatabaseVersion, error) {
	if err := ctx.Err(); err != nil {
		return scan.DatabaseVersion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.databaseErr != nil {
		return scan.DatabaseVersion{}, s.databaseErr
	}
	return s.database, nil
}

// Script queues results for a digest. Calls beyond the last queued result
// repeat it, so a one-result script is a constant answer and a two-result
// script is "clean, then dirty" -- which is the shape S-005's rescan-after-a-
// database-update test needs without having to interleave with the queue.
//
// Scripting the same digest again replaces the queue rather than appending, so
// a test that re-scripts between phases gets what it wrote.
func (s *Scanner) Script(digest string, results ...Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripts[digest] = cloneResults(results)
}

// cloneResults copies a script, findings and all, so that neither the caller's
// slice nor a report already handed out is a way to reach into the script
// afterwards.
func cloneResults(results []Result) []Result {
	out := slices.Clone(results)
	for i := range out {
		out[i].Findings = slices.Clone(out[i].Findings)
	}
	return out
}

// ScriptClean scripts a digest to scan clean.
func (s *Scanner) ScriptClean(digest string) {
	s.Script(digest, Result{})
}

// ScriptFindings scripts a digest to scan with findings.
func (s *Scanner) ScriptFindings(digest string, findings ...scan.Finding) {
	s.Script(digest, Result{Findings: findings})
}

// ScriptFailure scripts a digest to fail with cause.
func (s *Scanner) ScriptFailure(digest string, cause error) {
	s.Script(digest, Result{Err: cause})
}

// ScriptDatabaseUpdate queues one UpdateDB outcome: the version the database
// becomes, or an error that leaves it unchanged. Outcomes are consumed in
// order and the last repeats. An UpdateDB call with nothing queued fails with
// ErrNotScripted, for the same reason an unscripted scan does.
func (s *Scanner) ScriptDatabaseUpdate(version scan.DatabaseVersion, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, updateResult{version: version, err: err})
}

// SetDatabaseVersion installs a database version directly, without an update
// call. It is for arranging a starting state, not for asserting on one.
func (s *Scanner) SetDatabaseVersion(v scan.DatabaseVersion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.database = v
	s.databaseErr = nil
}

// SetDatabaseError makes DatabaseVersion answer with err instead of a version.
// A nil err clears it.
func (s *Scanner) SetDatabaseError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.databaseErr = err
}

// Scan answers from the script.
func (s *Scanner) Scan(ctx context.Context, target scan.Target) (scan.Report, error) {
	if err := ctx.Err(); err != nil {
		return scan.Report{}, err
	}
	if err := target.Validate(); err != nil {
		return scan.Report{}, err
	}

	result, startedAt, ok := s.take(target)
	if !ok {
		err := fmt.Errorf("%w for %s", ErrNotScripted, target)
		report := s.report(target, startedAt, 0).Failed(err)
		s.record(target, startedAt, err)
		return report, err
	}

	if result.Latency > 0 && s.wait != nil {
		if err := s.wait(ctx, result.Latency); err != nil {
			report := s.report(target, startedAt, result.Latency).Failed(err)
			s.record(target, startedAt, err)
			return report, err
		}
	}
	if err := ctx.Err(); err != nil {
		report := s.report(target, startedAt, result.Latency).Failed(err)
		s.record(target, startedAt, err)
		return report, err
	}

	report := s.report(target, startedAt, result.Latency)
	if result.Err != nil {
		err := fmt.Errorf("%w: %w", scan.ErrScanFailed, result.Err)
		s.record(target, startedAt, err)
		return report.Failed(err), err
	}

	report.Status = scan.StatusSucceeded
	report.Findings = slices.Clone(result.Findings)
	if err := report.Validate(); err != nil {
		wrapped := fmt.Errorf("%w for %s: %w", ErrInvalidScript, target, err)
		s.record(target, startedAt, wrapped)
		return report.Failed(wrapped), wrapped
	}
	s.record(target, startedAt, nil)
	return report, nil
}

// UpdateDB applies the next scripted outcome and records the source.
func (s *Scanner) UpdateDB(ctx context.Context, source scan.DatabaseSource) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, source)
	if len(s.updates) == 0 {
		return fmt.Errorf("%w for a database update", ErrNotScripted)
	}
	next := s.updates[0]
	if len(s.updates) > 1 {
		s.updates = s.updates[1:]
	}
	if next.err != nil {
		return next.err
	}
	s.database = next.version
	s.databaseErr = nil
	return nil
}

// take consumes the next scripted result for a target and stamps the scan's
// start time. The third result is false when nothing is scripted and no
// fallback is set.
func (s *Scanner) take(target scan.Target) (Result, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	startedAt := s.stamp()

	queued, ok := s.scripts[target.Digest]
	if !ok || len(queued) == 0 {
		if s.fallback == nil {
			s.advance(0)
			return Result{}, startedAt, false
		}
		s.advance(s.fallback.Latency)
		return *s.fallback, startedAt, true
	}
	next := queued[0]
	if len(queued) > 1 {
		s.scripts[target.Digest] = queued[1:]
	}
	s.advance(next.Latency)
	return next, startedAt, true
}

// stamp reads the clock. The caller holds the lock.
func (s *Scanner) stamp() time.Time {
	if s.now != nil {
		return s.now()
	}
	return epoch.Add(s.elapsed)
}

// advance moves the default clock past a scan. It is a no-op when a clock is
// injected, because then the test owns time. The caller holds the lock.
func (s *Scanner) advance(latency time.Duration) {
	if s.now != nil {
		return
	}
	s.elapsed += latency + tick
}

// report builds the skeleton every answer shares.
func (s *Scanner) report(target scan.Target, startedAt time.Time, latency time.Duration) scan.Report {
	s.mu.Lock()
	database := s.database
	s.mu.Unlock()

	return scan.Report{
		Target:         target,
		Scanner:        s.name,
		ScannerVersion: s.version,
		Database:       database,
		StartedAt:      startedAt,
		FinishedAt:     startedAt.Add(latency),
	}
}

// record appends to the call log.
func (s *Scanner) record(target scan.Target, at time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, Call{Target: target, At: at, Err: err})
}

// Calls returns every recorded scan, in order, including the ones the fake
// refused: what a caller asked for is as interesting as what it got.
func (s *Scanner) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// Targets returns the targets of every recorded scan, in order.
func (s *Scanner) Targets() []scan.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]scan.Target, 0, len(s.calls))
	for _, c := range s.calls {
		out = append(out, c.Target)
	}
	return out
}

// ScanCount reports how many times a digest was scanned, in any repository.
// It is what a single-flight or a no-double-scan assertion reads.
func (s *Scanner) ScanCount(digest string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, c := range s.calls {
		if c.Target.Digest == digest {
			count++
		}
	}
	return count
}

// DatabaseUpdates returns the sources every UpdateDB call was given, in order,
// including the ones that failed.
func (s *Scanner) DatabaseUpdates() []scan.DatabaseSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sources)
}

// ResetCalls clears the call log, leaving the scripts and the database alone.
// It is for a test with a setup phase whose calls would otherwise be counted by
// the assertions about the phase after it.
func (s *Scanner) ResetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
	s.sources = nil
}
