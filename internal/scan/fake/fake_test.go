package fake_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/scan"
	"github.com/steveokay/trove/internal/scan/fake"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func targetFor(digest string) scan.Target {
	return scan.Target{Repository: "team-a/api", Digest: digest}
}

func finding(cve string, severity scan.Severity, fixed string) scan.Finding {
	return scan.Finding{
		CVE:              cve,
		Package:          "openssl",
		InstalledVersion: "3.0.1",
		FixedVersion:     fixed,
		Severity:         severity,
		Source:           "alpine",
	}
}

// TestUnscriptedDigestIsNotClean is the property the fake exists for. A gating
// test that passed because the fake answered "clean" by default would pass with
// the gate deleted, so an unscripted digest is an explicit refusal.
func TestUnscriptedDigestIsNotClean(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{})

	report, err := s.Scan(t.Context(), targetFor(digestA))
	if !errors.Is(err, fake.ErrNotScripted) {
		t.Fatalf("Scan of an unscripted digest = %v, want ErrNotScripted", err)
	}
	if !strings.Contains(err.Error(), digestA) {
		t.Errorf("the refusal does not name the target: %v", err)
	}
	if report.Clean() {
		t.Fatal("an unscripted digest reported itself as clean")
	}
	if report.Succeeded() {
		t.Error("an unscripted digest produced a succeeded report")
	}
	if err := report.Validate(); err != nil {
		t.Errorf("the refusal's report does not validate: %v", err)
	}

	// It must not read as a scanner failure either: a scanner that broke and a
	// test that forgot a line are different problems.
	if errors.Is(err, scan.ErrScanFailed) {
		t.Error("ErrNotScripted wraps ErrScanFailed; a missing script would look like a broken scanner")
	}

	// The attempt is still recorded: what a caller asked for is as interesting
	// as what it got.
	if got := s.Calls(); len(got) != 1 || got[0].Target != targetFor(digestA) || got[0].Err == nil {
		t.Errorf("Calls() = %+v, want one recorded refusal", got)
	}
}

func TestScriptingAndTheRecorder(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{Name: "scripted", Version: "1.2.3"})
	s.ScriptClean(digestA)
	s.ScriptFindings(digestB, finding("CVE-2026-1", scan.SeverityHigh, "3.0.2"))

	if s.Name() != "scripted" || s.Version() != "1.2.3" {
		t.Errorf("identity = (%q, %q), want (scripted, 1.2.3)", s.Name(), s.Version())
	}

	clean, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !clean.Clean() {
		t.Errorf("a clean script produced %+v", clean)
	}
	if clean.Scanner != "scripted" || clean.ScannerVersion != "1.2.3" {
		t.Errorf("the report does not carry the engine identity: %+v", clean)
	}
	if clean.Target != targetFor(digestA) {
		t.Errorf("the report names %s, want %s", clean.Target, targetFor(digestA))
	}
	if err := clean.Validate(); err != nil {
		t.Errorf("a scripted report does not validate: %v", err)
	}

	dirty, err := s.Scan(t.Context(), targetFor(digestB))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if dirty.Clean() {
		t.Error("a report with findings reads as clean")
	}
	if got, want := dirty.Rollup(), (scan.Rollup{High: 1, Fixable: 1}); got != want {
		t.Errorf("Rollup() = %+v, want %+v", got, want)
	}

	// The recorder, in order and by digest.
	if got, want := s.Targets(), []scan.Target{targetFor(digestA), targetFor(digestB)}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Targets() = %v, want %v", got, want)
	}
	if got := s.ScanCount(digestA); got != 1 {
		t.Errorf("ScanCount(A) = %d, want 1", got)
	}
	if got := s.ScanCount("sha256:never"); got != 0 {
		t.Errorf("ScanCount of an unscanned digest = %d, want 0", got)
	}
	for _, c := range s.Calls() {
		if c.Err != nil {
			t.Errorf("a successful scan recorded an error: %v", c.Err)
		}
	}

	// The call log is a copy: a caller truncating it must not blind the fake.
	calls := s.Calls()
	calls[0].Target.Digest = "mutated"
	if s.Calls()[0].Target.Digest != digestA {
		t.Error("Calls() exposes the fake's own slice")
	}

	s.ResetCalls()
	if got := s.Calls(); len(got) != 0 {
		t.Errorf("ResetCalls left %d calls", len(got))
	}
	// Resetting the log must not reset the script.
	if _, err := s.Scan(t.Context(), targetFor(digestA)); err != nil {
		t.Errorf("ResetCalls dropped the script: %v", err)
	}
}

// TestScriptedSequenceRepeatsItsLast is what S-005's rescan test needs: clean
// today, dirty after the database update, without having to interleave with a
// queue draining in the background.
func TestScriptedSequenceRepeatsItsLast(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{})
	s.Script(digestA,
		fake.Result{},
		fake.Result{Findings: []scan.Finding{finding("CVE-2026-9", scan.SeverityCritical, "")}},
	)

	first, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !first.Clean() {
		t.Fatalf("the first scan is not clean: %+v", first)
	}

	for i := range 3 {
		next, err := s.Scan(t.Context(), targetFor(digestA))
		if err != nil {
			t.Fatalf("Scan %d: %v", i, err)
		}
		if worst, any := next.Worst(); !any || worst != scan.SeverityCritical {
			t.Fatalf("scan %d worst = (%q, %v), want (critical, true)", i, worst, any)
		}
	}

	// Re-scripting replaces the queue rather than appending to it.
	s.ScriptClean(digestA)
	again, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !again.Clean() {
		t.Errorf("re-scripting appended instead of replacing: %+v", again)
	}
	if got := s.ScanCount(digestA); got != 5 {
		t.Errorf("ScanCount = %d, want 5", got)
	}
}

func TestFailureInjection(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("cve database is unreadable")
	s := fake.New(fake.Options{})
	s.ScriptFailure(digestA, sentinel)

	report, err := s.Scan(t.Context(), targetFor(digestA))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Scan error = %v, want the injected sentinel", err)
	}
	if !errors.Is(err, scan.ErrScanFailed) {
		t.Errorf("Scan error = %v, want it to wrap ErrScanFailed", err)
	}
	if report.Succeeded() || report.Clean() {
		t.Errorf("an injected failure produced %+v", report)
	}
	if report.Status != scan.StatusFailed || report.Error == "" {
		t.Errorf("the failed report is not usable as a record: %+v", report)
	}
	if err := report.Validate(); err != nil {
		t.Errorf("the failed report does not validate: %v", err)
	}
	if got := s.Calls(); len(got) != 1 || !errors.Is(got[0].Err, sentinel) {
		t.Errorf("the recorder did not capture the failure: %+v", got)
	}
}

// TestInvalidScriptIsRefused keeps the fake honest: a result no real scanner
// could produce is refused rather than handed to a test that would then be
// tuned against an impossible report.
func TestInvalidScriptIsRefused(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{})
	s.ScriptFindings(digestA, scan.Finding{Package: "openssl", InstalledVersion: "1", Severity: scan.SeverityHigh})

	report, err := s.Scan(t.Context(), targetFor(digestA))
	if !errors.Is(err, fake.ErrInvalidScript) {
		t.Fatalf("Scan error = %v, want ErrInvalidScript", err)
	}
	if !errors.Is(err, scan.ErrInvalidReport) {
		t.Errorf("Scan error = %v, want it to name the invariant that was broken", err)
	}
	if report.Clean() || report.Succeeded() {
		t.Errorf("an invalid script produced a usable report: %+v", report)
	}
}

func TestInvalidTargetIsRefusedBeforeTheScript(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{Fallback: &fake.Result{}})

	for _, target := range []scan.Target{
		{Repository: "UPPER", Digest: digestA},
		{Repository: "team-a/api"},
		{Digest: digestA},
		{Repository: "team-a/api", Digest: "sha256:../../etc/passwd"},
	} {
		report, err := s.Scan(t.Context(), target)
		if !errors.Is(err, scan.ErrInvalidTarget) {
			t.Errorf("Scan(%+v) error = %v, want ErrInvalidTarget", target, err)
		}
		if report.Clean() {
			t.Errorf("Scan(%+v) reported clean despite an illegal target", target)
		}
	}
	if got := len(s.Calls()); got != 0 {
		t.Errorf("an illegal target was recorded as a scan (%d calls); it never reached the script", got)
	}
}

// TestFallbackIsOptIn covers the escape hatch tests about volume need, and
// pins that it is off unless asked for.
func TestFallbackIsOptIn(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{Fallback: &fake.Result{Findings: []scan.Finding{finding("CVE-1", scan.SeverityLow, "")}}})

	report, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got, want := report.Rollup(), (scan.Rollup{Low: 1}); got != want {
		t.Errorf("the fallback did not answer: %+v", got)
	}

	// A digest with its own script still wins over the fallback.
	s.ScriptClean(digestB)
	scripted, err := s.Scan(t.Context(), targetFor(digestB))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !scripted.Clean() {
		t.Errorf("the fallback overrode an explicit script: %+v", scripted)
	}
}

// TestLatencyIsRecordedNotSlept is the shape section 9's no-sleeps rule needs:
// the report claims the latency, the test does not spend it.
func TestLatencyIsRecordedNotSlept(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{})
	s.Script(digestA, fake.Result{Latency: 90 * time.Second})

	before := time.Now()
	report, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if elapsed := time.Since(before); elapsed > 5*time.Second {
		t.Fatalf("the default fake slept for %v", elapsed)
	}
	if got, want := report.Duration(), 90*time.Second; got != want {
		t.Errorf("Duration() = %v, want %v", got, want)
	}
	if !report.FinishedAt.After(report.StartedAt) {
		t.Error("the report does not advance from start to finish")
	}

	// The default clock advances, so a second scan does not claim to have run
	// at the same instant as the first.
	s.Script(digestA, fake.Result{})
	second, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !second.StartedAt.After(report.FinishedAt) {
		t.Errorf("the second scan started at %v, not after the first finished at %v", second.StartedAt, report.FinishedAt)
	}
}

// TestWaitIsDelegated is how S-009's block-until-scanned test holds a scan in
// flight: the fake asks the injected wait for the latency and does nothing else.
func TestWaitIsDelegated(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	asked := make(chan time.Duration, 1)
	s := fake.New(fake.Options{
		Wait: func(ctx context.Context, d time.Duration) error {
			asked <- d
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	s.Script(digestA, fake.Result{Latency: time.Second})
	s.Script(digestB, fake.Result{})

	done := make(chan scan.Report, 1)
	go func() {
		report, err := s.Scan(t.Context(), targetFor(digestA))
		if err != nil {
			t.Errorf("Scan: %v", err)
		}
		done <- report
	}()

	if got := <-asked; got != time.Second {
		t.Errorf("the wait was asked for %v, want 1s", got)
	}
	close(release)
	if report := <-done; !report.Clean() {
		t.Errorf("the released scan produced %+v", report)
	}

	// A result with no latency does not consult the wait at all, so the
	// hook does not have to tolerate being called by every unrelated scan.
	if _, err := s.Scan(t.Context(), targetFor(digestB)); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	select {
	case d := <-asked:
		t.Errorf("a zero-latency scan consulted the wait for %v", d)
	default:
	}
}

func TestWaitFailureIsAScanFailure(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("held too long")
	s := fake.New(fake.Options{
		Wait: func(context.Context, time.Duration) error { return sentinel },
	})
	s.Script(digestA, fake.Result{Latency: time.Second})

	report, err := s.Scan(t.Context(), targetFor(digestA))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Scan error = %v, want the wait's error", err)
	}
	if report.Clean() || report.Status != scan.StatusFailed {
		t.Errorf("a wait failure produced %+v", report)
	}
}

func TestCancellation(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{})
	s.ScriptClean(digestA)
	s.ScriptDatabaseUpdate(scan.DatabaseVersion{ID: "db-2"}, nil)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := s.Scan(ctx, targetFor(digestA)); !errors.Is(err, context.Canceled) {
		t.Errorf("Scan on a cancelled context = %v, want context.Canceled", err)
	}
	if _, err := s.DatabaseVersion(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("DatabaseVersion on a cancelled context = %v, want context.Canceled", err)
	}
	if err := s.UpdateDB(ctx, scan.DatabaseSource{}); !errors.Is(err, context.Canceled) {
		t.Errorf("UpdateDB on a cancelled context = %v, want context.Canceled", err)
	}
	if got := len(s.Calls()); got != 0 {
		t.Errorf("a cancelled scan was recorded (%d calls)", got)
	}
}

// TestCancellationDuringAScan covers the window between the wait returning and
// the report being built: a context cancelled while the scan was in flight must
// not produce a clean report.
func TestCancellationDuringAScan(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	s := fake.New(fake.Options{
		Wait: func(context.Context, time.Duration) error {
			cancel()
			return nil
		},
	})
	s.Script(digestA, fake.Result{Latency: time.Second})

	report, err := s.Scan(ctx, targetFor(digestA))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan error = %v, want context.Canceled", err)
	}
	if report.Clean() {
		t.Error("a cancelled scan reported clean")
	}
}

func TestDatabaseVersionDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	t.Run("the default is a usable database", func(t *testing.T) {
		t.Parallel()

		s := fake.New(fake.Options{})
		v, err := s.DatabaseVersion(t.Context())
		if err != nil {
			t.Fatalf("DatabaseVersion: %v", err)
		}
		if v.IsZero() {
			t.Error("the default scanner has no database; that state should have to be asked for")
		}
	})

	t.Run("an explicit version is reported and carried on reports", func(t *testing.T) {
		t.Parallel()

		want := scan.DatabaseVersion{ID: "2026-03-01", UpdatedAt: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)}
		s := fake.New(fake.Options{Database: want})
		s.ScriptClean(digestA)

		got, err := s.DatabaseVersion(t.Context())
		if err != nil || got != want {
			t.Fatalf("DatabaseVersion = (%+v, %v), want %+v", got, err, want)
		}
		report, err := s.Scan(t.Context(), targetFor(digestA))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if report.Database != want {
			t.Errorf("the report carries database %+v, want %+v", report.Database, want)
		}
	})

	t.Run("an unavailable database", func(t *testing.T) {
		t.Parallel()

		s := fake.New(fake.Options{DatabaseErr: scan.ErrDatabaseUnavailable})
		if _, err := s.DatabaseVersion(t.Context()); !errors.Is(err, scan.ErrDatabaseUnavailable) {
			t.Fatalf("DatabaseVersion = %v, want ErrDatabaseUnavailable", err)
		}

		s.SetDatabaseVersion(scan.DatabaseVersion{ID: "imported"})
		got, err := s.DatabaseVersion(t.Context())
		if err != nil || got.ID != "imported" {
			t.Fatalf("after SetDatabaseVersion: (%+v, %v)", got, err)
		}

		s.SetDatabaseError(errors.New("gone again"))
		if _, err := s.DatabaseVersion(t.Context()); err == nil {
			t.Fatal("SetDatabaseError did not take effect")
		}
		s.SetDatabaseError(nil)
		if _, err := s.DatabaseVersion(t.Context()); err != nil {
			t.Fatalf("SetDatabaseError(nil) did not clear it: %v", err)
		}
	})
}

func TestDatabaseUpdates(t *testing.T) {
	t.Parallel()

	t.Run("an unscripted update is refused", func(t *testing.T) {
		t.Parallel()

		s := fake.New(fake.Options{})
		if err := s.UpdateDB(t.Context(), scan.DatabaseSource{}); !errors.Is(err, fake.ErrNotScripted) {
			t.Fatalf("UpdateDB = %v, want ErrNotScripted", err)
		}
		// The attempt is still recorded, so a test can assert the update was
		// even attempted.
		if got := s.DatabaseUpdates(); len(got) != 1 {
			t.Errorf("DatabaseUpdates() = %v, want the refused attempt", got)
		}
	})

	t.Run("a scripted update installs a version", func(t *testing.T) {
		t.Parallel()

		installed := scan.DatabaseVersion{ID: "2026-03-02", UpdatedAt: time.Date(2026, time.March, 2, 0, 0, 0, 0, time.UTC)}
		s := fake.New(fake.Options{DatabaseErr: scan.ErrDatabaseUnavailable})
		s.ScriptDatabaseUpdate(installed, nil)

		before, _ := s.DatabaseVersion(t.Context())
		source := scan.DatabaseSource{ArchivePath: "/tmp/trivy-db.tar.gz"}
		if err := s.UpdateDB(t.Context(), source); err != nil {
			t.Fatalf("UpdateDB: %v", err)
		}
		after, err := s.DatabaseVersion(t.Context())
		if err != nil {
			t.Fatalf("DatabaseVersion: %v", err)
		}
		if after != installed {
			t.Errorf("DatabaseVersion = %+v, want %+v", after, installed)
		}
		if !before.Changed(after) {
			t.Error("the update did not read as a database change; the rescan pass would not fire")
		}
		if got := s.DatabaseUpdates(); len(got) != 1 || got[0] != source || !got[0].Offline() {
			t.Errorf("DatabaseUpdates() = %v, want the offline source", got)
		}
	})

	t.Run("a failing update leaves the database alone", func(t *testing.T) {
		t.Parallel()

		sentinel := errors.New("archive is truncated")
		s := fake.New(fake.Options{Database: scan.DatabaseVersion{ID: "db-1"}})
		s.ScriptDatabaseUpdate(scan.DatabaseVersion{}, sentinel)
		s.ScriptDatabaseUpdate(scan.DatabaseVersion{ID: "db-2"}, nil)

		if err := s.UpdateDB(t.Context(), scan.DatabaseSource{}); !errors.Is(err, sentinel) {
			t.Fatalf("UpdateDB = %v, want the injected error", err)
		}
		if v, _ := s.DatabaseVersion(t.Context()); v.ID != "db-1" {
			t.Errorf("a failed update changed the database to %q", v.ID)
		}

		// The next queued outcome is consumed in order, and the last repeats.
		for range 2 {
			if err := s.UpdateDB(t.Context(), scan.DatabaseSource{}); err != nil {
				t.Fatalf("UpdateDB: %v", err)
			}
		}
		if v, _ := s.DatabaseVersion(t.Context()); v.ID != "db-2" {
			t.Errorf("DatabaseVersion = %q, want db-2", v.ID)
		}
		if got := len(s.DatabaseUpdates()); got != 3 {
			t.Errorf("DatabaseUpdates() recorded %d calls, want 3", got)
		}

		s.ResetCalls()
		if got := s.DatabaseUpdates(); len(got) != 0 {
			t.Errorf("ResetCalls left %d update records", len(got))
		}
	})
}

// TestInjectedClockOwnsTime pins that a test supplying a clock gets its own
// readings and the fake's default advancement stays out of the way.
func TestInjectedClockOwnsTime(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	now := time.Date(2026, time.September, 5, 8, 0, 0, 0, time.UTC)
	s := fake.New(fake.Options{
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
	})
	s.Script(digestA, fake.Result{Latency: 30 * time.Second}, fake.Result{})

	first, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !first.StartedAt.Equal(now) {
		t.Errorf("StartedAt = %v, want the injected clock's reading %v", first.StartedAt, now)
	}
	if got, want := first.FinishedAt, now.Add(30*time.Second); !got.Equal(want) {
		t.Errorf("FinishedAt = %v, want %v", got, want)
	}

	// The fake must not advance an injected clock behind the test's back.
	second, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !second.StartedAt.Equal(now) {
		t.Errorf("the fake advanced the injected clock to %v", second.StartedAt)
	}

	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	if got, want := s.ScanCount(digestA), 2; got != want {
		t.Errorf("ScanCount = %d, want %d", got, want)
	}
	third, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !third.StartedAt.Equal(now) {
		t.Errorf("StartedAt = %v, want the advanced clock's reading %v", third.StartedAt, now)
	}
	if got := s.Calls()[2].At; !got.Equal(now) {
		t.Errorf("the recorder stamped %v, want %v", got, now)
	}
}

// TestConcurrentUse runs the fake the way the queue will: several workers at
// once, under the race detector. A fake that needed a lock held outside it
// would be a fake that shaped every test built on it.
func TestConcurrentUse(t *testing.T) {
	t.Parallel()

	s := fake.New(fake.Options{Fallback: &fake.Result{}})
	s.ScriptFindings(digestB, finding("CVE-1", scan.SeverityHigh, ""))

	const workers = 8
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			digest := digestA
			if i%2 == 0 {
				digest = digestB
			}
			if _, err := s.Scan(t.Context(), targetFor(digest)); err != nil {
				t.Errorf("Scan: %v", err)
			}
			s.ScriptDatabaseUpdate(scan.DatabaseVersion{ID: "db"}, nil)
			if err := s.UpdateDB(t.Context(), scan.DatabaseSource{}); err != nil {
				t.Errorf("UpdateDB: %v", err)
			}
			_ = s.Calls()
			_, _ = s.DatabaseVersion(t.Context())
		}()
	}
	wg.Wait()

	if got := len(s.Calls()); got != workers {
		t.Errorf("Calls() = %d, want %d", got, workers)
	}
	if got := s.ScanCount(digestA) + s.ScanCount(digestB); got != workers {
		t.Errorf("scan counts total %d, want %d", got, workers)
	}
	if got := len(s.DatabaseUpdates()); got != workers {
		t.Errorf("DatabaseUpdates() = %d, want %d", got, workers)
	}
}

// TestScriptedFindingsAreCopied stops a test from mutating a report it already
// received, or the script it already wrote, and seeing the other change.
func TestScriptedFindingsAreCopied(t *testing.T) {
	t.Parallel()

	findings := []scan.Finding{finding("CVE-1", scan.SeverityHigh, "")}
	s := fake.New(fake.Options{})
	s.ScriptFindings(digestA, findings...)

	report, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	report.Findings[0].Severity = scan.SeverityLow
	findings[0].CVE = "CVE-mutated"

	again, err := s.Scan(t.Context(), targetFor(digestA))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if again.Findings[0].Severity != scan.SeverityHigh || again.Findings[0].CVE != "CVE-1" {
		t.Errorf("the script was reachable through a returned report or the caller's slice: %+v", again.Findings[0])
	}
}
