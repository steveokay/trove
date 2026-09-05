package scan_test

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/scan"
)

// startedAt is the reference clock reading every report in this file uses.
// Nothing here reads the wall clock, which is the same rule the package itself
// is held to.
var startedAt = time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)

// target is a valid scan target; the reports below vary in everything else.
func target() scan.Target {
	return scan.Target{Repository: "team-a/api", Digest: "sha256:" + strings.Repeat("a", 64)}
}

// finding builds a valid finding with the severity and fix state a case needs.
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

// report builds a succeeded report carrying the given findings.
func report(findings ...scan.Finding) scan.Report {
	return scan.Report{
		Target:         target(),
		Scanner:        "fake",
		ScannerVersion: "0.0.0",
		Database:       scan.DatabaseVersion{ID: "db-1", UpdatedAt: startedAt},
		Status:         scan.StatusSucceeded,
		StartedAt:      startedAt,
		FinishedAt:     startedAt.Add(2 * time.Second),
		Findings:       findings,
	}
}

// TestSeverityOrderIsTotal walks every ordered pair in the closed set. The
// ordering is what ADR 0013's max-severity threshold compares against, so
// "critical outranks high" is not a fact to be assumed from the declaration
// order -- it is the assertion.
func TestSeverityOrderIsTotal(t *testing.T) {
	t.Parallel()

	// The expected order, written out rather than derived from Severities(), so
	// a reordering of the enum fails here instead of silently redefining what
	// "worse" means.
	order := []scan.Severity{
		scan.SeverityUnknown,
		scan.SeverityLow,
		scan.SeverityMedium,
		scan.SeverityHigh,
		scan.SeverityCritical,
	}
	if got := scan.Severities(); !slices.Equal(got, order) {
		t.Fatalf("Severities() = %v, want %v", got, order)
	}

	for i, a := range order {
		for j, b := range order {
			t.Run(fmt.Sprintf("%s_vs_%s", a, b), func(t *testing.T) {
				t.Parallel()

				got := a.Compare(b)
				switch {
				case i < j && got >= 0:
					t.Errorf("%s.Compare(%s) = %d, want negative", a, b, got)
				case i == j && got != 0:
					t.Errorf("%s.Compare(%s) = %d, want 0", a, b, got)
				case i > j && got <= 0:
					t.Errorf("%s.Compare(%s) = %d, want positive", a, b, got)
				}

				// Antisymmetry: the reverse comparison must have the opposite
				// sign, or sorting by it is not a sort.
				if reverse := b.Compare(a); sign(got) != -sign(reverse) {
					t.Errorf("%s.Compare(%s) = %d but %s.Compare(%s) = %d", a, b, got, b, a, reverse)
				}

				// AtLeast is the shape a gate reads in and must agree exactly.
				if want := i >= j; a.AtLeast(b) != want {
					t.Errorf("%s.AtLeast(%s) = %v, want %v", a, b, a.AtLeast(b), want)
				}
			})
		}
	}

	// Transitivity over every triple. A comparison that is not transitive
	// produces a "worst severity" that depends on the order the findings
	// happened to arrive in.
	for _, a := range order {
		for _, b := range order {
			for _, c := range order {
				if a.Compare(b) <= 0 && b.Compare(c) <= 0 && a.Compare(c) > 0 {
					t.Errorf("order is not transitive: %s <= %s <= %s but %s > %s", a, b, c, a, c)
				}
			}
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// TestSeverityEnumIsClosed proves the enum is total in the other sense: nothing
// outside the declared set is valid, and an invalid value cannot outrank a real
// one and slip past a threshold.
func TestSeverityEnumIsClosed(t *testing.T) {
	t.Parallel()

	for _, s := range scan.Severities() {
		if !s.Valid() {
			t.Errorf("%s is in Severities() but is not Valid()", s)
		}
		if s.String() != string(s) {
			t.Errorf("String() = %q, want %q", s.String(), string(s))
		}
	}

	for _, s := range []scan.Severity{"", "none", "informational", "CRITICAL", "criticals", "moderate"} {
		if s.Valid() {
			t.Errorf("%q is Valid(); the set is meant to be closed", s)
		}
		for _, valid := range scan.Severities() {
			if s.AtLeast(valid) {
				t.Errorf("invalid severity %q ranks at least %s; it could pass a threshold", s, valid)
			}
		}
	}

	// Severities() must hand back a copy, or a caller sorting it redefines the
	// order for everyone.
	first := scan.Severities()
	first[0] = "mutated"
	if scan.Severities()[0] != scan.SeverityUnknown {
		t.Error("Severities() exposes the package's own slice")
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    scan.Severity
		wantErr bool
	}{
		{in: "critical", want: scan.SeverityCritical},
		{in: "CRITICAL", want: scan.SeverityCritical},
		{in: "  High  ", want: scan.SeverityHigh},
		{in: "medium", want: scan.SeverityMedium},
		{in: "low", want: scan.SeverityLow},
		{in: "unknown", want: scan.SeverityUnknown},
		{in: "", wantErr: true},
		{in: "none", wantErr: true},
		{in: "hihg", wantErr: true},
		{in: "moderate", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()

			got, err := scan.ParseSeverity(tc.in)
			if tc.wantErr {
				if !errors.Is(err, scan.ErrInvalidSeverity) {
					t.Fatalf("ParseSeverity(%q) error = %v, want ErrInvalidSeverity", tc.in, err)
				}
				if got != "" {
					t.Errorf("ParseSeverity(%q) = %q on error, want empty", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSeverity(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()

	if got, want := scan.Statuses(), []scan.Status{scan.StatusSucceeded, scan.StatusFailed}; !slices.Equal(got, want) {
		t.Fatalf("Statuses() = %v, want %v", got, want)
	}
	for _, s := range scan.Statuses() {
		if !s.Valid() || s.String() != string(s) {
			t.Errorf("%q is not a well-formed status", s)
		}
	}
	for _, s := range []scan.Status{"", "running", "clean", "error"} {
		if s.Valid() {
			t.Errorf("%q is Valid(); the set is meant to be closed", s)
		}
	}

	got, err := scan.ParseStatus(" SUCCEEDED ")
	if err != nil || got != scan.StatusSucceeded {
		t.Errorf("ParseStatus = (%q, %v), want (succeeded, nil)", got, err)
	}
	if _, err := scan.ParseStatus("running"); !errors.Is(err, scan.ErrInvalidStatus) {
		t.Errorf("ParseStatus(running) error = %v, want ErrInvalidStatus", err)
	}

	statuses := scan.Statuses()
	statuses[0] = "mutated"
	if scan.Statuses()[0] != scan.StatusSucceeded {
		t.Error("Statuses() exposes the package's own slice")
	}
}

func TestFinding(t *testing.T) {
	t.Parallel()

	if finding("CVE-1", scan.SeverityHigh, "3.0.2").Fixable() != true {
		t.Error("a finding with a fixed version is not Fixable()")
	}
	if finding("CVE-1", scan.SeverityHigh, "").Fixable() != false {
		t.Error("a finding with no fixed version is Fixable()")
	}

	tests := []struct {
		name    string
		finding scan.Finding
		wantErr bool
	}{
		{name: "complete", finding: finding("CVE-2026-1", scan.SeverityHigh, "3.0.2")},
		{name: "no fix is a real answer", finding: finding("CVE-2026-1", scan.SeverityHigh, "")},
		{name: "no source is tolerated", finding: scan.Finding{CVE: "CVE-1", Package: "p", InstalledVersion: "1", Severity: scan.SeverityLow}},
		{name: "no cve", finding: scan.Finding{Package: "p", InstalledVersion: "1", Severity: scan.SeverityLow}, wantErr: true},
		{name: "no package", finding: scan.Finding{CVE: "CVE-1", InstalledVersion: "1", Severity: scan.SeverityLow}, wantErr: true},
		{name: "no installed version", finding: scan.Finding{CVE: "CVE-1", Package: "p", Severity: scan.SeverityLow}, wantErr: true},
		{name: "no severity", finding: scan.Finding{CVE: "CVE-1", Package: "p", InstalledVersion: "1"}, wantErr: true},
		{name: "a severity outside the enum", finding: scan.Finding{CVE: "CVE-1", Package: "p", InstalledVersion: "1", Severity: "moderate"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.finding.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, scan.ErrInvalidReport) {
				t.Errorf("Validate() = %v, want ErrInvalidReport", err)
			}
		})
	}
}

// TestRollupArithmeticMatchesItsFindings is the invariant a rollup exists for:
// every bucket, the total, the fixable split, and the worst severity must be
// exactly what the finding list says, because the rollup is what an operator
// sees and what a gate evaluates -- nobody re-derives it from the findings.
func TestRollupArithmeticMatchesItsFindings(t *testing.T) {
	t.Parallel()

	findings := []scan.Finding{
		finding("CVE-1", scan.SeverityCritical, "1.1"),
		finding("CVE-2", scan.SeverityCritical, ""),
		finding("CVE-3", scan.SeverityHigh, "2.2"),
		finding("CVE-4", scan.SeverityMedium, ""),
		finding("CVE-5", scan.SeverityMedium, ""),
		finding("CVE-6", scan.SeverityMedium, "3.3"),
		finding("CVE-7", scan.SeverityLow, ""),
		finding("CVE-8", scan.SeverityUnknown, "4.4"),
	}
	r := report(findings...)

	got := r.Rollup()
	want := scan.Rollup{Critical: 2, High: 1, Medium: 3, Low: 1, Unknown: 1, Fixable: 4}
	if got != want {
		t.Fatalf("Rollup() = %+v, want %+v", got, want)
	}

	// Recomputed from the findings rather than restated, so the two disagree if
	// either side drifts.
	var counted, fixable int
	for _, f := range findings {
		counted++
		if f.Fixable() {
			fixable++
		}
		if got.Count(f.Severity) == 0 {
			t.Errorf("severity %s is not counted in any bucket", f.Severity)
		}
	}
	if got.Total() != counted {
		t.Errorf("Total() = %d, want %d", got.Total(), counted)
	}
	if got.Fixable != fixable {
		t.Errorf("Fixable = %d, want %d", got.Fixable, fixable)
	}
	if got.Empty() {
		t.Error("Empty() is true for a rollup with findings")
	}

	worst, any := got.Worst()
	if !any || worst != scan.SeverityCritical {
		t.Errorf("Worst() = (%q, %v), want (critical, true)", worst, any)
	}
	if reportWorst, ok := r.Worst(); !ok || reportWorst != scan.SeverityCritical {
		t.Errorf("Report.Worst() = (%q, %v), want (critical, true)", reportWorst, ok)
	}

	// The fixable narrowing ADR 0013's `fixable-only` gates on: same type, same
	// comparison afterwards, a strictly smaller set.
	gotFixable := r.FixableRollup()
	wantFixable := scan.Rollup{Critical: 1, High: 1, Medium: 1, Low: 0, Unknown: 1, Fixable: 4}
	if gotFixable != wantFixable {
		t.Errorf("FixableRollup() = %+v, want %+v", gotFixable, wantFixable)
	}
	if gotFixable.Total() != gotFixable.Fixable {
		t.Errorf("FixableRollup totals %d over %d fixable; every counted finding must be fixable", gotFixable.Total(), gotFixable.Fixable)
	}
}

// TestFixableOnlyChangesTheWorstSeverity is the case the split exists for: an
// image whose only critical has no fix passes a fixable-only gate at critical
// and fails a plain one.
func TestFixableOnlyChangesTheWorstSeverity(t *testing.T) {
	t.Parallel()

	r := report(
		finding("CVE-1", scan.SeverityCritical, ""),
		finding("CVE-2", scan.SeverityMedium, "1.2"),
	)

	worst, any := r.Rollup().Worst()
	if !any || worst != scan.SeverityCritical {
		t.Fatalf("Rollup().Worst() = (%q, %v), want (critical, true)", worst, any)
	}
	fixableWorst, any := r.FixableRollup().Worst()
	if !any || fixableWorst != scan.SeverityMedium {
		t.Fatalf("FixableRollup().Worst() = (%q, %v), want (medium, true)", fixableWorst, any)
	}
	if !worst.AtLeast(scan.SeverityCritical) {
		t.Error("the plain rollup does not reach a critical threshold")
	}
	if fixableWorst.AtLeast(scan.SeverityCritical) {
		t.Error("the fixable-only rollup reaches a critical threshold it has no finding for")
	}
}

func TestRollupEdges(t *testing.T) {
	t.Parallel()

	var empty scan.Rollup
	if !empty.Empty() || empty.Total() != 0 {
		t.Error("the zero rollup is not empty")
	}
	if s, any := empty.Worst(); any || s != "" {
		t.Errorf("Worst() on an empty rollup = (%q, %v), want (\"\", false)", s, any)
	}
	if got := empty.Count("moderate"); got != 0 {
		t.Errorf("Count on a severity outside the enum = %d, want 0", got)
	}

	// A finding whose severity is outside the enum is counted in no bucket.
	// Report.Validate is what refuses it; inventing a bucket here would hide it.
	invalid := empty.Add(scan.Finding{CVE: "CVE-1", Package: "p", InstalledVersion: "1", Severity: "moderate", FixedVersion: "2"})
	if invalid != empty {
		t.Errorf("Add(invalid severity) = %+v, want the rollup unchanged", invalid)
	}

	// Worst walks down from the top, so a lower bucket answers only when every
	// higher one is empty.
	for _, s := range scan.Severities() {
		one := scan.Rollup{}.Add(finding("CVE-1", s, ""))
		got, any := one.Worst()
		if !any || got != s {
			t.Errorf("Worst() of a lone %s = (%q, %v)", s, got, any)
		}
		if one.Count(s) != 1 || one.Total() != 1 || one.Fixable != 0 {
			t.Errorf("Add(%s) produced %+v", s, one)
		}
	}

	// Merge is how S-006 builds a repository total out of per-manifest ones.
	a := scan.Rollup{Critical: 1, Medium: 2, Fixable: 1}
	b := scan.Rollup{High: 3, Medium: 1, Low: 4, Unknown: 5, Fixable: 6}
	merged := a.Merge(b)
	want := scan.Rollup{Critical: 1, High: 3, Medium: 3, Low: 4, Unknown: 5, Fixable: 7}
	if merged != want {
		t.Errorf("Merge = %+v, want %+v", merged, want)
	}
	if a != (scan.Rollup{Critical: 1, Medium: 2, Fixable: 1}) {
		t.Error("Merge mutated its receiver")
	}
	if merged.Total() != a.Total()+b.Total() {
		t.Errorf("Merge total = %d, want %d", merged.Total(), a.Total()+b.Total())
	}
}

// TestRollupMatchesTheEventPayloadShape is the alignment CLAUDE.md asks for:
// scan.Rollup and event.SeverityCounts are one shape, not two. A field added to
// either without the other is a scan.completed payload that no longer carries
// what the rollup counted.
func TestRollupMatchesTheEventPayloadShape(t *testing.T) {
	t.Parallel()

	ours := reflect.TypeOf(scan.Rollup{})
	theirs := reflect.TypeOf(event.SeverityCounts{})

	if ours.NumField() != theirs.NumField() {
		t.Fatalf("scan.Rollup has %d fields, event.SeverityCounts has %d", ours.NumField(), theirs.NumField())
	}
	for i := range ours.NumField() {
		a, b := ours.Field(i), theirs.Field(i)
		if a.Name != b.Name {
			t.Errorf("field %d: scan.Rollup.%s vs event.SeverityCounts.%s", i, a.Name, b.Name)
		}
		if a.Type != b.Type {
			t.Errorf("field %s: type %s vs %s", a.Name, a.Type, b.Type)
		}
		if a.Tag.Get("json") != b.Tag.Get("json") {
			t.Errorf("field %s: json tag %q vs %q", a.Name, a.Tag.Get("json"), b.Tag.Get("json"))
		}
	}

	// And the values line up too, not just the field names: a rollup converted
	// field by field into a payload carries the same numbers.
	r := report(
		finding("CVE-1", scan.SeverityCritical, "1.1"),
		finding("CVE-2", scan.SeverityUnknown, ""),
	).Rollup()
	counts := event.SeverityCounts{
		Critical: r.Critical,
		High:     r.High,
		Medium:   r.Medium,
		Low:      r.Low,
		Unknown:  r.Unknown,
		Fixable:  r.Fixable,
	}
	if counts != (event.SeverityCounts{Critical: 1, Unknown: 1, Fixable: 1}) {
		t.Errorf("converted payload = %+v", counts)
	}
}

// TestModelReachesNoVendorType walks the normalised model's fields. Section 6's
// rule is that a vendor's types are never the system of record; the way that
// breaks is not a deliberate decision but a struct field typed as somebody
// else's, so this refuses any type that is not ours or the standard library's.
func TestModelReachesNoVendorType(t *testing.T) {
	t.Parallel()

	const ourPackage = "github.com/steveokay/trove/internal/scan"
	allowed := map[string]bool{
		"":         true, // builtins and unnamed composite types
		"time":     true,
		ourPackage: true,
		"context":  true,
		"reflect":  true,
	}

	seen := make(map[reflect.Type]bool)
	var walk func(t *testing.T, typ reflect.Type, path string)
	walk = func(t *testing.T, typ reflect.Type, path string) {
		if seen[typ] {
			return
		}
		seen[typ] = true

		if pkgPath := typ.PkgPath(); !allowed[pkgPath] {
			t.Errorf("%s is %s, from %q -- the normalised model may only hold our own types and the standard library's", path, typ, pkgPath)
			return
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := range typ.NumField() {
				field := typ.Field(i)
				walk(t, field.Type, path+"."+field.Name)
			}
		case reflect.Slice, reflect.Array, reflect.Pointer, reflect.Map, reflect.Chan:
			walk(t, typ.Elem(), path+"[]")
		default:
		}
	}

	for _, v := range []any{scan.Report{}, scan.Finding{}, scan.Rollup{}, scan.Target{}, scan.DatabaseVersion{}, scan.DatabaseSource{}} {
		typ := reflect.TypeOf(v)
		walk(t, typ, typ.Name())
	}

	if !seen[reflect.TypeOf(scan.Finding{})] {
		t.Error("the walk never reached scan.Finding; it is not proving anything")
	}
}

// TestReportDistinguishesCleanFromFailed is the distinction gating depends on.
// An empty finding list is a clean bill of health for a succeeded scan and
// means nothing at all for a failed one.
func TestReportDistinguishesCleanFromFailed(t *testing.T) {
	t.Parallel()

	clean := report()
	if !clean.Succeeded() || !clean.Clean() {
		t.Error("a succeeded report with no findings is not Clean()")
	}

	dirty := report(finding("CVE-1", scan.SeverityLow, ""))
	if !dirty.Succeeded() || dirty.Clean() {
		t.Error("a report with findings is Clean()")
	}

	failed := report(finding("CVE-1", scan.SeverityCritical, "")).Failed(errors.New("database missing"))
	if failed.Succeeded() {
		t.Error("a failed report reports itself as succeeded")
	}
	if failed.Clean() {
		t.Error("a failed report reads as clean; that is a gate that opens when the scanner breaks")
	}
	if len(failed.Findings) != 0 {
		t.Errorf("Failed left %d findings; a partial list stored as a result is a clean bill for what it did not reach", len(failed.Findings))
	}
	if failed.Error != "database missing" {
		t.Errorf("Error = %q, want the cause", failed.Error)
	}
	if got := failed.Rollup(); !got.Empty() {
		t.Errorf("a failed report rolls up to %+v, want empty", got)
	}

	// A nil cause still leaves a reason, because a failure with no reason is a
	// report Validate refuses and an operator cannot act on.
	nilCause := report().Failed(nil)
	if nilCause.Error == "" {
		t.Error("Failed(nil) left no reason")
	}
	if err := nilCause.Validate(); err != nil {
		t.Errorf("Failed(nil) produced an invalid report: %v", err)
	}
}

func TestReportTiming(t *testing.T) {
	t.Parallel()

	r := report()
	if got, want := r.Duration(), 2*time.Second; got != want {
		t.Errorf("Duration() = %v, want %v", got, want)
	}

	now := r.FinishedAt.Add(90 * time.Minute)
	if got, want := r.Age(now), 90*time.Minute; got != want {
		t.Errorf("Age() = %v, want %v", got, want)
	}
	// A clock that moved backwards must not produce a negative age that would
	// defeat a staleness bound.
	if got := r.Age(r.FinishedAt.Add(-time.Hour)); got != 0 {
		t.Errorf("Age() before the finish time = %v, want 0", got)
	}

	tests := []struct {
		name   string
		now    time.Time
		maxAge time.Duration
		want   bool
	}{
		{name: "inside the bound", now: now, maxAge: 2 * time.Hour},
		{name: "exactly at the bound", now: now, maxAge: 90 * time.Minute},
		{name: "past the bound", now: now, maxAge: time.Hour, want: true},
		{name: "no bound configured", now: now.Add(10000 * time.Hour), maxAge: 0},
		{name: "a negative bound is no bound", now: now, maxAge: -time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := r.Stale(tc.now, tc.maxAge); got != tc.want {
				t.Errorf("Stale(%v, %v) = %v, want %v", tc.now, tc.maxAge, got, tc.want)
			}
		})
	}
}

func TestReportValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*scan.Report)
		wantErr error
	}{
		{name: "a complete succeeded report", mutate: func(*scan.Report) {}},
		{
			name:    "an invalid target",
			mutate:  func(r *scan.Report) { r.Target.Repository = "UPPER" },
			wantErr: scan.ErrInvalidTarget,
		},
		{
			name:    "no scanner",
			mutate:  func(r *scan.Report) { r.Scanner = "" },
			wantErr: scan.ErrInvalidReport,
		},
		{
			name:    "a status outside the enum",
			mutate:  func(r *scan.Report) { r.Status = "running" },
			wantErr: scan.ErrInvalidReport,
		},
		{
			name:    "no start time",
			mutate:  func(r *scan.Report) { r.StartedAt = time.Time{} },
			wantErr: scan.ErrInvalidReport,
		},
		{
			name:    "no finish time",
			mutate:  func(r *scan.Report) { r.FinishedAt = time.Time{} },
			wantErr: scan.ErrInvalidReport,
		},
		{
			name:    "finished before it started",
			mutate:  func(r *scan.Report) { r.FinishedAt = r.StartedAt.Add(-time.Second) },
			wantErr: scan.ErrInvalidReport,
		},
		{
			name: "a failure with no reason",
			mutate: func(r *scan.Report) {
				r.Status = scan.StatusFailed
				r.Findings = nil
			},
			wantErr: scan.ErrInvalidReport,
		},
		{
			name: "a failure carrying findings",
			mutate: func(r *scan.Report) {
				r.Status = scan.StatusFailed
				r.Error = "upstream refused"
				r.Findings = []scan.Finding{finding("CVE-1", scan.SeverityHigh, "")}
			},
			wantErr: scan.ErrInvalidReport,
		},
		{
			name: "a success carrying an error",
			mutate: func(r *scan.Report) {
				r.Error = "database missing"
			},
			wantErr: scan.ErrInvalidReport,
		},
		{
			name: "a malformed finding",
			mutate: func(r *scan.Report) {
				r.Findings = []scan.Finding{{Package: "p", InstalledVersion: "1", Severity: scan.SeverityLow}}
			},
			wantErr: scan.ErrInvalidReport,
		},
		{
			name: "a well-formed failure",
			mutate: func(r *scan.Report) {
				*r = r.Failed(errors.New("database missing"))
			},
		},
		{
			name:   "a clean success",
			mutate: func(r *scan.Report) { r.Findings = nil },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := report(finding("CVE-2026-1", scan.SeverityHigh, "3.0.2"))
			tc.mutate(&r)

			err := r.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
