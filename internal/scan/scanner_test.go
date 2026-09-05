package scan_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/reponame"
	"github.com/steveokay/trove/internal/scan"
)

func TestTargetValidate(t *testing.T) {
	t.Parallel()

	digest := "sha256:" + strings.Repeat("a", 64)

	tests := []struct {
		name    string
		target  scan.Target
		wantErr bool
	}{
		{name: "a repository and a digest", target: scan.Target{Repository: "team-a/api", Digest: digest}},
		{name: "a single-segment repository", target: scan.Target{Repository: "nginx", Digest: digest}},
		{name: "sha512", target: scan.Target{Repository: "nginx", Digest: "sha512:" + strings.Repeat("b", 128)}, wantErr: false},
		{name: "an unregistered algorithm is the storage layer's problem", target: scan.Target{Repository: "nginx", Digest: "blake3:abc"}, wantErr: false},
		{name: "no repository", target: scan.Target{Digest: digest}, wantErr: true},
		{name: "no digest", target: scan.Target{Repository: "nginx"}, wantErr: true},
		{name: "an uppercase repository", target: scan.Target{Repository: "Team-A/api", Digest: digest}, wantErr: true},
		{name: "a traversing repository", target: scan.Target{Repository: "../../etc", Digest: digest}, wantErr: true},
		{name: "a digest with no algorithm", target: scan.Target{Repository: "nginx", Digest: ":" + strings.Repeat("a", 64)}, wantErr: true},
		{name: "a digest with no hex", target: scan.Target{Repository: "nginx", Digest: "sha256:"}, wantErr: true},
		{name: "a digest with no colon", target: scan.Target{Repository: "nginx", Digest: strings.Repeat("a", 64)}, wantErr: true},
		{name: "a traversing digest", target: scan.Target{Repository: "nginx", Digest: "sha256:../../../etc/passwd"}, wantErr: true},
		{name: "a digest with a separator", target: scan.Target{Repository: "nginx", Digest: "sha256:aa/bb"}, wantErr: true},
		{name: "a digest with a backslash", target: scan.Target{Repository: "nginx", Digest: `sha256:aa\bb`}, wantErr: true},
		{name: "a digest with a space", target: scan.Target{Repository: "nginx", Digest: "sha256:aa bb"}, wantErr: true},
		{name: "a digest with a null byte", target: scan.Target{Repository: "nginx", Digest: "sha256:aa\x00bb"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.target.Validate()
			if tc.wantErr {
				if !errors.Is(err, scan.ErrInvalidTarget) {
					t.Fatalf("Validate() = %v, want ErrInvalidTarget", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestTargetRepositoryGrammarIsShared pins the design decision that the target
// does not carry its own idea of a legal repository name. A second grammar here
// would be a second answer to the question binding patterns and the router
// already answer, and the two would differ on exactly the input that matters.
func TestTargetRepositoryGrammarIsShared(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"team-a/api", "a/b/c/d", "x", "lib__x", "a-b.c_d/e"} {
		target := scan.Target{Repository: name, Digest: "sha256:abc"}
		if got, want := target.Validate() == nil, reponame.Valid(name); got != want {
			t.Errorf("Target.Validate accepts %q = %v, reponame.Valid = %v", name, got, want)
		}
	}
	for _, name := range []string{"", "UPPER", "a//b", "/a", "a/", "a b", "../x"} {
		target := scan.Target{Repository: name, Digest: "sha256:abc"}
		if target.Validate() == nil && !reponame.Valid(name) {
			t.Errorf("Target.Validate accepted %q, which is not a legal repository name", name)
		}
	}
}

func TestTargetString(t *testing.T) {
	t.Parallel()

	target := scan.Target{Repository: "team-a/api", Digest: "sha256:abc"}
	if got, want := target.String(), "team-a/api@sha256:abc"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestDatabaseVersion(t *testing.T) {
	t.Parallel()

	var zero scan.DatabaseVersion
	if !zero.IsZero() {
		t.Error("the zero DatabaseVersion does not report itself as zero")
	}
	if got := zero.String(); got != "" {
		t.Errorf("String() on the zero version = %q, want empty", got)
	}

	built := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	v := scan.DatabaseVersion{ID: "2026-03-01", UpdatedAt: built}
	if v.IsZero() {
		t.Error("a populated version reports itself as zero")
	}
	if got, want := v.String(), "2026-03-01"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestDatabaseVersionChangedIgnoresTimestamps is the rescan trigger's whole
// contract (S-005): re-reading the same database at a later time must not look
// like a new database, or every restart re-enqueues the registry.
func TestDatabaseVersionChangedIgnoresTimestamps(t *testing.T) {
	t.Parallel()

	first := scan.DatabaseVersion{ID: "2026-03-01", UpdatedAt: time.Date(2026, time.March, 1, 6, 0, 0, 0, time.UTC)}
	reimported := scan.DatabaseVersion{ID: "2026-03-01", UpdatedAt: time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)}
	newer := scan.DatabaseVersion{ID: "2026-03-02", UpdatedAt: first.UpdatedAt}

	if first.Changed(reimported) {
		t.Error("the same database re-read at a later time reads as changed")
	}
	if !first.Changed(newer) {
		t.Error("a different database does not read as changed")
	}
	if first.Changed(first) {
		t.Error("a version reports itself as changed")
	}
	if !first.Changed(scan.DatabaseVersion{}) {
		t.Error("losing the database does not read as changed")
	}
}

func TestDatabaseSourceOffline(t *testing.T) {
	t.Parallel()

	if (scan.DatabaseSource{}).Offline() {
		t.Error("the default source claims to be offline; empty means the configured remote")
	}
	if !(scan.DatabaseSource{ArchivePath: "/var/lib/trove/db.tar.gz"}).Offline() {
		t.Error("an archive source does not report itself as offline")
	}
}

// TestEngineComposesTheADRInterface pins the one place S-001 departs from
// ADR 0017's sketch: the ADR draws Scan, DBVersion, and UpdateDB as one
// interface, and this package splits the update off so that the queue, the
// rescan pass, and the gating evaluator do not depend on it. Engine is the
// ADR's interface, reassembled, and an implementation of it satisfies both
// halves.
func TestEngineComposesTheADRInterface(t *testing.T) {
	t.Parallel()

	var engine scan.Engine = stubEngine{}
	var scanner scan.Scanner = engine
	var updater scan.DatabaseUpdater = engine

	if scanner.Name() != "stub" {
		t.Errorf("Name() = %q, want %q", scanner.Name(), "stub")
	}
	if err := updater.UpdateDB(t.Context(), scan.DatabaseSource{}); err != nil {
		t.Errorf("UpdateDB: %v", err)
	}
}

// stubEngine is the smallest thing that satisfies the frozen interface, so the
// composition above is checked by the compiler and not by a comment.
type stubEngine struct{}

func (stubEngine) Name() string    { return "stub" }
func (stubEngine) Version() string { return "0" }

func (stubEngine) DatabaseVersion(context.Context) (scan.DatabaseVersion, error) {
	return scan.DatabaseVersion{}, scan.ErrDatabaseUnavailable
}

func (stubEngine) Scan(context.Context, scan.Target) (scan.Report, error) {
	return scan.Report{}, scan.ErrScanFailed
}

func (stubEngine) UpdateDB(context.Context, scan.DatabaseSource) error { return nil }

// TestSentinelsAreDistinct guards the error vocabulary callers branch on. A
// sentinel that matched another would collapse two operator actions -- import a
// database, fix a broken scanner -- into one.
func TestSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"ErrInvalidTarget":       scan.ErrInvalidTarget,
		"ErrInvalidReport":       scan.ErrInvalidReport,
		"ErrInvalidSeverity":     scan.ErrInvalidSeverity,
		"ErrInvalidStatus":       scan.ErrInvalidStatus,
		"ErrScanFailed":          scan.ErrScanFailed,
		"ErrDatabaseUnavailable": scan.ErrDatabaseUnavailable,
	}
	for name, err := range sentinels {
		if err == nil {
			t.Fatalf("%s is nil", name)
		}
		for otherName, other := range sentinels {
			if name == otherName {
				continue
			}
			if errors.Is(err, other) {
				t.Errorf("errors.Is(%s, %s) is true; the two are not distinguishable", name, otherName)
			}
		}
	}
}
