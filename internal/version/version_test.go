package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetReportsRuntimeFacts(t *testing.T) {
	t.Parallel()

	got := Get()

	if got.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", got.GoVersion, runtime.Version())
	}
	want := runtime.GOOS + "/" + runtime.GOARCH
	if got.Platform != want {
		t.Errorf("Platform = %q, want %q", got.Platform, want)
	}
	for _, f := range []struct{ name, value string }{
		{"Version", got.Version},
		{"Commit", got.Commit},
		{"Date", got.Date},
	} {
		if f.value == "" {
			t.Errorf("%s is empty; ldflags defaults must be non-empty", f.name)
		}
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		info Info
		want []string
	}{
		{
			name: "stamped release",
			info: Info{
				Version:   "1.2.3",
				Commit:    "abc1234",
				Date:      "2026-09-01T10:00:00Z",
				GoVersion: "go1.23.0",
				Platform:  "linux/amd64",
			},
			want: []string{"trove 1.2.3", "abc1234", "2026-09-01T10:00:00Z", "go1.23.0", "linux/amd64"},
		},
		{
			name: "unstamped developer build",
			info: Info{
				Version:   "dev",
				Commit:    "unknown",
				Date:      "unknown",
				GoVersion: "go1.23.0",
				Platform:  "windows/amd64",
			},
			want: []string{"trove dev", "unknown", "windows/amd64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.info.String()
			for _, substr := range tt.want {
				if !strings.Contains(got, substr) {
					t.Errorf("String() = %q, missing %q", got, substr)
				}
			}
		})
	}
}
