package reponame_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/reponame"
)

func TestValidNames(t *testing.T) {
	t.Parallel()

	valid := []string{
		"nginx",
		"library/nginx",
		"team-a/api",
		"a",
		"0",
		"a.b",
		"a_b",
		"a__b",
		"a-b",
		"a---b",
		"deeply/nested/path/to/a/repository",
		"registry.k8s.io/pause",
		"team-a/sub.team_1/api-v2",
		strings.Repeat("a", reponame.MaxLength),
	}

	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := reponame.Validate(name); err != nil {
				t.Errorf("Validate(%q) = %v, want nil", name, err)
			}
			if !reponame.Valid(name) {
				t.Errorf("Valid(%q) = false", name)
			}
		})
	}
}

// The grammar is a security boundary, not a formality: a name reaches a
// filesystem path, an object key, a URL to an upstream, and a binding pattern.
func TestInvalidNames(t *testing.T) {
	t.Parallel()

	invalid := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"traversal", "../etc/passwd"},
		{"traversal segment", "team-a/../secret"},
		{"dot segment", "team-a/./api"},
		{"double dot alone", ".."},
		{"leading slash", "/team-a"},
		{"trailing slash", "team-a/"},
		{"empty segment", "team-a//api"},
		{"backslash", `team-a\api`},
		{"uppercase", "Team-A/api"},
		{"space", "team a"},
		{"null byte", "team\x00a"},
		{"newline", "team\na"},
		{"leading separator", "-team"},
		{"trailing separator", "team-"},
		{"leading dot", ".team"},
		{"trailing dot", "team."},
		{"leading underscore", "_team"},
		{"wildcard", "team-*"},
		{"colon", "team:tag"},
		{"at", "team@sha256"},
		{"percent encoding", "team%2fa"},
		{"unicode", "téam"},
		{"too long", strings.Repeat("a", reponame.MaxLength+1)},
		{"tab", "team\ta"},
		{"question mark", "team?a"},
		{"hash", "team#a"},
	}

	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := reponame.Validate(tt.input)
			if !errors.Is(err, reponame.ErrInvalid) {
				t.Fatalf("Validate(%q) = %v, want ErrInvalid", tt.input, err)
			}
			if reponame.Valid(tt.input) {
				t.Errorf("Valid(%q) = true", tt.input)
			}

			var invalidErr *reponame.InvalidError
			if !errors.As(err, &invalidErr) {
				t.Fatalf("error type = %T, want *reponame.InvalidError", err)
			}
			if invalidErr.Name != tt.input {
				t.Errorf("error carries %q, want %q", invalidErr.Name, tt.input)
			}
			if invalidErr.Reason == "" {
				t.Error("error carries no reason")
			}
		})
	}
}

func TestSegmentsAndPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		segments []string
		prefix   string
	}{
		{name: "nginx", segments: []string{"nginx"}, prefix: "nginx"},
		{name: "all/library/nginx", segments: []string{"all", "library", "nginx"}, prefix: "all"},
		{name: "team-a/api", segments: []string{"team-a", "api"}, prefix: "team-a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := reponame.Segments(tt.name)
			if len(got) != len(tt.segments) {
				t.Fatalf("Segments(%q) = %v, want %v", tt.name, got, tt.segments)
			}
			for i := range got {
				if got[i] != tt.segments[i] {
					t.Errorf("Segments(%q)[%d] = %q, want %q", tt.name, i, got[i], tt.segments[i])
				}
			}
			// The first segment is the entity a request routes to; the full
			// name is what bindings and catalogs use (ADR 0005).
			if got := reponame.Prefix(tt.name); got != tt.prefix {
				t.Errorf("Prefix(%q) = %q, want %q", tt.name, got, tt.prefix)
			}
		})
	}
}

// FuzzValidate asserts the property every layer downstream relies on: a name
// this package accepts is safe to put in a path, a key, or a URL.
func FuzzValidate(f *testing.F) {
	seeds := []string{
		"nginx",
		"team-a/api",
		"../etc/passwd",
		"team-a//api",
		"TEAM/api",
		"team\x00a",
		"a__b.c-d/e",
		"",
		"/",
		strings.Repeat("a/", 200),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		if err := reponame.Validate(name); err != nil {
			if !errors.Is(err, reponame.ErrInvalid) {
				t.Fatalf("Validate(%q) failed with %v, want ErrInvalid", name, err)
			}
			return
		}

		forbidden := []string{"..", "//", `\`, "\x00", ":", "@", "*", "?", "%", " ", "\t", "\n"}
		for _, substring := range forbidden {
			if strings.Contains(name, substring) {
				t.Fatalf("accepted %q, which contains %q", name, substring)
			}
		}
		switch {
		case strings.HasPrefix(name, "/"), strings.HasSuffix(name, "/"):
			t.Fatalf("accepted %q, which has an empty path component", name)
		case strings.ToLower(name) != name:
			t.Fatalf("accepted %q, which is not lowercase", name)
		case len(name) > reponame.MaxLength:
			t.Fatalf("accepted %q, which is %d characters", name, len(name))
		}

		// Every component is non-empty and starts and ends with an
		// alphanumeric, which is what makes the whole name safe to join to a
		// path without further sanitising.
		for _, segment := range reponame.Segments(name) {
			if segment == "" {
				t.Fatalf("accepted %q, which has an empty component", name)
			}
			if !alphanumeric(segment[0]) || !alphanumeric(segment[len(segment)-1]) {
				t.Fatalf("accepted %q, whose component %q is not bounded by alphanumerics", name, segment)
			}
		}
	})
}

func alphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
