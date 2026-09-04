package repo_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/repo"
	"github.com/steveokay/trove/internal/reponame"
)

// The resolution matrix: every shape of name the router can meet, and what it
// routes to. A name the grammar rejects never produces an entity at all —
// routing something invalid is how traversal starts.
func TestSplit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entity    string
		remainder string
		wantErr   bool
	}{
		{name: "all/library/nginx", entity: "all", remainder: "library/nginx"},
		{name: "team-a/api", entity: "team-a", remainder: "api"},
		{name: "apps", entity: "apps", remainder: ""},
		{name: "a/b", entity: "a", remainder: "b"},
		{name: "mirror/library/ubuntu.base", entity: "mirror", remainder: "library/ubuntu.base"},
		{name: "", wantErr: true},
		{name: "/leading", wantErr: true},
		{name: "trailing/", wantErr: true},
		{name: "double//slash", wantErr: true},
		{name: "Upper/case", wantErr: true},
		{name: "dots/../traversal", wantErr: true},
		{name: "under_score/_leading", wantErr: true},
		{name: strings.Repeat("a", 256), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			entity, remainder, err := repo.Split(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Split(%q) = (%q, %q), want an error", tt.name, entity, remainder)
				}
				if !errors.Is(err, reponame.ErrInvalid) {
					t.Errorf("error %v is not reponame.ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Split(%q): %v", tt.name, err)
			}
			if entity != tt.entity || remainder != tt.remainder {
				t.Errorf("Split(%q) = (%q, %q), want (%q, %q)", tt.name, entity, remainder, tt.entity, tt.remainder)
			}
		})
	}
}

// FuzzSplit holds the router to its two invariants: it never accepts what the
// grammar rejects, and what it returns reassembles into exactly the input.
func FuzzSplit(f *testing.F) {
	for _, seed := range []string{"all/library/nginx", "apps", "a/b/c/d", "..", "a//b", "system/x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		entity, remainder, err := repo.Split(name)
		if err != nil {
			if reponame.Valid(name) {
				t.Fatalf("Split rejected the valid name %q", name)
			}
			return
		}
		if !reponame.Valid(name) {
			t.Fatalf("Split accepted the invalid name %q", name)
		}
		joined := entity
		if remainder != "" {
			joined = entity + "/" + remainder
		}
		if joined != name {
			t.Fatalf("Split(%q) = (%q, %q) does not reassemble", name, entity, remainder)
		}
		if strings.Contains(entity, "/") {
			t.Fatalf("entity %q spans segments", entity)
		}
	})
}

func TestValidateEntityName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"apps", "team-a", "mirror", "a", "x2", "ubuntu.base"} {
		if err := repo.ValidateEntityName(name); err != nil {
			t.Errorf("ValidateEntityName(%q) = %v, want nil", name, err)
		}
	}
	tests := []struct {
		name   string
		reason string
	}{
		{"", "empty"},
		{"two/segments", "one path segment"},
		{"system", "reserved"},
		{"System", "lowercase"},
		{"-leading", "components"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := repo.ValidateEntityName(tt.name)
			if err == nil {
				t.Fatalf("ValidateEntityName(%q) = nil, want a refusal", tt.name)
			}
			if !errors.Is(err, reponame.ErrInvalid) {
				t.Errorf("error %v is not reponame.ErrInvalid", err)
			}
		})
	}
	// The reserved prefix is refused as an entity even though it is a legal
	// name shape: the refusal must be the entity rule, not the grammar.
	if reponame.Valid("system") != true {
		t.Fatal("the grammar itself rejects 'system'; the reservation test proves nothing")
	}
}

// The write-rules matrix (ADR 0005): only hosted takes client writes, and the
// answer depends on nothing but the type — there is no configuration
// parameter in the signature through which that could change.
func TestWritable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		t    meta.RepositoryType
		want bool
	}{
		{meta.Hosted, true},
		{meta.Proxy, false},
		{meta.Group, false},
		{meta.RepositoryType("virtual"), false},
		{meta.RepositoryType(""), false},
	}
	for _, tt := range tests {
		if got := repo.Writable(tt.t); got != tt.want {
			t.Errorf("Writable(%q) = %v, want %v", tt.t, got, tt.want)
		}
	}
}
