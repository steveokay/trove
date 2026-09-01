package meta

import (
	"errors"
	"fmt"
	"testing"
)

func TestRepositoryTypeValid(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		typ  RepositoryType
		want bool
	}{
		{Hosted, true},
		{Proxy, true},
		{Group, true},
		{RepositoryType(""), false},
		{RepositoryType("virtual"), false},
		{RepositoryType("HOSTED"), false},
	} {
		if got := tt.typ.Valid(); got != tt.want {
			t.Errorf("RepositoryType(%q).Valid() = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

func TestRefKindValid(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		kind RefKind
		want bool
	}{
		{RefConfig, true},
		{RefLayer, true},
		{RefChild, true},
		{RefSubject, true},
		{RefKind(""), false},
		{RefKind("sideways"), false},
	} {
		if got := tt.kind.Valid(); got != tt.want {
			t.Errorf("RefKind(%q).Valid() = %v, want %v", tt.kind, got, tt.want)
		}
	}
}

func TestScopeFilterMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter ScopeFilter
		repo   string
		want   bool
	}{
		{"all matches anything", ScopeFilter{All: true}, "team-a/api", true},
		{"exact match", ScopeFilter{Exact: "team-a/api"}, "team-a/api", true},
		{"exact miss", ScopeFilter{Exact: "team-a/api"}, "team-a/apix", false},
		{"prefix match", ScopeFilter{Prefix: "team-a/"}, "team-a/api", true},
		{"prefix match at depth", ScopeFilter{Prefix: "team-a/"}, "team-a/sub/api", true},
		{"prefix miss", ScopeFilter{Prefix: "team-a/"}, "team-b/api", false},
		{
			// "team-a/*" grants what is under team-a/, not the bare name
			// itself, and must not match a sibling that merely starts the same
			// way -- "team-alpha/api" is a different team.
			name:   "prefix does not match a longer sibling name",
			filter: ScopeFilter{Prefix: "team-a/"},
			repo:   "team-alpha/api",
			want:   false,
		},
		{"prefix does not match the bare prefix", ScopeFilter{Prefix: "team-a/"}, "team-a/", false},
		{"empty filter matches nothing", ScopeFilter{}, "anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.filter.Matches(tt.repo); got != tt.want {
				t.Errorf("ScopeFilter%+v.Matches(%q) = %v, want %v", tt.filter, tt.repo, got, tt.want)
			}
		})
	}
}

func TestVisibility(t *testing.T) {
	t.Parallel()

	t.Run("unrestricted allows everything", func(t *testing.T) {
		t.Parallel()

		v := Unrestricted()
		if !v.IsUnrestricted() {
			t.Error("IsUnrestricted() = false")
		}
		if !v.Allows("anything/at/all") {
			t.Error("Allows() = false for an unrestricted view")
		}
		if len(v.Filters()) != 0 {
			t.Errorf("Filters() = %v, want none", v.Filters())
		}
	})

	t.Run("zero value allows nothing", func(t *testing.T) {
		t.Parallel()

		// This is the property that makes the type worth having: an
		// accidentally-empty Visibility hides everything instead of exposing
		// everything.
		var v Visibility
		if v.IsUnrestricted() {
			t.Error("the zero Visibility must not be unrestricted")
		}
		if v.Allows("team-a/api") {
			t.Error("the zero Visibility must allow nothing")
		}
	})

	t.Run("no filters allows nothing", func(t *testing.T) {
		t.Parallel()

		if VisibleTo().Allows("team-a/api") {
			t.Error("a subject with no bindings must see nothing")
		}
	})

	t.Run("union of filters", func(t *testing.T) {
		t.Parallel()

		v := VisibleTo(ScopeFilter{Prefix: "team-a/"}, ScopeFilter{Exact: "public/nginx"})
		for _, tc := range []struct {
			repo string
			want bool
		}{
			{"team-a/api", true},
			{"public/nginx", true},
			{"team-b/api", false},
		} {
			if got := v.Allows(tc.repo); got != tc.want {
				t.Errorf("Allows(%q) = %v, want %v", tc.repo, got, tc.want)
			}
		}
		if len(v.Filters()) != 2 {
			t.Errorf("Filters() returned %d filters, want 2", len(v.Filters()))
		}
	})
}

func TestListOptionsEffectiveLimit(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		limit int
		want  int
	}{
		{0, DefaultPageSize},
		{-5, DefaultPageSize},
		{1, 1},
		{50, 50},
		{MaxPageSize, MaxPageSize},
		{MaxPageSize + 1, MaxPageSize},
		{1 << 20, MaxPageSize},
	} {
		if got := (ListOptions{Limit: tt.limit}).EffectiveLimit(); got != tt.want {
			t.Errorf("ListOptions{Limit: %d}.EffectiveLimit() = %d, want %d", tt.limit, got, tt.want)
		}
	}
}

func TestErrorTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		sentinel error
		wantMsg  string
	}{
		{
			name:     "not found",
			err:      NotFound("repository", "team-a/api"),
			sentinel: ErrNotFound,
			wantMsg:  `repository "team-a/api" not found`,
		},
		{
			name:     "conflict",
			err:      Conflict("repository", "dup"),
			sentinel: ErrConflict,
			wantMsg:  `repository "dup" already exists`,
		},
		{
			name:     "referenced",
			err:      Referenced("manifest", "sha256:abc", []string{"sha256:index"}),
			sentinel: ErrReferenced,
			wantMsg:  `manifest "sha256:abc" is still referenced by [sha256:index]`,
		},
		{
			name:     "invalid",
			err:      Invalid("name", "must not be empty"),
			sentinel: ErrInvalid,
			wantMsg:  "invalid name: must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false; callers match on sentinels, never on text", tt.err, tt.sentinel)
			}
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
			// Sentinels must stay distinct: matching the wrong one would send
			// a caller down the wrong branch.
			for _, other := range []error{ErrNotFound, ErrConflict, ErrStale, ErrInvalid, ErrReferenced} {
				if other == tt.sentinel {
					continue
				}
				if errors.Is(tt.err, other) {
					t.Errorf("%v also matches %v; sentinels must not overlap", tt.err, other)
				}
			}
		})
	}
}

func TestErrorsCarryTheirDetails(t *testing.T) {
	t.Parallel()

	err := Referenced("manifest", "sha256:child", []string{"sha256:a", "sha256:b"})

	var refErr *ReferencedError
	if !errors.As(err, &refErr) {
		t.Fatalf("errors.As failed for %T", err)
	}
	if len(refErr.By) != 2 {
		t.Errorf("By = %v, want both parents so the caller can say what to delete first", refErr.By)
	}

	wrapped := fmt.Errorf("deleting child: %w", err)
	if !errors.Is(wrapped, ErrReferenced) {
		t.Error("sentinel did not survive wrapping with %w")
	}
	if !errors.As(wrapped, &refErr) {
		t.Error("typed error did not survive wrapping with %w")
	}
}
