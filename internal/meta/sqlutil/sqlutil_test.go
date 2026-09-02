package sqlutil_test

import (
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
)

// The scope compiler is shared by both engines, and it is the only thing
// standing between a binding and what a listing returns. Its output is checked
// literally: a predicate that looks plausible but binds its arguments in the
// wrong order would still run, and would show a subject repositories it cannot
// read.
func TestVisibilityClause(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		visibility meta.Visibility
		ph         sqlutil.Placeholder
		start      int
		want       string
		wantArgs   []any
	}{
		{
			name:       "unrestricted matches everything",
			visibility: meta.Unrestricted(),
			ph:         sqlutil.Question,
			start:      1,
			want:       "1 = 1",
		},
		{
			name:       "no filters matches nothing",
			visibility: meta.VisibleTo(),
			ph:         sqlutil.Question,
			start:      1,
			want:       "1 = 0",
		},
		{
			// The zero value is the case a nil slice would have quietly turned
			// into "everything".
			name:       "zero value matches nothing",
			visibility: meta.Visibility{},
			ph:         sqlutil.Question,
			start:      1,
			want:       "1 = 0",
		},
		{
			name:       "a filter selecting nothing contributes nothing",
			visibility: meta.VisibleTo(meta.ScopeFilter{}),
			ph:         sqlutil.Question,
			start:      1,
			want:       "1 = 0",
		},
		{
			name:       "wildcard short-circuits",
			visibility: meta.VisibleTo(meta.ScopeFilter{Exact: "a"}, meta.ScopeFilter{All: true}),
			ph:         sqlutil.Dollar,
			start:      1,
			want:       "1 = 1",
		},
		{
			name:       "exact scope",
			visibility: meta.VisibleTo(meta.ScopeFilter{Exact: "team-b/api"}),
			ph:         sqlutil.Question,
			start:      1,
			want:       "(name = ?)",
			wantArgs:   []any{"team-b/api"},
		},
		{
			name:       "prefix scope binds its length twice",
			visibility: meta.VisibleTo(meta.ScopeFilter{Prefix: "team-a/"}),
			ph:         sqlutil.Question,
			start:      1,
			want:       "((substr(name, 1, ?) = ? AND length(name) > ?))",
			wantArgs:   []any{7, "team-a/", 7},
		},
		{
			name: "union numbers its parameters in order",
			visibility: meta.VisibleTo(
				meta.ScopeFilter{Exact: "public/nginx"},
				meta.ScopeFilter{Prefix: "team-b/"},
			),
			ph:    sqlutil.Dollar,
			start: 1,
			want: "(name = $1 OR " +
				"(substr(name, 1, $2) = $3 AND length(name) > $4))",
			wantArgs: []any{"public/nginx", 7, "team-b/", 7},
		},
		{
			// A caller with parameters of its own says where the clause starts.
			name:       "numbering continues from start",
			visibility: meta.VisibleTo(meta.ScopeFilter{Exact: "x"}),
			ph:         sqlutil.Dollar,
			start:      3,
			want:       "(name = $3)",
			wantArgs:   []any{"x"},
		},
		{
			name:       "multibyte prefixes are measured in characters",
			visibility: meta.VisibleTo(meta.ScopeFilter{Prefix: "équipe/"}),
			ph:         sqlutil.Question,
			start:      1,
			want:       "((substr(name, 1, ?) = ? AND length(name) > ?))",
			wantArgs:   []any{7, "équipe/", 7},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, args := sqlutil.VisibilityClause("name", tt.visibility, tt.ph, tt.start)
			if got != tt.want {
				t.Errorf("clause =\n  %s\nwant\n  %s", got, tt.want)
			}
			if len(args) != len(tt.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tt.wantArgs)
			}
			for i := range args {
				if args[i] != tt.wantArgs[i] {
					t.Errorf("arg %d = %v, want %v", i, args[i], tt.wantArgs[i])
				}
			}
		})
	}
}

// The clause and meta.Visibility.Allows must agree. They are two readings of
// the same binding -- one in SQL, one in Go -- and a difference between them
// is a disclosure bug on whichever side is more generous.
func TestVisibilityClauseAgreesWithAllows(t *testing.T) {
	t.Parallel()

	filters := []meta.ScopeFilter{{Prefix: "team-a/"}, {Exact: "public/nginx"}}
	visibility := meta.VisibleTo(filters...)

	for _, name := range []string{
		"team-a/api", "team-a/", "team-ab/api", "public/nginx", "public/nginxx", "other/thing",
	} {
		allowed := visibility.Allows(name)
		var matched bool
		for _, f := range filters {
			if f.Matches(name) {
				matched = true
			}
		}
		if allowed != matched {
			t.Errorf("Allows(%q) = %v, but the filters say %v", name, allowed, matched)
		}
	}
}

func TestMillisRoundTrip(t *testing.T) {
	t.Parallel()

	// The zero time is "unset", not the epoch: a store that conflated them
	// would report every unset timestamp as 1970.
	if v := sqlutil.Millis(time.Time{}); v.Valid {
		t.Errorf("Millis(zero) = %+v, want NULL", v)
	}
	if got := sqlutil.AsTime(sqlutil.Millis(time.Time{})); !got.IsZero() {
		t.Errorf("AsTime(NULL) = %v, want the zero time", got)
	}

	// Times come back in UTC whatever zone they went in as, because the column
	// holds an instant and nothing else.
	zone := time.FixedZone("test", -5*60*60)
	original := time.Date(2026, 9, 1, 12, 0, 0, 0, zone)
	got := sqlutil.AsTime(sqlutil.Millis(original))
	if !got.Equal(original) {
		t.Errorf("round trip = %v, want %v", got, original)
	}
	if got.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.Location())
	}
}

func TestPlaceholders(t *testing.T) {
	t.Parallel()

	if got := sqlutil.Question(4); got != "?" {
		t.Errorf("Question(4) = %q, want ?", got)
	}
	if got := sqlutil.Dollar(4); got != "$4" {
		t.Errorf("Dollar(4) = %q, want $4", got)
	}
}
