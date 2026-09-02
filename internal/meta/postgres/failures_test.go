package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/metatest"
)

// A store whose database has failed must say so. Returning a zero value and a
// nil error would read as "no such repository" or "no bindings", which is how
// a broken database turns into a silent authorization or deletion bug.

// TestEveryMethodSurfacesADeadDatabase closes the pool without closing the
// store, so every method gets past its open check and then fails on its first
// statement.
func TestEveryMethodSurfacesADeadDatabase(t *testing.T) {
	t.Parallel()

	store := open(t)
	if err := store.db.Close(); err != nil {
		t.Fatalf("close pool: %v", err)
	}

	calls := metatest.Calls(context.Background(), store)
	if len(calls) != len(metatest.MethodNames()) {
		t.Fatalf("got %d calls, want one per store method", len(calls))
	}
	for _, c := range calls {
		t.Run(c.Name, func(t *testing.T) {
			if err := c.Fn(); err == nil {
				t.Errorf("%s against a dead database returned no error", c.Name)
			}
		})
	}
}

// childTables are the tables nothing else references, so they can be dropped
// to break a query without disturbing the rows a method reads first.
var childTables = []string{
	"manifest_refs", "tags", "group_members", "upload_sessions",
	"group_subjects", "role_verbs", "bindings",
	"user_credentials", "robot_credentials", "access_tokens", "sessions",
}

// cancelDigest mirrors the digest metatest builds for its per-method call
// table, so the seeded manifest is the one those calls ask for.
var cancelDigest = meta.Digest(fmt.Sprintf("sha256:%064x", []byte("cancel")))

// seedBroken builds a store holding just enough for a method to get past its
// first lookup, then drops the tables the second half of that method needs.
func seedBroken(t *testing.T) *Store {
	t.Helper()

	store := open(t)
	ctx := context.Background()

	// A group repository, so the member-list methods get past their type check.
	if _, err := store.CreateRepository(ctx, meta.Repository{Name: "repo", Type: meta.Group}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	if err := store.PutManifest(ctx, meta.Manifest{Repository: "repo", Digest: cancelDigest}, nil); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	// A robot, so the robot-credential path gets past its kind check.
	if err := store.CreateSubject(ctx, meta.Subject{ID: "s", Kind: meta.Robot, Name: "s"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	if err := store.CreateGroup(ctx, meta.SubjectGroup{ID: "g", Name: "g"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := store.CreateRole(ctx, meta.Role{Name: "r"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	for _, table := range childTables {
		if _, err := store.db.ExecContext(ctx, `DROP TABLE `+table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
	return store
}

// TestMethodsSurfaceFailuresAfterTheirFirstQuery covers the half of each
// method that runs once its lookups have succeeded: the write, the join, or
// the second read that a dead pool never reaches.
func TestMethodsSurfaceFailuresAfterTheirFirstQuery(t *testing.T) {
	t.Parallel()

	methods := []string{
		"SetGroupMembers", "ListGroupMembers",
		"PutManifest", "DeleteManifest", "ListManifestRefs",
		"PutTag", "ListTags", "CreateUpload",
		"AddGroupMember", "RemoveGroupMember", "ListGroupMemberSubjects", "ListSubjectGroups",
		"DeleteSubject", "DeleteGroup",
		"GetRole", "UpdateRoleVerbs", "DeleteRole",
		"ListEffectiveBindings",
		"PutUserCredential", "PutRobotCredential",
		"CreateAccessToken", "ListAccessTokens", "CreateSession",
	}

	store := seedBroken(t)
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			call, ok := callByName(metatest.Calls(context.Background(), store), name)
			if !ok {
				t.Fatalf("%s is not in the contract's call table", name)
			}
			if err := call(); err == nil {
				t.Errorf("%s returned no error with its tables dropped", name)
			}
		})
	}
}

// TestCreateRoleSurfacesAVerbFailure covers the verb write, which the call
// table cannot reach because it creates a role with no verbs.
func TestCreateRoleSurfacesAVerbFailure(t *testing.T) {
	t.Parallel()

	store := seedBroken(t)
	err := store.CreateRole(context.Background(), meta.Role{Name: "publisher", Verbs: []string{"repo:write"}})
	if err == nil {
		t.Error("CreateRole returned no error with role_verbs dropped")
	}
}

// asConflict only translates the one SQLSTATE that means "you lost a race".
// Anything else has to reach the caller unchanged: swallowing an unrelated
// failure as a conflict would tell an operator the wrong thing, and the
// contract's other error cases would stop being distinguishable.
func TestOnlyUniqueViolationsBecomeConflicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"unique violation", &pgconn.PgError{Code: uniqueViolation}, true},
		{"wrapped unique violation", fmt.Errorf("insert: %w", &pgconn.PgError{Code: uniqueViolation}), true},
		{"foreign key violation", &pgconn.PgError{Code: "23503"}, false},
		{"undefined table", &pgconn.PgError{Code: "42P01"}, false},
		{"not a postgres error", errors.New("connection reset"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asConflict(tt.err, "repository", "example")
			if errors.Is(got, meta.ErrConflict) != tt.want {
				t.Errorf("asConflict(%v) = %v, want ErrConflict: %v", tt.err, got, tt.want)
			}
		})
	}
}

func callByName(calls []struct {
	Name string
	Fn   func() error
}, name string) (func() error, bool) {
	for _, c := range calls {
		if c.Name == name {
			return c.Fn, true
		}
	}
	return nil, false
}
