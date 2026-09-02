package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/metatest"
)

// A store whose database has failed must say so. Returning a zero value and a
// nil error would read as "no such repository" or "no bindings", which is how
// a broken database turns into a silent authorization or deletion bug.

// openInternal opens a store from inside the package, so a test can reach the
// handle and break it deliberately.
func openInternal(t *testing.T) *Store {
	t.Helper()

	store, err := Open(context.Background(), Options{
		Path: filepath.Join(t.TempDir(), "trove.db"),
		Now:  func() time.Time { return migrateTestTime },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

// TestEveryMethodSurfacesADeadDatabase closes the handle without closing the
// store, so every method gets past its open check and then fails on its first
// statement.
func TestEveryMethodSurfacesADeadDatabase(t *testing.T) {
	t.Parallel()

	store := openInternal(t)
	if err := store.db.Close(); err != nil {
		t.Fatalf("close handle: %v", err)
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

	store := openInternal(t)
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
// the second read that a dead handle never reaches.
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

	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := seedBroken(t)
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
