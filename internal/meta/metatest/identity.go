package metatest

import (
	"errors"
	"testing"

	"github.com/steveokay/trove/internal/meta"
)

// identityTests are appended to the contract suite by Run.
func identityTests() []suiteCase {
	return []suiteCase{
		{"SubjectCRUD", testSubjectCRUD},
		{"SubjectValidation", testSubjectValidation},
		{"SubjectDisabling", testSubjectDisabling},
		{"AnonymousSubjectIsSeededAndUndeletable", testAnonymousSubjectIsSeeded},
		{"ListSubjectsPaginates", testListSubjectsPaginates},
		{"GroupMembershipIsASet", testGroupMembershipIsASet},
		{"GroupCRUD", testGroupCRUD},
		{"RoleCRUD", testRoleCRUD},
		{"BuiltinRolesAreReadOnly", testBuiltinRolesAreReadOnly},
		{"PutBuiltinRoleConverges", testPutBuiltinRoleConverges},
		{"BindingCRUD", testBindingCRUD},
		{"BindingIntegrity", testBindingIntegrity},
		{"EffectiveBindingsIncludeGroups", testEffectiveBindingsIncludeGroups},
		{"EffectiveBindingsFollowDeletions", testEffectiveBindingsFollowDeletions},
		{"DisabledSubjectHasNoPermissions", testDisabledSubjectHasNoPermissions},
	}
}

func mustCreateSubject(t *testing.T, s meta.Store, name string, kind meta.SubjectKind) meta.Subject {
	t.Helper()

	subject := meta.Subject{ID: "id-" + name, Kind: kind, Name: name, CreatedAt: testTime}
	if err := s.CreateSubject(ctx(), subject); err != nil {
		t.Fatalf("CreateSubject(%q): %v", name, err)
	}
	return subject
}

func mustCreateGroup(t *testing.T, s meta.Store, name string) meta.SubjectGroup {
	t.Helper()

	group := meta.SubjectGroup{ID: "gid-" + name, Name: name, CreatedAt: testTime}
	if err := s.CreateGroup(ctx(), group); err != nil {
		t.Fatalf("CreateGroup(%q): %v", name, err)
	}
	return group
}

func mustCreateRole(t *testing.T, s meta.Store, name string, verbs ...string) meta.Role {
	t.Helper()

	role := meta.Role{Name: name, Verbs: verbs}
	if err := s.CreateRole(ctx(), role); err != nil {
		t.Fatalf("CreateRole(%q): %v", name, err)
	}
	return role
}

func testSubjectCRUD(t *testing.T, s meta.Store) {
	created := mustCreateSubject(t, s, "alice", meta.User)

	got, err := s.GetSubject(ctx(), "alice")
	if err != nil {
		t.Fatalf("GetSubject: %v", err)
	}
	if got.ID != created.ID || got.Kind != meta.User || got.Disabled {
		t.Errorf("subject = %+v, want it to round-trip enabled", got)
	}

	// Robots and users share one namespace and one code path.
	mustCreateSubject(t, s, "robot$ci", meta.Robot)

	if err := s.DeleteSubject(ctx(), "alice"); err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}
	_, err = s.GetSubject(ctx(), "alice")
	requireErrIs(t, err, meta.ErrNotFound, "GetSubject after delete")
	requireErrIs(t, s.DeleteSubject(ctx(), "alice"), meta.ErrNotFound, "DeleteSubject twice")
}

func testSubjectValidation(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "taken", meta.User)

	tests := []struct {
		name    string
		subject meta.Subject
		want    error
	}{
		{"empty name", meta.Subject{ID: "x", Kind: meta.User}, meta.ErrInvalid},
		{"empty id", meta.Subject{Name: "x", Kind: meta.User}, meta.ErrInvalid},
		{"unknown kind", meta.Subject{ID: "x", Name: "x", Kind: meta.SubjectKind("service")}, meta.ErrInvalid},
		{"duplicate name", meta.Subject{ID: "other", Name: "taken", Kind: meta.User}, meta.ErrConflict},
		{"duplicate id", meta.Subject{ID: "id-taken", Name: "different", Kind: meta.User}, meta.ErrConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireErrIs(t, s.CreateSubject(ctx(), tt.subject), tt.want, "CreateSubject")
		})
	}
}

func testSubjectDisabling(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "bob", meta.User)

	if err := s.SetSubjectDisabled(ctx(), "bob", true); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}
	got, err := s.GetSubject(ctx(), "bob")
	if err != nil {
		t.Fatalf("GetSubject: %v", err)
	}
	if !got.Disabled {
		t.Error("subject is not disabled")
	}

	// Disabling is reversible; deleting is not. Both must exist.
	if err := s.SetSubjectDisabled(ctx(), "bob", false); err != nil {
		t.Fatalf("SetSubjectDisabled(false): %v", err)
	}
	got, err = s.GetSubject(ctx(), "bob")
	if err != nil {
		t.Fatalf("GetSubject: %v", err)
	}
	if got.Disabled {
		t.Error("subject did not come back enabled")
	}

	requireErrIs(t, s.SetSubjectDisabled(ctx(), "ghost", true), meta.ErrNotFound, "SetSubjectDisabled on a missing subject")
}

// A fresh store already holds the anonymous subject. Every request with no
// credentials resolves to it (ADR 0001), so a store without it would force a
// special case into the one authorization path -- and the special case is what
// the model exists to avoid.
func testAnonymousSubjectIsSeeded(t *testing.T, s meta.Store) {
	anonymous, err := s.GetSubject(ctx(), meta.AnonymousSubjectName)
	if err != nil {
		t.Fatalf("the anonymous subject is not seeded: %v", err)
	}
	if anonymous.Kind != meta.Anonymous {
		t.Errorf("kind = %q, want %q", anonymous.Kind, meta.Anonymous)
	}
	// Bindings reference subject ids, so an operator granting anonymous access
	// binds to this value. A generated id would differ between deployments and
	// make the grant unportable.
	if anonymous.ID != meta.AnonymousSubjectID {
		t.Errorf("id = %q, want the reserved %q", anonymous.ID, meta.AnonymousSubjectID)
	}
	if anonymous.Disabled {
		t.Error("the anonymous subject is seeded disabled")
	}

	// Seeding is not creation: the name is taken, like any other.
	requireErrIs(t, s.CreateSubject(ctx(), meta.Subject{
		ID: "id-other", Kind: meta.Anonymous, Name: meta.AnonymousSubjectName,
	}), meta.ErrConflict, "CreateSubject(anonymous) on a seeded store")

	// Deleting it would turn the one authorization path into a special case.
	err = s.DeleteSubject(ctx(), meta.AnonymousSubjectName)
	requireErrIs(t, err, meta.ErrInvalid, "DeleteSubject(anonymous)")

	// It can still be disabled, which is how an operator turns anonymous
	// access off wholesale without unpicking its bindings.
	if err := s.SetSubjectDisabled(ctx(), meta.AnonymousSubjectName, true); err != nil {
		t.Errorf("SetSubjectDisabled(anonymous): %v", err)
	}
	if err := s.SetSubjectDisabled(ctx(), meta.AnonymousSubjectName, false); err != nil {
		t.Errorf("SetSubjectDisabled(anonymous, false): %v", err)
	}
}

func testListSubjectsPaginates(t *testing.T, s meta.Store) {
	const created = 5
	for i := 0; i < created; i++ {
		mustCreateSubject(t, s, string(rune('a'+i))+"-user", meta.User)
	}
	// Plus the seeded anonymous subject: a listing shows what is there, and
	// what is there always includes it.
	const total = created + 1

	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > total {
			t.Fatal("subject pagination did not terminate")
		}
		page, err := s.ListSubjects(ctx(), meta.ListOptions{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListSubjects: %v", err)
		}
		for _, subject := range page.Subjects {
			seen = append(seen, subject.Name)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if len(seen) != total {
		t.Fatalf("stitched pages returned %d subjects, want %d: %v", len(seen), total, seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("subjects are not ordered or repeat: %v", seen)
		}
	}
}

func testGroupCRUD(t *testing.T, s meta.Store) {
	mustCreateGroup(t, s, "platform")

	got, err := s.GetGroup(ctx(), "platform")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.ID != "gid-platform" {
		t.Errorf("group = %+v, want it to round-trip", got)
	}

	requireErrIs(t, s.CreateGroup(ctx(), meta.SubjectGroup{ID: "x", Name: "platform"}), meta.ErrConflict, "CreateGroup twice")
	requireErrIs(t, s.CreateGroup(ctx(), meta.SubjectGroup{ID: "x"}), meta.ErrInvalid, "CreateGroup without a name")
	requireErrIs(t, s.CreateGroup(ctx(), meta.SubjectGroup{Name: "x"}), meta.ErrInvalid, "CreateGroup without an id")

	mustCreateGroup(t, s, "auditors")
	groups, err := s.ListGroups(ctx())
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 2 || groups[0].Name != "auditors" {
		t.Errorf("groups = %+v, want both ordered by name", groups)
	}

	if err := s.DeleteGroup(ctx(), "auditors"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	requireErrIs(t, s.DeleteGroup(ctx(), "auditors"), meta.ErrNotFound, "DeleteGroup twice")
	_, err = s.GetGroup(ctx(), "auditors")
	requireErrIs(t, err, meta.ErrNotFound, "GetGroup after delete")
}

func testGroupMembershipIsASet(t *testing.T, s meta.Store) {
	mustCreateSubject(t, s, "alice", meta.User)
	mustCreateSubject(t, s, "bob", meta.User)
	mustCreateGroup(t, s, "platform")

	if err := s.AddGroupMember(ctx(), "platform", "alice"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	// Adding twice is not an error: membership is a set, and an admin
	// re-adding somebody should not be punished for it.
	if err := s.AddGroupMember(ctx(), "platform", "alice"); err != nil {
		t.Fatalf("AddGroupMember (repeat): %v", err)
	}
	if err := s.AddGroupMember(ctx(), "platform", "bob"); err != nil {
		t.Fatalf("AddGroupMember(bob): %v", err)
	}

	members, err := s.ListGroupMemberSubjects(ctx(), "platform")
	if err != nil {
		t.Fatalf("ListGroupMemberSubjects: %v", err)
	}
	if len(members) != 2 || members[0].Name != "alice" || members[1].Name != "bob" {
		t.Errorf("members = %+v, want alice and bob ordered by name", members)
	}

	groups, err := s.ListSubjectGroups(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListSubjectGroups: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "platform" {
		t.Errorf("groups = %+v, want platform", groups)
	}

	if err := s.RemoveGroupMember(ctx(), "platform", "alice"); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	requireErrIs(t, s.RemoveGroupMember(ctx(), "platform", "alice"), meta.ErrNotFound, "RemoveGroupMember twice")

	requireErrIs(t, s.AddGroupMember(ctx(), "ghost", "alice"), meta.ErrNotFound, "AddGroupMember to a missing group")
	requireErrIs(t, s.AddGroupMember(ctx(), "platform", "ghost"), meta.ErrNotFound, "AddGroupMember of a missing subject")
	_, err = s.ListGroupMemberSubjects(ctx(), "ghost")
	requireErrIs(t, err, meta.ErrNotFound, "ListGroupMemberSubjects of a missing group")
	_, err = s.ListSubjectGroups(ctx(), "ghost")
	requireErrIs(t, err, meta.ErrNotFound, "ListSubjectGroups of a missing subject")
	requireErrIs(t, s.RemoveGroupMember(ctx(), "ghost", "alice"), meta.ErrNotFound, "RemoveGroupMember from a missing group")
}

func testRoleCRUD(t *testing.T, s meta.Store) {
	mustCreateRole(t, s, "publisher", "repo:read", "repo:write", "tag:delete")

	got, err := s.GetRole(ctx(), "publisher")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if len(got.Verbs) != 3 {
		t.Errorf("verbs = %v, want three", got.Verbs)
	}
	if got.Builtin {
		t.Error("a created role must not claim to be built in")
	}

	// Mutating a returned role must not reach stored state.
	got.Verbs[0] = "system:maintenance"
	again, err := s.GetRole(ctx(), "publisher")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	for _, v := range again.Verbs {
		if v == "system:maintenance" {
			t.Fatal("mutating a returned role changed stored permissions")
		}
	}

	if err := s.UpdateRoleVerbs(ctx(), "publisher", []string{"repo:read"}); err != nil {
		t.Fatalf("UpdateRoleVerbs: %v", err)
	}
	got, err = s.GetRole(ctx(), "publisher")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if len(got.Verbs) != 1 || got.Verbs[0] != "repo:read" {
		t.Errorf("verbs = %v, want the replacement set", got.Verbs)
	}

	// Roles are listed by the admin API and the role editor, ordered by name.
	mustCreateRole(t, s, "auditor", "audit:read")
	roles, err := s.ListRoles(ctx())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 2 || roles[0].Name != "auditor" || roles[1].Name != "publisher" {
		t.Fatalf("roles = %+v, want both ordered by name", roles)
	}
	roles[0].Verbs = append(roles[0].Verbs, "role:write")
	if again, err := s.GetRole(ctx(), "auditor"); err != nil {
		t.Fatalf("GetRole: %v", err)
	} else if len(again.Verbs) != 1 {
		t.Errorf("mutating a listed role changed stored permissions: %v", again.Verbs)
	}

	requireErrIs(t, s.CreateRole(ctx(), meta.Role{Name: "publisher"}), meta.ErrConflict, "CreateRole twice")
	requireErrIs(t, s.CreateRole(ctx(), meta.Role{}), meta.ErrInvalid, "CreateRole without a name")
	requireErrIs(t, s.UpdateRoleVerbs(ctx(), "ghost", nil), meta.ErrNotFound, "UpdateRoleVerbs on a missing role")
	requireErrIs(t, s.DeleteRole(ctx(), "ghost"), meta.ErrNotFound, "DeleteRole on a missing role")

	if err := s.DeleteRole(ctx(), "publisher"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	_, err = s.GetRole(ctx(), "publisher")
	requireErrIs(t, err, meta.ErrNotFound, "GetRole after delete")
}

func testPutBuiltinRoleConverges(t *testing.T, s meta.Store) {
	// The seeding path (Z-014). Operators cannot edit built-ins, but the
	// system itself must be able to bring "admin means every verb" back to
	// true after an upgrade grows the vocabulary -- or after somebody edits
	// the row in the database, which this heals at the next start.

	// Only a role marked builtin may travel this path.
	requireErrIs(t, s.PutBuiltinRole(ctx(), meta.Role{Name: "sneaky", Verbs: []string{"repo:read"}}),
		meta.ErrInvalid, "PutBuiltinRole without the builtin flag")
	requireErrIs(t, s.PutBuiltinRole(ctx(), meta.Role{Builtin: true, Verbs: []string{"repo:read"}}),
		meta.ErrInvalid, "PutBuiltinRole without a name")

	// Creates when absent.
	if err := s.PutBuiltinRole(ctx(), meta.Role{
		Name: "admin", Builtin: true, Verbs: []string{"repo:read", "repo:write"},
	}); err != nil {
		t.Fatalf("PutBuiltinRole (create): %v", err)
	}
	got, err := s.GetRole(ctx(), "admin")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if !got.Builtin || len(got.Verbs) != 2 {
		t.Fatalf("stored role = %+v, want builtin with two verbs", got)
	}

	// A binding referencing the role must survive replacement: replacing the
	// definition is an upgrade, not a deletion, and an engine that modelled it
	// as delete-and-recreate would cascade every admin binding away.
	mustCreateSubject(t, s, "alice", meta.User)
	if err := s.CreateBinding(ctx(), meta.Binding{
		ID: "b-keep", PrincipalKind: meta.PrincipalSubject, PrincipalID: "id-alice",
		Role: "admin", Scope: "system",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	// Replaces wholesale when present: the new set is exact, not merged.
	if err := s.PutBuiltinRole(ctx(), meta.Role{
		Name: "admin", Builtin: true, Verbs: []string{"repo:read", "user:write", "gc:run"},
	}); err != nil {
		t.Fatalf("PutBuiltinRole (replace): %v", err)
	}
	got, err = s.GetRole(ctx(), "admin")
	if err != nil {
		t.Fatalf("GetRole after replace: %v", err)
	}
	want := map[string]bool{"repo:read": true, "user:write": true, "gc:run": true}
	if len(got.Verbs) != len(want) {
		t.Fatalf("verbs after replace = %v, want exactly %v", got.Verbs, want)
	}
	for _, verb := range got.Verbs {
		if !want[verb] {
			t.Fatalf("verbs after replace = %v, want exactly %v", got.Verbs, want)
		}
	}
	if !got.Builtin {
		t.Error("replacement dropped the builtin flag")
	}
	if _, err := s.GetBinding(ctx(), "b-keep"); err != nil {
		t.Errorf("GetBinding after replace: %v, want the binding to survive", err)
	}

	// A custom role is an operator's, and this path may not overwrite it.
	if err := s.CreateRole(ctx(), meta.Role{Name: "theirs", Verbs: []string{"repo:read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	requireErrIs(t, s.PutBuiltinRole(ctx(), meta.Role{Name: "theirs", Builtin: true, Verbs: []string{"gc:run"}}),
		meta.ErrConflict, "PutBuiltinRole over a custom role")
	got, err = s.GetRole(ctx(), "theirs")
	if err != nil {
		t.Fatalf("GetRole(theirs): %v", err)
	}
	if got.Builtin || len(got.Verbs) != 1 || got.Verbs[0] != "repo:read" {
		t.Errorf("custom role after refused put = %+v, want it untouched", got)
	}
}

func testBuiltinRolesAreReadOnly(t *testing.T, s meta.Store) {
	if err := s.CreateRole(ctx(), meta.Role{
		Name: "admin", Builtin: true, Verbs: []string{"repo:read", "role:write"},
	}); err != nil {
		t.Fatalf("CreateRole(builtin): %v", err)
	}

	// Redefining "admin" would silently change what every admin binding
	// grants, so the store refuses both edits and deletion.
	requireErrIs(t, s.UpdateRoleVerbs(ctx(), "admin", []string{"repo:read"}), meta.ErrInvalid, "UpdateRoleVerbs on a built-in role")
	requireErrIs(t, s.DeleteRole(ctx(), "admin"), meta.ErrInvalid, "DeleteRole on a built-in role")

	got, err := s.GetRole(ctx(), "admin")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if len(got.Verbs) != 2 {
		t.Errorf("verbs = %v, want the built-in set untouched", got.Verbs)
	}
	if !got.Builtin {
		t.Error("Builtin flag did not round-trip")
	}
}

func testBindingCRUD(t *testing.T, s meta.Store) {
	alice := mustCreateSubject(t, s, "alice", meta.User)
	mustCreateRole(t, s, "developer", "repo:read")

	binding := meta.Binding{
		ID:            "b1",
		PrincipalKind: meta.PrincipalSubject,
		PrincipalID:   alice.ID,
		Role:          "developer",
		Scope:         "team-a/*",
		CreatedAt:     testTime,
	}
	if err := s.CreateBinding(ctx(), binding); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	got, err := s.GetBinding(ctx(), "b1")
	if err != nil {
		t.Fatalf("GetBinding: %v", err)
	}
	if got.Scope != "team-a/*" || got.Role != "developer" {
		t.Errorf("binding = %+v, want it to round-trip", got)
	}

	all, err := s.ListBindings(ctx())
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("got %d bindings, want 1", len(all))
	}

	if err := s.DeleteBinding(ctx(), "b1"); err != nil {
		t.Fatalf("DeleteBinding: %v", err)
	}
	requireErrIs(t, s.DeleteBinding(ctx(), "b1"), meta.ErrNotFound, "DeleteBinding twice")
	_, err = s.GetBinding(ctx(), "b1")
	requireErrIs(t, err, meta.ErrNotFound, "GetBinding after delete")
}

func testBindingIntegrity(t *testing.T, s meta.Store) {
	alice := mustCreateSubject(t, s, "alice", meta.User)
	group := mustCreateGroup(t, s, "platform")
	mustCreateRole(t, s, "developer", "repo:read")

	valid := meta.Binding{
		ID: "b1", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID,
		Role: "developer", Scope: "team-a/*",
	}
	if err := s.CreateBinding(ctx(), valid); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	tests := []struct {
		name    string
		binding meta.Binding
		want    error
	}{
		{
			name:    "duplicate id",
			binding: meta.Binding{ID: "b1", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID, Role: "developer", Scope: "other/*"},
			want:    meta.ErrConflict,
		},
		{
			// Two identical grants add nothing but would double-count in the
			// explainer, making effective permissions harder to read.
			name:    "duplicate grant",
			binding: meta.Binding{ID: "b2", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID, Role: "developer", Scope: "team-a/*"},
			want:    meta.ErrConflict,
		},
		{
			name:    "missing role",
			binding: meta.Binding{ID: "b3", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID, Role: "ghost", Scope: "*"},
			want:    meta.ErrNotFound,
		},
		{
			name:    "missing subject",
			binding: meta.Binding{ID: "b4", PrincipalKind: meta.PrincipalSubject, PrincipalID: "nobody", Role: "developer", Scope: "*"},
			want:    meta.ErrNotFound,
		},
		{
			name:    "missing group",
			binding: meta.Binding{ID: "b5", PrincipalKind: meta.PrincipalGroup, PrincipalID: "nogroup", Role: "developer", Scope: "*"},
			want:    meta.ErrNotFound,
		},
		{
			name:    "unknown principal kind",
			binding: meta.Binding{ID: "b6", PrincipalKind: meta.PrincipalKind("robotic"), PrincipalID: alice.ID, Role: "developer", Scope: "*"},
			want:    meta.ErrInvalid,
		},
		{
			name:    "empty scope",
			binding: meta.Binding{ID: "b7", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID, Role: "developer"},
			want:    meta.ErrInvalid,
		},
		{
			name:    "empty id",
			binding: meta.Binding{PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID, Role: "developer", Scope: "*"},
			want:    meta.ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireErrIs(t, s.CreateBinding(ctx(), tt.binding), tt.want, "CreateBinding")
		})
	}

	// The same role and scope granted to a group is a different binding.
	if err := s.CreateBinding(ctx(), meta.Binding{
		ID: "b8", PrincipalKind: meta.PrincipalGroup, PrincipalID: group.ID,
		Role: "developer", Scope: "team-a/*",
	}); err != nil {
		t.Errorf("CreateBinding for a group with the same grant: %v", err)
	}
}

func testEffectiveBindingsIncludeGroups(t *testing.T, s meta.Store) {
	alice := mustCreateSubject(t, s, "alice", meta.User)
	mustCreateSubject(t, s, "bob", meta.User)
	group := mustCreateGroup(t, s, "platform")
	mustCreateRole(t, s, "developer", "repo:read")
	mustCreateRole(t, s, "operator", "repo:write")

	if err := s.AddGroupMember(ctx(), "platform", "alice"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}

	direct := meta.Binding{
		ID: "b-direct", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID,
		Role: "developer", Scope: "team-a/*",
	}
	viaGroup := meta.Binding{
		ID: "b-group", PrincipalKind: meta.PrincipalGroup, PrincipalID: group.ID,
		Role: "operator", Scope: "team-b/*",
	}
	for _, b := range []meta.Binding{direct, viaGroup} {
		if err := s.CreateBinding(ctx(), b); err != nil {
			t.Fatalf("CreateBinding(%s): %v", b.ID, err)
		}
	}

	effective, err := s.ListEffectiveBindings(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 2 {
		t.Fatalf("got %d effective bindings, want 2 (direct plus group)", len(effective))
	}

	// Provenance is what makes the explainer useful: "via platform" beats
	// "you have it".
	byID := map[string]meta.EffectiveBinding{}
	for _, b := range effective {
		byID[b.ID] = b
	}
	if byID["b-direct"].ViaGroup != "" {
		t.Errorf("direct binding reports ViaGroup %q, want empty", byID["b-direct"].ViaGroup)
	}
	if byID["b-group"].ViaGroup != "platform" {
		t.Errorf("group binding reports ViaGroup %q, want platform", byID["b-group"].ViaGroup)
	}

	// A subject in no groups sees only its own bindings -- here, none.
	bobs, err := s.ListEffectiveBindings(ctx(), "bob")
	if err != nil {
		t.Fatalf("ListEffectiveBindings(bob): %v", err)
	}
	if len(bobs) != 0 {
		t.Errorf("bob has %d effective bindings, want none", len(bobs))
	}

	_, err = s.ListEffectiveBindings(ctx(), "ghost")
	requireErrIs(t, err, meta.ErrNotFound, "ListEffectiveBindings for a missing subject")
}

func testEffectiveBindingsFollowDeletions(t *testing.T, s meta.Store) {
	alice := mustCreateSubject(t, s, "alice", meta.User)
	group := mustCreateGroup(t, s, "platform")
	mustCreateRole(t, s, "developer", "repo:read")

	if err := s.AddGroupMember(ctx(), "platform", "alice"); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	for _, b := range []meta.Binding{
		{ID: "b-direct", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID, Role: "developer", Scope: "a/*"},
		{ID: "b-group", PrincipalKind: meta.PrincipalGroup, PrincipalID: group.ID, Role: "developer", Scope: "b/*"},
	} {
		if err := s.CreateBinding(ctx(), b); err != nil {
			t.Fatalf("CreateBinding: %v", err)
		}
	}

	// Leaving a group revokes what the group granted, immediately.
	if err := s.RemoveGroupMember(ctx(), "platform", "alice"); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	effective, err := s.ListEffectiveBindings(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 1 || effective[0].ID != "b-direct" {
		t.Fatalf("effective = %+v, want only the direct binding after leaving the group", effective)
	}

	// Deleting a role revokes every binding that granted it: a dangling
	// binding would grant nothing yet still appear in the explainer.
	if err := s.DeleteRole(ctx(), "developer"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	effective, err = s.ListEffectiveBindings(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 0 {
		t.Errorf("effective = %+v, want none after the role was deleted", effective)
	}

	// Deleting a group takes its bindings with it.
	mustCreateRole(t, s, "auditor", "audit:read")
	if err := s.CreateBinding(ctx(), meta.Binding{
		ID: "b-group2", PrincipalKind: meta.PrincipalGroup, PrincipalID: group.ID,
		Role: "auditor", Scope: "system",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	if err := s.DeleteGroup(ctx(), "platform"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, err := s.GetBinding(ctx(), "b-group2"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("binding survived its group: %v", err)
	}

	// And deleting a subject takes its bindings with it.
	if err := s.CreateBinding(ctx(), meta.Binding{
		ID: "b-direct2", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID,
		Role: "auditor", Scope: "system",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	if err := s.DeleteSubject(ctx(), "alice"); err != nil {
		t.Fatalf("DeleteSubject: %v", err)
	}
	if _, err := s.GetBinding(ctx(), "b-direct2"); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("binding survived its subject: %v", err)
	}
}

func testDisabledSubjectHasNoPermissions(t *testing.T, s meta.Store) {
	alice := mustCreateSubject(t, s, "alice", meta.User)
	mustCreateRole(t, s, "admin-ish", "repo:read", "repo:write")

	if err := s.CreateBinding(ctx(), meta.Binding{
		ID: "b1", PrincipalKind: meta.PrincipalSubject, PrincipalID: alice.ID,
		Role: "admin-ish", Scope: "*",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	effective, err := s.ListEffectiveBindings(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 1 {
		t.Fatalf("got %d effective bindings, want 1 while enabled", len(effective))
	}

	// Disabling must take effect everywhere at once. Returning bindings here
	// and relying on each caller to check Disabled is how a revoked account
	// keeps working somewhere nobody remembered.
	if err := s.SetSubjectDisabled(ctx(), "alice", true); err != nil {
		t.Fatalf("SetSubjectDisabled: %v", err)
	}
	effective, err = s.ListEffectiveBindings(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 0 {
		t.Errorf("a disabled subject reported %d effective bindings, want none", len(effective))
	}

	// Re-enabling restores them: the bindings were never deleted.
	if err := s.SetSubjectDisabled(ctx(), "alice", false); err != nil {
		t.Fatalf("SetSubjectDisabled(false): %v", err)
	}
	effective, err = s.ListEffectiveBindings(ctx(), "alice")
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 1 {
		t.Errorf("re-enabled subject has %d effective bindings, want 1", len(effective))
	}
}
