package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/sqlutil"
)

// --- subjects ---

func scanSubject(sc sqlutil.Scanner) (meta.Subject, error) {
	var (
		subject meta.Subject
		kind    string
		created sql.NullInt64
	)
	if err := sc.Scan(&subject.ID, &subject.Name, &kind, &subject.Disabled, &created); err != nil {
		return meta.Subject{}, err
	}
	subject.Kind = meta.SubjectKind(kind)
	subject.CreatedAt = sqlutil.AsTime(created)
	return subject, nil
}

// CreateSubject stores a user, robot, or the anonymous subject. Names and ids
// are both unique across all kinds: one namespace, one code path.
func (s *Store) CreateSubject(ctx context.Context, subject meta.Subject) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if subject.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}
	if subject.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if !subject.Kind.Valid() {
		return meta.Invalid("kind", fmt.Sprintf("unknown subject kind %q", subject.Kind))
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		nameTaken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM subjects WHERE name = ?`, subject.Name)
		if err != nil {
			return err
		}
		if nameTaken {
			return meta.Conflict("subject", subject.Name)
		}
		idTaken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM subjects WHERE id = ?`, subject.ID)
		if err != nil {
			return err
		}
		if idTaken {
			return meta.Conflict("subject id", subject.ID)
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO subjects (id, name, kind, disabled, created_at) VALUES (?, ?, ?, ?, ?)`,
			subject.ID, subject.Name, string(subject.Kind), subject.Disabled, sqlutil.Millis(subject.CreatedAt))
		return err
	})
}

// GetSubject returns a subject by name.
func (s *Store) GetSubject(ctx context.Context, name string) (meta.Subject, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Subject{}, err
	}
	return s.subject(ctx, s.db, name)
}

func (s *Store) subject(ctx context.Context, q sqlutil.Querier, name string) (meta.Subject, error) {
	subject, err := scanSubject(q.QueryRowContext(ctx,
		`SELECT id, name, kind, disabled, created_at FROM subjects WHERE name = ?`, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Subject{}, meta.NotFound("subject", name)
	case err != nil:
		return meta.Subject{}, fmt.Errorf("scan subject: %w", err)
	default:
		return subject, nil
	}
}

// ListSubjects returns a page of subjects ordered by name.
func (s *Store) ListSubjects(ctx context.Context, opts meta.ListOptions) (meta.SubjectPage, error) {
	if err := s.ready(ctx); err != nil {
		return meta.SubjectPage{}, err
	}

	limit := opts.EffectiveLimit()
	subjects, err := sqlutil.Collect(ctx, s.db,
		`SELECT id, name, kind, disabled, created_at FROM subjects
		 WHERE name > ? ORDER BY name LIMIT ?`,
		[]any{opts.Cursor, limit + 1},
		func(rows *sql.Rows) (meta.Subject, error) { return scanSubject(rows) })
	if err != nil {
		return meta.SubjectPage{}, err
	}

	page := meta.SubjectPage{Subjects: subjects}
	if len(subjects) > limit {
		page.Subjects = subjects[:limit]
		page.NextCursor = subjects[limit-1].Name
	}
	return page, nil
}

// SetSubjectDisabled enables or disables a subject. Disabling is reversible
// and keeps bindings intact; deletion does not.
func (s *Store) SetSubjectDisabled(ctx context.Context, name string, disabled bool) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db, `UPDATE subjects SET disabled = ? WHERE name = ?`, disabled, name)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("subject", name)
	}
	return nil
}

// DeleteSubject removes a subject with its group memberships, bindings, and
// secrets. A credential outliving its subject would be a usable secret
// belonging to nobody.
func (s *Store) DeleteSubject(ctx context.Context, name string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		subject, err := s.subject(ctx, tx, name)
		if err != nil {
			return err
		}
		if subject.Kind == meta.Anonymous {
			return meta.Invalid("subject", "the anonymous subject cannot be deleted: every unauthenticated request resolves to it")
		}

		// Memberships, credentials, tokens, and sessions cascade with the row.
		// Bindings do not: principal_id is polymorphic and carries no foreign
		// key, so they are removed here.
		if _, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM bindings WHERE principal_kind = ? AND principal_id = ?`,
			string(meta.PrincipalSubject), subject.ID); err != nil {
			return err
		}
		_, err = sqlutil.Execute(ctx, tx, `DELETE FROM subjects WHERE name = ?`, name)
		return err
	})
}

// --- groups ---

func scanGroup(sc sqlutil.Scanner) (meta.SubjectGroup, error) {
	var (
		group   meta.SubjectGroup
		created sql.NullInt64
	)
	if err := sc.Scan(&group.ID, &group.Name, &created); err != nil {
		return meta.SubjectGroup{}, err
	}
	group.CreatedAt = sqlutil.AsTime(created)
	return group, nil
}

// CreateGroup stores a local group.
func (s *Store) CreateGroup(ctx context.Context, group meta.SubjectGroup) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if group.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}
	if group.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM subject_groups WHERE name = ? OR id = ?`,
			group.Name, group.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("group", group.Name)
		}
		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO subject_groups (id, name, created_at) VALUES (?, ?, ?)`,
			group.ID, group.Name, sqlutil.Millis(group.CreatedAt))
		return err
	})
}

// GetGroup returns a group by name.
func (s *Store) GetGroup(ctx context.Context, name string) (meta.SubjectGroup, error) {
	if err := s.ready(ctx); err != nil {
		return meta.SubjectGroup{}, err
	}
	return s.group(ctx, s.db, name)
}

func (s *Store) group(ctx context.Context, q sqlutil.Querier, name string) (meta.SubjectGroup, error) {
	group, err := scanGroup(q.QueryRowContext(ctx,
		`SELECT id, name, created_at FROM subject_groups WHERE name = ?`, name))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.SubjectGroup{}, meta.NotFound("group", name)
	case err != nil:
		return meta.SubjectGroup{}, fmt.Errorf("scan group: %w", err)
	default:
		return group, nil
	}
}

// ListGroups returns every group, ordered by name.
func (s *Store) ListGroups(ctx context.Context) ([]meta.SubjectGroup, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db, `SELECT id, name, created_at FROM subject_groups ORDER BY name`, nil,
		func(rows *sql.Rows) (meta.SubjectGroup, error) { return scanGroup(rows) })
}

// DeleteGroup removes a group, its memberships, and its bindings.
func (s *Store) DeleteGroup(ctx context.Context, name string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		group, err := s.group(ctx, tx, name)
		if err != nil {
			return err
		}
		if _, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM bindings WHERE principal_kind = ? AND principal_id = ?`,
			string(meta.PrincipalGroup), group.ID); err != nil {
			return err
		}
		_, err = sqlutil.Execute(ctx, tx, `DELETE FROM subject_groups WHERE name = ?`, name)
		return err
	})
}

// AddGroupMember puts a subject in a group. Adding twice is not an error:
// membership is a set.
func (s *Store) AddGroupMember(ctx context.Context, group, subject string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := s.group(ctx, tx, group); err != nil {
			return err
		}
		if _, err := s.subject(ctx, tx, subject); err != nil {
			return err
		}
		_, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO group_subjects (group_name, subject_name) VALUES (?, ?)
			 ON CONFLICT (group_name, subject_name) DO NOTHING`,
			group, subject)
		return err
	})
}

// RemoveGroupMember takes a subject out of a group.
func (s *Store) RemoveGroupMember(ctx context.Context, group, subject string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := s.group(ctx, tx, group); err != nil {
			return err
		}
		affected, err := sqlutil.Execute(ctx, tx,
			`DELETE FROM group_subjects WHERE group_name = ? AND subject_name = ?`, group, subject)
		if err != nil {
			return err
		}
		if affected == 0 {
			return meta.NotFound("group member", subject)
		}
		return nil
	})
}

// ListGroupMemberSubjects returns a group's members, ordered by name.
func (s *Store) ListGroupMemberSubjects(ctx context.Context, group string) ([]meta.Subject, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := s.group(ctx, s.db, group); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT s.id, s.name, s.kind, s.disabled, s.created_at
		 FROM subjects s JOIN group_subjects gs ON gs.subject_name = s.name
		 WHERE gs.group_name = ? ORDER BY s.name`,
		[]any{group},
		func(rows *sql.Rows) (meta.Subject, error) { return scanSubject(rows) })
}

// ListSubjectGroups returns the groups a subject belongs to, ordered by name.
func (s *Store) ListSubjectGroups(ctx context.Context, subject string) ([]meta.SubjectGroup, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if _, err := s.subject(ctx, s.db, subject); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT g.id, g.name, g.created_at
		 FROM subject_groups g JOIN group_subjects gs ON gs.group_name = g.name
		 WHERE gs.subject_name = ? ORDER BY g.name`,
		[]any{subject},
		func(rows *sql.Rows) (meta.SubjectGroup, error) { return scanGroup(rows) })
}

// --- roles ---

// CreateRole stores a role. Verbs are stored expanded and explicit, one row
// each, so the vocabulary enumeration test and the explainer both see concrete
// verbs (ADR 0002).
func (s *Store) CreateRole(ctx context.Context, role meta.Role) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if role.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM roles WHERE name = ?`, role.Name)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("role", role.Name)
		}
		if _, err := sqlutil.Execute(ctx, tx, `INSERT INTO roles (name, builtin) VALUES (?, ?)`,
			role.Name, role.Builtin); err != nil {
			return err
		}
		return insertVerbs(ctx, tx, role.Name, role.Verbs)
	})
}

// insertVerbs writes a role's verb set. Repeating a verb is not an error: the
// set is what matters, and a duplicate would grant nothing extra.
func insertVerbs(ctx context.Context, tx *sql.Tx, role string, verbs []string) error {
	for _, verb := range verbs {
		if _, err := sqlutil.Execute(ctx, tx,
			`INSERT INTO role_verbs (role_name, verb) VALUES (?, ?)
			 ON CONFLICT (role_name, verb) DO NOTHING`, role, verb); err != nil {
			return err
		}
	}
	return nil
}

// GetRole returns a role by name.
func (s *Store) GetRole(ctx context.Context, name string) (meta.Role, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Role{}, err
	}
	return s.role(ctx, s.db, name)
}

func (s *Store) role(ctx context.Context, q sqlutil.Querier, name string) (meta.Role, error) {
	role := meta.Role{Name: name}
	err := q.QueryRowContext(ctx, `SELECT name, builtin FROM roles WHERE name = ?`, name).
		Scan(&role.Name, &role.Builtin)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Role{}, meta.NotFound("role", name)
	case err != nil:
		return meta.Role{}, fmt.Errorf("scan role: %w", err)
	}

	verbs, err := sqlutil.Collect(ctx, q, `SELECT verb FROM role_verbs WHERE role_name = ? ORDER BY verb`,
		[]any{name},
		func(rows *sql.Rows) (string, error) {
			var verb string
			return verb, rows.Scan(&verb)
		})
	if err != nil {
		return meta.Role{}, err
	}
	role.Verbs = verbs
	return role, nil
}

// ListRoles returns every role, ordered by name.
func (s *Store) ListRoles(ctx context.Context) ([]meta.Role, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	// One row per (role, verb) assembled in order, so listing every role's
	// permissions is one query rather than one per role.
	type roleVerb struct {
		name    string
		builtin bool
		verb    sql.NullString
	}
	rows, err := sqlutil.Collect(ctx, s.db,
		`SELECT r.name, r.builtin, v.verb
		 FROM roles r LEFT JOIN role_verbs v ON v.role_name = r.name
		 ORDER BY r.name, v.verb`, nil,
		func(rows *sql.Rows) (roleVerb, error) {
			var rv roleVerb
			return rv, rows.Scan(&rv.name, &rv.builtin, &rv.verb)
		})
	if err != nil {
		return nil, err
	}

	var out []meta.Role
	for _, rv := range rows {
		if len(out) == 0 || out[len(out)-1].Name != rv.name {
			out = append(out, meta.Role{Name: rv.name, Builtin: rv.builtin})
		}
		if rv.verb.Valid {
			current := &out[len(out)-1]
			current.Verbs = append(current.Verbs, rv.verb.String)
		}
	}
	return out, nil
}

// UpdateRoleVerbs replaces a custom role's verb set. Redefining a built-in
// would silently change what every binding to it grants, so built-ins are
// read-only.
// PutBuiltinRole creates or replaces a built-in role's definition (Z-014).
// The role row is updated in place rather than recreated, so bindings that
// name it survive: replacement is an upgrade, not a deletion.
func (s *Store) PutBuiltinRole(ctx context.Context, role meta.Role) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if !role.Builtin {
		return meta.Invalid("role", "only a built-in role may travel the seeding path")
	}
	if role.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		existing, err := s.role(ctx, tx, role.Name)
		switch {
		case errors.Is(err, meta.ErrNotFound):
			if _, err := sqlutil.Execute(ctx, tx,
				`INSERT INTO roles (name, builtin) VALUES (?, ?)`, role.Name, true); err != nil {
				return err
			}
		case err != nil:
			return err
		case !existing.Builtin:
			// A custom role of the same name is an operator's, not ours.
			return meta.Conflict("role", role.Name)
		default:
			if _, err := sqlutil.Execute(ctx, tx,
				`DELETE FROM role_verbs WHERE role_name = ?`, role.Name); err != nil {
				return err
			}
		}
		return insertVerbs(ctx, tx, role.Name, role.Verbs)
	})
}

func (s *Store) UpdateRoleVerbs(ctx context.Context, name string, verbs []string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		role, err := s.role(ctx, tx, name)
		if err != nil {
			return err
		}
		if role.Builtin {
			return meta.Invalid("role", fmt.Sprintf("built-in role %q is read-only", name))
		}
		if _, err := sqlutil.Execute(ctx, tx, `DELETE FROM role_verbs WHERE role_name = ?`, name); err != nil {
			return err
		}
		return insertVerbs(ctx, tx, name, verbs)
	})
}

// DeleteRole removes a custom role and every binding that granted it: a
// dangling binding would grant nothing yet still appear in the explainer.
func (s *Store) DeleteRole(ctx context.Context, name string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		role, err := s.role(ctx, tx, name)
		if err != nil {
			return err
		}
		if role.Builtin {
			return meta.Invalid("role", fmt.Sprintf("built-in role %q cannot be deleted", name))
		}
		_, err = sqlutil.Execute(ctx, tx, `DELETE FROM roles WHERE name = ?`, name)
		return err
	})
}

// --- bindings ---

const bindingColumns = `id, principal_kind, principal_id, role_name, scope, created_at`

func scanBinding(sc sqlutil.Scanner) (meta.Binding, error) {
	var (
		binding meta.Binding
		kind    string
		created sql.NullInt64
	)
	if err := sc.Scan(&binding.ID, &kind, &binding.PrincipalID, &binding.Role, &binding.Scope, &created); err != nil {
		return meta.Binding{}, err
	}
	binding.PrincipalKind = meta.PrincipalKind(kind)
	binding.CreatedAt = sqlutil.AsTime(created)
	return binding, nil
}

// CreateBinding grants a role to a subject or group within a scope. Bindings
// are additive and there are no deny rules, so the only integrity rules are
// that both ends exist and that the same grant is not recorded twice.
func (s *Store) CreateBinding(ctx context.Context, binding meta.Binding) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if binding.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if !binding.PrincipalKind.Valid() {
		return meta.Invalid("principal_kind", fmt.Sprintf("unknown principal kind %q", binding.PrincipalKind))
	}
	if binding.Scope == "" {
		return meta.Invalid("scope", "must not be empty")
	}

	return sqlutil.InTx(ctx, s.db, func(tx *sql.Tx) error {
		taken, err := sqlutil.Exists(ctx, tx, `SELECT 1 FROM bindings WHERE id = ?`, binding.ID)
		if err != nil {
			return err
		}
		if taken {
			return meta.Conflict("binding", binding.ID)
		}
		if _, err := s.role(ctx, tx, binding.Role); err != nil {
			return err
		}
		found, err := principalExists(ctx, tx, binding.PrincipalKind, binding.PrincipalID)
		if err != nil {
			return err
		}
		if !found {
			return meta.NotFound(string(binding.PrincipalKind), binding.PrincipalID)
		}

		// A duplicate grant adds nothing but would double-count in the
		// explainer, so it is a conflict rather than a silent no-op.
		duplicate, err := sqlutil.Exists(ctx, tx,
			`SELECT 1 FROM bindings WHERE principal_kind = ? AND principal_id = ? AND role_name = ? AND scope = ?`,
			string(binding.PrincipalKind), binding.PrincipalID, binding.Role, binding.Scope)
		if err != nil {
			return err
		}
		if duplicate {
			return meta.Conflict("binding", fmt.Sprintf("%s/%s -> %s @ %s",
				binding.PrincipalKind, binding.PrincipalID, binding.Role, binding.Scope))
		}

		_, err = sqlutil.Execute(ctx, tx,
			`INSERT INTO bindings (`+bindingColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
			binding.ID, string(binding.PrincipalKind), binding.PrincipalID,
			binding.Role, binding.Scope, sqlutil.Millis(binding.CreatedAt))
		return err
	})
}

// principalExists reports whether the subject or group a binding names is real.
func principalExists(ctx context.Context, tx *sql.Tx, kind meta.PrincipalKind, id string) (bool, error) {
	switch kind {
	case meta.PrincipalGroup:
		return sqlutil.Exists(ctx, tx, `SELECT 1 FROM subject_groups WHERE id = ?`, id)
	default:
		return sqlutil.Exists(ctx, tx, `SELECT 1 FROM subjects WHERE id = ?`, id)
	}
}

// GetBinding returns one binding by id.
func (s *Store) GetBinding(ctx context.Context, id string) (meta.Binding, error) {
	if err := s.ready(ctx); err != nil {
		return meta.Binding{}, err
	}

	binding, err := scanBinding(s.db.QueryRowContext(ctx,
		`SELECT `+bindingColumns+` FROM bindings WHERE id = ?`, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return meta.Binding{}, meta.NotFound("binding", id)
	case err != nil:
		return meta.Binding{}, fmt.Errorf("scan binding: %w", err)
	default:
		return binding, nil
	}
}

// ListBindings returns every binding, ordered by id.
func (s *Store) ListBindings(ctx context.Context) ([]meta.Binding, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	return sqlutil.Collect(ctx, s.db, `SELECT `+bindingColumns+` FROM bindings ORDER BY id`, nil,
		func(rows *sql.Rows) (meta.Binding, error) { return scanBinding(rows) })
}

// DeleteBinding removes one binding by id.
func (s *Store) DeleteBinding(ctx context.Context, id string) error {
	if err := s.ready(ctx); err != nil {
		return err
	}

	affected, err := sqlutil.Execute(ctx, s.db, `DELETE FROM bindings WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if affected == 0 {
		return meta.NotFound("binding", id)
	}
	return nil
}

// ListEffectiveBindings returns every binding that applies to a subject,
// directly or through a group, each tagged with how it arrived. This is the
// single query authorization runs per request and the same data the explainer
// renders, so the two can never disagree.
func (s *Store) ListEffectiveBindings(ctx context.Context, subjectName string) ([]meta.EffectiveBinding, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}

	subject, err := s.subject(ctx, s.db, subjectName)
	if err != nil {
		return nil, err
	}
	// A disabled subject holds nothing. Enforcing it in the query means every
	// caller gets it, rather than each remembering to check.
	if subject.Disabled {
		return nil, nil
	}

	return sqlutil.Collect(ctx, s.db,
		`SELECT b.id AS id, b.principal_kind AS principal_kind, b.principal_id AS principal_id,
		        b.role_name AS role_name, b.scope AS scope, b.created_at AS created_at, '' AS via_group
		   FROM bindings b
		   JOIN subjects s ON s.id = b.principal_id
		  WHERE b.principal_kind = 'subject' AND s.name = ?
		 UNION ALL
		 SELECT b.id, b.principal_kind, b.principal_id, b.role_name, b.scope, b.created_at, g.name
		   FROM bindings b
		   JOIN subject_groups g ON g.id = b.principal_id
		   JOIN group_subjects gs ON gs.group_name = g.name
		  WHERE b.principal_kind = 'group' AND gs.subject_name = ?
		 ORDER BY id`,
		[]any{subjectName, subjectName},
		func(rows *sql.Rows) (meta.EffectiveBinding, error) {
			var (
				effective meta.EffectiveBinding
				kind      string
				created   sql.NullInt64
			)
			if err := rows.Scan(&effective.ID, &kind, &effective.PrincipalID, &effective.Role,
				&effective.Scope, &created, &effective.ViaGroup); err != nil {
				return meta.EffectiveBinding{}, err
			}
			effective.PrincipalKind = meta.PrincipalKind(kind)
			effective.CreatedAt = sqlutil.AsTime(created)
			return effective, nil
		})
}
