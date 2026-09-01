package memory

import (
	"context"
	"fmt"
	"sort"

	"github.com/steveokay/trove/internal/meta"
)

// --- subjects ---

// CreateSubject stores a subject.
func (s *Store) CreateSubject(ctx context.Context, subject meta.Subject) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
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
	if _, exists := s.subjects[subject.Name]; exists {
		return meta.Conflict("subject", subject.Name)
	}
	for _, existing := range s.subjects {
		if existing.ID == subject.ID {
			return meta.Conflict("subject id", subject.ID)
		}
	}

	s.subjects[subject.Name] = subject
	return nil
}

// GetSubject returns a subject by name.
func (s *Store) GetSubject(ctx context.Context, name string) (meta.Subject, error) {
	if err := ctx.Err(); err != nil {
		return meta.Subject{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Subject{}, err
	}

	subject, ok := s.subjects[name]
	if !ok {
		return meta.Subject{}, meta.NotFound("subject", name)
	}
	return subject, nil
}

// ListSubjects returns a page of subjects ordered by name.
func (s *Store) ListSubjects(ctx context.Context, opts meta.ListOptions) (meta.SubjectPage, error) {
	if err := ctx.Err(); err != nil {
		return meta.SubjectPage{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.SubjectPage{}, err
	}

	names := make([]string, 0, len(s.subjects))
	for name := range s.subjects {
		if name > opts.Cursor {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	limit := opts.EffectiveLimit()
	page := meta.SubjectPage{}
	for i, name := range names {
		if i == limit {
			page.NextCursor = names[i-1]
			break
		}
		page.Subjects = append(page.Subjects, s.subjects[name])
	}
	return page, nil
}

// SetSubjectDisabled enables or disables a subject.
func (s *Store) SetSubjectDisabled(ctx context.Context, name string, disabled bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	subject, ok := s.subjects[name]
	if !ok {
		return meta.NotFound("subject", name)
	}
	subject.Disabled = disabled
	s.subjects[name] = subject
	return nil
}

// DeleteSubject removes a subject with its memberships and bindings.
func (s *Store) DeleteSubject(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	subject, ok := s.subjects[name]
	if !ok {
		return meta.NotFound("subject", name)
	}
	if subject.Kind == meta.Anonymous {
		return meta.Invalid("subject", "the anonymous subject cannot be deleted: every unauthenticated request resolves to it")
	}

	delete(s.subjects, name)
	for group := range s.groupMembers {
		delete(s.groupMembers[group], name)
	}
	s.dropBindings(meta.PrincipalSubject, subject.ID)

	// Credentials outliving their subject would be usable secrets belonging
	// to nobody, so they go with it.
	delete(s.userCredentials, name)
	delete(s.robotCredentials, name)
	for id, token := range s.accessTokens {
		if token.Subject == name {
			delete(s.accessTokens, id)
		}
	}
	for id, session := range s.sessions {
		if session.Subject == name {
			delete(s.sessions, id)
		}
	}
	return nil
}

// --- groups ---

// CreateGroup stores a local group.
func (s *Store) CreateGroup(ctx context.Context, group meta.SubjectGroup) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if group.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}
	if group.ID == "" {
		return meta.Invalid("id", "must not be empty")
	}
	if _, exists := s.subjectGroups[group.Name]; exists {
		return meta.Conflict("group", group.Name)
	}

	s.subjectGroups[group.Name] = group
	s.groupMembers[group.Name] = make(map[string]bool)
	return nil
}

// GetGroup returns a group by name.
func (s *Store) GetGroup(ctx context.Context, name string) (meta.SubjectGroup, error) {
	if err := ctx.Err(); err != nil {
		return meta.SubjectGroup{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.SubjectGroup{}, err
	}

	group, ok := s.subjectGroups[name]
	if !ok {
		return meta.SubjectGroup{}, meta.NotFound("group", name)
	}
	return group, nil
}

// ListGroups returns every group ordered by name.
func (s *Store) ListGroups(ctx context.Context) ([]meta.SubjectGroup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	out := make([]meta.SubjectGroup, 0, len(s.subjectGroups))
	for _, g := range s.subjectGroups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteGroup removes a group, its memberships, and its bindings.
func (s *Store) DeleteGroup(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	group, ok := s.subjectGroups[name]
	if !ok {
		return meta.NotFound("group", name)
	}

	delete(s.subjectGroups, name)
	delete(s.groupMembers, name)
	s.dropBindings(meta.PrincipalGroup, group.ID)
	return nil
}

// AddGroupMember puts a subject in a group; membership is a set.
func (s *Store) AddGroupMember(ctx context.Context, group, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.subjectGroups[group]; !ok {
		return meta.NotFound("group", group)
	}
	if _, ok := s.subjects[subject]; !ok {
		return meta.NotFound("subject", subject)
	}

	s.groupMembers[group][subject] = true
	return nil
}

// RemoveGroupMember takes a subject out of a group.
func (s *Store) RemoveGroupMember(ctx context.Context, group, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.subjectGroups[group]; !ok {
		return meta.NotFound("group", group)
	}
	if !s.groupMembers[group][subject] {
		return meta.NotFound("group member", subject)
	}

	delete(s.groupMembers[group], subject)
	return nil
}

// ListGroupMemberSubjects returns a group's members ordered by name.
func (s *Store) ListGroupMemberSubjects(ctx context.Context, group string) ([]meta.Subject, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	if _, ok := s.subjectGroups[group]; !ok {
		return nil, meta.NotFound("group", group)
	}

	var out []meta.Subject
	for name := range s.groupMembers[group] {
		if subject, ok := s.subjects[name]; ok {
			out = append(out, subject)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListSubjectGroups returns the groups a subject belongs to.
func (s *Store) ListSubjectGroups(ctx context.Context, subject string) ([]meta.SubjectGroup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	if _, ok := s.subjects[subject]; !ok {
		return nil, meta.NotFound("subject", subject)
	}

	var out []meta.SubjectGroup
	for group, members := range s.groupMembers {
		if members[subject] {
			out = append(out, s.subjectGroups[group])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- roles ---

// CreateRole stores a role.
func (s *Store) CreateRole(ctx context.Context, role meta.Role) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if role.Name == "" {
		return meta.Invalid("name", "must not be empty")
	}
	if _, exists := s.roles[role.Name]; exists {
		return meta.Conflict("role", role.Name)
	}

	stored := role
	stored.Verbs = append([]string(nil), role.Verbs...)
	sort.Strings(stored.Verbs)
	s.roles[role.Name] = stored
	return nil
}

// GetRole returns a role by name.
func (s *Store) GetRole(ctx context.Context, name string) (meta.Role, error) {
	if err := ctx.Err(); err != nil {
		return meta.Role{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Role{}, err
	}

	role, ok := s.roles[name]
	if !ok {
		return meta.Role{}, meta.NotFound("role", name)
	}
	return cloneRole(role), nil
}

// ListRoles returns every role ordered by name.
func (s *Store) ListRoles(ctx context.Context) ([]meta.Role, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	out := make([]meta.Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, cloneRole(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpdateRoleVerbs replaces a custom role's verbs. Built-ins are read-only.
func (s *Store) UpdateRoleVerbs(ctx context.Context, name string, verbs []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	role, ok := s.roles[name]
	if !ok {
		return meta.NotFound("role", name)
	}
	if role.Builtin {
		return meta.Invalid("role", fmt.Sprintf("built-in role %q is read-only", name))
	}

	role.Verbs = append([]string(nil), verbs...)
	sort.Strings(role.Verbs)
	s.roles[name] = role
	return nil
}

// DeleteRole removes a custom role and every binding that granted it.
func (s *Store) DeleteRole(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	role, ok := s.roles[name]
	if !ok {
		return meta.NotFound("role", name)
	}
	if role.Builtin {
		return meta.Invalid("role", fmt.Sprintf("built-in role %q cannot be deleted", name))
	}

	delete(s.roles, name)
	// A binding to a role that no longer exists would grant nothing but would
	// still show up in the explainer, so remove them with the role.
	for id, b := range s.bindings {
		if b.Role == name {
			delete(s.bindings, id)
		}
	}
	return nil
}

// --- bindings ---

// CreateBinding grants a role to a principal within a scope.
func (s *Store) CreateBinding(ctx context.Context, binding meta.Binding) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
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
	if _, exists := s.bindings[binding.ID]; exists {
		return meta.Conflict("binding", binding.ID)
	}
	if _, ok := s.roles[binding.Role]; !ok {
		return meta.NotFound("role", binding.Role)
	}
	if !s.principalExists(binding.PrincipalKind, binding.PrincipalID) {
		return meta.NotFound(string(binding.PrincipalKind), binding.PrincipalID)
	}

	// Duplicates would double-count in the explainer without granting
	// anything extra, so they are a conflict rather than a silent no-op.
	for _, existing := range s.bindings {
		if existing.PrincipalKind == binding.PrincipalKind &&
			existing.PrincipalID == binding.PrincipalID &&
			existing.Role == binding.Role &&
			existing.Scope == binding.Scope {
			return meta.Conflict("binding", fmt.Sprintf("%s/%s -> %s @ %s",
				binding.PrincipalKind, binding.PrincipalID, binding.Role, binding.Scope))
		}
	}

	s.bindings[binding.ID] = binding
	return nil
}

// GetBinding returns one binding by id.
func (s *Store) GetBinding(ctx context.Context, id string) (meta.Binding, error) {
	if err := ctx.Err(); err != nil {
		return meta.Binding{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return meta.Binding{}, err
	}

	binding, ok := s.bindings[id]
	if !ok {
		return meta.Binding{}, meta.NotFound("binding", id)
	}
	return binding, nil
}

// ListBindings returns every binding ordered by id.
func (s *Store) ListBindings(ctx context.Context) ([]meta.Binding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	out := make([]meta.Binding, 0, len(s.bindings))
	for _, b := range s.bindings {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteBinding removes one binding by id.
func (s *Store) DeleteBinding(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	if _, ok := s.bindings[id]; !ok {
		return meta.NotFound("binding", id)
	}
	delete(s.bindings, id)
	return nil
}

// ListEffectiveBindings returns everything granting permission to a subject,
// tagged with how it reached them.
func (s *Store) ListEffectiveBindings(ctx context.Context, subjectName string) ([]meta.EffectiveBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}

	subject, ok := s.subjects[subjectName]
	if !ok {
		return nil, meta.NotFound("subject", subjectName)
	}
	// A disabled subject holds nothing. Enforcing it here means every caller
	// gets it, rather than each remembering to check.
	if subject.Disabled {
		return nil, nil
	}

	groupIDs := make(map[string]string) // group id -> group name
	for group, members := range s.groupMembers {
		if members[subjectName] {
			groupIDs[s.subjectGroups[group].ID] = group
		}
	}

	var out []meta.EffectiveBinding
	for _, b := range s.bindings {
		switch b.PrincipalKind {
		case meta.PrincipalSubject:
			if b.PrincipalID == subject.ID {
				out = append(out, meta.EffectiveBinding{Binding: b})
			}
		case meta.PrincipalGroup:
			if name, ok := groupIDs[b.PrincipalID]; ok {
				out = append(out, meta.EffectiveBinding{Binding: b, ViaGroup: name})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- helpers ---

func (s *Store) principalExists(kind meta.PrincipalKind, id string) bool {
	switch kind {
	case meta.PrincipalSubject:
		for _, subject := range s.subjects {
			if subject.ID == id {
				return true
			}
		}
	case meta.PrincipalGroup:
		for _, group := range s.subjectGroups {
			if group.ID == id {
				return true
			}
		}
	}
	return false
}

// dropBindings removes every binding for a principal. Callers hold the lock.
func (s *Store) dropBindings(kind meta.PrincipalKind, id string) {
	for bindingID, b := range s.bindings {
		if b.PrincipalKind == kind && b.PrincipalID == id {
			delete(s.bindings, bindingID)
		}
	}
}

func cloneRole(r meta.Role) meta.Role {
	r.Verbs = append([]string(nil), r.Verbs...)
	return r
}
