package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Role is a named set of permission verbs.
//
// Roles are the only place verbs are bundled. The vocabulary itself has no
// bundle verb and no wildcards (ADR 0002): a role holds the expanded, explicit
// list, so the enumeration test and the effective-permission explainer both
// see concrete verbs rather than something that has to be interpreted.
type Role struct {
	// Name identifies the role in bindings and in the admin API.
	Name string
	// Builtin marks a role that ships with trove. Built-ins are read-only:
	// the store refuses to modify or delete them, so nobody can quietly
	// redefine what "admin" means for every binding that names it.
	Builtin bool
	// Verbs is the expanded verb set, sorted.
	Verbs []Verb
}

// The built-in roles (ADR 0001). They compose only vocabulary verbs -- there
// is no permission a built-in has that a custom role could not be granted, and
// none that bypasses a check.
const (
	// RoleAdmin holds every verb, and is bound at "system" and "*" both:
	// the two scopes are disjoint, so administering the system and reaching
	// every repository are two grants rather than one.
	RoleAdmin = "admin"
	// RoleOperator runs the registry without administering its people.
	RoleOperator = "operator"
	// RolePublisher reads and pushes within its scope.
	RolePublisher = "publisher"
	// RoleDeveloper reads within its scope.
	RoleDeveloper = "developer"
	// RoleAuditor reads everything and writes nothing, anywhere.
	RoleAuditor = "auditor"
	// RoleAnonymousReader is what anonymous access would grant. It exists but
	// ships unbound: anonymous access is off until an administrator binds it,
	// so a fresh install is not readable by the internet because somebody
	// forgot to look.
	RoleAnonymousReader = "anonymous-reader"
)

// builtinRoles are defined once, here, and seeded from these definitions.
//
// Three of them are derived from the vocabulary rather than listed by hand,
// because that is how ADR 0001 words them -- "every verb", "everything except
// user and role administration", "every read verb". A hand-written list would
// answer a different question the day a verb is added: the ADR's intent is the
// rule, so the rule is what is written.
var builtinRoles = func() map[string]Role {
	roles := []Role{
		{Name: RoleAdmin, Verbs: AllVerbs()},
		{Name: RoleOperator, Verbs: verbsExcept("user:", "role:")},
		{
			Name: RolePublisher,
			Verbs: []Verb{
				RepoList, RepoRead, RepoWrite, TagDelete, ReferrerRead, ScanRead, SearchRead,
			},
		},
		{
			Name:  RoleDeveloper,
			Verbs: []Verb{RepoList, RepoRead, ReferrerRead, ScanRead, SearchRead},
		},
		{Name: RoleAuditor, Verbs: readVerbs()},
		{
			Name:  RoleAnonymousReader,
			Verbs: []Verb{RepoList, RepoRead, ReferrerRead},
		},
	}

	out := make(map[string]Role, len(roles))
	for _, role := range roles {
		role.Builtin = true
		sortVerbs(role.Verbs)
		out[role.Name] = role
	}
	return out
}()

// verbsExcept returns every verb whose name does not start with one of the
// given prefixes.
func verbsExcept(prefixes ...string) []Verb {
	var out []Verb
	for _, verb := range AllVerbs() {
		excluded := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(string(verb), prefix) {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, verb)
		}
	}
	return out
}

// readVerbs returns every verb that only reads.
//
// It is the ":read" suffix plus repo:list, which is a read of the catalog that
// happens not to be spelled that way. An auditor that could not see a
// repository exists could not audit it.
func readVerbs() []Verb {
	out := []Verb{RepoList}
	for _, verb := range AllVerbs() {
		if strings.HasSuffix(string(verb), ":read") {
			out = append(out, verb)
		}
	}
	return out
}

func sortVerbs(verbs []Verb) {
	sort.Slice(verbs, func(i, j int) bool { return verbs[i] < verbs[j] })
}

// BuiltinRoles returns every built-in role, ordered by name, as fresh copies.
//
// This is the definition the bootstrap path seeds from (Z-014), and the one a
// drift test compares stored rows against: a built-in that has been edited in
// the database no longer means what its name says.
func BuiltinRoles() []Role {
	names := make([]string, 0, len(builtinRoles))
	for name := range builtinRoles {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Role, 0, len(names))
	for _, name := range names {
		out = append(out, builtinRoles[name].clone())
	}
	return out
}

// BuiltinRole returns one built-in role by name.
func BuiltinRole(name string) (Role, bool) {
	role, ok := builtinRoles[name]
	if !ok {
		return Role{}, false
	}
	return role.clone(), true
}

// IsBuiltin reports whether the name belongs to a built-in role. Callers use
// it to refuse an edit before attempting one the store would reject anyway,
// so the error names the reason rather than the constraint.
func IsBuiltin(name string) bool {
	_, ok := builtinRoles[name]
	return ok
}

// clone copies a role so a caller cannot mutate the package's definitions
// through a returned slice.
func (r Role) clone() Role {
	out := r
	out.Verbs = make([]Verb, len(r.Verbs))
	copy(out.Verbs, r.Verbs)
	return out
}

// Grants reports whether the role includes the verb.
func (r Role) Grants(verb Verb) bool {
	for _, candidate := range r.Verbs {
		if candidate == verb {
			return true
		}
	}
	return false
}

// ErrInvalidRole reports a role that cannot be stored.
var ErrInvalidRole = fmt.Errorf("invalid role")

// Validate reports whether a custom role is well formed.
//
// The only rules are that it has a name and that every verb is in the
// vocabulary. There is deliberately no verb a custom role cannot hold
// (ADR 0001): a permission an administrator cannot delegate would be a
// permission that only exists in code.
func (r Role) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalidRole)
	}
	for _, verb := range r.Verbs {
		if !verb.Valid() {
			return fmt.Errorf("%w: %w", ErrInvalidRole, &UnknownVerbError{Verb: string(verb)})
		}
	}
	return nil
}

// NewRole builds a custom role from verb strings, rejecting anything outside
// the vocabulary. It is what the admin API and the role editor construct from.
func NewRole(name string, verbs []string) (Role, error) {
	parsed, err := ParseVerbs(verbs)
	if err != nil {
		return Role{}, fmt.Errorf("%w: %w", ErrInvalidRole, err)
	}
	role := Role{Name: name, Verbs: dedupeVerbs(parsed)}
	if err := role.Validate(); err != nil {
		return Role{}, err
	}
	return role, nil
}

// dedupeVerbs sorts and removes repeats, so a role's stored list is canonical
// and two roles granting the same thing look the same.
func dedupeVerbs(verbs []Verb) []Verb {
	if len(verbs) == 0 {
		return nil
	}
	sortVerbs(verbs)

	out := verbs[:1]
	for _, verb := range verbs[1:] {
		if verb != out[len(out)-1] {
			out = append(out, verb)
		}
	}
	return out
}
