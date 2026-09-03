package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
)

// The bootstrap admin's reserved identifiers. The id is a fixed word for the
// same reason the anonymous subject's is: bindings reference ids, and the two
// bootstrap bindings below must mean the same thing in every deployment.
const (
	AdminName = "admin"
	AdminID   = "admin"
)

// The bootstrap bindings' ids, fixed so a torn first boot can recognise its
// own half-finished work and complete it instead of duplicating it.
const (
	adminSystemBindingID = "bootstrap-admin-system"
	adminAllBindingID    = "bootstrap-admin-all"
)

// BootstrapStore is the part of the metadata store bootstrap needs, declared
// by the consumer (§11).
type BootstrapStore interface {
	GetRole(ctx context.Context, name string) (meta.Role, error)
	PutBuiltinRole(ctx context.Context, role meta.Role) error
	ListSubjects(ctx context.Context, opts meta.ListOptions) (meta.SubjectPage, error)
	CreateSubject(ctx context.Context, subject meta.Subject) error
	GetUserCredential(ctx context.Context, subject string) (meta.UserCredential, error)
	PutUserCredential(ctx context.Context, cred meta.UserCredential) error
	CreateBinding(ctx context.Context, binding meta.Binding) error
}

// BootstrapResult reports what a boot did.
type BootstrapResult struct {
	// AdminCreated is true when this boot created the admin's credential --
	// on the first boot, or when completing one that crashed half-way.
	AdminCreated bool
	// Password is the generated admin password, present only when
	// AdminCreated. It is printed once by the caller and stored nowhere:
	// only its Argon2id hash survives this function.
	Password string
}

// SeedBuiltinRoles converges the stored built-in roles to their definitions
// in authz.BuiltinRoles.
//
// It runs on every start, not only the first: an upgrade that grows the
// vocabulary changes what "admin means every verb" expands to, and a built-in
// row edited in the database needs healing, not preserving. A custom role
// squatting a built-in name is refused loudly (the store's conflict), because
// a deployment whose "admin" is not the admin role is misconfigured in the
// worst possible way.
func SeedBuiltinRoles(ctx context.Context, store BootstrapStore) error {
	for _, role := range authz.BuiltinRoles() {
		verbs := make([]string, len(role.Verbs))
		for i, verb := range role.Verbs {
			verbs[i] = string(verb)
		}

		stored, err := store.GetRole(ctx, role.Name)
		switch {
		case errors.Is(err, meta.ErrNotFound):
			// Falls through to the put.
		case err != nil:
			return fmt.Errorf("read role %q: %w", role.Name, err)
		case stored.Builtin && sameVerbSet(stored.Verbs, verbs):
			continue
		}

		if err := store.PutBuiltinRole(ctx, meta.Role{Name: role.Name, Builtin: true, Verbs: verbs}); err != nil {
			return fmt.Errorf("seed role %q: %w", role.Name, err)
		}
	}
	return nil
}

// Bootstrap prepares a deployment for its first login (Z-014, ADR 0004).
//
// It always converges the built-in roles, and it creates the admin account
// exactly when no user could log in otherwise: on a fresh store, or when a
// crashed first boot left the admin subject without a credential. The
// password is generated, returned for a single print, and marked for forced
// rotation -- there is never a default credential. Any other state is left
// alone: a reboot must not rotate the admin password behind the operator's
// back, and a store with users in it already has an administration.
func Bootstrap(ctx context.Context, store BootstrapStore, hasher Hasher, now func() time.Time) (BootstrapResult, error) {
	if now == nil {
		now = time.Now
	}

	if err := SeedBuiltinRoles(ctx, store); err != nil {
		return BootstrapResult{}, err
	}

	needed, err := adminNeeded(ctx, store)
	if err != nil || !needed {
		return BootstrapResult{}, err
	}

	password, err := generatePassword()
	if err != nil {
		return BootstrapResult{}, err
	}
	hash, err := hasher.Hash(password)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("hash the admin password: %w", err)
	}

	// Each write tolerates its own prior success, so completing a torn boot
	// is the same code as a fresh one. The credential is written last with no
	// conflict tolerance: it is the step whose absence means "still torn".
	subject := meta.Subject{ID: AdminID, Kind: meta.User, Name: AdminName, CreatedAt: now()}
	if err := store.CreateSubject(ctx, subject); err != nil && !errors.Is(err, meta.ErrConflict) {
		return BootstrapResult{}, fmt.Errorf("create the admin subject: %w", err)
	}
	for _, binding := range []meta.Binding{
		// The two grants of ADR 0001: administering the system, and reaching
		// every repository. The scopes are disjoint, so both are needed.
		{ID: adminSystemBindingID, PrincipalKind: meta.PrincipalSubject, PrincipalID: AdminID,
			Role: authz.RoleAdmin, Scope: "system", CreatedAt: now()},
		{ID: adminAllBindingID, PrincipalKind: meta.PrincipalSubject, PrincipalID: AdminID,
			Role: authz.RoleAdmin, Scope: "*", CreatedAt: now()},
	} {
		if err := store.CreateBinding(ctx, binding); err != nil && !errors.Is(err, meta.ErrConflict) {
			return BootstrapResult{}, fmt.Errorf("bind admin at %q: %w", binding.Scope, err)
		}
	}
	if err := store.PutUserCredential(ctx, meta.UserCredential{
		Subject: AdminName, Hash: hash, MustRotate: true,
	}); err != nil {
		return BootstrapResult{}, fmt.Errorf("store the admin credential: %w", err)
	}

	return BootstrapResult{AdminCreated: true, Password: password}, nil
}

// adminNeeded decides whether this boot must produce a usable admin.
func adminNeeded(ctx context.Context, store BootstrapStore) (bool, error) {
	hasUser := false
	var admin *meta.Subject

	cursor := ""
	for {
		page, err := store.ListSubjects(ctx, meta.ListOptions{Limit: meta.MaxPageSize, Cursor: cursor})
		if err != nil {
			return false, fmt.Errorf("list subjects: %w", err)
		}
		for _, subject := range page.Subjects {
			if subject.Kind == meta.User {
				hasUser = true
			}
			if subject.Name == AdminName {
				held := subject
				admin = &held
			}
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	if admin != nil && admin.Kind != meta.User {
		if hasUser {
			// Somebody administers this deployment; the odd subject is
			// theirs to explain.
			return false, nil
		}
		return false, fmt.Errorf(
			"cannot bootstrap: subject %q exists and is a %s, not a user -- remove it or create a user another way",
			AdminName, admin.Kind)
	}

	switch {
	case !hasUser:
		return true, nil
	case admin != nil:
		// The admin user exists. If it has no credential, the first boot
		// crashed between creating the subject and storing the hash, and
		// nobody can log in: that is the first boot still in progress.
		_, err := store.GetUserCredential(ctx, AdminName)
		switch {
		case errors.Is(err, meta.ErrNotFound):
			return true, nil
		case err != nil:
			return false, fmt.Errorf("read the admin credential: %w", err)
		default:
			return false, nil
		}
	default:
		return false, nil
	}
}

// sameVerbSet compares verb lists as sets, because the two sides may not
// agree on order.
func sameVerbSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, verb := range a {
		seen[verb] = true
	}
	for _, verb := range b {
		if !seen[verb] {
			return false
		}
	}
	return true
}

// generatePassword returns 192 bits of randomness in a form an operator can
// copy: 32 characters, URL-safe alphabet, no padding.
func generatePassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
