package authn_test

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authz"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
)

var bootTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

func bootClock() time.Time { return bootTime }

func newBootStore(t *testing.T) *memory.Store {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

func TestSeedBuiltinRolesCreatesAndConverges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)

	if err := authn.SeedBuiltinRoles(ctx, store); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}

	for _, want := range authz.BuiltinRoles() {
		got, err := store.GetRole(ctx, want.Name)
		if err != nil {
			t.Fatalf("GetRole(%q): %v", want.Name, err)
		}
		if !got.Builtin {
			t.Errorf("%q seeded without the builtin flag", want.Name)
		}
		if len(got.Verbs) != len(want.Verbs) {
			t.Errorf("%q has %d verbs, want %d", want.Name, len(got.Verbs), len(want.Verbs))
		}
	}

	// Idempotent: a second run changes nothing and reports nothing.
	if err := authn.SeedBuiltinRoles(ctx, store); err != nil {
		t.Fatalf("SeedBuiltinRoles (second run): %v", err)
	}

	// Convergent: a stored built-in that has drifted from its definition --
	// an upgrade that grew the vocabulary, or a row edited in the database --
	// is brought back at the next start.
	if err := store.PutBuiltinRole(ctx, meta.Role{
		Name: authz.RoleAdmin, Builtin: true, Verbs: []string{"repo:read"},
	}); err != nil {
		t.Fatalf("PutBuiltinRole (inject drift): %v", err)
	}
	if err := authn.SeedBuiltinRoles(ctx, store); err != nil {
		t.Fatalf("SeedBuiltinRoles (converge): %v", err)
	}
	admin, err := store.GetRole(ctx, authz.RoleAdmin)
	if err != nil {
		t.Fatalf("GetRole(admin): %v", err)
	}
	if len(admin.Verbs) != len(authz.AllVerbs()) {
		t.Errorf("admin has %d verbs after convergence, want every one of the %d",
			len(admin.Verbs), len(authz.AllVerbs()))
	}

	// Drift that keeps the count but swaps a verb converges too: the
	// comparison is a set, not a length.
	if err := store.PutBuiltinRole(ctx, meta.Role{
		Name: authz.RoleAnonymousReader, Builtin: true,
		Verbs: []string{"repo:list", "repo:read", "gc:run"},
	}); err != nil {
		t.Fatalf("PutBuiltinRole (swap drift): %v", err)
	}
	if err := authn.SeedBuiltinRoles(ctx, store); err != nil {
		t.Fatalf("SeedBuiltinRoles (swap drift): %v", err)
	}
	reader, err := store.GetRole(ctx, authz.RoleAnonymousReader)
	if err != nil {
		t.Fatalf("GetRole(anonymous-reader): %v", err)
	}
	for _, verb := range reader.Verbs {
		if verb == "gc:run" {
			t.Error("the swapped-in verb survived convergence")
		}
	}
}

// A custom role squatting on a built-in name cannot be adopted or overwritten;
// the seeder must say so rather than skip it, because a deployment whose
// "admin" is not the admin role is misconfigured in the worst possible way.
func TestSeedBuiltinRolesRefusesASquattedName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)
	if err := store.CreateRole(ctx, meta.Role{Name: authz.RoleAdmin, Verbs: []string{"repo:read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	err := authn.SeedBuiltinRoles(ctx, store)
	if !errors.Is(err, meta.ErrConflict) {
		t.Fatalf("SeedBuiltinRoles = %v, want the conflict surfaced", err)
	}
}

var passwordShape = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

func TestBootstrapFirstRun(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)

	result, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !result.AdminCreated {
		t.Fatal("AdminCreated = false on a fresh store")
	}
	if !passwordShape.MatchString(result.Password) {
		t.Fatalf("password %q, want 32 URL-safe characters", result.Password)
	}

	subject, err := store.GetSubject(ctx, authn.AdminName)
	if err != nil {
		t.Fatalf("GetSubject(admin): %v", err)
	}
	if subject.Kind != meta.User || subject.ID != authn.AdminID {
		t.Errorf("admin subject = %+v, want a user with the reserved id", subject)
	}

	cred, err := store.GetUserCredential(ctx, authn.AdminName)
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if !cred.MustRotate {
		t.Error("MustRotate = false: the generated password must not be usable forever")
	}
	if err := authn.Verify(cred.Hash, result.Password); err != nil {
		t.Errorf("Verify(stored hash, printed password): %v", err)
	}

	// The two grants of ADR 0001: administering the system, and reaching
	// every repository -- disjoint scopes, so both are needed.
	effective, err := store.ListEffectiveBindings(ctx, authn.AdminName)
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	scopes := map[string]bool{}
	for _, binding := range effective {
		if binding.Role != authz.RoleAdmin {
			t.Errorf("binding %s grants role %q, want admin", binding.ID, binding.Role)
		}
		scopes[binding.Scope] = true
	}
	if !scopes["system"] || !scopes["*"] {
		t.Errorf("admin bound at %v, want system and *", scopes)
	}

	// Roles came with it.
	if _, err := store.GetRole(ctx, authz.RoleDeveloper); err != nil {
		t.Errorf("GetRole(developer) after bootstrap: %v", err)
	}
}

func TestBootstrapSecondRunIsANoOp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)

	first, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock)
	if err != nil {
		t.Fatalf("Bootstrap (first): %v", err)
	}
	second, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock)
	if err != nil {
		t.Fatalf("Bootstrap (second): %v", err)
	}
	if second.AdminCreated || second.Password != "" {
		t.Fatalf("second boot = %+v, want nothing created and no password", second)
	}

	// The credential is untouched: a reboot must never rotate the admin
	// password behind the operator's back.
	cred, err := store.GetUserCredential(ctx, authn.AdminName)
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if err := authn.Verify(cred.Hash, first.Password); err != nil {
		t.Errorf("the first boot's password no longer verifies: %v", err)
	}
}

func TestBootstrapSkipsWhenAUserExists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)
	if err := store.CreateSubject(ctx, meta.Subject{ID: "u-carol", Kind: meta.User, Name: "carol"}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}

	result, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.AdminCreated {
		t.Fatal("bootstrap created an admin although a user already exists")
	}
	if _, err := store.GetSubject(ctx, authn.AdminName); !errors.Is(err, meta.ErrNotFound) {
		t.Errorf("GetSubject(admin) = %v, want not found", err)
	}

	// The roles converge on every start regardless.
	if _, err := store.GetRole(ctx, authz.RoleAdmin); err != nil {
		t.Errorf("GetRole(admin role): %v", err)
	}
}

// A crash between creating the subject and storing its credential must not
// strand the deployment: the admin exists, cannot log in, and no further boot
// would touch it. Bootstrap treats "the admin user exists but has no
// credential" as the first boot still in progress and completes it.
func TestBootstrapCompletesATornFirstBoot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)
	if err := store.CreateSubject(ctx, meta.Subject{ID: authn.AdminID, Kind: meta.User, Name: authn.AdminName}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}
	// One binding already landed before the crash; the other did not.
	if err := store.CreateRole(ctx, meta.Role{Name: authz.RoleAdmin, Builtin: true, Verbs: []string{"repo:read"}}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.CreateBinding(ctx, meta.Binding{
		ID: "bootstrap-admin-system", PrincipalKind: meta.PrincipalSubject,
		PrincipalID: authn.AdminID, Role: authz.RoleAdmin, Scope: "system",
	}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}

	result, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !result.AdminCreated || result.Password == "" {
		t.Fatalf("result = %+v, want the torn boot completed with a fresh password", result)
	}

	cred, err := store.GetUserCredential(ctx, authn.AdminName)
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if !cred.MustRotate {
		t.Error("MustRotate = false after completion")
	}
	effective, err := store.ListEffectiveBindings(ctx, authn.AdminName)
	if err != nil {
		t.Fatalf("ListEffectiveBindings: %v", err)
	}
	if len(effective) != 2 {
		t.Errorf("%d effective bindings, want both scopes despite one pre-existing", len(effective))
	}
}

// A robot or group squatting the admin name with no users at all is a
// configuration so strange that proceeding would be worse than explaining.
func TestBootstrapRefusesAnAdminNameCollision(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newBootStore(t)
	if err := store.CreateSubject(ctx, meta.Subject{ID: "r-admin", Kind: meta.Robot, Name: authn.AdminName}); err != nil {
		t.Fatalf("CreateSubject: %v", err)
	}

	if _, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock); err == nil {
		t.Fatal("Bootstrap succeeded although a robot holds the admin name")
	}
}

// brokenBootStore fails one method, so each failure is proven to surface
// rather than to leave a half-bootstrapped deployment that reads as healthy.
type brokenBootStore struct {
	*memory.Store
	failList    bool
	failCred    bool
	failGetCred bool
	failBinding bool
}

func (b *brokenBootStore) ListSubjects(ctx context.Context, opts meta.ListOptions) (meta.SubjectPage, error) {
	if b.failList {
		return meta.SubjectPage{}, errors.New("disk on fire")
	}
	return b.Store.ListSubjects(ctx, opts)
}

func (b *brokenBootStore) PutUserCredential(ctx context.Context, cred meta.UserCredential) error {
	if b.failCred {
		return errors.New("disk on fire")
	}
	return b.Store.PutUserCredential(ctx, cred)
}

func (b *brokenBootStore) GetUserCredential(ctx context.Context, subject string) (meta.UserCredential, error) {
	if b.failGetCred {
		return meta.UserCredential{}, errors.New("disk on fire")
	}
	return b.Store.GetUserCredential(ctx, subject)
}

func (b *brokenBootStore) CreateBinding(ctx context.Context, binding meta.Binding) error {
	if b.failBinding {
		return errors.New("disk on fire")
	}
	return b.Store.CreateBinding(ctx, binding)
}

func TestBootstrapSurfacesStoreFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("subject listing", func(t *testing.T) {
		t.Parallel()
		store := &brokenBootStore{Store: newBootStore(t), failList: true}
		if _, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock); err == nil {
			t.Fatal("Bootstrap succeeded with an unreadable subject table")
		}
	})

	t.Run("credential write", func(t *testing.T) {
		t.Parallel()
		store := &brokenBootStore{Store: newBootStore(t), failCred: true}
		if _, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock); err == nil {
			t.Fatal("Bootstrap succeeded without storing the credential")
		}
	})

	t.Run("binding write", func(t *testing.T) {
		t.Parallel()
		store := &brokenBootStore{Store: newBootStore(t), failBinding: true}
		if _, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock); err == nil {
			t.Fatal("Bootstrap succeeded without binding the admin")
		}
	})

	t.Run("credential read during the torn-boot check", func(t *testing.T) {
		t.Parallel()
		store := &brokenBootStore{Store: newBootStore(t), failGetCred: true}
		if err := store.Store.CreateSubject(ctx, meta.Subject{
			ID: authn.AdminID, Kind: meta.User, Name: authn.AdminName,
		}); err != nil {
			t.Fatalf("CreateSubject: %v", err)
		}
		if _, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock); err == nil {
			t.Fatal("Bootstrap succeeded although the torn-boot check could not read")
		}
	})

	t.Run("an unusable hasher", func(t *testing.T) {
		t.Parallel()
		if _, err := authn.Bootstrap(ctx, newBootStore(t), authn.Hasher{}, bootClock); err == nil {
			t.Fatal("Bootstrap succeeded with zero-valued hashing parameters")
		}
	})

	t.Run("a squatted built-in role", func(t *testing.T) {
		t.Parallel()
		store := newBootStore(t)
		if err := store.CreateRole(ctx, meta.Role{Name: authz.RoleAdmin, Verbs: []string{"repo:read"}}); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if _, err := authn.Bootstrap(ctx, store, authn.NewHasher(), bootClock); err == nil {
			t.Fatal("Bootstrap succeeded over a squatted built-in role")
		}
	})
}
