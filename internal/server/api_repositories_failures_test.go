package server_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/server"
)

// reposFaultyStore fails one named repository call while the guard's own
// lookups keep working, so the failure lands in the handler under test rather
// than in the authorization that precedes it.
type reposFaultyStore struct {
	*memory.Store
	fail string
}

var errReposStore = errors.New("the disk went away")

func (f *reposFaultyStore) CreateRepository(ctx context.Context, r meta.Repository) (meta.Repository, error) {
	switch f.fail {
	case "CreateRepository":
		return meta.Repository{}, errReposStore
	case "CreateRepositoryInvalid":
		// The store's own invariants refusing past the handler's checks.
		return meta.Repository{}, meta.Invalid("name", "the store says no")
	}
	return f.Store.CreateRepository(ctx, r)
}

func (f *reposFaultyStore) GetRepository(ctx context.Context, name string) (meta.Repository, error) {
	if f.fail == "GetRepository" {
		return meta.Repository{}, errReposStore
	}
	return f.Store.GetRepository(ctx, name)
}

func (f *reposFaultyStore) ListRepositories(ctx context.Context, opts meta.ListOptions) (meta.RepositoryPage, error) {
	if f.fail == "ListRepositories" {
		return meta.RepositoryPage{}, errReposStore
	}
	return f.Store.ListRepositories(ctx, opts)
}

func (f *reposFaultyStore) UpdateRepositoryConfig(ctx context.Context, name string, config []byte,
	expected int64, actor string, at time.Time,
) (meta.Repository, error) {
	switch f.fail {
	case "UpdateRepositoryConfig":
		return meta.Repository{}, errReposStore
	case "UpdateRepositoryConfigVanished":
		// Deleted between the handler's read and its write.
		return meta.Repository{}, meta.NotFound("repository", name)
	}
	return f.Store.UpdateRepositoryConfig(ctx, name, config, expected, actor, at)
}

func (f *reposFaultyStore) DeleteRepository(ctx context.Context, name string) error {
	switch f.fail {
	case "DeleteRepository":
		return errReposStore
	case "DeleteRepositoryVanished":
		return meta.NotFound("repository", name)
	}
	return f.Store.DeleteRepository(ctx, name)
}

// reposArmedFixture is the fixture with one repository call rigged to fail.
func reposArmedFixture(t *testing.T, fail string) reposFixture {
	t.Helper()

	f := newReposFixture(t)
	reposCreate(t, f, "thing", "hosted", "")

	router := server.NewRouter(&server.Guard{
		Subjects: f.store,
		Bindings: f.store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
		Challenge: func(*http.Request) string { return `Bearer realm="trove"` },
	})
	(&server.Repositories{
		Store:    &reposFaultyStore{Store: f.store, fail: fail},
		Bindings: f.store,
		Now:      func() time.Time { return reposTime },
	}).Register(router)
	return reposFixture{store: f.store, router: router}
}

// A store that cannot answer fails closed with a problem document, never a
// confident answer: telling an operator their repository does not exist
// because a disk hiccupped is how a recreate destroys the original.
func TestReposStoreFailuresAreServerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fail   string
		method string
		target string
		body   string
		status int
	}{
		{
			fail: "CreateRepository", method: http.MethodPost, target: "/api/v1/repositories",
			body: `{"name": "x", "type": "hosted"}`, status: http.StatusInternalServerError,
		},
		{
			fail: "CreateRepositoryInvalid", method: http.MethodPost, target: "/api/v1/repositories",
			body: `{"name": "x", "type": "hosted"}`, status: http.StatusBadRequest,
		},
		{
			fail: "GetRepository", method: http.MethodGet, target: "/api/v1/repositories/thing",
			status: http.StatusInternalServerError,
		},
		{
			fail: "ListRepositories", method: http.MethodGet, target: "/api/v1/repositories",
			status: http.StatusInternalServerError,
		},
		{
			fail: "UpdateRepositoryConfig", method: http.MethodPut, target: "/api/v1/repositories/thing/config",
			body: `{"config": {}, "expected_version": 1}`, status: http.StatusInternalServerError,
		},
		{
			fail: "UpdateRepositoryConfigVanished", method: http.MethodPut, target: "/api/v1/repositories/thing/config",
			body: `{"config": {}, "expected_version": 1}`, status: http.StatusNotFound,
		},
		{
			fail: "DeleteRepository", method: http.MethodDelete, target: "/api/v1/repositories/thing?confirm=thing",
			status: http.StatusInternalServerError,
		},
		{
			fail: "DeleteRepositoryVanished", method: http.MethodDelete, target: "/api/v1/repositories/thing?confirm=thing",
			status: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.fail+" "+tt.method, func(t *testing.T) {
			t.Parallel()
			armed := reposArmedFixture(t, tt.fail)
			rec := armed.do(t, tt.method, tt.target, "root", tt.body)
			if rec.Code != tt.status {
				t.Fatalf("%s with %s failing: %d %s, want %d", tt.method, tt.fail, rec.Code, rec.Body, tt.status)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
				t.Errorf("Content-Type = %q, want problem+json", ct)
			}
		})
	}
}

// reposBrokenBindings cannot answer, so the handler's own sub-decisions --
// proxy:read on a get, proxy:write on a config change -- have decided nothing
// and must refuse rather than assume.
type reposBrokenBindings struct{}

func (reposBrokenBindings) ListEffectiveBindings(context.Context, string) ([]meta.EffectiveBinding, error) {
	return nil, errReposStore
}

func (reposBrokenBindings) GetRole(context.Context, string) (meta.Role, error) {
	return meta.Role{}, errReposStore
}

func TestReposProxySubDecisionFailsClosed(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	reposCreate(t, f, "mirror", "proxy", reposProxyConfig)

	router := server.NewRouter(&server.Guard{
		Subjects: f.store,
		Bindings: f.store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	// The guard reads bindings from the working store; only the handler's own
	// sub-decision reads the broken one.
	(&server.Repositories{
		Store: f.store, Bindings: reposBrokenBindings{}, Now: func() time.Time { return reposTime },
	}).Register(router)
	broken := reposFixture{store: f.store, router: router}

	for _, tt := range []struct{ method, target, body string }{
		{http.MethodGet, "/api/v1/repositories/mirror", ""},
		{
			http.MethodPut, "/api/v1/repositories/mirror/config",
			`{"config": {"upstream": "https://ghcr.io"}, "expected_version": 1}`,
		},
	} {
		rec := broken.do(t, tt.method, tt.target, "root", tt.body)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s with unreadable bindings: %d %s, want 500", tt.method, rec.Code, rec.Body)
		}
	}
}

// The zero-valued handler is safe: a real clock and the admin API's problem
// renderer, which is what serve relies on by not setting them.
func TestReposHandlerDefaults(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	router := server.NewRouter(&server.Guard{
		Subjects: f.store,
		Bindings: f.store,
		Credentials: func(r *http.Request) (string, error) {
			return r.Header.Get("X-Test-Subject"), nil
		},
	})
	(&server.Repositories{Store: f.store, Bindings: f.store}).Register(router)
	bare := reposFixture{store: f.store, router: router}

	before := time.Now()
	rec := bare.do(t, http.MethodPost, "/api/v1/repositories", "root", `{"name": "defaulted", "type": "hosted"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with defaults: %d %s", rec.Code, rec.Body)
	}
	if created := reposDecode(t, rec); created.CreatedAt.Before(before) {
		t.Errorf("CreatedAt = %s, want the real clock", created.CreatedAt)
	}
	// The default renderer is the admin API's.
	refused := bare.do(t, http.MethodPost, "/api/v1/repositories", "root", `{"name": "system", "type": "hosted"}`)
	if ct := refused.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Errorf("default Content-Type = %q", ct)
	}
}

// An oversized body is refused rather than buffered: an admin request is a
// handful of fields, and anything approaching the cap is not one.
func TestReposOversizedBodyIsRefused(t *testing.T) {
	t.Parallel()

	f := newReposFixture(t)
	huge := `{"name": "x", "type": "hosted", "config": {"junk": "` + strings.Repeat("a", 1<<21) + `"}}`
	if rec := f.do(t, http.MethodPost, "/api/v1/repositories", "root", huge); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized create: %d, want 400", rec.Code)
	}
	f2 := newReposFixture(t)
	reposCreate(t, f2, "thing", "hosted", "")
	hugeConfig := `{"config": {"junk": "` + strings.Repeat("a", 1<<21) + `"}, "expected_version": 1}`
	if rec := f2.do(t, http.MethodPut, "/api/v1/repositories/thing/config", "root", hugeConfig); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized update: %d, want 400", rec.Code)
	}
}
