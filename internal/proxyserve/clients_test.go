package proxyserve_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steveokay/trove/internal/meta"
	metamemory "github.com/steveokay/trove/internal/meta/memory"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxyserve"
	"github.com/steveokay/trove/internal/secretbox"
)

// The client cache (C-020).
//
// Two rules are worth a test each, because getting either wrong is invisible
// until an operator changes something and nothing happens:
//
//   - a reconfigured proxy gets a new client, because the upstream URL and the
//     trusted-host list are baked into one;
//   - a rotated credential does *not*, because credentials are read per
//     request and never baked in.
//
// The Build seam means none of this opens a socket.

// recordingBuilder captures the options each client was built with.
type recordingBuilder struct {
	built []proxy.Options
	err   error
}

func (r *recordingBuilder) build(opts proxy.Options) (proxy.Client, error) {
	r.built = append(r.built, opts)
	if r.err != nil {
		return nil, r.err
	}
	return &builtClient{}, nil
}

// builtClient is a distinguishable client that is never called. It is a
// pointer so that two of them compare unequal, which is the whole question
// these tests ask.
type builtClient struct{ proxy.Client }

// clientEnv is a store holding one proxy repository, `hub`.
type clientEnv struct {
	store *metamemory.Store
	built *recordingBuilder
	cache *proxyserve.ClientCache
}

func newClientEnv(t *testing.T, config string, tweak func(*proxyserve.ClientCacheOptions)) *clientEnv {
	t.Helper()

	store := metamemory.New()
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: "hub", Type: meta.Proxy, Config: json.RawMessage(config),
		CreatedAt: time.Unix(0, 0), UpdatedAt: time.Unix(0, 0),
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	built := &recordingBuilder{}
	opts := proxyserve.ClientCacheOptions{Meta: store, Build: built.build}
	if tweak != nil {
		tweak(&opts)
	}
	cache, err := proxyserve.NewClientCache(opts)
	if err != nil {
		t.Fatalf("NewClientCache: %v", err)
	}
	return &clientEnv{store: store, built: built, cache: cache}
}

func TestAClientIsBuiltOnceAndReused(t *testing.T) {
	t.Parallel()

	env := newClientEnv(t, `{"upstream":"https://registry-1.docker.io"}`, nil)

	first, err := env.cache.ClientFor(context.Background(), "hub")
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	second, err := env.cache.ClientFor(context.Background(), "hub")
	if err != nil {
		t.Fatalf("ClientFor (again): %v", err)
	}
	if first != second {
		t.Error("a second call built a new client, losing the tokens and rate-limit standing of the first")
	}
	if len(env.built.built) != 1 {
		t.Errorf("built %d clients, want 1", len(env.built.built))
	}
	if got := env.built.built[0].Upstream; got != "https://registry-1.docker.io" {
		t.Errorf("Upstream = %q, want the entity's", got)
	}
}

// TestReconfiguringAProxyRetiresItsClient: the version in the repository row
// is part of the key, so an update replaces the client rather than needing
// something to notice and evict it.
func TestReconfiguringAProxyRetiresItsClient(t *testing.T) {
	t.Parallel()

	env := newClientEnv(t, `{"upstream":"https://registry-1.docker.io"}`, nil)
	ctx := context.Background()

	before, err := env.cache.ClientFor(ctx, "hub")
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}

	record, err := env.store.GetRepository(ctx, "hub")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	updated := `{"upstream":"https://ghcr.io","trusted_hosts":["pkg-containers.githubusercontent.com"]}`
	if _, err := env.store.UpdateRepositoryConfig(ctx, "hub", json.RawMessage(updated),
		record.ConfigVersion, "operator", time.Unix(100, 0)); err != nil {
		t.Fatalf("UpdateRepositoryConfig: %v", err)
	}

	after, err := env.cache.ClientFor(ctx, "hub")
	if err != nil {
		t.Fatalf("ClientFor after reconfiguration: %v", err)
	}
	if len(env.built.built) != 2 {
		t.Fatalf("built %d clients, want a second one for the new configuration", len(env.built.built))
	}
	if after == before {
		t.Error("a reconfigured proxy kept the client built from its old upstream")
	}
	rebuilt := env.built.built[1]
	if rebuilt.Upstream != "https://ghcr.io" {
		t.Errorf("Upstream = %q, want the new one", rebuilt.Upstream)
	}
	if len(rebuilt.Redirects.TrustedHosts) != 1 ||
		rebuilt.Redirects.TrustedHosts[0] != "pkg-containers.githubusercontent.com" {
		t.Errorf("TrustedHosts = %v, want the entity's own list and nothing global",
			rebuilt.Redirects.TrustedHosts)
	}
}

// TestARotatedCredentialNeedsNoInvalidation. The credential source reads the
// sealed row per request, so the client built before a rotation serves the
// value written after it -- which is why the cache key says nothing about
// credentials.
func TestARotatedCredentialNeedsNoInvalidation(t *testing.T) {
	t.Parallel()

	key, err := secretbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keys, err := secretbox.NewKeyring(key)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	ctx := context.Background()
	env := newClientEnv(t, `{"upstream":"https://registry-1.docker.io"}`, func(o *proxyserve.ClientCacheOptions) {
		o.Keys = keys
	})
	env.cache = mustClientCache(t, proxyserve.ClientCacheOptions{
		Meta: env.store, Credentials: env.store, Keys: keys, Build: env.built.build,
	})

	if _, err := env.cache.ClientFor(ctx, "hub"); err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	credentials := env.built.built[0].Credentials
	if credentials == nil {
		t.Fatal("a deployment with a keyring built an anonymous client")
	}

	// Sealed and written *after* the client already existed.
	sealed, err := keys.Seal([]byte(`{"username":"robot","password":"s3cret"}`),
		secretbox.ProxyCredential("hub"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := env.store.PutProxyCredential(ctx, meta.ProxyCredential{
		Repository: "hub", Sealed: sealed, RotatedAt: time.Unix(200, 0),
	}); err != nil {
		t.Fatalf("PutProxyCredential: %v", err)
	}

	user, pass, err := credentials.Basic(ctx)
	if err != nil {
		t.Fatalf("Basic: %v", err)
	}
	if user != "robot" || pass != "s3cret" {
		t.Errorf("Basic() = %q/%q, want the value written after the client was built", user, pass)
	}
	if len(env.built.built) != 1 {
		t.Errorf("built %d clients: a rotation should need no rebuild", len(env.built.built))
	}
}

// TestADeploymentWithNoKeyringBuildsAnonymousClients: the public registries
// C-014 ships presets for need no credential, and demanding one that is not
// there would fail every pull through them.
func TestADeploymentWithNoKeyringBuildsAnonymousClients(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		tweak func(*proxyserve.ClientCacheOptions)
	}{
		{name: "neither half", tweak: nil},
		{
			name: "a credential store but no keys",
			tweak: func(o *proxyserve.ClientCacheOptions) {
				o.Credentials = metamemory.New()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newClientEnv(t, `{"upstream":"https://registry-1.docker.io"}`, tc.tweak)
			if _, err := env.cache.ClientFor(context.Background(), "hub"); err != nil {
				t.Fatalf("ClientFor: %v", err)
			}
			if got := env.built.built[0].Credentials; got != nil {
				t.Errorf("Credentials = %v, want nil when nothing can open a sealed value", got)
			}
		})
	}
}

// TestAClientCannotBeBuiltFor covers every refusal. None of them is a missing
// repository: a proxy that cannot be given a client is a configuration
// failure, and reporting it as a 404 sends the operator to look for the image.
func TestAClientCannotBeBuiltFor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		entity string
		setup  func(t *testing.T, env *clientEnv)
		want   string
	}{
		{
			name:   "a repository that is not there",
			entity: "absent",
			want:   "read the configuration",
		},
		{
			name:   "a repository that is not a proxy",
			entity: "internal",
			setup: func(t *testing.T, env *clientEnv) {
				if _, err := env.store.CreateRepository(context.Background(), meta.Repository{
					Name: "internal", Type: meta.Hosted,
				}); err != nil {
					t.Fatalf("CreateRepository: %v", err)
				}
			},
			want: "not a proxy",
		},
		{
			name:   "configuration that does not parse",
			entity: "junk",
			setup: func(t *testing.T, env *clientEnv) {
				if _, err := env.store.CreateRepository(context.Background(), meta.Repository{
					Name: "junk", Type: meta.Proxy, Config: json.RawMessage(`{"upstream":`),
				}); err != nil {
					t.Fatalf("CreateRepository: %v", err)
				}
			},
			want: "parse the configuration",
		},
		{
			name:   "a client that refuses to be built",
			entity: "hub",
			setup:  func(_ *testing.T, env *clientEnv) { env.built.err = errors.New("no socket for you") },
			want:   "build the upstream client",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newClientEnv(t, `{"upstream":"https://registry-1.docker.io"}`, nil)
			if tc.setup != nil {
				tc.setup(t, env)
			}

			client, err := env.cache.ClientFor(context.Background(), tc.entity)
			if err == nil {
				t.Fatalf("ClientFor(%q) returned a client", tc.entity)
			}
			if client != nil {
				t.Error("a failure returned a client as well")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestAClientCacheNeedsAStore(t *testing.T) {
	t.Parallel()

	_, err := proxyserve.NewClientCache(proxyserve.ClientCacheOptions{})
	if !errors.Is(err, proxyserve.ErrInvalidOptions) {
		t.Errorf("NewClientCache(zero) = %v, want ErrInvalidOptions", err)
	}
}

// TestTheDefaultBuilderIsTheRealClient: with no Build supplied the cache makes
// a real proxy client, which is what serve relies on.
func TestTheDefaultBuilderIsTheRealClient(t *testing.T) {
	t.Parallel()

	store := metamemory.New()
	if _, err := store.CreateRepository(context.Background(), meta.Repository{
		Name: "hub", Type: meta.Proxy, Config: json.RawMessage(`{"upstream":"https://registry-1.docker.io"}`),
	}); err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	cache := mustClientCache(t, proxyserve.ClientCacheOptions{Meta: store})

	client, err := cache.ClientFor(context.Background(), "hub")
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	if client == nil {
		t.Fatal("the default builder produced no client")
	}
}

func mustClientCache(t *testing.T, opts proxyserve.ClientCacheOptions) *proxyserve.ClientCache {
	t.Helper()

	cache, err := proxyserve.NewClientCache(opts)
	if err != nil {
		t.Fatalf("NewClientCache: %v", err)
	}
	return cache
}
