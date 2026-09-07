package proxyserve

import (
	"context"
	"fmt"
	"sync"

	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/repo"
)

// Building the upstream client for a proxy entity (C-020).
//
// A client is not a value to make per request. It carries the tokens an
// upstream issued, the rate-limit standing that decides whether the next call
// may be made at all (C-009), and a connection pool -- state whose whole
// purpose is to be shared across the requests to one upstream. So clients are
// cached, and the interesting question is when a cached one stops being right.
//
// Two things can make it stale, and they are handled differently:
//
//   - **Configuration.** The upstream URL and the trusted-host list are baked
//     into the client, so a reconfigured proxy needs a new one. The
//     repository row carries a config version (C-016 writes a revision on
//     every update), and that version is part of the cache key -- an update
//     therefore retires the old client rather than requiring anything to
//     notice and evict it.
//   - **Credentials.** They are *not* baked in. proxy.StoredCredentials reads
//     the sealed row and opens it on each request (C-003), so a rotation takes
//     effect on the next pull with no invalidation at all. That is why the
//     cache key does not mention credentials: there is nothing cached to go
//     stale.

// CredentialStore supplies sealed upstream credentials.
type CredentialStore interface {
	GetProxyCredential(ctx context.Context, repository string) (meta.ProxyCredential, error)
}

// Keys opens sealed values.
type Keys = proxy.Opener

// ClientCache builds and reuses one upstream client per proxy entity.
type ClientCache struct {
	meta        Store
	credentials CredentialStore
	keys        Keys
	build       func(proxy.Options) (proxy.Client, error)

	mu      sync.Mutex
	clients map[string]cachedClient
}

// cachedClient is one entity's client and the configuration version it was
// built from.
type cachedClient struct {
	client  proxy.Client
	version int64
}

// ClientCacheOptions configures a ClientCache. Meta is required; the rest are
// what a client needs to authenticate.
type ClientCacheOptions struct {
	// Meta reads repository rows for their configuration and version.
	Meta Store

	// Credentials and Keys are how a client reaches its upstream secret. Both
	// nil means every proxy is anonymous, which is a legitimate deployment --
	// the public registries C-014 ships presets for need no credential.
	Credentials CredentialStore
	Keys        Keys

	// Build makes a client from options. Nil means proxy.New; it exists so a
	// test can watch what a client would have been built with without opening
	// a socket.
	Build func(proxy.Options) (proxy.Client, error)
}

// NewClientCache builds a cache.
func NewClientCache(opts ClientCacheOptions) (*ClientCache, error) {
	if opts.Meta == nil {
		return nil, errInvalid("a metadata store is required to build upstream clients")
	}

	c := &ClientCache{
		meta: opts.Meta, credentials: opts.Credentials, keys: opts.Keys,
		build: opts.Build, clients: map[string]cachedClient{},
	}
	if c.build == nil {
		c.build = func(o proxy.Options) (proxy.Client, error) { return proxy.New(o) }
	}
	return c, nil
}

// ClientFor returns the client for a proxy entity, building one when the
// configuration it was built from has changed.
func (c *ClientCache) ClientFor(ctx context.Context, entity string) (proxy.Client, error) {
	record, err := c.meta.GetRepository(ctx, entity)
	if err != nil {
		return nil, fmt.Errorf("read the configuration of %q: %w", entity, err)
	}
	if record.Type != meta.Proxy {
		return nil, fmt.Errorf("%q is a %s, not a proxy", entity, record.Type)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cached, ok := c.clients[entity]; ok && cached.version == record.ConfigVersion {
		return cached.client, nil
	}

	config, err := repo.ParseProxyConfig(record.Config)
	if err != nil {
		return nil, fmt.Errorf("parse the configuration of %q: %w", entity, err)
	}

	client, err := c.build(proxy.Options{
		Upstream: config.Upstream,
		// Credentials read the sealed row per request, so a rotation needs no
		// invalidation here. A proxy with no stored credential fails its first
		// authenticated call loudly rather than falling back to anonymous,
		// which is what C-003 decided: a silent downgrade turns a revoked
		// secret into a 404 and sends the operator to debug the wrong system.
		Credentials: c.credentialsFor(entity),
		Redirects: proxy.RedirectPolicy{
			// The entity's own list, and nothing global: a host trusted for
			// Docker Hub has no business being trusted for somebody's internal
			// registry (C-014).
			TrustedHosts: config.TrustedHosts,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("build the upstream client for %q: %w", entity, err)
	}

	c.clients[entity] = cachedClient{client: client, version: record.ConfigVersion}
	return client, nil
}

// credentialsFor returns the credential source for an entity, or nil when this
// deployment has no keyring to open one with.
func (c *ClientCache) credentialsFor(entity string) proxy.Credentials {
	if c.credentials == nil || c.keys == nil {
		return nil
	}
	return proxy.StoredCredentials{Repository: entity, Store: c.credentials, Keys: c.keys}
}

// ClientCache is what a Server's Clients seam expects.
var _ Clients = (*ClientCache)(nil)
