package cli

import (
	"context"
	"errors"
	"fmt"
	iofs "io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"time"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/authn/token"
	"github.com/steveokay/trove/internal/blob"
	"github.com/steveokay/trove/internal/blob/fs"
	"github.com/steveokay/trove/internal/blob/s3"
	"github.com/steveokay/trove/internal/cache"
	"github.com/steveokay/trove/internal/config"
	"github.com/steveokay/trove/internal/event"
	"github.com/steveokay/trove/internal/groupserve"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/postgres"
	"github.com/steveokay/trove/internal/meta/sqlite"
	"github.com/steveokay/trove/internal/proxy"
	"github.com/steveokay/trove/internal/proxyserve"
	"github.com/steveokay/trove/internal/registry"
	"github.com/steveokay/trove/internal/secretbox"
	"github.com/steveokay/trove/internal/server"
	"github.com/steveokay/trove/internal/version"
)

// runServe loads configuration, claims the data directory, bootstraps the
// deployment, and serves until the context is cancelled.
func runServe(ctx context.Context, env Env, args []string) error {
	cfg, err := config.Load(config.Options{Args: args, Output: env.Stderr})
	if err != nil {
		return err
	}

	log, err := server.NewLogger(cfg.Log, env.Stderr)
	if err != nil {
		return err
	}
	log = log.With("version", version.Get().Version)

	store, err := openMetaStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open metadata store: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Error("closing the metadata store", "error", err)
		}
	}()

	boot, err := authn.Bootstrap(ctx, store, authn.NewHasher(), nil)
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	if boot.AdminCreated {
		// Printed exactly once, to stdout rather than the log stream, so it
		// cannot end up in a shipped logfile. Rotation is forced on first
		// login; there is never a default credential (ADR 0004).
		fmt.Fprintf(env.Stdout,
			"\nInitial admin credentials (shown once; rotation is required on first login):\n"+
				"  username: %s\n  password: %s\n\n", authn.AdminName, boot.Password)
	}

	limiter, err := authn.NewAttemptLimiter(authn.DefaultAccountLimit, authn.DefaultAddressLimit, nil)
	if err != nil {
		return fmt.Errorf("build the auth rate limiter: %w", err)
	}
	login, err := authn.NewPasswordLogin(store, limiter, authn.NewHasher())
	if err != nil {
		return fmt.Errorf("build the login path: %w", err)
	}

	ring, err := openKeyring(cfg.Auth.SecretsKeyFile, log)
	if err != nil {
		return fmt.Errorf("open secrets keyfile: %w", err)
	}
	robots := authn.NewRobotSecrets(store, ring, limiter, nil)

	signingKey, err := token.LoadOrCreateKey(cfg.Auth.TokenSigningKeyFile)
	if err != nil {
		return fmt.Errorf("open token signing key: %w", err)
	}
	signer, err := token.NewSigner(signingKey, time.Duration(cfg.Auth.TokenTTL), nil, nil)
	if err != nil {
		return fmt.Errorf("build the token signer: %w", err)
	}

	hosted, err := openHostedBlobStore(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("open blob storage: %w", err)
	}
	// The cache's own store, over a disjoint root. This line and the one above
	// it are the whole of ADR 0009's wall 2: two instances, chosen here and
	// nowhere else, so nothing downstream can be handed the wrong one.
	cached, err := openCacheBlobStore(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("open cache storage: %w", err)
	}

	// The event bus and its outbox (E-001). The bus fans out in process; the
	// outbox subscriber is what makes an event durable, and it writes inside
	// the transaction that produced the event, so a row exists exactly when
	// the change that caused it committed (ADR 0012).
	bus := event.New(event.Options{Log: log})
	outbox, err := event.NewOutbox(event.OutboxOptions{
		Store:        store,
		PersistPulls: cfg.Events.PersistPulls,
		Log:          log,
	})
	if err != nil {
		return fmt.Errorf("build the event outbox: %w", err)
	}
	unsubscribe, err := bus.Subscribe(outbox.Subscription())
	if err != nil {
		return fmt.Errorf("subscribe the event outbox: %w", err)
	}
	defer unsubscribe()

	// Pull statistics ride a batcher so the hot path never writes (R-010), and
	// cache accesses ride their own for the same reason (C-013): a pull that
	// waited on an LRU write would be paying for eviction's convenience.
	pulls := registry.NewPullBatcher(registry.PullBatcherOptions{Meta: store, Log: log})
	touches, err := cache.NewTouchBatcher(cache.TouchBatcherOptions{Meta: store, Log: log})
	if err != nil {
		return fmt.Errorf("build the cache access batcher: %w", err)
	}

	servers, err := proxyAndGroupServers(store, hosted, cached, ring, bus, touches, cfg, log)
	if err != nil {
		return err
	}

	evictor, err := buildEvictor(store, cached, bus, cfg, log)
	if err != nil {
		return err
	}

	// Everything that can fail is built before anything starts running, so an
	// error on the way up never leaves a goroutine behind. The two background
	// loops go last and are stopped in the reverse order after serving ends.
	//
	// The interim reaper loop (R-011): same store values the handlers got, so
	// it cannot be pointed at a cache root (ADR 0009). Hourly is 1/24 of the
	// default TTL; P-006's scheduler replaces the loop, keeping ReapOnce.
	reaper := &registry.UploadReaper{
		Meta:  store,
		Store: hosted,
		TTL:   time.Duration(cfg.Registry.UploadSessionTTL),
		Log:   log,
	}
	reapCtx, stopReaper := context.WithCancel(ctx)
	reaperDone := make(chan struct{})
	go func() {
		defer close(reaperDone)
		reaper.Run(reapCtx, time.Hour)
	}()

	stopEviction := startCacheEviction(ctx, evictor, touches, log)

	srv := server.New(cfg, log, buildRouter(store, hosted, login, robots, signer, ring, cfg.Server.ExternalURL,
		int64(cfg.Registry.MaxManifestBytes), pulls, servers, log))
	err = srv.Run(ctx)
	// Stop the reaper after the listener is down and wait it out, so shutdown
	// never races a sweep mid-delete.
	stopReaper()
	<-reaperDone
	// The sweep stops next, and is waited out: a delete half-done when the
	// store closed would leave bytes with no row, which is the one direction
	// eviction is never allowed to fail in (ADR 0009).
	stopEviction()
	// The listener is drained, so no further pull can be observed: flush what
	// the batcher holds before the deferred store.Close takes the database
	// away. The shutdown context is already done, so the flush gets its own.
	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFlush()
	if cerr := pulls.Close(flushCtx); cerr != nil {
		log.Error("flushing pull statistics", "error", cerr)
	}
	if cerr := touches.Close(flushCtx); cerr != nil {
		log.Error("flushing cache accesses", "error", cerr)
	}
	// Drain the bus before the deferred store.Close: the outbox writes what it
	// has accepted, and a drain into a closed store would lose exactly the
	// events a shutdown is most likely to be asked about.
	if cerr := bus.Close(flushCtx); cerr != nil {
		log.Error("draining the event bus", "error", cerr)
	}
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// buildRouter assembles the served route table: one guard in front of every
// route, bearer tokens layered over basic auth as the one credential path
// (ADR 0004), the must-rotate gate armed, and the OCI token flow's two
// endpoints. A test walks the result, so what serve actually serves is pinned
// rather than assumed.
func buildRouter(store meta.Store, hosted registry.BlobStore, login *authn.PasswordLogin,
	robots *authn.RobotSecrets, signer *token.Signer, ring *secretbox.Keyring,
	externalURL string, maxManifestBytes int64, pulls registry.PullRecorder,
	servers registry.ContentServers, log *slog.Logger,
) *server.Router {
	challenge := server.TokenChallenge(externalURL)
	credentials := server.Bearer(signer, server.BasicAuth(login, robots))

	router := server.NewRouter(&server.Guard{
		Subjects:    store,
		Bindings:    store,
		Rotation:    store,
		Credentials: credentials,
		Challenge:   challenge,
		// The two error contracts, split by path: the OCI tree speaks the
		// spec's envelope, everything else problem+json (ADR 0015).
		Errors: server.SplitErrors{V2: registry.SpecErrors{}, Default: server.ProblemErrors{}},
		Log:    log,
	})
	(&server.AuthExplain{Subjects: store, Bindings: store, Log: log}).Register(router)
	(&server.AuthPassword{Login: login, Store: store, Hasher: authn.NewHasher(), Log: log}).Register(router)
	(&server.TokenEndpoint{
		Credentials: credentials, Subjects: store, Bindings: store,
		Signer: signer, Challenge: challenge, Log: log,
	}).Register(router)
	(&server.V2Root{
		Credentials: credentials, Subjects: store, Challenge: challenge, Log: log,
	}).Register(router)
	(&server.Repositories{Store: store, Bindings: store, Keys: ring, Log: log}).Register(router)
	(&registry.Blobs{Store: hosted, Meta: store, Bindings: store, Servers: servers, Log: log}).Register(router)
	(&registry.Manifests{
		Meta: store, MaxBytes: maxManifestBytes, Pulls: pulls, Servers: servers, Log: log,
	}).Register(router)
	(&registry.Tags{Meta: store, Bindings: store, Log: log}).Register(router)
	(&registry.Catalog{Meta: store, Log: log}).Register(router)
	(&registry.Referrers{Meta: store, Bindings: store, Log: log}).Register(router)
	return router
}

// openHostedBlobStore opens the configured driver over the *hosted* half of
// the storage: cached content gets its own disjoint instance when Phase 4
// wires it, and the separation is made here, at wiring time (ADR 0009).
func openHostedBlobStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (registry.BlobStore, error) {
	corrupt := func(_ context.Context, desc blob.Descriptor, err error) {
		// The blob.corrupt event lands with E-001; until then the log is the
		// audit trail for quarantined content.
		log.Error("corrupt blob quarantined", "digest", desc.Digest, "error", err)
	}
	switch cfg.Storage.Driver {
	case "s3":
		return s3.New(ctx, s3.Options{
			Endpoint:        cfg.Storage.S3.Endpoint,
			Bucket:          cfg.Storage.S3.Bucket,
			Region:          cfg.Storage.S3.Region,
			Prefix:          path.Join(cfg.Storage.S3.Prefix, "hosted"),
			AccessKeyID:     cfg.Storage.S3.AccessKeyID,
			SecretAccessKey: cfg.Storage.S3.SecretAccessKey,
			UseSSL:          cfg.Storage.S3.UseSSL,
			Redirect:        cfg.Storage.S3.Redirect,
			OnCorrupt:       corrupt,
		})
	default:
		// Config validation admits only fs and s3, and fs is the default.
		return fs.New(fs.Options{
			Root:      filepath.Join(cfg.Storage.FS.Root, "hosted"),
			OnCorrupt: corrupt,
		})
	}
}

// openKeyring loads the secrets keyfile, generating one on the first run
// (Q21): an operator should get a working deployment without ever thinking
// about key material, but an existing keyfile that cannot be read is fatal --
// with sealed values and credential digests in the database, starting with a
// fresh key would silently orphan them all (ADR 0016).
func openKeyring(path string, log *slog.Logger) (*secretbox.Keyring, error) {
	ring, err := secretbox.Load(path)
	if err == nil {
		return ring, nil
	}
	if !errors.Is(err, iofs.ErrNotExist) {
		return nil, err
	}

	ring, err = secretbox.Create(path)
	if err != nil {
		return nil, err
	}
	// Worth a log line: this file is now part of every backup (Q21).
	log.Info("generated a new secrets keyfile", "path", path)
	return ring, nil
}

// openMetaStore opens the configured metadata store. Both engines migrate on
// open unless the operator staged the upgrade themselves (§3).
func openMetaStore(ctx context.Context, cfg *config.Config) (meta.Store, error) {
	switch cfg.Database.Driver {
	case "postgres":
		return postgres.Open(ctx, postgres.Options{
			DSN:           cfg.Database.DSN,
			NoAutoMigrate: !cfg.Database.AutoMigrate,
		})
	default:
		// Config validation admits only sqlite and postgres, and sqlite is
		// the default (ADR 0006).
		return sqlite.Open(ctx, sqlite.Options{
			Path:          cfg.Database.DSN,
			NoAutoMigrate: !cfg.Database.AutoMigrate,
		})
	}
}

// openCacheBlobStore opens the *cached* half of the storage: a second instance
// of the same driver over a disjoint root or key prefix (ADR 0007, ADR 0009).
//
// It is a near-copy of openHostedBlobStore, and deliberately not a shared
// helper taking a "which half" argument. That argument is exactly the seam the
// separation exists to prevent: evicting a cached blob is always recoverable
// and deleting a hosted one never is, so the two are chosen by two lines of
// wiring rather than by a parameter somebody can pass wrong.
func openCacheBlobStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (proxy.CacheBlobStore, error) {
	corrupt := func(_ context.Context, desc blob.Descriptor, err error) {
		log.Error("corrupt cached blob quarantined", "digest", desc.Digest, "error", err)
	}
	switch cfg.Storage.Driver {
	case "s3":
		return s3.New(ctx, s3.Options{
			Endpoint:        cfg.Storage.S3.Endpoint,
			Bucket:          cfg.Storage.S3.Bucket,
			Region:          cfg.Storage.S3.Region,
			Prefix:          path.Join(cfg.Storage.S3.Prefix, "cache"),
			AccessKeyID:     cfg.Storage.S3.AccessKeyID,
			SecretAccessKey: cfg.Storage.S3.SecretAccessKey,
			UseSSL:          cfg.Storage.S3.UseSSL,
			Redirect:        cfg.Storage.S3.Redirect,
			OnCorrupt:       corrupt,
		})
	default:
		return fs.New(fs.Options{
			Root:      filepath.Join(cfg.Storage.FS.Root, "cache"),
			OnCorrupt: corrupt,
		})
	}
}

// proxyAndGroupServers builds what serves the repository types this registry
// does not hold content for (C-020).
//
// Everything here is constructed once and shared: the filler holds the
// single-flight group that collapses concurrent identical pulls (C-006) and
// the backoff standing that keeps a throttled upstream from being hammered
// (C-009), and both are worthless if each request gets its own.
func proxyAndGroupServers(store meta.Store, hosted registry.BlobStore, cached proxy.CacheBlobStore,
	ring *secretbox.Keyring, bus *event.Bus, touches *cache.TouchBatcher, cfg *config.Config, log *slog.Logger,
) (registry.ContentServers, error) {
	filler, err := proxy.NewFiller(proxy.FillerOptions{
		Blobs: cached, Meta: store, Events: bus, Log: log,
	})
	if err != nil {
		return registry.ContentServers{}, fmt.Errorf("build the cache filler: %w", err)
	}

	clients, err := proxyserve.NewClientCache(proxyserve.ClientCacheOptions{
		Meta: store, Credentials: store, Keys: ring,
	})
	if err != nil {
		return registry.ContentServers{}, fmt.Errorf("build the upstream client cache: %w", err)
	}

	proxies, err := proxyserve.New(proxyserve.Options{
		Meta: store, Clients: clients, Filler: filler, Touches: touches,
		// The deployment-wide defaults a repository's own configuration
		// overrides. They are applied here rather than inside proxyserve
		// because a zero TTL means "revalidate every pull" and is therefore
		// not a missing value any package below may fill in (ADR 0008).
		TagTTL:      time.Duration(cfg.Cache.TagTTL),
		NegativeTTL: time.Duration(cfg.Cache.NegativeTTL),
		Offline:     proxy.OfflineMode(cfg.Cache.OfflineMode),
		Log:         log,
	})
	if err != nil {
		return registry.ContentServers{}, fmt.Errorf("build the proxy server: %w", err)
	}

	groups, err := groupserve.New(groupserve.Options{
		Meta: store, Bindings: store, Events: bus, Log: log,
		Members: groupserve.Members{
			// A hosted member reads the hosted store; a proxy member goes
			// through the same server a direct proxy pull does, so a group
			// member is cached exactly as it would be on its own.
			Hosted: &registry.HostedContent{Meta: store, Store: hosted},
			Proxy:  proxies,
		},
	})
	if err != nil {
		return registry.ContentServers{}, fmt.Errorf("build the group server: %w", err)
	}

	return registry.ContentServers{Proxy: proxies, Group: groups}, nil
}

// buildEvictor makes the cache's evictor (C-013).
//
// The budget is the deployment's; per-proxy carve-outs have no configuration
// field yet, so the map is empty and every proxy shares the global budget.
// Adding the field belongs with whoever decides what a per-proxy budget means
// for a group's members.
func buildEvictor(store meta.Store, cached proxy.CacheBlobStore, bus *event.Bus,
	cfg *config.Config, log *slog.Logger,
) (*cache.Evictor, error) {
	evictor, err := cache.New(cache.Options{
		Meta:   store,
		Blobs:  cached,
		Events: bus,
		Budget: cache.Budget{Global: int64(cfg.Cache.Budget)},
		Log:    log,
	})
	if err != nil {
		return nil, fmt.Errorf("build the cache evictor: %w", err)
	}
	return evictor, nil
}

// startCacheEviction runs the sweep loop, returning a function that ends it
// and waits for it.
//
// It cannot fail, which is why it starts here rather than where the evictor is
// built: nothing between this line and the listener may return early, or the
// goroutine outlives the process that was supposed to own it.
func startCacheEviction(ctx context.Context, evictor *cache.Evictor,
	touches *cache.TouchBatcher, log *slog.Logger,
) func() {
	scheduler, err := cache.NewScheduler(cache.SchedulerOptions{
		Evictor: evictor,
		// Flushed before every sweep, or eviction would rank content served
		// seconds ago as the coldest thing in the cache (C-013).
		Touches: touches,
		Log:     log,
	})
	if err != nil {
		// Unreachable: the evictor above is non-nil and every other option has
		// a default. Reported rather than ignored, and the server still serves
		// -- a cache that stops evicting grows, which is visible in the storage
		// metrics; a registry that refuses to start serves nothing.
		log.Error("cache eviction is not running", "error", err)
		return func() {}
	}

	sweepCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = scheduler.Run(sweepCtx)
	}()

	return func() {
		stop()
		<-done
	}
}
