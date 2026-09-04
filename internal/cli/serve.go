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
	"github.com/steveokay/trove/internal/config"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/postgres"
	"github.com/steveokay/trove/internal/meta/sqlite"
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

	// Pull statistics ride a batcher so the hot path never writes (R-010).
	pulls := registry.NewPullBatcher(registry.PullBatcherOptions{Meta: store, Log: log})

	srv := server.New(cfg, log, buildRouter(store, hosted, login, robots, signer, cfg.Server.ExternalURL,
		int64(cfg.Registry.MaxManifestBytes), pulls, log))
	err = srv.Run(ctx)
	// Stop the reaper after the listener is down and wait it out, so shutdown
	// never races a sweep mid-delete.
	stopReaper()
	<-reaperDone
	// The listener is drained, so no further pull can be observed: flush what
	// the batcher holds before the deferred store.Close takes the database
	// away. The shutdown context is already done, so the flush gets its own.
	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFlush()
	if cerr := pulls.Close(flushCtx); cerr != nil {
		log.Error("flushing pull statistics", "error", cerr)
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
	robots *authn.RobotSecrets, signer *token.Signer, externalURL string, maxManifestBytes int64,
	pulls registry.PullRecorder, log *slog.Logger,
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
	(&registry.Blobs{Store: hosted, Meta: store, Bindings: store, Log: log}).Register(router)
	(&registry.Manifests{Meta: store, MaxBytes: maxManifestBytes, Pulls: pulls, Log: log}).Register(router)
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
