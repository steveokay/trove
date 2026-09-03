package cli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/steveokay/trove/internal/authn"
	"github.com/steveokay/trove/internal/config"
	"github.com/steveokay/trove/internal/meta"
	"github.com/steveokay/trove/internal/meta/postgres"
	"github.com/steveokay/trove/internal/meta/sqlite"
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

	srv := server.New(cfg, log, buildRouter(store, login, log))
	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// buildRouter assembles the served route table: one guard in front of every
// route, basic auth as the bootstrap-era credential path (ADR 0004), and the
// must-rotate gate armed. A test walks the result, so what serve actually
// serves is pinned rather than assumed.
func buildRouter(store meta.Store, login *authn.PasswordLogin, log *slog.Logger) *server.Router {
	router := server.NewRouter(&server.Guard{
		Subjects:    store,
		Bindings:    store,
		Rotation:    store,
		Credentials: server.BasicAuth(login),
		Log:         log,
	})
	(&server.AuthExplain{Subjects: store, Bindings: store, Log: log}).Register(router)
	(&server.AuthPassword{Login: login, Store: store, Hasher: authn.NewHasher(), Log: log}).Register(router)
	return router
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
