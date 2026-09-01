package cli

import (
	"context"
	"fmt"
	"net/http"

	"github.com/steveokay/trove/internal/config"
	"github.com/steveokay/trove/internal/server"
	"github.com/steveokay/trove/internal/version"
)

// runServe loads configuration, claims the data directory, and serves until
// the context is cancelled.
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

	srv := server.New(cfg, log, placeholderHandler())
	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// placeholderHandler stands in until the registry and admin routers land
// (Phases 2 and 3). It refuses everything explicitly rather than 404ing, so a
// half-built server is never mistaken for a working one.
func placeholderHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"error":"trove is not serving requests yet","path":%q}`+"\n", r.URL.Path)
	})
}
