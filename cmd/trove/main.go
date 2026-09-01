// Command trove is the single entrypoint for the trove OCI registry.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/steveokay/trove/internal/cli"
)

func main() {
	// SIGINT and SIGTERM cancel the context, which asks long-running commands
	// to drain and stop. A second signal restores default behaviour, so an
	// impatient operator can always force the issue.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := cli.Env{Stdout: os.Stdout, Stderr: os.Stderr}

	if err := cli.Run(ctx, env, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trove:", err)
		if errors.Is(err, cli.ErrUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
