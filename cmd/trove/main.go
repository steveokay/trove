// Command trove is the single entrypoint for the trove OCI registry.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/steveokay/trove/internal/cli"
)

func main() {
	env := cli.Env{Stdout: os.Stdout, Stderr: os.Stderr}

	if err := cli.Run(env, os.Args[1:]); err != nil {
		if errors.Is(err, cli.ErrUsage) {
			fmt.Fprintln(os.Stderr, "trove:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "trove:", err)
		os.Exit(1)
	}
}
