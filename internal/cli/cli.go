// Package cli implements the trove command-line dispatch. It is kept separate
// from package main so every command path is testable; main only supplies the
// process's streams and exit code.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/steveokay/trove/internal/version"
)

// ErrUsage indicates the invocation was malformed. Callers exit with code 2.
var ErrUsage = errors.New("usage error")

// Env carries the process environment a command may write to.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
}

// command is one top-level subcommand.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, env Env, args []string) error
}

// commands is the dispatch table. Subcommands are implemented across later
// tasks; each unimplemented entry reports that plainly rather than pretending
// to succeed.
var commands = []command{
	{"serve", "run the registry server", runServe},
	{"migrate", "import content from another registry", notImplemented("migrate")},
	{"gc", "run garbage collection", notImplemented("gc")},
	{"verify", "verify stored content against recorded digests", notImplemented("verify")},
	{"db", "manage the vulnerability database", notImplemented("db")},
	{"policy", "inspect and apply policies", notImplemented("policy")},
	{"auth", "inspect authentication and effective permissions", notImplemented("auth")},
	{"admin", "administrative operations", notImplemented("admin")},
	{"support-bundle", "collect a diagnostic bundle", notImplemented("support-bundle")},
	{"version", "print build information", runVersion},
}

// Run dispatches args (without the program name) and returns an error suitable
// for exit-code mapping by the caller. Cancelling ctx asks a long-running
// command, such as serve, to shut down gracefully.
func Run(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		writeUsage(env.Stderr)
		return fmt.Errorf("%w: no subcommand given", ErrUsage)
	}

	name := args[0]
	switch name {
	case "-h", "--help", "help":
		writeUsage(env.Stdout)
		return nil
	}

	for _, c := range commands {
		if c.name == name {
			return c.run(ctx, env, args[1:])
		}
	}

	writeUsage(env.Stderr)
	return fmt.Errorf("%w: unknown subcommand %q", ErrUsage, name)
}

func runVersion(_ context.Context, env Env, args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	short := fs.Bool("short", false, "print only the version string")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	info := version.Get()
	if *short {
		fmt.Fprintln(env.Stdout, info.Version)
		return nil
	}
	fmt.Fprintln(env.Stdout, info)
	return nil
}

func notImplemented(name string) func(context.Context, Env, []string) error {
	return func(_ context.Context, _ Env, _ []string) error {
		return fmt.Errorf("subcommand %q is not implemented yet", name)
	}
}

func writeUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("trove - self-hosted OCI registry\n\nusage: trove <command> [flags]\n\ncommands:\n")

	names := make([]command, len(commands))
	copy(names, commands)
	sort.Slice(names, func(i, j int) bool { return names[i].name < names[j].name })

	width := 0
	for _, c := range names {
		if len(c.name) > width {
			width = len(c.name)
		}
	}
	for _, c := range names {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, c.name, c.summary)
	}
	b.WriteString("\nrun 'trove <command> -h' for command flags\n")

	fmt.Fprint(w, b.String())
}
