//go:build !windows

package conformance

import (
	"os"
	"os/exec"
)

// interrupt asks the registry to shut down the way an operator would, so the
// graceful drain runs and the test sees the same shutdown path production
// does.
func interrupt(cmd *exec.Cmd) error { return cmd.Process.Signal(os.Interrupt) }

// isWindows reports whether the built binary needs an .exe suffix.
func isWindows() bool { return false }
