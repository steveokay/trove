//go:build windows

package conformance

import (
	"errors"
	"os/exec"
)

// errNoInterrupt reports that this platform cannot signal another process.
// Windows has no SIGINT to send, so the caller falls back to killing it: the
// graceful drain is exercised on the Linux runners that gate merges, and a
// developer's local run only needs the port back.
var errNoInterrupt = errors.New("windows cannot interrupt another process")

func interrupt(*exec.Cmd) error { return errNoInterrupt }

// isWindows reports whether the built binary needs an .exe suffix.
func isWindows() bool { return true }
