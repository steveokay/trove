// Package version reports build metadata stamped into the binary at link time.
package version

import (
	"fmt"
	"runtime"
)

// Values are overridden at build time with -ldflags -X. Defaults describe an
// unstamped developer build.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Info describes the running build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build metadata for the running binary.
func Get() Info {
	return Info{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String renders the one-line form used by "trove version".
func (i Info) String() string {
	return fmt.Sprintf("trove %s (commit %s, built %s, %s, %s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.Platform)
}
