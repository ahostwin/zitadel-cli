// Package version provides build information.
package version

import (
	"fmt"
	"runtime"
)

// Build information, populated at build time via ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info returns formatted version information.
func Info() string {
	return fmt.Sprintf("%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
}

// Full returns full version information.
func Full() string {
	return fmt.Sprintf(`zitadel-cli %s
  Commit:     %s
  Build Date: %s
  Go Version: %s
  OS/Arch:    %s/%s`,
		Version, Commit, BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
