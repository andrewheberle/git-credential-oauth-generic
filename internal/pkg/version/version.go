package version

import (
	"runtime/debug"
	"sync"
)

// version is set at build time with -ldflags "-X ...version.version=...".
var version = "dev"

// resolved works out the version once: the build-time value, or the module
// version from the build info for "go install" builds.
var resolved = sync.OnceValue(func() string {
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			return info.Main.Version
		}
	}
	return version
})

// Version returns the helper's version. It is safe for concurrent use.
func Version() string {
	return resolved()
}
