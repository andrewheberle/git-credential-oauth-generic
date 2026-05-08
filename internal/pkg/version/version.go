package version

import "runtime/debug"

var version = "dev"

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if ok && version == "dev" {
		version = info.Main.Version
	}

	return version
}
