package python

import (
	"github.com/knostic/open-ant-cli/internal/config"
)

// withConfigEnv passes the Go resolver's exact choice to Python. This is
// important when the Python package comes from a wheel or another location
// that cannot walk back to the OpenAnt checkout on its own.
func withConfigEnv(env []string) []string {
	path, err := config.ResolvedPath()
	if err != nil || path == "" {
		return env
	}
	return setEnv(env, config.ConfigFileEnv, path)
}
