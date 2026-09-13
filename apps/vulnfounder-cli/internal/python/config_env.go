package python

import (
	"os"
	"strings"

	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config"
)

// withConfigEnv passes the Go resolver's exact choice to Python. This is
// important when the Python package comes from a wheel or another location
// that cannot walk back to the VulnFounder checkout on its own.
func withConfigEnv(env []string) []string {
	// An explicit VULNFOUNDER_CONFIG_FILE (or its legacy VulnFounder alias) is
	// authoritative, even when the file is
	// missing: Python must then surface the user's configuration error instead
	// of silently selecting another credential file.
	explicit := strings.TrimSpace(os.Getenv(config.ConfigFileEnv))
	if explicit == "" {
		explicit = strings.TrimSpace(os.Getenv(config.LegacyConfigFileEnv))
	}
	path, err := config.ResolvedPath()
	if err != nil || path == "" {
		return env
	}
	// When the CLI is launched with `go run`, the temporary executable lives
	// outside the checkout, so the Go resolver cannot discover the project root.
	// It would otherwise return a non-existent legacy path and pass it as an
	// explicit override; Python would then see an empty config and fall back to
	// the built-in Anthropic provider, ignoring the project's canonical
	// config/vulnfounder configuration. Leave an implicit, non-existent path
	// unset so Python can resolve the project-local config from its installed
	// package location.
	if explicit == "" {
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			return env
		}
	}
	return setEnv(env, config.ConfigFileEnv, path)
}
