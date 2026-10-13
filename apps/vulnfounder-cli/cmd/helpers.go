package cmd

import (
	"vulnfounder/apps/vulnfounder-cli/internal/python"
)

// ensurePython detects the Python runtime and validates that openant is installed.
// If needed, creates a managed venv below the active VulnFounder result root
// and installs the package.
func ensurePython() (*python.RuntimeInfo, error) {
	return python.EnsureRuntime()
}
