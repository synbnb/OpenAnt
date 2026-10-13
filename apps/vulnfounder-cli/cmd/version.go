package cmd

import (
	"runtime"

	"github.com/spf13/cobra"
	"vulnfounder/apps/vulnfounder-cli/internal/output"
	"vulnfounder/apps/vulnfounder-cli/internal/python"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	pythonVersion := ""
	rt, err := python.DetectRuntime()
	if err == nil {
		pythonVersion = rt.Version
	}

	output.PrintVersion(version, runtime.Version(), pythonVersion)
}
