package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output"
)

var diffCmd = &cobra.Command{
	Use:   "diff [repository-path]",
	Short: "Scan only the code changed vs a base ref, GitHub PR, or the staged index",
	Long: `Diff runs the full scan pipeline but filters to units whose bodies
overlap a git diff hunk. One of --diff-base, --pr, or --staged is required.

Examples:
  vulnfounder diff --diff-base origin/main
  vulnfounder diff --pr 123
  vulnfounder diff --staged                       # pre-commit hook usage
  vulnfounder diff --diff-base HEAD~5 --diff-scope callers --verify

All scan flags (--level, --workers, --verify, etc.) work the same here.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if scanDiffBase == "" && scanPR == 0 && !scanStaged {
			output.PrintError("vulnfounder diff requires --diff-base <ref>, --pr <N>, or --staged")
			os.Exit(2)
		}
		runScan(cmd, args)
	},
}

func init() {
	registerScanFlags(diffCmd)
}
