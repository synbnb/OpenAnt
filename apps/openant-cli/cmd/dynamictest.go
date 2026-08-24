package cmd

import (
	"fmt"
	"os"

	"github.com/knostic/open-ant-cli/internal/checkpoint"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/spf13/cobra"
)

var dynamicTestCmd = &cobra.Command{
	Use:   "dynamic-test [pipeline-output-path]",
	Short: "Run dynamic testing with Docker or Claude Code",
	Long: `Dynamic-test supports two modes:

  docker       Run the existing Docker-isolated exploit tester.
  claude-code  Prepare a task workspace for Claude Code. The workspace
               contains source code, static artifacts, an OpenHarmony
               public tool library and a dynamic-testing Skill. OpenAnt
               does not start Docker or Claude Code in this mode.

Requires pipeline_output.json from the build-output or scan command.
Claude Code mode also requires --repo-path (unless the pipeline output
contains a repository path).`,
	Args: cobra.MaximumNArgs(1),
	Run:  runDynamicTest,
}

var (
	dynamicTestOutput     string
	dynamicTestMaxRetries int
	dynamicTestLLMConfig  string
	dynamicTestMode       string
	dynamicTestRepoPath   string
)

func init() {
	dynamicTestCmd.Flags().StringVarP(&dynamicTestOutput, "output", "o", "", "Output directory")
	dynamicTestCmd.Flags().IntVar(&dynamicTestMaxRetries, "max-retries", 3, "Max retries per finding on error")
	dynamicTestCmd.Flags().StringVar(&dynamicTestLLMConfig, "llm-config", "", "Name of the llm-config (resolved from OPENANT_CONFIG_FILE, project-local config/openant/config.json, or the legacy user config; defaults to the file's default_llm).")
	dynamicTestCmd.Flags().StringVar(&dynamicTestMode, "mode", "docker", "Execution mode: docker or claude-code")
	dynamicTestCmd.Flags().StringVar(&dynamicTestRepoPath, "repo-path", "", "Source repository path (required by claude-code mode when not present in project context)")
}

func validateDynamicTestMode(mode string) error {
	if mode != "docker" && mode != "claude-code" {
		return fmt.Errorf("unsupported dynamic-test mode %q: choose docker or claude-code", mode)
	}
	return nil
}

func runDynamicTest(cmd *cobra.Command, args []string) {
	if err := validateDynamicTestMode(dynamicTestMode); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	pipelineOutputPath, ctx, err := resolveFileArg(args, "pipeline_output.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Check pipeline_output.json exists before launching Python
	if _, err := os.Stat(pipelineOutputPath); err != nil {
		output.PrintError("pipeline_output.json not found. Run 'openant build-output' first.")
		os.Exit(2)
	}

	// Apply project defaults
	if ctx != nil {
		if dynamicTestOutput == "" {
			dynamicTestOutput = ctx.ScanDir
		}
		if dynamicTestRepoPath == "" {
			dynamicTestRepoPath = ctx.RepoPath
		}
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Auto-detect Docker checkpoints. Claude Code mode creates an immutable
	// task package on every invocation instead of resuming Docker attempts.
	if ctx != nil && dynamicTestMode == "docker" {
		if cpInfo := checkpoint.DetectViaPython(rt.Path, ctx.ScanDir, "dynamic_test"); cpInfo != nil {
			if checkpoint.PromptResume(cpInfo, "dynamic-test", quiet) {
				// Resume — Python auto-detects checkpoint dir in output dir
			} else {
				_ = checkpoint.Clean(cpInfo.Dir)
			}
		}
	}

	pyArgs := []string{"dynamic-test", pipelineOutputPath, "--mode", dynamicTestMode}
	if dynamicTestOutput != "" {
		pyArgs = append(pyArgs, "--output", dynamicTestOutput)
	}
	if dynamicTestMaxRetries != 3 {
		pyArgs = append(pyArgs, "--max-retries", fmt.Sprintf("%d", dynamicTestMaxRetries))
	}

	// Pass repo path for Docker source staging or the Claude Code source link.
	if dynamicTestRepoPath != "" {
		pyArgs = append(pyArgs, "--repo-path", dynamicTestRepoPath)
	}
	if dynamicTestLLMConfig != "" {
		pyArgs = append(pyArgs, "--llm-config", dynamicTestLLMConfig)
	}

	apiKey := ""
	if dynamicTestMode == "docker" {
		apiKey = requireAPIKey()
	}
	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, apiKey)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	if result.Envelope.Status == "interrupted" {
		os.Exit(130)
	} else if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintDynamicTestSummary(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}
