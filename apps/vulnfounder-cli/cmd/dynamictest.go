package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/checkpoint"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python"
)

var dynamicTestCmd = &cobra.Command{
	Use:   "dynamic-test [pipeline-output-path]",
	Short: "Run Docker, Claude Code or OpenHarmony device dynamic testing",
	Long: `Dynamic-test supports three modes:

  docker       Run the existing Docker-isolated exploit tester.
  claude-code  Prepare a task workspace for Claude Code. The workspace
               contains source code, static artifacts, an OpenHarmony
               public tool library and a dynamic-testing Skill. VulnFounder
               does not start Docker or Claude Code in this mode.
  openharmony-device
               Run an auditable Agentic Loop against an explicitly selected
               OpenHarmony development board. Read-only by default; state
               changes require --allow-state-change.

Requires pipeline_output.json from the build-output or scan command.
Claude Code mode also requires --repo-path (unless the pipeline output
contains a repository path).`,
	Args: cobra.MaximumNArgs(1),
	Run:  runDynamicTest,
}

var (
	dynamicTestOutput            string
	dynamicTestMaxRetries        int
	dynamicTestLLMConfig         string
	dynamicTestMode              string
	dynamicTestRepoPath          string
	dynamicTestDevice            string
	dynamicTestHDC               string
	dynamicTestMaxRounds         int
	dynamicTestMaxCommands       int
	dynamicTestDeviceTimeout     int
	dynamicTestDeviceWallTimeout int
	dynamicTestAllowStateChange  bool
	dynamicTestCanaryPath        string
	dynamicTestCarrierRoot       string
	dynamicTestCarrierID         string
	dynamicTestCarrierBundle     string
	dynamicTestCarrierAbility    string
	dynamicTestExecuteCarrier    bool
)

func init() {
	dynamicTestCmd.Flags().StringVarP(&dynamicTestOutput, "output", "o", "", "Output directory")
	dynamicTestCmd.Flags().IntVar(&dynamicTestMaxRetries, "max-retries", 3, "Max retries per finding on error")
	dynamicTestCmd.Flags().StringVar(&dynamicTestLLMConfig, "llm-config", "", "Name of the llm-config (resolved from VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json, or legacy aliases; defaults to the file's default_llm).")
	dynamicTestCmd.Flags().StringVar(&dynamicTestMode, "mode", "docker", "Execution mode: docker, claude-code, or openharmony-device")
	dynamicTestCmd.Flags().StringVar(&dynamicTestRepoPath, "repo-path", "", "Source repository path (required by claude-code mode when not present in project context)")
	dynamicTestCmd.Flags().StringVar(&dynamicTestDevice, "device", "", "Explicit HDC device serial (required by openharmony-device)")
	dynamicTestCmd.Flags().StringVar(&dynamicTestHDC, "hdc", "", "HDC executable path (optional)")
	dynamicTestCmd.Flags().IntVar(&dynamicTestMaxRounds, "device-max-rounds", 16, "Agentic Loop maximum rounds")
	dynamicTestCmd.Flags().IntVar(&dynamicTestMaxCommands, "device-max-commands", 512, "Maximum device commands")
	dynamicTestCmd.Flags().IntVar(&dynamicTestDeviceTimeout, "device-timeout", 30, "Per-device-command timeout in seconds")
	dynamicTestCmd.Flags().IntVar(&dynamicTestDeviceWallTimeout, "device-wall-timeout", 1200, "Total device run timeout in seconds")
	dynamicTestCmd.Flags().BoolVar(&dynamicTestAllowStateChange, "allow-state-change", false, "Explicitly allow state-changing device commands")
	dynamicTestCmd.Flags().StringVar(&dynamicTestCanaryPath, "canary-path", "/data/local/tmp/vulnfounder-canary", "Safe canary root on the device")
	dynamicTestCmd.Flags().StringVar(&dynamicTestCarrierRoot, "carrier-root", "", "Reviewed HAP carrier root")
	dynamicTestCmd.Flags().StringVar(&dynamicTestCarrierID, "carrier-id", "", "Only execute the reviewed carrier for this finding ID")
	dynamicTestCmd.Flags().StringVar(&dynamicTestCarrierBundle, "carrier-bundle", "com.security.research.trigger", "Reviewed carrier bundle name")
	dynamicTestCmd.Flags().StringVar(&dynamicTestCarrierAbility, "carrier-ability", "EntryAbility", "Reviewed carrier Ability name")
	dynamicTestCmd.Flags().BoolVar(&dynamicTestExecuteCarrier, "execute-carrier", false, "Explicitly execute reviewed HAP carriers; requires --allow-state-change")
}

func validateDynamicTestMode(mode string) error {
	if mode != "docker" && mode != "claude-code" && mode != "openharmony-device" {
		return fmt.Errorf("unsupported dynamic-test mode %q: choose docker, claude-code, or openharmony-device", mode)
	}
	return nil
}

func runDynamicTest(cmd *cobra.Command, args []string) {
	if err := validateDynamicTestMode(dynamicTestMode); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}
	if dynamicTestMode == "openharmony-device" && dynamicTestDevice == "" {
		output.PrintError("--mode openharmony-device requires --device SERIAL")
		os.Exit(2)
	}

	pipelineOutputPath, ctx, err := resolveFileArg(args, "pipeline_output.json")
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Check pipeline_output.json exists before launching Python
	if _, err := os.Stat(pipelineOutputPath); err != nil {
		output.PrintError("pipeline_output.json not found. Run 'vulnfounder build-output' first.")
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
	if dynamicTestMode == "openharmony-device" {
		pyArgs = append(pyArgs, "--device", dynamicTestDevice)
		if dynamicTestHDC != "" {
			pyArgs = append(pyArgs, "--hdc", dynamicTestHDC)
		}
		pyArgs = append(pyArgs,
			"--max-rounds", fmt.Sprintf("%d", dynamicTestMaxRounds),
			"--max-commands", fmt.Sprintf("%d", dynamicTestMaxCommands),
			"--device-timeout", fmt.Sprintf("%d", dynamicTestDeviceTimeout),
			"--device-wall-timeout", fmt.Sprintf("%d", dynamicTestDeviceWallTimeout),
			"--canary-path", dynamicTestCanaryPath,
			"--carrier-bundle", dynamicTestCarrierBundle,
			"--carrier-ability", dynamicTestCarrierAbility,
		)
		if dynamicTestCarrierRoot != "" {
			pyArgs = append(pyArgs, "--carrier-root", dynamicTestCarrierRoot)
		}
		if dynamicTestCarrierID != "" {
			pyArgs = append(pyArgs, "--carrier-id", dynamicTestCarrierID)
		}
		if dynamicTestAllowStateChange {
			pyArgs = append(pyArgs, "--allow-state-change")
		}
		if dynamicTestExecuteCarrier {
			pyArgs = append(pyArgs, "--execute-carrier")
		}
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
