package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/checkpoint"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/git"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/languages"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/output"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python"
)

var scanCmd = &cobra.Command{
	Use:   "scan [repository-path]",
	Short: "Scan a repository for vulnerabilities (full pipeline)",
	Long: `Scan runs the full pipeline:
  init → parse → app-context → enhance → analyze → verify → build-output → dynamic-test → report

This is the recommended command for most users. It produces a complete
vulnerability report with false positive elimination.

If no repository path is given, the active project is used (see: vulnfounder init).

Dynamic testing runs by default when requested and uses Docker. Use
--dynamic-test-mode claude-code to prepare a Claude Code task workspace
without Docker, or --skip-dynamic-test to opt out.

Each step writes a {step}.report.json file with timing, cost, and metadata.
A final scan.report.json aggregates all step reports.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runScan,
}

var (
	scanOutput                      string
	scanLanguage                    string
	scanPlatform                    string
	scanLevel                       string
	scanVerify                      bool
	scanNoContext                   bool
	scanScopeManifest               string
	scanNoEnhance                   bool
	scanEnhanceMode                 string
	scanNoReport                    bool
	scanSkipDynamicTest             bool
	scanDynamicTestMode             string
	scanLimit                       int
	scanLLMConfig                   string
	scanWorkers                     int
	scanBackoff                     int
	scanFull                        bool
	scanIncremental                 bool
	scanDiffBase                    string
	scanPR                          int
	scanStaged                      bool
	scanDiffScope                   string
	scanLLMReachability             bool
	scanLLMReachabilityMaxCodeBytes int
	scanLLMCallGraphRecovery        bool
	scanLLMCallGraphIterative       bool
	scanLLMCallGraphCandidateReview bool
	scanLLMCallGraphProjection      bool
	scanClangSemantic               bool
	scanClangCompileCommands        string
	scanClangBuildStatus            string
	scanClangMaxFiles               int
	scanClangTimeoutSeconds         int
	scanClangBatchSize              int
	scanClangDependencyRetries      int
	scanClangDefinitionLoadMaxFiles int
	scanLibraryMode                 bool
)

func init() {
	registerScanFlags(scanCmd)
}

// registerScanFlags wires the full scan-pipeline flag set onto cmd. Used by
// scanCmd and by the thin diffCmd wrapper so that both surfaces accept the
// same knobs.
func registerScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output directory (default: project scan dir or temp dir)")
	cmd.Flags().StringVarP(&scanLanguage, "language", "l", "", languages.FlagHelp())
	cmd.Flags().StringVar(&scanPlatform, "platform", "auto", "Platform mode: auto, generic, openharmony")
	cmd.Flags().StringVar(&scanLevel, "level", "reachable", "Processing level: all, reachable, codeql, exploitable")
	cmd.Flags().BoolVar(&scanVerify, "verify", false, "Enable Stage 2 attacker simulation")
	cmd.Flags().BoolVar(&scanNoContext, "no-context", false, "Skip application context generation")
	cmd.Flags().StringVar(&scanScopeManifest, "scope-manifest", "", "Use a user-confirmed socket scan_scope.json to narrow a local repository scan")
	cmd.Flags().BoolVar(&scanNoEnhance, "no-enhance", false, "Skip context enhancement step")
	cmd.Flags().StringVar(&scanEnhanceMode, "enhance-mode", "agentic", "Enhancement mode: agentic (thorough) or single-shot (fast)")
	cmd.Flags().BoolVar(&scanNoReport, "no-report", false, "Skip report generation")
	cmd.Flags().BoolVar(&scanSkipDynamicTest, "skip-dynamic-test", false, "Skip dynamic testing (default: run selected dynamic-test mode)")
	cmd.Flags().StringVar(&scanDynamicTestMode, "dynamic-test-mode", "docker", "Dynamic-test mode: docker or claude-code")
	cmd.Flags().IntVar(&scanLimit, "limit", 0, "Max units to analyze (0 = no limit)")
	cmd.Flags().StringVar(&scanLLMConfig, "llm-config", "", "Name of the llm-config (resolved from VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json, or legacy aliases; defaults to the file's default_llm).")
	cmd.Flags().IntVar(&scanWorkers, "workers", 8, "Number of parallel workers for LLM steps (default: 8)")
	cmd.Flags().IntVar(&scanBackoff, "backoff", 30, "Seconds to wait when rate-limited (default: 30)")
	cmd.Flags().BoolVar(&scanFull, "full", false, "Force full scan (rejects --incremental/--diff-base/--pr)")
	cmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Incremental against the last successful scan on this project")
	cmd.Flags().StringVar(&scanDiffBase, "diff-base", "", "Incremental mode: filter pipeline to units overlapping diff vs this ref (e.g. origin/main, HEAD~5)")
	cmd.Flags().IntVar(&scanPR, "pr", 0, "Incremental mode against a GitHub PR number (requires gh; mutex with --diff-base)")
	cmd.Flags().BoolVar(&scanStaged, "staged", false, "Incremental mode against the staged index vs HEAD (pre-commit hook usage; mutex with --diff-base/--pr)")
	cmd.Flags().StringVar(&scanDiffScope, "diff-scope", "changed_functions", "Diff scope: changed_files, changed_functions, callers")
	cmd.Flags().BoolVar(&scanLLMReachability, "llm-reachability", false, "Enable the LLM reachability review stage (Opus). Surfaces entry points and external-input sites the structural pass would miss by reviewing the full codebase before the reachability filter is applied. Off by default — enabling this incurs cost proportional to total repo size, not the filtered unit count (~one Opus call per 25 units across the whole codebase).")
	cmd.Flags().IntVar(&scanLLMReachabilityMaxCodeBytes, "llm-reachability-max-code-bytes", 1500, "Max code bytes per unit sent to the LLM reachability stage (default: 1500). Higher values (e.g. 4096, 8192) catch entry-point indicators past byte 1500 in long handlers / generated code, at proportional Opus cost increase. Only meaningful with --llm-reachability.")
	cmd.Flags().BoolVar(&scanLLMCallGraphRecovery, "llm-call-graph-recovery", false, "Enable the advisory OpenHarmony indirect-call recovery review. Writes llm_call_graph_recovery.json without modifying the native call graph.")
	cmd.Flags().BoolVar(&scanLLMCallGraphIterative, "llm-call-graph-iterative-recovery", false, "Enable the entry-driven, bounded multi-round OpenHarmony indirect-call recovery. Writes llm_call_graph_recovery_rounds.json without modifying the native call graph.")
	cmd.Flags().BoolVar(&scanLLMCallGraphCandidateReview, "llm-call-graph-candidate-review", false, "Enable the advisory OpenHarmony candidate-edge review. Writes llm_call_graph_candidate_review.json without modifying the native call graph.")
	cmd.Flags().BoolVar(&scanLLMCallGraphProjection, "llm-call-graph-projection", false, "Project validated high-confidence OpenHarmony recovery decisions into llm_call_graph_overlay.json and, for reachable scans, use it in a promote-only BFS re-filter. The native call graph is never rewritten.")
	cmd.Flags().BoolVar(&scanClangSemantic, "clang-semantic", false, "Enable bounded Clang semantic extraction for OpenHarmony C/C++ call facts.")
	cmd.Flags().StringVar(&scanClangCompileCommands, "clang-compile-commands", "", "Optional compile_commands.json path for --clang-semantic.")
	cmd.Flags().StringVar(&scanClangBuildStatus, "clang-build-status", "compile_database", "Clang build-context provenance: compile_database, complete, manual_rebuild, reconstructed_candidate, or unknown.")
	cmd.Flags().IntVar(&scanClangMaxFiles, "clang-max-files", 128, "Maximum translation units processed by Clang.")
	cmd.Flags().IntVar(&scanClangTimeoutSeconds, "clang-timeout-seconds", 30, "Per-translation-unit Clang timeout in seconds.")
	cmd.Flags().IntVar(&scanClangBatchSize, "clang-batch-size", 16, "Number of translation units per resumable Clang batch.")
	cmd.Flags().IntVar(&scanClangDependencyRetries, "clang-dependency-retries", 1, "Bounded retries for missing-header dependency discovery.")
	cmd.Flags().IntVar(&scanClangDefinitionLoadMaxFiles, "clang-definition-load-max-files", 16, "Maximum extra translation units loaded for declaration-to-definition candidates.")
	cmd.Flags().BoolVar(&scanLibraryMode, "library-mode", false, "Seed the exported public API as reachability entry points, for a library whose public API is being dropped by the structural filter. Blunt: keeps most units — prefer letting fuzz/bin/route entry points seed reachability first.")
}

func validateScanPlatform(platform string) error {
	switch platform {
	case "auto", "generic", "openharmony":
		return nil
	default:
		return fmt.Errorf("unsupported platform %q: choose auto, generic, or openharmony", platform)
	}
}

func buildScanPyArgs(repoPath string) []string {
	pyArgs := []string{"scan", repoPath}
	if scanPlatform != "auto" {
		pyArgs = append(pyArgs, "--platform", scanPlatform)
	}
	return pyArgs
}

func runScan(cmd *cobra.Command, args []string) {
	if err := validateScanPlatform(scanPlatform); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}
	if err := validateDynamicTestMode(scanDynamicTestMode); err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}
	// Fail-fast on missing Docker when dynamic-test will run, before we
	// resolve the project, write meta.json, or shell to Python. Otherwise
	// the user burns the whole pipeline only to error at the last step.
	if !scanSkipDynamicTest && scanDynamicTestMode == "docker" {
		if err := checkDockerAvailable(); err != nil {
			output.PrintError(err.Error())
			os.Exit(2)
		}
	}

	repoPath, ctx, err := resolveRepoArg(args)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Apply project defaults if using project context
	if ctx != nil {
		if scanOutput == "" {
			scanOutput = ctx.ScanDir
		}
		if scanLanguage == "" {
			scanLanguage = ctx.Language
		}
	}
	if scanLanguage == "" {
		scanLanguage = "auto"
	}

	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Decide full vs incremental, honoring init's running meta.json if
	// present (init was just run for this commit and recorded the choice).
	decision, err := resolveScanMode(ctx, repoPath)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Build the diff manifest from the decision before checkpoint
	// detection so that any PR-mode checkout happens first and the scan
	// dir is up-to-date.
	manifestOpts := diffOpts{}
	if decision.Kind == config.ScanKindDiff {
		manifestOpts.base = decision.Base
		manifestOpts.scope = decision.Scope
		manifestOpts.staged = decision.Staged
	}
	manifestPath, err := prepareDiffManifest(repoPath, scanOutput, manifestOpts)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Check for interrupted runs in the scan directory
	if ctx != nil && scanOutput != "" {
		steps := []string{"enhance", "analyze", "verify"}
		for _, step := range steps {
			if cpInfo := checkpoint.DetectViaPython(rt.Path, scanOutput, step); cpInfo != nil {
				if !checkpoint.PromptResume(cpInfo, step, quiet) {
					_ = checkpoint.Clean(cpInfo.Dir)
				}
				// Note: Python side auto-detects and uses the checkpoint dir,
				// so we only need to clean if the user wants a fresh start.
			}
		}
	}

	// Build Python CLI args
	pyArgs := buildScanPyArgs(repoPath)
	if scanOutput != "" {
		pyArgs = append(pyArgs, "--output", scanOutput)
	}
	if scanLanguage != "auto" {
		pyArgs = append(pyArgs, "--language", scanLanguage)
	}
	if scanLevel != "reachable" {
		pyArgs = append(pyArgs, "--level", scanLevel)
	}
	if scanVerify {
		pyArgs = append(pyArgs, "--verify")
	}
	if scanNoContext {
		pyArgs = append(pyArgs, "--no-context")
	}
	if scanScopeManifest != "" {
		pyArgs = append(pyArgs, "--scope-manifest", scanScopeManifest)
	}
	if scanNoEnhance {
		pyArgs = append(pyArgs, "--no-enhance")
	}
	if scanEnhanceMode != "agentic" {
		pyArgs = append(pyArgs, "--enhance-mode", scanEnhanceMode)
	}
	if scanNoReport {
		pyArgs = append(pyArgs, "--no-report")
	}
	if !scanSkipDynamicTest {
		pyArgs = append(pyArgs, "--dynamic-test")
		if scanDynamicTestMode != "docker" {
			pyArgs = append(pyArgs, "--dynamic-test-mode", scanDynamicTestMode)
		}
	}
	if scanLimit > 0 {
		pyArgs = append(pyArgs, "--limit", fmt.Sprintf("%d", scanLimit))
	}
	if scanLLMConfig != "" {
		pyArgs = append(pyArgs, "--llm-config", scanLLMConfig)
	}
	if scanWorkers != 8 {
		pyArgs = append(pyArgs, "--workers", fmt.Sprintf("%d", scanWorkers))
	}
	if scanBackoff != 30 {
		pyArgs = append(pyArgs, "--backoff", fmt.Sprintf("%d", scanBackoff))
	}
	if manifestPath != "" {
		pyArgs = append(pyArgs, "--diff-manifest", manifestPath)
	}
	if scanLLMReachability {
		pyArgs = append(pyArgs, "--llm-reachability")
	}
	if scanLibraryMode {
		pyArgs = append(pyArgs, "--library-mode")
	}
	if scanLLMReachabilityMaxCodeBytes != 1500 {
		pyArgs = append(pyArgs, "--llm-reachability-max-code-bytes", fmt.Sprintf("%d", scanLLMReachabilityMaxCodeBytes))
	}
	pyArgs = appendScanLLMCallGraphPyArgs(pyArgs)
	pyArgs = appendScanClangPyArgs(pyArgs)

	// Pass repository metadata from project context so reports don't show
	// [NOT PROVIDED] placeholders.
	if ctx != nil && ctx.Project != nil {
		if ctx.Project.Name != "" {
			pyArgs = append(pyArgs, "--repo-name", ctx.Project.Name)
		}
		if ctx.Project.RepoURL != "" {
			pyArgs = append(pyArgs, "--repo-url", ctx.Project.RepoURL)
		}
		if ctx.Project.CommitSHA != "" {
			pyArgs = append(pyArgs, "--commit-sha", ctx.Project.CommitSHA)
		}
	}

	result, err := python.Invoke(rt.Path, pyArgs, "", quiet, requireAPIKey())
	if err != nil {
		finalizeScanMetaIfProject(ctx, config.ScanStatusFailed)
		output.PrintError(err.Error())
		os.Exit(2)
	}

	switch result.Envelope.Status {
	case "interrupted":
		finalizeScanMetaIfProject(ctx, config.ScanStatusInterrupted)
	case "success":
		finalizeScanMetaIfProject(ctx, config.ScanStatusSuccess)
	default:
		finalizeScanMetaIfProject(ctx, config.ScanStatusFailed)
	}

	if result.Envelope.Status == "interrupted" {
		os.Exit(130)
	} else if jsonOutput {
		output.PrintJSON(result.Envelope)
	} else if result.Envelope.Status == "success" {
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			output.PrintScanSummaryV2(data)
		}
	} else {
		output.PrintErrors(result.Envelope.Errors)
	}

	os.Exit(result.ExitCode)
}

// appendScanLLMCallGraphPyArgs keeps the OpenHarmony recovery/projection
// switches in one testable bridge. The Python scanner remains the source of
// truth for their semantics; the Go CLI only forwards explicitly enabled
// options.
func appendScanLLMCallGraphPyArgs(pyArgs []string) []string {
	if scanLLMCallGraphRecovery {
		pyArgs = append(pyArgs, "--llm-call-graph-recovery")
	}
	if scanLLMCallGraphIterative {
		pyArgs = append(pyArgs, "--llm-call-graph-iterative-recovery")
	}
	if scanLLMCallGraphCandidateReview {
		pyArgs = append(pyArgs, "--llm-call-graph-candidate-review")
	}
	if scanLLMCallGraphProjection {
		pyArgs = append(pyArgs, "--llm-call-graph-projection")
	}
	return pyArgs
}

// appendScanClangPyArgs forwards the bounded Clang options to the Python
// scanner. Clang remains opt-in so existing CLI scans keep their historical
// cost and semantics.
func appendScanClangPyArgs(pyArgs []string) []string {
	if !scanClangSemantic {
		return pyArgs
	}
	pyArgs = append(pyArgs, "--clang-semantic")
	if scanClangCompileCommands != "" {
		pyArgs = append(pyArgs, "--clang-compile-commands", scanClangCompileCommands)
	}
	if scanClangBuildStatus != "" && scanClangBuildStatus != "compile_database" {
		pyArgs = append(pyArgs, "--clang-build-status", scanClangBuildStatus)
	}
	if scanClangMaxFiles != 128 {
		pyArgs = append(pyArgs, "--clang-max-files", fmt.Sprintf("%d", scanClangMaxFiles))
	}
	if scanClangTimeoutSeconds != 30 {
		pyArgs = append(pyArgs, "--clang-timeout-seconds", fmt.Sprintf("%d", scanClangTimeoutSeconds))
	}
	if scanClangBatchSize != 16 {
		pyArgs = append(pyArgs, "--clang-batch-size", fmt.Sprintf("%d", scanClangBatchSize))
	}
	if scanClangDependencyRetries != 1 {
		pyArgs = append(pyArgs, "--clang-dependency-retries", fmt.Sprintf("%d", scanClangDependencyRetries))
	}
	if scanClangDefinitionLoadMaxFiles != 16 {
		pyArgs = append(pyArgs, "--clang-definition-load-max-files", fmt.Sprintf("%d", scanClangDefinitionLoadMaxFiles))
	}
	return pyArgs
}

// finalizeScanMetaIfProject updates the scan-run meta.json with a terminal
// status when the scan ran against a known project. Ad-hoc scans without
// project context have no meta.json and are silently skipped.
func finalizeScanMetaIfProject(ctx *projectContext, status string) {
	if ctx == nil || ctx.Project == nil {
		return
	}
	if err := config.FinalizeScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort, status); err != nil {
		output.PrintWarning(fmt.Sprintf("Failed to update scan meta: %s", err))
	}
}

// resolveScanMode produces the modeDecision for this scan run. Honors a
// running meta.json from a recent `openant init` (so the user is not
// re-prompted), otherwise calls selectMode with the scan flags.
//
// When running against a project, also writes meta.json status=running
// reflecting the decision so step verbs and finalizeScanMetaIfProject
// have something to read/update.
func resolveScanMode(ctx *projectContext, repoPath string) (modeDecision, error) {
	flagsPassed := scanFull || scanIncremental || scanDiffBase != "" || scanPR > 0 || scanStaged

	// Reuse init's pending decision when no flags override it.
	if !flagsPassed && ctx != nil && ctx.Project != nil {
		existing, err := config.LoadScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort)
		if err == nil && existing.Status == config.ScanStatusRunning {
			return modeDecision{Kind: existing.Kind, Base: existing.Base, Scope: existing.Scope}, nil
		}
	}

	projectName := ""
	if ctx != nil && ctx.Project != nil {
		projectName = ctx.Project.Name
	}

	decision, err := selectMode(modeOpts{
		full:        scanFull,
		incremental: scanIncremental,
		diffBase:    scanDiffBase,
		pr:          scanPR,
		staged:      scanStaged,
		scope:       scanDiffScope,
		projectName: projectName,
		repoPath:    repoPath,
	})
	if err != nil {
		return modeDecision{}, err
	}

	// Record the decision in meta.json status=running if we have a project.
	// finalizeScanMetaIfProject will flip it terminal when the pipeline ends.
	if ctx != nil && ctx.Project != nil {
		meta := config.NewScanMeta(
			decision.Kind,
			ctx.Project.CommitSHA,
			git.CurrentBranch(repoPath),
			ctx.Project.Language,
		)
		meta.Base = decision.Base
		meta.Scope = decision.Scope
		if err := config.SaveScanMeta(ctx.Project.Name, ctx.Project.CommitSHAShort, meta); err != nil {
			output.PrintWarning(fmt.Sprintf("Failed to write scan meta: %s", err))
		}
	}

	return decision, nil
}
