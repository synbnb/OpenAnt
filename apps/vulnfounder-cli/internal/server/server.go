// Package server implements the VulnFounder web UI HTTP server.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/report"
	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/types"
	uifiles "github.com/synbnb/vulnfounder/apps/vulnfounder-cli/ui"
)

// Job status constants.
const (
	StatusRunning = "running"
	StatusDone    = "done"
	StatusError   = "error"
)

// jobMeta is the on-disk metadata written immediately on job creation.
type jobMeta struct {
	ID                          string    `json:"id"`
	Repo                        string    `json:"repo"`
	StartedAt                   time.Time `json:"started_at"`
	Platform                    string    `json:"platform,omitempty"`
	Languages                   []string  `json:"languages,omitempty"`
	Level                       string    `json:"level,omitempty"`
	NoContext                   bool      `json:"no_context,omitempty"`
	ScopeManifest               string    `json:"scope_manifest,omitempty"`
	NoEnhance                   bool      `json:"no_enhance,omitempty"`
	EnhanceMode                 string    `json:"enhance_mode,omitempty"`
	NoReport                    bool      `json:"no_report,omitempty"`
	NoSkipTests                 bool      `json:"no_skip_tests,omitempty"`
	AllLanguages                bool      `json:"all_languages,omitempty"`
	MultiLanguage               bool      `json:"multi_language,omitempty"`
	MinLanguageFiles            int       `json:"min_language_files,omitempty"`
	MinLanguageShare            float64   `json:"min_language_share,omitempty"`
	StrictLanguages             bool      `json:"strict_languages,omitempty"`
	Limit                       int       `json:"limit,omitempty"`
	Verify                      bool      `json:"verify,omitempty"`
	LibraryMode                 bool      `json:"library_mode,omitempty"`
	LLMConfig                   string    `json:"llm_config,omitempty"`
	Workers                     int       `json:"workers,omitempty"`
	Backoff                     int       `json:"backoff,omitempty"`
	LLMReachability             bool      `json:"llm_reachability,omitempty"`
	LLMReachabilityMaxCodeBytes int       `json:"llm_reachability_max_code_bytes,omitempty"`
	LLMCallGraphRecovery        bool      `json:"llm_call_graph_recovery,omitempty"`
	LLMCallGraphIterative       bool      `json:"llm_call_graph_iterative_recovery,omitempty"`
	LLMCallGraphCandidateReview bool      `json:"llm_call_graph_candidate_review,omitempty"`
	LLMCallGraphProjection      bool      `json:"llm_call_graph_projection,omitempty"`
	DispatchCodeEvidence        bool      `json:"openharmony_dispatch_code_evidence,omitempty"`
	ClangSemantic               bool      `json:"clang_semantic,omitempty"`
	ClangBuildStatus            string    `json:"clang_build_status,omitempty"`
	ClangMaxFiles               int       `json:"clang_max_files,omitempty"`
	ClangTimeoutSeconds         int       `json:"clang_timeout_seconds,omitempty"`
	ClangBatchSize              int       `json:"clang_batch_size,omitempty"`
	ClangDependencyRetries      int       `json:"clang_dependency_retries,omitempty"`
	ClangDefinitionLoadMaxFiles int       `json:"clang_definition_load_max_files,omitempty"`
	DynamicTest                 bool      `json:"dynamic_test,omitempty"`
	DynamicTestMode             string    `json:"dynamic_test_mode,omitempty"`
	TaskWorkspace               string    `json:"task_workspace,omitempty"`
	PublicToolLibrary           string    `json:"public_tool_library,omitempty"`
	TaskManifestPath            string    `json:"task_manifest_path,omitempty"`
	CandidateManifest           string    `json:"candidate_manifest,omitempty"`
	LaunchCommand               string    `json:"launch_command,omitempty"`
	CandidateCount              int       `json:"candidate_count,omitempty"`
}

// Job represents a single scan job.
type Job struct {
	mu              sync.Mutex
	ID              string
	Repo            string
	StartedAt       time.Time
	Status          string
	LogBuf          []string
	logBytes        int  // total bytes buffered, to bound memory (see addLog)
	logCapped       bool // true once a line/byte limit was hit; no more appends
	ReportPath      string
	ReportPathZH    string
	SummaryPath     string
	SummaryPathZH   string
	DisclosurePaths []string
	Cancel          context.CancelFunc

	// Internal scan parameters (not exposed via API)
	apiKey                      string
	languages                   []string
	platform                    string
	level                       string
	noContext                   bool
	scopeManifest               string
	noEnhance                   bool
	enhanceMode                 string
	noReport                    bool
	noSkipTests                 bool
	allLanguages                bool
	multiLanguage               bool
	minLanguageFiles            int
	minLanguageShare            float64
	strictLanguages             bool
	limit                       int
	llmConfig                   string
	workers                     int
	backoff                     int
	libraryMode                 bool
	verify                      bool
	llmReachability             bool
	llmReachabilityMaxCodeBytes int
	llmCallGraphRecovery        bool
	llmCallGraphIterative       bool
	llmCallGraphCandidateReview bool
	llmCallGraphProjection      bool
	dispatchCodeEvidence        bool
	clangSemantic               bool
	clangBuildStatus            string
	clangMaxFiles               int
	clangTimeoutSeconds         int
	clangBatchSize              int
	clangDependencyRetries      int
	clangDefinitionLoadMaxFiles int
	dynamicTest                 bool
	dynamicTestMode             string
	claudeTask                  *claudeTaskInfo
	claude                      *claudeSession
	ctx                         context.Context
	done                        chan struct{} // closed by runJob after it stops touching the job dir
}

func (j *Job) addLog(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.logCapped {
		return
	}
	line = strings.ReplaceAll(line, "\r", " ")
	line = strings.ReplaceAll(line, "\n", " ")
	// Bound memory against a repo that floods stderr — by line count AND total
	// bytes (a few huge lines can blow past a line cap). Cap and stop (rather than
	// trim the front) so SSE replay indices stay stable.
	const maxLogLines = 20000
	const maxLogBytes = 8 << 20 // 8 MiB
	// Check the PROJECTED size so a single line can't overshoot the cap before
	// truncation fires on the next call — the bound stays a hard ceiling.
	if len(j.LogBuf) >= maxLogLines || j.logBytes+len(line) > maxLogBytes {
		j.LogBuf = append(j.LogBuf, "[log truncated: limit reached]")
		j.logCapped = true
		return
	}
	j.logBytes += len(line)
	j.LogBuf = append(j.LogBuf, line)
}

func (j *Job) setDone(reportPath, summaryPath, reportPathZH, summaryPathZH string, disclosurePaths []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = StatusDone
	j.ReportPath = reportPath
	j.ReportPathZH = reportPathZH
	j.SummaryPath = summaryPath
	j.SummaryPathZH = summaryPathZH
	j.DisclosurePaths = disclosurePaths
}

func (j *Job) setError() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = StatusError
}

// manager is the in-memory job store.
type manager struct {
	mu     sync.RWMutex
	jobs   map[string]*Job
	outDir string
}

func newManager(outDir string) *manager {
	return &manager{jobs: make(map[string]*Job), outDir: outDir}
}

func (m *manager) add(j *Job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[j.ID] = j
}

func (m *manager) get(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return j, ok
}

func (m *manager) remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, id)
}

func (m *manager) all() []*Job {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].StartedAt.After(out[k].StartedAt)
	})
	return out
}

func (m *manager) cancelAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, j := range m.jobs {
		j.mu.Lock()
		if j.Cancel != nil {
			j.Cancel()
		}
		j.mu.Unlock()
	}
}

// Server is the web UI HTTP server.
type Server struct {
	pythonPath             string
	outDir                 string
	mgr                    *manager
	tmplIndex              *template.Template
	tmplScan               *template.Template
	tmplArtifact           *template.Template
	tmplSum                *template.Template
	tmplDisclosure         *template.Template
	tmplSourceLocator      *template.Template
	tmplExposureSurface    *template.Template
	tmplExposureLocator    *template.Template
	tmplDeviceSocketAssets *template.Template
	tmplSocketScope        *template.Template
	sem                    chan struct{}
	csrfToken              string
	sourceLocatorMu        sync.Mutex     // serializes Web source-locator mutations, including deletion
	exposureSurfaceMu      sync.Mutex     // serializes Web exposure-surface mutations, including deletion
	wg                     sync.WaitGroup // tracks in-flight runJob goroutines for shutdown
	shutdownDone           chan struct{}  // closed once cancel+drain completes
	drainMu                sync.Mutex     // guards draining; makes wg.Add happen-before wg.Wait
	draining               bool           // set at shutdown so no new job is added after Wait starts
	deviceSocketJobsMu     sync.RWMutex   // protects Agentic device Socket runs observed by the Web UI
	deviceSocketJobs       map[string]*deviceSocketAssetJob
}

// New creates a new Server.  It parses UI templates and recovers any existing
// jobs from disk at outDir.
func New(pythonPath, outDir string) (*Server, error) {
	tmplIndex, err := template.ParseFS(uifiles.FS, "index.html")
	if err != nil {
		return nil, fmt.Errorf("parse index.html: %w", err)
	}
	tmplScan, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		return nil, fmt.Errorf("parse scan.html: %w", err)
	}
	tmplArtifact, err := template.ParseFS(uifiles.FS, "artifact-view.html")
	if err != nil {
		return nil, fmt.Errorf("parse artifact-view.html: %w", err)
	}
	tmplSum, err := template.ParseFS(uifiles.FS, "summary.html")
	if err != nil {
		return nil, fmt.Errorf("parse summary.html: %w", err)
	}
	tmplDisclosure, err := template.ParseFS(uifiles.FS, "disclosure.html")
	if err != nil {
		return nil, fmt.Errorf("parse disclosure.html: %w", err)
	}
	tmplSourceLocator, err := template.ParseFS(uifiles.FS, "source-locator.html")
	if err != nil {
		return nil, fmt.Errorf("parse source-locator.html: %w", err)
	}
	tmplExposureSurface, err := template.ParseFS(uifiles.FS, "exposure-surface.html")
	if err != nil {
		return nil, fmt.Errorf("parse exposure-surface.html: %w", err)
	}
	tmplExposureLocator, err := template.ParseFS(uifiles.FS, "exposure-locator.html")
	if err != nil {
		return nil, fmt.Errorf("parse exposure-locator.html: %w", err)
	}
	tmplDeviceSocketAssets, err := template.ParseFS(uifiles.FS, "device-socket-assets.html")
	if err != nil {
		return nil, fmt.Errorf("parse device-socket-assets.html: %w", err)
	}
	tmplSocketScope, err := template.ParseFS(uifiles.FS, "socket-scope.html")
	if err != nil {
		return nil, fmt.Errorf("parse socket-scope.html: %w", err)
	}

	// Per-instance CSRF synchronizer token: 32 hex chars from crypto/rand,
	// stable for the server's lifetime and embedded in served pages.
	tokBytes := make([]byte, 16)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}

	s := &Server{
		pythonPath:             pythonPath,
		outDir:                 outDir,
		mgr:                    newManager(outDir),
		tmplIndex:              tmplIndex,
		tmplScan:               tmplScan,
		tmplArtifact:           tmplArtifact,
		tmplSum:                tmplSum,
		tmplDisclosure:         tmplDisclosure,
		tmplSourceLocator:      tmplSourceLocator,
		tmplExposureSurface:    tmplExposureSurface,
		tmplExposureLocator:    tmplExposureLocator,
		tmplDeviceSocketAssets: tmplDeviceSocketAssets,
		tmplSocketScope:        tmplSocketScope,
		sem:                    make(chan struct{}, 4),
		csrfToken:              hex.EncodeToString(tokBytes),
		shutdownDone:           make(chan struct{}),
		deviceSocketJobs:       make(map[string]*deviceSocketAssetJob),
	}
	s.recoverJobs()
	return s, nil
}

// recoverJobs scans outDir for existing job directories and restores them.
func (s *Server) recoverJobs() {
	entries, err := os.ReadDir(s.outDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		// Only restore dirs whose name is a real job ID; anything else can't be
		// deleted via the API (jobIDRe-gated) and isn't one of our jobs.
		if !jobIDRe.MatchString(id) {
			continue
		}
		jobDir := filepath.Join(s.outDir, id)

		job := &Job{ID: id}

		// Try to read meta.json.
		if data, err := os.ReadFile(filepath.Join(jobDir, "meta.json")); err == nil {
			var m jobMeta
			if json.Unmarshal(data, &m) == nil {
				job.Repo = m.Repo
				job.StartedAt = m.StartedAt
				job.platform = m.Platform
				job.languages = append([]string(nil), m.Languages...)
				job.level = m.Level
				if job.level == "" {
					job.level = defaultScanLevel
				}
				job.noContext = m.NoContext
				job.scopeManifest = m.ScopeManifest
				job.noEnhance = m.NoEnhance
				job.enhanceMode = m.EnhanceMode
				if job.enhanceMode == "" {
					job.enhanceMode = defaultEnhanceMode
				}
				job.noReport = m.NoReport
				job.noSkipTests = m.NoSkipTests
				job.allLanguages = m.AllLanguages
				job.multiLanguage = m.MultiLanguage
				job.minLanguageFiles = m.MinLanguageFiles
				if job.minLanguageFiles == 0 {
					job.minLanguageFiles = defaultMinLanguageFiles
				}
				job.minLanguageShare = m.MinLanguageShare
				if job.minLanguageShare == 0 {
					job.minLanguageShare = defaultMinLanguageShare
				}
				job.strictLanguages = m.StrictLanguages
				job.limit = m.Limit
				job.verify = m.Verify
				job.libraryMode = m.LibraryMode
				job.llmConfig = m.LLMConfig
				job.workers = m.Workers
				if job.workers == 0 {
					job.workers = defaultScanWorkers
				}
				job.backoff = m.Backoff
				if job.backoff == 0 {
					job.backoff = defaultScanBackoff
				}
				job.llmReachability = m.LLMReachability
				job.llmReachabilityMaxCodeBytes = m.LLMReachabilityMaxCodeBytes
				if job.llmReachabilityMaxCodeBytes == 0 {
					job.llmReachabilityMaxCodeBytes = defaultLLMReachabilityMaxCodeBytes
				}
				job.llmCallGraphRecovery = m.LLMCallGraphRecovery
				job.llmCallGraphIterative = m.LLMCallGraphIterative
				job.llmCallGraphCandidateReview = m.LLMCallGraphCandidateReview
				job.llmCallGraphProjection = m.LLMCallGraphProjection
				job.dispatchCodeEvidence = m.DispatchCodeEvidence
				job.clangSemantic = m.ClangSemantic
				job.clangBuildStatus = m.ClangBuildStatus
				if job.clangBuildStatus == "" {
					job.clangBuildStatus = defaultClangBuildStatus
				}
				job.clangMaxFiles = m.ClangMaxFiles
				if job.clangMaxFiles == 0 {
					job.clangMaxFiles = defaultClangMaxFiles
				}
				job.clangTimeoutSeconds = m.ClangTimeoutSeconds
				if job.clangTimeoutSeconds == 0 {
					job.clangTimeoutSeconds = defaultClangTimeoutSeconds
				}
				job.clangBatchSize = m.ClangBatchSize
				if job.clangBatchSize == 0 {
					job.clangBatchSize = defaultClangBatchSize
				}
				job.clangDependencyRetries = m.ClangDependencyRetries
				if job.clangDependencyRetries == 0 {
					job.clangDependencyRetries = defaultClangDependencyRetries
				}
				job.clangDefinitionLoadMaxFiles = m.ClangDefinitionLoadMaxFiles
				if job.clangDefinitionLoadMaxFiles == 0 {
					job.clangDefinitionLoadMaxFiles = defaultClangDefinitionLoadMaxFiles
				}
				job.dynamicTest = m.DynamicTest
				job.dynamicTestMode = m.DynamicTestMode
				if job.dynamicTestMode == "" && job.dynamicTest {
					job.dynamicTestMode = "docker"
				}
				if m.TaskWorkspace != "" {
					job.claudeTask = &claudeTaskInfo{
						Mode:              job.dynamicTestMode,
						TaskWorkspace:     m.TaskWorkspace,
						PublicToolLibrary: m.PublicToolLibrary,
						TaskManifestPath:  m.TaskManifestPath,
						CandidateManifest: m.CandidateManifest,
						LaunchCommand:     m.LaunchCommand,
						CandidateCount:    m.CandidateCount,
					}
				}
			}
		}

		// Fall back: infer repo from git config and mtime from dir.
		if job.Repo == "" {
			job.Repo = inferRepoURL(jobDir)
		}
		if job.StartedAt.IsZero() {
			if info, err := os.Stat(jobDir); err == nil {
				job.StartedAt = info.ModTime()
			}
		}

		// A scan can finish its Python pipeline successfully while the Web
		// post-processing step that renders report.html is interrupted (for
		// example, when the Web process is restarted).  Do not turn that
		// completed scan into a failure merely because the optional HTML wrapper
		// is absent.  Prefer the aggregate scan report, then the final report
		// stage, and finally recent checkpoint activity for an in-flight run.
		job.Status = recoveredJobStatus(jobDir)
		populateRecoveredArtifacts(job, jobDir)

		// Load persisted logs if available. Sanitize each line the same way
		// addLog does (a repo can write logs.txt during --dynamic-test) so a bare
		// CR can't inject an SSE field/event on replay, and cap the count.
		if data, err := os.ReadFile(filepath.Join(jobDir, "logs.txt")); err == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			const maxLogLines = 20000
			if len(lines) > maxLogLines {
				lines = append(lines[:maxLogLines:maxLogLines], "[log truncated: too many lines]")
			}
			for i, l := range lines {
				l = strings.ReplaceAll(l, "\r", " ")
				lines[i] = strings.ReplaceAll(l, "\n", " ")
			}
			job.LogBuf = lines
		}

		s.mgr.add(job)
	}
}

// recoveredJobStatus determines the status of a job restored after the Web
// process was restarted.  The old implementation used report.html as the
// sole completion marker, but HTML is a Web-owned post-processing artifact and
// is not written by every direct/previous scan invocation.
func recoveredJobStatus(jobDir string) string {
	if isRegularNoSymlink(jobDir, filepath.Join(jobDir, "report.html")) {
		return StatusDone
	}

	// scan.report.json is the authoritative aggregate result when present.
	for _, name := range []string{"scan.report.json", "report.report.json"} {
		status, ok := readPersistedStatus(jobDir, name)
		if !ok {
			continue
		}
		switch status {
		case "success":
			return StatusDone
		case "error":
			return StatusError
		case "running", "pending", "partial":
			// A partial stage report is not a failed scan.  If it is the
			// latest evidence and the output is still being updated, expose
			// the job as running until an aggregate result is written.
			if recoveredJobActive(jobDir) {
				return StatusRunning
			}
		}
	}

	if recoveredJobActive(jobDir) {
		return StatusRunning
	}
	return StatusError
}

// readPersistedStatus reads only a small, server-owned stage envelope.  It
// deliberately ignores malformed or symlinked files so a damaged output
// directory cannot make the Web server trust arbitrary data.
func readPersistedStatus(jobDir, name string) (string, bool) {
	path := filepath.Join(jobDir, name)
	f, _, err := openRegularInRoot(jobDir, path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	var envelope struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(f, maxPipelineReportBytes)).Decode(&envelope); err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(envelope.Status)), envelope.Status != ""
}

// recoveredJobActive recognizes a scan that is still producing artifacts.
// The time bound prevents an abandoned in_progress checkpoint from being
// displayed forever after a process crash, while allowing a just-restarted
// direct Python scan to be shown as running before its next stage report is
// written.
func recoveredJobActive(jobDir string) bool {
	const activityWindow = 15 * time.Minute
	cutoff := time.Now().Add(-activityWindow)
	var latest time.Time
	var latestStatus string

	entries, err := os.ReadDir(jobDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".report.json") {
				continue
			}
			path := filepath.Join(jobDir, entry.Name())
			info, err := os.Stat(path)
			if err != nil || info.ModTime().Before(latest) {
				continue
			}
			latest = info.ModTime()
			if status, ok := readPersistedStatus(jobDir, entry.Name()); ok {
				latestStatus = status
			}
		}
	}

	for _, path := range []string{
		filepath.Join(jobDir, "analyze_checkpoints", "_summary.json"),
		filepath.Join(jobDir, "enhance_checkpoints", "_summary.json"),
		filepath.Join(jobDir, "logs.txt"),
	} {
		info, err := os.Stat(path)
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
			latestStatus = "in_progress"
		}
	}

	if latest.IsZero() || latest.Before(cutoff) {
		return false
	}
	return latestStatus != "error"
}

// populateRecoveredArtifacts restores all available report links even when
// report.html itself is missing.  This keeps completed summaries and
// disclosure documents visible in the Web UI after a restart.
func populateRecoveredArtifacts(job *Job, jobDir string) {
	reportPath := filepath.Join(jobDir, "report.html")
	if isRegularNoSymlink(jobDir, reportPath) {
		job.ReportPath = reportPath
	}
	zhReportPath := filepath.Join(jobDir, "report.zh-CN.html")
	if isRegularNoSymlink(jobDir, zhReportPath) {
		job.ReportPathZH = zhReportPath
	}
	for _, sp := range []string{
		filepath.Join(jobDir, "report", "SUMMARY_REPORT.md"),
		filepath.Join(jobDir, "SUMMARY_REPORT.md"),
	} {
		if isRegularNoSymlink(jobDir, sp) {
			job.SummaryPath = sp
			break
		}
	}
	for _, sp := range []string{
		filepath.Join(jobDir, "report", "SUMMARY_REPORT.zh-CN.md"),
		filepath.Join(jobDir, "SUMMARY_REPORT.zh-CN.md"),
	} {
		if isRegularNoSymlink(jobDir, sp) {
			job.SummaryPathZH = sp
			break
		}
	}
	job.DisclosurePaths = findDisclosures(jobDir)
}

// refreshRecoveredJob synchronizes a job restored from disk with artifacts
// written after the Web server started.  This matters for scans launched by a
// previous Web process (or directly from the CLI): their Python process cannot
// call Job.setDone, so the first aggregate report is the transition observed
// by the current Web instance.
func (s *Server) refreshRecoveredJob(job *Job) {
	job.mu.Lock()
	recovered := job.done == nil
	job.mu.Unlock()
	if !recovered {
		return
	}

	jobDir := filepath.Join(s.outDir, job.ID)
	status := recoveredJobStatus(jobDir)
	job.mu.Lock()
	job.Status = status
	job.mu.Unlock()
	populateRecoveredArtifacts(job, jobDir)
}

// inferRepoURL tries to read the origin remote URL from repo/.git/config.
func inferRepoURL(jobDir string) string {
	gitConfig := filepath.Join(jobDir, "repo", ".git", "config")
	f, err := os.Open(gitConfig)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inOrigin := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == `[remote "origin"]` {
			inOrigin = true
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url =") {
			return strings.TrimSpace(strings.TrimPrefix(line, "url ="))
		}
		if strings.HasPrefix(line, "[") {
			inOrigin = false
		}
	}
	return ""
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /repositories", s.handleRepositories)
	mux.HandleFunc("POST /scan", s.handleStartScan)
	mux.HandleFunc("GET /assets/{name}", s.handleAsset)
	mux.HandleFunc("GET /scan/{id}", s.handleScanPage)
	mux.HandleFunc("GET /scan/{id}/logs", s.handleScanLogs)
	mux.HandleFunc("GET /scan/{id}/pipeline", s.handlePipeline)
	mux.HandleFunc("GET /scan/{id}/claude", s.handleClaudeInfo)
	mux.HandleFunc("GET /scan/{id}/claude/events", s.handleClaudeEvents)
	mux.HandleFunc("POST /scan/{id}/claude/message", s.handleClaudeMessage)
	mux.HandleFunc("POST /scan/{id}/claude/stop", s.handleClaudeStop)
	mux.HandleFunc("GET /scan/{id}/claude/files", s.handleClaudeFiles)
	mux.HandleFunc("GET /scan/{id}/claude/file", s.handleClaudeFile)
	mux.HandleFunc("GET /scan/{id}/artifacts", s.handleArtifacts)
	mux.HandleFunc("GET /scan/{id}/artifact/{name}", s.handleArtifact)
	mux.HandleFunc("GET /scan/{id}/artifact-view/{name}", s.handleArtifactView)
	mux.HandleFunc("GET /scan/{id}/explore/{name}", s.handleExploreArtifact)
	mux.HandleFunc("GET /report/{id}", s.handleReport)
	mux.HandleFunc("GET /summary/{id}", s.handleSummary)
	mux.HandleFunc("GET /disclosures/{id}", s.handleDisclosureList)
	mux.HandleFunc("GET /disclosure/{id}/{filename}", s.handleDisclosure)
	mux.HandleFunc("DELETE /scan/{id}", s.handleDeleteScan)
	// Source locator routes share this loopback server, CSRF protection and
	// security headers with scan jobs; no second port or cross-origin bridge is
	// introduced.
	mux.HandleFunc("GET /source-locator", s.handleSourceLocatorIndex)
	// Unified OpenHarmony workflow: device exposure inspection is stage 1 and
	// source location is stage 2. The underlying APIs remain separate so old
	// sessions and clients stay compatible.
	mux.HandleFunc("GET /exposure-locator", s.handleExposureLocatorIndex)
	// Device-level Socket inventory is a separate, read-only discovery stage.
	// It maintains a latest snapshot per board and does not replace the
	// target-specific exposure-surface session APIs.
	mux.HandleFunc("GET /device-socket-assets", s.handleDeviceSocketAssetIndex)
	mux.HandleFunc("GET /device-socket-assets/snapshots", s.handleDeviceSocketAssetSnapshots)
	mux.HandleFunc("POST /device-socket-assets/scan", s.handleDeviceSocketAssetScan)
	mux.HandleFunc("GET /device-socket-assets/runs", s.handleDeviceSocketAssetRuns)
	mux.HandleFunc("GET /device-socket-assets/runs/{run_id}/events", s.handleDeviceSocketAssetRunEvents)
	mux.HandleFunc("GET /device-socket-assets/runs/{run_id}/artifact/{name}", s.handleDeviceSocketAssetRunArtifact)
	mux.HandleFunc("GET /device-socket-assets/runs/{run_id}", s.handleDeviceSocketAssetRun)
	mux.HandleFunc("GET /device-socket-assets/snapshots/{serial}", s.handleDeviceSocketAssetSnapshot)
	mux.HandleFunc("GET /device-socket-assets/snapshots/{serial}/artifact/{name}", s.handleDeviceSocketAssetArtifact)
	mux.HandleFunc("GET /source-locator/sessions", s.handleSourceLocatorSessions)
	mux.HandleFunc("POST /source-locator/sessions", s.handleSourceLocatorCreate)
	mux.HandleFunc("GET /source-locator/sessions/{id}", s.handleSourceLocatorStatus)
	mux.HandleFunc("GET /source-locator/sessions/{id}/handoff", s.handleSourceLocatorHandoff)
	mux.HandleFunc("GET /source-locator/sessions/{id}/events/snapshot", s.handleSourceLocatorEventSnapshot)
	mux.HandleFunc("GET /source-locator/sessions/{id}/events", s.handleSourceLocatorEvents)
	mux.HandleFunc("POST /source-locator/sessions/{id}/message", s.handleSourceLocatorMessage)
	mux.HandleFunc("POST /source-locator/sessions/{id}/advance", s.handleSourceLocatorAdvance)
	mux.HandleFunc("POST /source-locator/sessions/{id}/approve", s.handleSourceLocatorApprove)
	mux.HandleFunc("POST /source-locator/sessions/{id}/select-version", s.handleSourceLocatorSelectVersion)
	mux.HandleFunc("POST /source-locator/sessions/{id}/reject", s.handleSourceLocatorReject)
	mux.HandleFunc("POST /source-locator/sessions/{id}/cancel", s.handleSourceLocatorCancel)
	mux.HandleFunc("DELETE /source-locator/sessions/{id}", s.handleSourceLocatorDelete)
	mux.HandleFunc("GET /source-locator/sessions/{id}/artifact/{name...}", s.handleSourceLocatorArtifact)
	// Standalone OpenHarmony device exposure-surface inspection. Its initial
	// probes are read-only; the separate start/skip decision routes require
	// CSRF and an explicit pending option, and do not alter ordinary scan jobs
	// or source-locator handoff behavior.
	mux.HandleFunc("GET /exposure-surface", s.handleExposureSurfaceIndex)
	mux.HandleFunc("GET /exposure-surface/sessions", s.handleExposureSurfaceSessions)
	mux.HandleFunc("POST /exposure-surface/sessions", s.handleExposureSurfaceCreate)
	mux.HandleFunc("GET /exposure-surface/sessions/{id}", s.handleExposureSurfaceStatus)
	mux.HandleFunc("POST /exposure-surface/sessions/{id}/start", s.handleExposureSurfaceStart)
	mux.HandleFunc("POST /exposure-surface/sessions/{id}/start-service", s.handleExposureSurfaceStartService)
	mux.HandleFunc("POST /exposure-surface/sessions/{id}/skip-start", s.handleExposureSurfaceSkipStart)
	mux.HandleFunc("POST /exposure-surface/sessions/{id}/cancel", s.handleExposureSurfaceCancel)
	mux.HandleFunc("GET /exposure-surface/sessions/{id}/events/snapshot", s.handleExposureSurfaceEventSnapshot)
	mux.HandleFunc("GET /exposure-surface/sessions/{id}/events", s.handleExposureSurfaceEvents)
	mux.HandleFunc("DELETE /exposure-surface/sessions/{id}", s.handleExposureSurfaceDelete)
	mux.HandleFunc("GET /exposure-surface/sessions/{id}/artifact/{name}", s.handleExposureSurfaceArtifact)
	// Socket-guided scan scope discovery is separate from the ordinary scan
	// form: discovery proposes evidence-backed directories and the selected
	// manifest is applied only after explicit user confirmation.
	mux.HandleFunc("GET /socket-scope", s.handleSocketScopeIndex)
	mux.HandleFunc("POST /socket-scope/discover", s.handleSocketScopeDiscover)
	mux.HandleFunc("POST /socket-scope/select", s.handleSocketScopeSelect)
	return securityHeaders(mux)
}

// securityHeaders wraps h with defensive response headers on every route. The
// pages render untrusted LLM/scanned-repo content, so we deny framing, stop
// content-type sniffing, and suppress referrer leakage of the local URL.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS-rebinding guard for EVERY route (GET included): a non-loopback Host
		// means the request was aimed at another name rebound to 127.0.0.1, so a
		// remote page can't read the index (CSRF token + job list) or any report.
		if !hostHeaderIsLoopback(r) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
		h.ServeHTTP(w, r)
	})
}

// supportedLanguages is the allowlist the scan form's language checkboxes draw
// from; handleStartScan rejects any other value so an attacker-crafted POST
// cannot splice arbitrary tokens into the scanner argv.
var supportedLanguages = map[string]bool{
	"c": true, "go": true, "javascript": true, "php": true, "python": true,
	"ruby": true, "rust": true, "swift": true, "zig": true,
}

var supportedPlatforms = map[string]bool{
	"auto":        true,
	"generic":     true,
	"openharmony": true,
}

const (
	defaultScanLevel                   = "reachable"
	defaultEnhanceMode                 = "agentic"
	defaultScanWorkers                 = 8
	defaultScanBackoff                 = 30
	defaultMinLanguageFiles            = 5
	defaultMinLanguageShare            = 0.02
	maxScanLimit                       = 1_000_000
	maxScanWorkers                     = 64
	maxScanBackoff                     = 3600
	maxMinLanguageFiles                = 1_000_000
	defaultLLMReachabilityMaxCodeBytes = 1500
	minLLMReachabilityMaxCodeBytes     = 256
	maxLLMReachabilityMaxCodeBytes     = 32768
	defaultClangBuildStatus            = "compile_database"
	defaultClangMaxFiles               = 128
	defaultClangTimeoutSeconds         = 30
	defaultClangBatchSize              = 16
	defaultClangDependencyRetries      = 1
	defaultClangDefinitionLoadMaxFiles = 16
	maxClangMaxFiles                   = 10000
	maxClangTimeoutSeconds             = 600
	maxClangBatchSize                  = 256
	maxClangDependencyRetries          = 5
	maxClangDefinitionLoadMaxFiles     = 256
)

var supportedScanLevels = map[string]bool{
	"all":         true,
	"reachable":   true,
	"codeql":      true,
	"exploitable": true,
}

var supportedEnhanceModes = map[string]bool{
	"agentic":     true,
	"single-shot": true,
}

// normalizeBoundedInt validates a numeric Web option before it is placed in
// the child-process argv. Empty values use the scanner's documented default.
func normalizeBoundedInt(raw string, fallback, min, max int) (int, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < min || parsed > max {
		return 0, false
	}
	return parsed, true
}

func normalizeScanLevel(raw string) (string, bool) {
	level := strings.TrimSpace(raw)
	if level == "" {
		level = defaultScanLevel
	}
	return level, supportedScanLevels[level]
}

func normalizeEnhanceMode(raw string) (string, bool) {
	mode := strings.TrimSpace(raw)
	if mode == "" {
		mode = defaultEnhanceMode
	}
	return mode, supportedEnhanceModes[mode]
}

func normalizeMinLanguageShare(raw string) (float64, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultMinLanguageShare, true
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 || parsed > 1 {
		return 0, false
	}
	return parsed, true
}

func normalizeLLMConfigName(raw string, cfg *config.Config) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", true
	}
	if config.IsBuiltinLLMConfigName(name) {
		return name, true
	}
	if cfg == nil || !cfg.LLMConfigExists(name) {
		return "", false
	}
	return name, true
}

// normalizeLLMReachabilityMaxCodeBytes keeps the Web option within a bounded
// range. The reachability stage reviews the whole repository, so an
// unbounded value could multiply prompt size and model cost unexpectedly.
func normalizeLLMReachabilityMaxCodeBytes(raw string) (int, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultLLMReachabilityMaxCodeBytes, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minLLMReachabilityMaxCodeBytes || parsed > maxLLMReachabilityMaxCodeBytes {
		return 0, false
	}
	return parsed, true
}

// normalizePlatform validates the Web UI's platform selector. Empty input
// preserves the historical scanner default (auto), while unknown values are
// rejected before any job state or child process is created.
func normalizePlatform(raw string) (string, bool) {
	platform := strings.TrimSpace(raw)
	if platform == "" {
		platform = "auto"
	}
	return platform, supportedPlatforms[platform]
}

func platformArgs(raw string) []string {
	platform, ok := normalizePlatform(raw)
	if !ok || platform == "auto" {
		return nil
	}
	return []string{"--platform", platform}
}

// repositoryOption is the server-owned repository catalog entry exposed to
// the Web UI. value is intentionally unexported: browsers receive an opaque
// ID and label, while POST /scan resolves the ID back to this trusted value on
// the server side.
type repositoryOption struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Source string `json:"source"`

	value     string
	priority  int
	startedAt time.Time
}

type repositoriesResponse struct {
	Repositories []repositoryOption `json:"repositories"`
}

func isCloneURL(repo string) bool {
	return strings.HasPrefix(repo, "https://") ||
		strings.HasPrefix(repo, "http://") ||
		strings.HasPrefix(repo, "git@")
}

func repositoryIdentity(repo string) string {
	repo = strings.TrimSpace(repo)
	if isCloneURL(repo) {
		return repo
	}
	if abs, err := filepath.Abs(repo); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(repo)
}

func repositoryOptionID(repo string) string {
	sum := sha256.Sum256([]byte(repositoryIdentity(repo)))
	return "repo-" + hex.EncodeToString(sum[:12])
}

// usableRepositoryValue mirrors the values the Web scanner can actually
// consume. HTTP(S) URLs with embedded credentials are rejected because the
// value is persisted in job metadata and logs. Local entries must still be
// existing directories when they enter the catalog.
func usableRepositoryValue(raw string) bool {
	repo := strings.TrimSpace(raw)
	if repo == "" || strings.HasPrefix(repo, "-") {
		return false
	}
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		u, err := url.Parse(repo)
		return err == nil && u.User == nil
	}
	if isCloneURL(repo) {
		return true
	}
	if strings.HasPrefix(repo, "ssh://") {
		return false
	}
	info, err := os.Stat(repo)
	return err == nil && info.IsDir()
}

func addRepositoryOption(options *[]repositoryOption, seen map[string]struct{}, source, label, value string, priority int, startedAt time.Time) {
	value = strings.TrimSpace(value)
	if !usableRepositoryValue(value) {
		return
	}
	identity := repositoryIdentity(value)
	if _, exists := seen[identity]; exists {
		return
	}
	seen[identity] = struct{}{}
	label = strings.TrimSpace(label)
	if label == "" {
		label = value
	}
	*options = append(*options, repositoryOption{
		ID:        repositoryOptionID(value),
		Label:     label,
		Source:    source,
		value:     value,
		priority:  priority,
		startedAt: startedAt,
	})
}

// sourceCodeRepositoryOptions discovers the independent Git repositories kept
// under the project-local source_code_base directory. Only direct child
// directories with their own .git metadata are eligible; this avoids treating
// arbitrary documentation/build directories or nested project files as scan
// targets. Symlinked children and symlinked .git metadata are skipped so a
// catalog entry cannot silently point outside the project-local corpus.
func sourceCodeRepositoryOptions(options *[]repositoryOption, seen map[string]struct{}) {
	root, err := config.SourceCodeBaseDir()
	if err != nil || root == "" {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		repoPath := filepath.Join(root, entry.Name())
		gitMetadata, err := os.Lstat(filepath.Join(repoPath, ".git"))
		if err != nil || gitMetadata.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !gitMetadata.IsDir() && !gitMetadata.Mode().IsRegular() {
			continue
		}
		addRepositoryOption(options, seen, "source_code_base", "Project source — "+entry.Name(), repoPath, -1, time.Time{})
	}
}

func (s *Server) repositoryOptions() []repositoryOption {
	options := make([]repositoryOption, 0)
	seen := make(map[string]struct{})

	// The project-local corpus is the most portable source of repositories: it
	// travels with a VulnFounder checkout and does not depend on ~/.openant state.
	sourceCodeRepositoryOptions(&options, seen)

	// Initialized projects are the most stable choices and therefore appear
	// first. A remote project normally has a local clone path; if that clone was
	// removed, fall back to its credential-free origin URL so the normal clone
	// path can recreate it.
	if names, err := config.ListProjects(); err == nil {
		sort.Strings(names)
		for _, name := range names {
			project, err := config.LoadProject(name)
			if err != nil || project == nil {
				continue
			}
			value := strings.TrimSpace(project.RepoPath)
			if !usableRepositoryValue(value) {
				value = strings.TrimSpace(project.RepoURL)
			}
			label := project.Name
			if label == "" {
				label = name
			}
			addRepositoryOption(&options, seen, "project", label+" — "+value, value, 0, time.Time{})
		}
	}

	// Recent jobs provide a useful history even when the user never ran
	// `vulnfounder init`. The manager already orders jobs newest-first.
	for _, job := range s.mgr.all() {
		job.mu.Lock()
		repo := job.Repo
		startedAt := job.StartedAt
		job.mu.Unlock()
		addRepositoryOption(&options, seen, "recent", "Recent scan — "+repo, repo, 1, startedAt)
	}

	sort.SliceStable(options, func(i, j int) bool {
		if options[i].priority != options[j].priority {
			return options[i].priority < options[j].priority
		}
		if options[i].priority == 1 && !options[i].startedAt.Equal(options[j].startedAt) {
			return options[i].startedAt.After(options[j].startedAt)
		}
		return options[i].Label < options[j].Label
	})
	return options
}

func (s *Server) resolveRepositoryID(id string) (string, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false
	}
	for _, option := range s.repositoryOptions() {
		if option.ID == id {
			return option.value, true
		}
	}
	return "", false
}

// jobIDRe matches the hex job IDs randomID produces; used to reject any other
// shape before an id reaches the filesystem.
var jobIDRe = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

// hostIsLoopback reports whether host binds to loopback ONLY. Fails closed:
// anything not provably loopback (incl. "", 0.0.0.0, ::, hostnames) is false.
func hostIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Start binds the server and begins serving.  Tries addr first, then falls
// back to any available port on 127.0.0.1.  Returns the bound URL.
func (s *Server) Start(ctx context.Context, addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if !hostIsLoopback(host) {
		return "", fmt.Errorf("refusing to bind %q: the VulnFounder web UI is local-only and must listen on a loopback address (127.0.0.1 or localhost)", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Fall back to OS-assigned port.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", fmt.Errorf("listen: %w", err)
		}
	}
	url := "http://" + ln.Addr().String()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		// Mark draining before Wait so any in-flight handleStartScan either added
		// its job already (happens-before) or is refused — no Add races Wait.
		s.drainMu.Lock()
		s.draining = true
		s.drainMu.Unlock()
		s.mgr.cancelAll() // cancel job ctxs -> killer goroutines SIGKILL process groups
		s.cancelDeviceSocketAssetJobs()
		_ = srv.Close() // stop listening + drop conns immediately (an open SSE stream
		//                   would make graceful Shutdown block forever)
		// Wait for in-flight runJob goroutines to finish their kill+cleanup, bounded
		// so a wedged job cannot hang process exit.
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		close(s.shutdownDone)
	}()

	go func() {
		_ = srv.Serve(ln)
	}()

	return url, nil
}

// WaitShutdown blocks until the ctx-triggered shutdown (cancel in-flight scans +
// stop the listener) has completed, so the caller can exit without orphaning
// child scanner process groups. Safe to call after Start returns.
func (s *Server) WaitShutdown() { <-s.shutdownDone }

// ─── Handlers ──────────────────────────────────────────────────────────────

type jobView struct {
	ID           string
	Repo         string
	StartedAt    string
	Status       string
	HasReport    bool
	HasReportZH  bool
	HasSummary   bool
	HasSummaryZH bool
}

// pipelineStepSpec describes the stable order shown by the web UI.  The
// scanner writes one {step}.report.json file for completed stages; stages
// without a report are projected from the live Job state below.
type pipelineStepSpec struct {
	ID          string
	Label       string
	Description string
	Inputs      []string
	Outputs     []string
	Optional    bool
}

var pipelineStepSpecs = []pipelineStepSpec{
	{
		ID:          "parse",
		Label:       "Parse",
		Description: "Discover eligible source files, extract functions, and build native call relationships.",
		Inputs:      []string{"repository source", "platform selection", "language selection"},
		Outputs:     []string{"platform profile", "parsed dataset", "native analyzer output", "call-graph index"},
	},
	{
		ID:          "app-context",
		Label:       "App Context",
		Description: "Build the application threat model and platform-aware security context used by later LLM stages.",
		Inputs:      []string{"repository evidence", "platform profile"},
		Outputs:     []string{"application security context"},
	},
	{
		ID:          "llm-reachability",
		Label:       "LLM Reachability",
		Description: "Use an optional model pass to add likely entry points or external-input signals missed by structural detection.",
		Inputs:      []string{"full parsed dataset", "application context"},
		Outputs:     []string{"LLM reachability signals", "promoted entry points"},
		Optional:    true,
	},
	{
		ID:          "llm-call-graph-recovery",
		Label:       "LLM Call-Graph Recovery",
		Description: "Review OpenHarmony residual indirect-call sites and record evidence-backed recovery decisions without rewriting the native graph.",
		Inputs:      []string{"call-graph residual diagnostics", "function index", "entry-point hints"},
		Outputs:     []string{"recovery decisions", "recovery report"},
		Optional:    true,
	},
	{
		ID:          "llm-call-graph-candidate-review",
		Label:       "Candidate Edge Review",
		Description: "Audit deterministic candidate handlers with a model and keep accepted edges separate from the native call graph.",
		Inputs:      []string{"candidate call edges", "source evidence", "function index"},
		Outputs:     []string{"candidate-review decisions", "candidate-review report"},
		Optional:    true,
	},
	{
		ID:          "llm-call-graph-projection",
		Label:       "Call-Graph Projection",
		Description: "Project validated recovery decisions into an additive semantic overlay and optionally re-run promote-only reachability filtering.",
		Inputs:      []string{"recovery report", "candidate-review report", "unfiltered dataset"},
		Outputs:     []string{"semantic call-graph overlay", "reachability projection summary"},
		Optional:    true,
	},
	{
		ID:          "openharmony-dispatch-code-evidence",
		Label:       "Dispatch-Code Evidence",
		Description: "Extract source-backed integer dispatch selectors for OpenHarmony IPC and System Ability registrations without changing graph edges.",
		Inputs:      []string{"dispatch registrations", "source and header constants", "call-graph residuals"},
		Outputs:     []string{"dispatch-code evidence"},
		Optional:    true,
	},
	{
		ID:          "enhance",
		Label:       "Enhance",
		Description: "Attach callers, callees, semantic context, platform boundaries, and security guards to analysis units.",
		Inputs:      []string{"parsed dataset", "application context", "reachability signals"},
		Outputs:     []string{"enhanced dataset"},
	},
	{
		ID:          "analyze",
		Label:       "Analyze",
		Description: "Run the primary LLM vulnerability analysis on the selected code units.",
		Inputs:      []string{"enhanced dataset", "application context", "analysis prompts"},
		Outputs:     []string{"candidate security findings"},
	},
	{
		ID:          "verify",
		Label:       "Verify",
		Description: "Simulate an attacker path for candidate findings and reject unsupported or non-exploitable claims.",
		Inputs:      []string{"candidate findings", "source context", "threat model"},
		Outputs:     []string{"verified findings"},
		Optional:    true,
	},
	{
		ID:          "build-output",
		Label:       "Build Output",
		Description: "Normalize analysis and verification results into the stable pipeline output schema.",
		Inputs:      []string{"analysis results", "verification results"},
		Outputs:     []string{"pipeline output"},
	},
	{
		ID:          "dynamic-test",
		Label:       "Dynamic Test",
		Description: "Optionally validate candidate findings with Docker isolation or an interactive Claude Code task workspace.",
		Inputs:      []string{"pipeline findings", "target runtime", "selected execution mode"},
		Outputs:     []string{"dynamic-test task/results", "dynamic-test report"},
		Optional:    true,
	},
	{
		ID:          "report",
		Label:       "Report",
		Description: "Generate human-readable summary, HTML, and disclosure reports from the final findings.",
		Inputs:      []string{"pipeline output", "dynamic-test evidence"},
		Outputs:     []string{"aggregate scan report", "HTML report", "summary", "disclosure reports"},
	},
}

type pipelineStepView struct {
	ID              string             `json:"id"`
	Label           string             `json:"label"`
	Description     string             `json:"description"`
	Inputs          []string           `json:"inputs"`
	Outputs         []string           `json:"outputs"`
	Optional        bool               `json:"optional"`
	Status          string             `json:"status"`
	Timestamp       string             `json:"timestamp,omitempty"`
	DurationSeconds *float64           `json:"duration_seconds,omitempty"`
	CostUSD         *float64           `json:"cost_usd,omitempty"`
	CostCNY         *float64           `json:"cost_cny,omitempty"`
	CostAmount      *float64           `json:"cost_amount,omitempty"`
	CostCurrency    string             `json:"cost_currency,omitempty"`
	CostsByCurrency map[string]float64 `json:"costs_by_currency,omitempty"`
	TokenUsage      map[string]int     `json:"token_usage,omitempty"`
	Summary         map[string]any     `json:"summary,omitempty"`
	Errors          []string           `json:"errors,omitempty"`
}

type pipelineView struct {
	ID          string             `json:"id"`
	Repo        string             `json:"repo"`
	StartedAt   time.Time          `json:"started_at"`
	Status      string             `json:"status"`
	Platform    string             `json:"platform,omitempty"`
	CurrentStep string             `json:"current_step,omitempty"`
	Steps       []pipelineStepView `json:"steps"`
}

type pipelineRequestOptions struct {
	verify                      bool
	noContext                   bool
	noEnhance                   bool
	noReport                    bool
	llmReachability             bool
	llmCallGraphRecovery        bool
	llmCallGraphIterative       bool
	llmCallGraphCandidateReview bool
	llmCallGraphProjection      bool
	dispatchCodeEvidence        bool
	dynamicTest                 bool
}

type pipelineReportFile struct {
	Step            string             `json:"step"`
	Status          string             `json:"status"`
	Timestamp       string             `json:"timestamp"`
	DurationSeconds float64            `json:"duration_seconds"`
	CostUSD         float64            `json:"cost_usd"`
	CostCNY         float64            `json:"cost_cny"`
	CostAmount      float64            `json:"cost_amount"`
	CostCurrency    string             `json:"cost_currency"`
	CostsByCurrency map[string]float64 `json:"costs_by_currency"`
	TokenUsage      map[string]int     `json:"token_usage"`
	Summary         map[string]any     `json:"summary"`
	Errors          []string           `json:"errors"`
}

const maxPipelineReportBytes = 2 << 20

// requestedPipelineStep reflects the Web UI's invocation choices. Optional
// stages and explicitly skipped core stages are marked not_requested when the
// corresponding form option was not selected.
func requestedPipelineStep(id string, opts pipelineRequestOptions) bool {
	switch id {
	case "app-context":
		return !opts.noContext
	case "enhance":
		return !opts.noEnhance
	case "report":
		return !opts.noReport
	case "llm-reachability":
		return opts.llmReachability
	case "llm-call-graph-recovery":
		return opts.llmCallGraphRecovery || opts.llmCallGraphIterative
	case "llm-call-graph-candidate-review":
		return opts.llmCallGraphCandidateReview
	case "llm-call-graph-projection":
		return opts.llmCallGraphProjection
	case "openharmony-dispatch-code-evidence":
		return opts.dispatchCodeEvidence
	case "verify":
		return opts.verify
	case "dynamic-test":
		return opts.dynamicTest
	default:
		return true
	}
}

func normalizePipelineStatus(status string) string {
	switch status {
	case "success", "skipped", "error", "running", "pending", "partial":
		return status
	default:
		return "error"
	}
}

func readPipelineReport(jobDir string, spec pipelineStepSpec) (*pipelineReportFile, bool, error) {
	path := filepath.Join(jobDir, spec.ID+".report.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false, nil
	}
	f, fi, err := openRegularInRoot(jobDir, path)
	if err != nil {
		return nil, true, err
	}
	defer f.Close()
	if fi.Size() > maxPipelineReportBytes {
		return nil, true, fmt.Errorf("stage report exceeds %d bytes", maxPipelineReportBytes)
	}
	var report pipelineReportFile
	if err := json.NewDecoder(f).Decode(&report); err != nil {
		return nil, true, err
	}
	return &report, true, nil
}

func pipelineStepFromLog(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "[parse]") || strings.Contains(lower, "parsing repository"):
		return "parse"
	case strings.Contains(lower, "[app-context]") || strings.Contains(lower, "application context"):
		return "app-context"
	case strings.Contains(lower, "[llm-reachability]") || strings.Contains(lower, "llm reachability"):
		return "llm-reachability"
	case strings.Contains(lower, "call-graph recovery") || strings.Contains(lower, "call graph recovery") ||
		strings.Contains(lower, "indirect-call recovery") || strings.Contains(lower, "调用图恢复"):
		return "llm-call-graph-recovery"
	case strings.Contains(lower, "candidate-edge review") || strings.Contains(lower, "candidate edge review") ||
		strings.Contains(lower, "候选边复核"):
		return "llm-call-graph-candidate-review"
	case strings.Contains(lower, "call-edge projection") || strings.Contains(lower, "call edge projection") ||
		strings.Contains(lower, "调用边投影"):
		return "llm-call-graph-projection"
	case strings.Contains(lower, "dispatch-code evidence") || strings.Contains(lower, "dispatch code evidence") ||
		strings.Contains(lower, "分派码证据"):
		return "openharmony-dispatch-code-evidence"
	case strings.Contains(lower, "[enhance]") || strings.Contains(lower, "context enhancement"):
		return "enhance"
	case strings.Contains(lower, "[analyze]") || strings.Contains(lower, "[detect]") || strings.Contains(lower, "vulnerability analysis"):
		return "analyze"
	case strings.Contains(lower, "[verify]") || strings.Contains(lower, "verification"):
		return "verify"
	case strings.Contains(lower, "[build-output]") || strings.Contains(lower, "building pipeline_output"):
		return "build-output"
	case strings.Contains(lower, "[dynamic-test]") || strings.Contains(lower, "dynamic test"):
		return "dynamic-test"
	case strings.Contains(lower, "[report]") || strings.Contains(lower, "generating reports"):
		return "report"
	default:
		return ""
	}
}

func (s *Server) pipelineView(job *Job) pipelineView {
	job.mu.Lock()
	status := job.Status
	logs := append([]string(nil), job.LogBuf...)
	verify := job.verify
	noContext := job.noContext
	noEnhance := job.noEnhance
	noReport := job.noReport
	llmReachability := job.llmReachability
	llmCallGraphRecovery := job.llmCallGraphRecovery
	llmCallGraphIterative := job.llmCallGraphIterative
	llmCallGraphCandidateReview := job.llmCallGraphCandidateReview
	llmCallGraphProjection := job.llmCallGraphProjection
	dispatchCodeEvidence := job.dispatchCodeEvidence
	dynamicTest := job.dynamicTest
	dynamicTestMode := job.dynamicTestMode
	claudeStatus := ""
	if job.claude != nil {
		claudeStatus, _, _ = job.claude.snapshot()
	}
	view := pipelineView{
		ID:        job.ID,
		Repo:      job.Repo,
		StartedAt: job.StartedAt,
		Status:    status,
		Platform:  job.platform,
	}
	job.mu.Unlock()

	for i := len(logs) - 1; i >= 0; i-- {
		if step := pipelineStepFromLog(logs[i]); step != "" {
			view.CurrentStep = step
			break
		}
	}

	jobDir := filepath.Join(s.outDir, job.ID)
	requestOptions := pipelineRequestOptions{
		verify: verify, noContext: noContext, noEnhance: noEnhance, noReport: noReport,
		llmReachability:      llmReachability,
		llmCallGraphRecovery: llmCallGraphRecovery, llmCallGraphIterative: llmCallGraphIterative,
		llmCallGraphCandidateReview: llmCallGraphCandidateReview,
		llmCallGraphProjection:      llmCallGraphProjection, dispatchCodeEvidence: dispatchCodeEvidence,
		dynamicTest: dynamicTest,
	}
	view.Steps = make([]pipelineStepView, 0, len(pipelineStepSpecs))
	for _, spec := range pipelineStepSpecs {
		step := pipelineStepView{
			ID:          spec.ID,
			Label:       spec.Label,
			Description: spec.Description,
			Inputs:      append([]string(nil), spec.Inputs...),
			Outputs:     append([]string(nil), spec.Outputs...),
			Optional:    spec.Optional,
			Status:      "pending",
		}
		report, exists, err := readPipelineReport(jobDir, spec)
		if err != nil {
			step.Status = "error"
			step.Errors = []string{fmt.Sprintf("read stage report: %v", err)}
		} else if exists {
			step.Status = normalizePipelineStatus(report.Status)
			step.Timestamp = report.Timestamp
			step.DurationSeconds = &report.DurationSeconds
			step.CostUSD = &report.CostUSD
			step.CostCNY = &report.CostCNY
			step.CostAmount = &report.CostAmount
			step.CostCurrency = report.CostCurrency
			step.CostsByCurrency = report.CostsByCurrency
			step.TokenUsage = report.TokenUsage
			step.Summary = report.Summary
			step.Errors = report.Errors
		} else if !requestedPipelineStep(spec.ID, requestOptions) {
			step.Status = "not_requested"
		} else if status == StatusRunning && view.CurrentStep == spec.ID {
			step.Status = "running"
		} else if status == StatusError && view.CurrentStep == spec.ID {
			step.Status = "error"
		}
		if spec.ID == "dynamic-test" && dynamicTest && dynamicTestMode == "claude-code" {
			switch claudeStatus {
			case claudeStatusPrepared, claudeStatusStarting, claudeStatusRunning:
				step.Status = "running"
			case claudeStatusBlocked, claudeStatusError:
				step.Status = "error"
				step.Errors = append(step.Errors, "Claude Code 会话未能运行："+claudeStatus)
			}
		}
		view.Steps = append(view.Steps, step)
	}
	return view
}

func (s *Server) handlePipeline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.refreshRecoveredJob(job)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.pipelineView(job))
}

// artifactSpec is the server-owned allowlist of scan outputs that may be
// inspected through the Web UI.  It intentionally excludes the cloned
// repository, arbitrary paths, logs (which have a dedicated SSE endpoint),
// and report/disclosure files (which have dedicated renderers).
type artifactSpec struct {
	Name        string
	Label       string
	Category    string
	Stage       string
	Description string
}

var scanArtifactSpecs = []artifactSpec{
	{Name: "parse.report.json", Label: "Parse stage report", Category: "stage-report", Stage: "parse", Description: "Execution status, duration, summary counters, token usage, and errors recorded for source parsing."},
	{Name: "app-context.report.json", Label: "Application context stage report", Category: "stage-report", Stage: "app-context", Description: "Execution record for application classification and threat-model construction."},
	{Name: "llm-reachability.report.json", Label: "LLM reachability stage report", Category: "stage-report", Stage: "llm-reachability", Description: "Execution record for the optional model-assisted reachability review."},
	{Name: "llm-call-graph-recovery.report.json", Label: "LLM call-graph recovery stage report", Category: "stage-report", Stage: "llm-call-graph-recovery", Description: "Execution record for model review of OpenHarmony indirect-call residuals."},
	{Name: "llm-call-graph-candidate-review.report.json", Label: "Candidate edge review stage report", Category: "stage-report", Stage: "llm-call-graph-candidate-review", Description: "Execution record for model review of deterministic candidate handler edges."},
	{Name: "llm-call-graph-projection.report.json", Label: "Call-graph projection stage report", Category: "stage-report", Stage: "llm-call-graph-projection", Description: "Execution record for the additive semantic call-graph overlay."},
	{Name: "openharmony-dispatch-code-evidence.report.json", Label: "Dispatch-code evidence stage report", Category: "stage-report", Stage: "openharmony-dispatch-code-evidence", Description: "Execution record for source-backed OpenHarmony dispatch selector extraction."},
	{Name: "enhance.report.json", Label: "Enhancement stage report", Category: "stage-report", Stage: "enhance", Description: "Execution record for adding callers, callees, semantic context, and platform security signals."},
	{Name: "analyze.report.json", Label: "Analysis stage report", Category: "stage-report", Stage: "analyze", Description: "Execution record for primary LLM vulnerability detection, including model usage and errors."},
	{Name: "verify.report.json", Label: "Verification stage report", Category: "stage-report", Stage: "verify", Description: "Execution record for attacker-path verification and false-positive reduction."},
	{Name: "build-output.report.json", Label: "Build-output stage report", Category: "stage-report", Stage: "build-output", Description: "Execution record for converting stage results into the stable pipeline output format."},
	{Name: "dynamic-test.report.json", Label: "Dynamic-test stage report", Category: "stage-report", Stage: "dynamic-test", Description: "Execution record for Docker observations or the Claude Code task workspace and session."},
	{Name: "report-data.report.json", Label: "Report-data stage report", Category: "stage-report", Stage: "report", Description: "Execution record for assembling report data and remediation guidance."},
	{Name: "report.report.json", Label: "Report stage report", Category: "stage-report", Stage: "report", Description: "Execution record for final HTML, summary, and disclosure report generation."},
	{Name: "scan.report.json", Label: "Aggregate scan report", Category: "stage-report", Stage: "report", Description: "Cross-stage execution summary with overall status, cumulative model usage, cost, and errors."},
	{Name: "platform_profile.json", Label: "OpenHarmony platform profile", Category: "platform", Stage: "parse", Description: "Detected OpenHarmony components, languages, build metadata, platform boundaries, and source coverage evidence."},
	{Name: "application_context.json", Label: "Application security context", Category: "context", Stage: "app-context", Description: "Threat model describing application purpose, attacker profiles, trust boundaries, input sources, and vulnerability criteria."},
	{Name: "dataset.json", Label: "Parsed dataset", Category: "dataset", Stage: "parse", Description: "Function-level analysis units produced from source code, including origin locations and direct call relationships."},
	{Name: "dataset_enhanced.json", Label: "Enhanced dataset", Category: "dataset", Stage: "enhance", Description: "Analysis units after caller, callee, semantic, platform, and guard context has been attached. The Web viewer can also derive an Agentic context graph from the model-selected functions without changing the native call graph."},
	{Name: "analyzer_output.json", Label: "Native analyzer output", Category: "graph", Stage: "parse", Description: "Native parser output containing function definitions, source locations, code, forward calls, and reverse calls."},
	{Name: "call_graph.json", Label: "Raw call-graph index", Category: "graph", Stage: "parse", Description: "Native call-graph index containing functions, forward edges, reverse edges, and graph statistics."},
	{Name: "call_graphs.json", Label: "Call-graph index", Category: "graph", Stage: "parse", Description: "Language-to-file index locating the call graph generated for each parsed language."},
	{Name: "llm_reachability.json", Label: "LLM reachability signals", Category: "reachability", Stage: "llm-reachability", Description: "Model-proposed entry-point, external-input, and cross-process signals with confidence, source evidence, semantic-BFS seed decisions, and review reasons."},
	{Name: "llm_call_graph_recovery.json", Label: "LLM call-graph recovery", Category: "graph-recovery", Stage: "llm-call-graph-recovery", Description: "Evidence-backed model decisions for residual indirect-call sites. This advisory artifact does not rewrite the native call graph."},
	{Name: "llm_call_graph_recovery_rounds.json", Label: "Iterative call-graph recovery", Category: "graph-recovery", Stage: "llm-call-graph-recovery", Description: "Entry-driven multi-round recovery trace, including scheduled sites, model decisions, accepted edges, and unresolved sites."},
	{Name: "llm_call_graph_candidate_review.json", Label: "Candidate edge review", Category: "graph-recovery", Stage: "llm-call-graph-candidate-review", Description: "Separate model review of deterministic candidate handler edges, with evidence and confidence for each accepted or rejected candidate."},
	{Name: "llm_call_graph_overlay.json", Label: "Semantic call-graph overlay", Category: "graph-recovery", Stage: "llm-call-graph-projection", Description: "Additive projection of validated semantic edges. It is kept separate from call_graph.json and records rejected or duplicate edges."},
	{Name: "openharmony_dispatch_code_evidence.json", Label: "Dispatch-code evidence", Category: "dispatch-evidence", Stage: "openharmony-dispatch-code-evidence", Description: "Source-backed integer selector evidence for OpenHarmony IPC/System Ability dispatch registrations."},
	{Name: "results.json", Label: "Stage 1 analysis results", Category: "results", Stage: "analyze", Description: "Candidate vulnerabilities emitted by the primary analysis before attacker-path verification."},
	{Name: "results_verified.json", Label: "Stage 2 verified results", Category: "results", Stage: "verify", Description: "Candidate findings annotated with verification verdicts, exploit paths, confidence, and rejection reasons."},
	{Name: "dynamic_test_results.json", Label: "Dynamic-test results", Category: "dynamic-test", Stage: "dynamic-test", Description: "Structured observations from isolated runtime checks for selected findings."},
	{Name: "dynamic_test_results.md", Label: "Dynamic-test report", Category: "dynamic-test", Stage: "dynamic-test", Description: "Human-readable account of dynamic-test setup, execution, observations, and limitations."},
	{Name: "pipeline_results.json", Label: "Pipeline stage results", Category: "results", Stage: "build-output", Description: "Intermediate pipeline result containing stage success and stage-level outputs."},
	{Name: "scan_results.json", Label: "Raw scan results", Category: "results", Stage: "parse", Description: "Raw scan result containing scanned files, scope, counters, and scan time."},
	{Name: "scan_scope_applied.json", Label: "Applied socket scan scope", Category: "scope", Stage: "parse", Description: "The confirmed socket target, repository identity, selected scan root, and the evidence manifest used for this scan."},
	{Name: "pipeline_output.json", Label: "Pipeline output", Category: "results", Stage: "build-output", Description: "Stable normalized finding set consumed by dynamic testing and final report generation."},
}

var scanArtifactSpecByName = func() map[string]artifactSpec {
	byName := make(map[string]artifactSpec, len(scanArtifactSpecs))
	for _, spec := range scanArtifactSpecs {
		byName[spec.Name] = spec
	}
	return byName
}()

const (
	// maxArtifactBytes bounds the largest allow-listed artifact that the web
	// server will serve.  Some real OpenHarmony datasets are 100MB+, so the
	// previous 8MB ceiling made valid results impossible to inspect.  The
	// structured explorer below still streams large collections instead of
	// decoding them into one in-memory object.
	maxArtifactBytes         = 256 << 20
	maxInMemoryArtifactBytes = 8 << 20
)

type artifactView struct {
	Name        string    `json:"name"`
	Label       string    `json:"label"`
	Category    string    `json:"category"`
	Stage       string    `json:"stage"`
	Description string    `json:"description"`
	Size        int64     `json:"size"`
	ModifiedAt  time.Time `json:"modified_at"`
	ContentType string    `json:"content_type"`
	URL         string    `json:"url"`
}

func artifactContentType(name string) string {
	if strings.HasSuffix(name, ".json") {
		return "application/json; charset=utf-8"
	}
	if strings.HasSuffix(name, ".md") {
		return "text/markdown; charset=utf-8"
	}
	return "application/octet-stream"
}

func (s *Server) listArtifacts(jobID string) []artifactView {
	jobDir := filepath.Join(s.outDir, jobID)
	artifacts := make([]artifactView, 0, len(scanArtifactSpecs))
	for _, spec := range scanArtifactSpecs {
		path := filepath.Join(jobDir, spec.Name)
		if !isRegularNoSymlink(jobDir, path) {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		artifacts = append(artifacts, artifactView{
			Name:        spec.Name,
			Label:       spec.Label,
			Category:    spec.Category,
			Stage:       spec.Stage,
			Description: spec.Description,
			Size:        fi.Size(),
			ModifiedAt:  fi.ModTime().UTC(),
			ContentType: artifactContentType(spec.Name),
			URL:         "/scan/" + jobID + "/artifact/" + spec.Name,
		})
	}
	return artifacts
}

func (s *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.mgr.get(id); !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.listArtifacts(id))
}

func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.mgr.get(id); !ok {
		http.NotFound(w, r)
		return
	}
	name := r.PathValue("name")
	spec, ok := scanArtifactSpecByName[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	jobDir := filepath.Join(s.outDir, id)
	path := filepath.Join(jobDir, spec.Name)
	f, fi, err := openRegularInRoot(jobDir, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if fi.Size() > maxArtifactBytes {
		http.Error(w, "artifact is too large to view", http.StatusRequestEntityTooLarge)
		return
	}

	w.Header().Set("Content-Type", artifactContentType(spec.Name))
	w.Header().Set("Content-Disposition", `inline; filename="`+spec.Name+`"`)
	http.ServeContent(w, r, spec.Name, fi.ModTime(), f)
}

// artifactPageData is intentionally metadata-only. The standalone viewer
// fetches the allow-listed artifact through handleArtifact, so the HTML page
// never embeds potentially large or untrusted JSON into the template.
type artifactPageData struct {
	ID          string
	Name        string
	Label       string
	Stage       string
	Description string
}

// handleArtifactView serves the independent child-window shell used by the
// scan page's friendly-view action. It shares the same allowlist and regular
// file checks as the raw artifact endpoint; C2 will add artifact-specific
// Chinese field forms inside this shell.
func (s *Server) handleArtifactView(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.mgr.get(id); !ok {
		http.NotFound(w, r)
		return
	}
	name := r.PathValue("name")
	spec, ok := scanArtifactSpecByName[name]
	if !ok || !strings.HasSuffix(spec.Name, ".json") {
		http.NotFound(w, r)
		return
	}
	jobDir := filepath.Join(s.outDir, id)
	path := filepath.Join(jobDir, spec.Name)
	if !isRegularNoSymlink(jobDir, path) {
		http.NotFound(w, r)
		return
	}
	if s.tmplArtifact == nil {
		http.Error(w, "artifact viewer is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := artifactPageData{
		ID:          id,
		Name:        spec.Name,
		Label:       spec.Label,
		Stage:       spec.Stage,
		Description: spec.Description,
	}
	if err := s.tmplArtifact.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// explorerItemView is the lightweight row returned by the structured browser.
// The full object is fetched only when the user selects a row, which keeps the
// page responsive for large analyzer_output.json files.
type explorerItemView struct {
	ID        string         `json:"id"`
	Label     string         `json:"label"`
	File      string         `json:"file,omitempty"`
	StartLine int            `json:"start_line,omitempty"`
	EndLine   int            `json:"end_line,omitempty"`
	Summary   map[string]any `json:"summary,omitempty"`
}

type explorerView struct {
	Artifact             string             `json:"artifact"`
	Kind                 string             `json:"kind"`
	CollectionKey        string             `json:"collection_key,omitempty"`
	Query                string             `json:"query,omitempty"`
	Offset               int                `json:"offset,omitempty"`
	Limit                int                `json:"limit,omitempty"`
	Total                int                `json:"total,omitempty"`
	NextOffset           *int               `json:"next_offset,omitempty"`
	ItemID               string             `json:"item_id,omitempty"`
	AvailableCollections []string           `json:"available_collections,omitempty"`
	Items                []explorerItemView `json:"items,omitempty"`
	Item                 any                `json:"item,omitempty"`
	Data                 any                `json:"data,omitempty"`
	RootSummary          map[string]any     `json:"root_summary,omitempty"`
	AvailableFields      []string           `json:"available_fields,omitempty"`
}

const (
	defaultExplorerLimit = 40
	maxExplorerLimit     = 200
	maxExplorerQuery     = 256
	maxExplorerItemID    = 2048
)

type explorerFilters struct {
	Query          string
	Language       string
	UnitType       string
	Verdict        string
	Classification string
	EntryPoint     *bool
	Reachable      *bool
}

func parseExplorerFilters(r *http.Request) (explorerFilters, int, int, error) {
	q := r.URL.Query()
	filters := explorerFilters{
		Query:          strings.TrimSpace(q.Get("q")),
		Language:       strings.TrimSpace(q.Get("language")),
		UnitType:       strings.TrimSpace(q.Get("unit_type")),
		Verdict:        strings.TrimSpace(q.Get("verdict")),
		Classification: strings.TrimSpace(q.Get("classification")),
	}
	if len(filters.Query) > maxExplorerQuery || len(filters.Language) > maxExplorerQuery ||
		len(filters.UnitType) > maxExplorerQuery || len(filters.Verdict) > maxExplorerQuery ||
		len(filters.Classification) > maxExplorerQuery {
		return explorerFilters{}, 0, 0, fmt.Errorf("explorer query is too long")
	}
	parseBool := func(name string) (*bool, error) {
		value := strings.TrimSpace(q.Get(name))
		if value == "" {
			return nil, nil
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("%s must be true or false", name)
		}
		return &parsed, nil
	}
	var err error
	if filters.EntryPoint, err = parseBool("entry_point"); err != nil {
		return explorerFilters{}, 0, 0, err
	}
	if filters.Reachable, err = parseBool("reachable"); err != nil {
		return explorerFilters{}, 0, 0, err
	}

	offset := 0
	if raw := strings.TrimSpace(q.Get("offset")); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return explorerFilters{}, 0, 0, fmt.Errorf("offset must be a non-negative integer")
		}
	}
	limit := defaultExplorerLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > maxExplorerLimit {
			return explorerFilters{}, 0, 0, fmt.Errorf("limit must be between 1 and %d", maxExplorerLimit)
		}
	}
	return filters, offset, limit, nil
}

func mapString(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if raw, ok := value[key]; ok {
			if text, ok := raw.(string); ok {
				return text
			}
		}
	}
	return ""
}

func mapBool(value map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if raw, ok := value[key]; ok {
			if flag, ok := raw.(bool); ok {
				return flag, true
			}
		}
	}
	return false, false
}

func mapInt(value map[string]any, keys ...string) int {
	for _, key := range keys {
		if raw, ok := value[key]; ok {
			switch number := raw.(type) {
			case float64:
				return int(number)
			case int:
				return number
			}
		}
	}
	return 0
}

func explorerItemID(index int, key string, value any) string {
	if key != "" {
		return key
	}
	if object, ok := value.(map[string]any); ok {
		for _, field := range []string{"id", "unit_id", "route_key", "function_id", "name"} {
			if text := mapString(object, field); text != "" {
				return text
			}
		}
	}
	return fmt.Sprintf("index:%d", index)
}

func explorerLabel(artifact, id string, value any) string {
	if object, ok := value.(map[string]any); ok {
		switch artifact {
		case "dataset.json":
			if name := mapString(object, "id"); name != "" {
				return name
			}
		case "analyzer_output.json":
			if name := mapString(object, "name"); name != "" {
				return name
			}
		case "results.json", "results_verified.json":
			if functionName := mapString(object, "function_analyzed", "function_name"); functionName != "" {
				return functionName
			}
			if route := mapString(object, "route_key", "unit_id"); route != "" {
				return route
			}
			if finding := mapString(object, "finding", "verdict"); finding != "" {
				return finding
			}
		}
	}
	return id
}

func explorerLocation(artifact string, value any) (string, int, int) {
	object, ok := value.(map[string]any)
	if !ok {
		return "", 0, 0
	}
	if artifact == "dataset.json" {
		if code, ok := object["code"].(map[string]any); ok {
			if origin, ok := code["primary_origin"].(map[string]any); ok {
				return mapString(origin, "file_path", "filePath"), mapInt(origin, "start_line", "startLine"), mapInt(origin, "end_line", "endLine")
			}
		}
	}
	return mapString(object, "filePath", "file_path", "file"), mapInt(object, "startLine", "start_line"), mapInt(object, "endLine", "end_line")
}

func explorerSummary(artifact string, value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	summary := make(map[string]any)
	copyField := func(output, input string) {
		if raw, ok := object[input]; ok {
			summary[output] = raw
		}
	}
	switch artifact {
	case "dataset.json":
		copyField("language", "language")
		copyField("unit_type", "unit_type")
		copyField("reachable", "reachable")
		copyField("is_entry_point", "is_entry_point")
		copyField("direct_calls", "direct_calls")
		if metadata, ok := object["metadata"].(map[string]any); ok {
			summary["is_exported"] = metadata["is_exported"]
		}
	case "analyzer_output.json":
		copyField("language", "language")
		copyField("unit_type", "unitType")
		copyField("class", "className")
		copyField("is_exported", "isExported")
		copyField("direct_calls", "direct_calls")
	case "results.json", "results_verified.json":
		copyField("verdict", "verdict")
		copyField("confidence", "confidence")
		copyField("cwe", "cwe_id")
		copyField("classification", "security_classification")
	}
	return summary
}

func explorerMatches(artifact string, id string, value any, filters explorerFilters) bool {
	object, _ := value.(map[string]any)
	searchable, _ := json.Marshal(value)
	if filters.Query != "" {
		needle := strings.ToLower(filters.Query)
		if !strings.Contains(strings.ToLower(id+" "+string(searchable)), needle) {
			return false
		}
	}
	if object == nil {
		return filters.Language == "" && filters.UnitType == "" && filters.Verdict == "" && filters.Classification == "" && filters.EntryPoint == nil && filters.Reachable == nil
	}
	if filters.Language != "" && !strings.EqualFold(filters.Language, mapString(object, "language")) {
		return false
	}
	if filters.UnitType != "" && !strings.EqualFold(filters.UnitType, mapString(object, "unit_type", "unitType")) {
		return false
	}
	if filters.Verdict != "" && !strings.EqualFold(filters.Verdict, mapString(object, "verdict")) {
		return false
	}
	if filters.Classification != "" && !strings.EqualFold(filters.Classification, mapString(object, "security_classification", "classification")) {
		return false
	}
	if filters.EntryPoint != nil {
		flag, present := mapBool(object, "is_entry_point", "isEntryPoint")
		if !present || flag != *filters.EntryPoint {
			return false
		}
	}
	if filters.Reachable != nil {
		flag, present := mapBool(object, "reachable", "reachable_from_entry")
		if !present || flag != *filters.Reachable {
			return false
		}
	}
	return true
}

type explorerCollectionItem struct {
	ID    string
	Value any
}

func explorerCollection(artifact string, data any, requested string) (string, []explorerCollectionItem, bool) {
	object, ok := data.(map[string]any)
	if !ok {
		return "", nil, false
	}
	keys := []string{"units", "functions", "call_graph", "reverse_call_graph", "results", "findings", "signals"}
	if requested != "" {
		keys = []string{requested}
	}
	for _, key := range keys {
		if !explorerCollectionAllowed(artifact, key) {
			continue
		}
		if values, ok := object[key].([]any); ok {
			items := make([]explorerCollectionItem, 0, len(values))
			for index, value := range values {
				items = append(items, explorerCollectionItem{ID: explorerItemID(index, "", value), Value: value})
			}
			return key, items, true
		}
		if values, ok := object[key].(map[string]any); ok {
			keys := make([]string, 0, len(values))
			for id := range values {
				keys = append(keys, id)
			}
			sort.Strings(keys)
			items := make([]explorerCollectionItem, 0, len(keys))
			for _, id := range keys {
				items = append(items, explorerCollectionItem{ID: explorerItemID(0, id, values[id]), Value: values[id]})
			}
			return key, items, true
		}
	}
	return "", nil, false
}

func explorerCollectionKeys(artifact string, data any) []string {
	object, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0)
	for _, key := range []string{"units", "functions", "call_graph", "reverse_call_graph", "results", "findings", "signals"} {
		if _, ok := object[key]; !ok || !explorerCollectionAllowed(artifact, key) {
			continue
		}
		switch object[key].(type) {
		case []any, map[string]any:
			keys = append(keys, key)
		}
	}
	return keys
}

func explorerRootSummary(artifact, collectionKey string, collectionKeys []string, data any) map[string]any {
	object, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	collectionSet := make(map[string]struct{}, len(collectionKeys))
	for _, key := range collectionKeys {
		collectionSet[key] = struct{}{}
	}
	summary := make(map[string]any)
	for key, value := range object {
		if key == collectionKey {
			continue
		}
		// Collection fields are exposed through their own paginated view. Do not
		// duplicate potentially large maps/arrays in every response.
		if _, isCollection := collectionSet[key]; isCollection {
			continue
		}
		summary[key] = value
	}
	return summary
}

// explorerCollectionAllowed keeps the collection allowlist deliberately
// small.  It is shared by the regular and streaming explorers so a large
// artifact cannot expose arbitrary top-level data as a paginated collection.
func explorerCollectionAllowed(artifact, key string) bool {
	switch artifact {
	case "analyzer_output.json":
		return key == "functions" || key == "call_graph" || key == "reverse_call_graph"
	case "dataset.json", "dataset_enhanced.json":
		return key == "units"
	case "pipeline_output.json":
		// `results` is a small verdict-counter object in this artifact, not a
		// browsable collection. Only the normalized findings list is paginated.
		return key == "findings"
	default:
		switch key {
		case "units", "functions", "call_graph", "reverse_call_graph", "results", "findings", "signals":
			return true
		default:
			return false
		}
	}
}

type streamedExplorerCollection struct {
	Key           string
	Total         int
	Items         []explorerCollectionItem
	Matched       *explorerCollectionItem
	WasCollection bool
}

// streamExplorerCollectionBody consumes one large array/map value from a
// top-level JSON object.  It retains only the requested page (or requested
// item) while still counting all matching records, so a 100MB dataset does not
// become a 100MB Go object on every request.
func streamExplorerCollectionBody(dec *json.Decoder, opening json.Delim, artifact, key string, filters explorerFilters, offset, limit int, itemID string) (streamedExplorerCollection, error) {
	result := streamedExplorerCollection{Key: key, WasCollection: true, Items: make([]explorerCollectionItem, 0, limit)}
	process := func(index int, mapKey string, value any) {
		if !explorerMatches(artifact, explorerItemID(index, mapKey, value), value, filters) {
			return
		}
		candidate := explorerCollectionItem{ID: explorerItemID(index, mapKey, value), Value: value}
		if itemID != "" {
			if candidate.ID == itemID {
				copy := candidate
				result.Matched = &copy
			}
		} else if result.Total >= offset && result.Total < offset+limit {
			result.Items = append(result.Items, candidate)
		}
		result.Total++
	}

	switch opening {
	case '[':
		index := 0
		for dec.More() {
			var value any
			if err := dec.Decode(&value); err != nil {
				return streamedExplorerCollection{}, err
			}
			process(index, "", value)
			index++
		}
	case '{':
		index := 0
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return streamedExplorerCollection{}, err
			}
			mapKey, ok := token.(string)
			if !ok {
				return streamedExplorerCollection{}, fmt.Errorf("collection map key is not a string")
			}
			var value any
			if err := dec.Decode(&value); err != nil {
				return streamedExplorerCollection{}, err
			}
			process(index, mapKey, value)
			index++
		}
	default:
		return streamedExplorerCollection{}, fmt.Errorf("collection value is not an array or object")
	}
	if _, err := dec.Token(); err != nil {
		return streamedExplorerCollection{}, err
	}
	return result, nil
}

func chooseExplorerCollection(artifact string, available []string, requested string) string {
	if requested != "" {
		for _, key := range available {
			if key == requested {
				return requested
			}
		}
		return ""
	}
	for _, key := range []string{"units", "functions", "call_graph", "reverse_call_graph", "results", "findings", "signals"} {
		if !explorerCollectionAllowed(artifact, key) {
			continue
		}
		for _, candidate := range available {
			if candidate == key {
				return key
			}
		}
	}
	return ""
}

// Some artifacts contain large secondary indexes (for example the fully
// inlined code_by_route map in results.json, or include/macro maps in the
// call-graph index). They are useful for the raw download but would make a
// one-page explorer response needlessly large. Consume them with the decoder
// and leave them out of root_summary; their primary paginated collections and
// statistics remain available for inspection.
func explorerOmitLargeRootField(artifact, key string) bool {
	if artifact == "results.json" && key == "code_by_route" {
		return true
	}
	if artifact == "call_graph.json" || artifact == "analyzer_output.json" {
		switch key {
		case "includes", "macros", "macro_aliases", "prototypes":
			return true
		}
	}
	return false
}

func discardJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delim {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil { // object key
				return err
			}
			if err := discardJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := discardJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	_, err = decoder.Token() // closing delimiter
	return err
}

// exploreLargeArtifact is the streaming counterpart of handleExploreArtifact
// for artifacts larger than maxInMemoryArtifactBytes.  It returns itemMissing
// separately so the HTTP handler can preserve the normal 404 semantics for a
// requested item.
func exploreLargeArtifact(f *os.File, artifact string, filters explorerFilters, offset, limit int, requestedCollection, itemID string) (view explorerView, itemMissing bool, err error) {
	decoder := json.NewDecoder(f)
	opening, err := decoder.Token()
	if err != nil {
		return explorerView{}, false, err
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return explorerView{}, false, fmt.Errorf("artifact root is not an object")
	}

	root := make(map[string]any)
	available := make([]string, 0, 3)
	collections := make(map[string]streamedExplorerCollection)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return explorerView{}, false, err
		}
		key, ok := token.(string)
		if !ok {
			return explorerView{}, false, fmt.Errorf("artifact field name is not a string")
		}
		if explorerCollectionAllowed(artifact, key) {
			valueToken, err := decoder.Token()
			if err != nil {
				return explorerView{}, false, err
			}
			valueDelimiter, isDelimiter := valueToken.(json.Delim)
			if isDelimiter && (valueDelimiter == '[' || valueDelimiter == '{') {
				collection, err := streamExplorerCollectionBody(decoder, valueDelimiter, artifact, key, filters, offset, limit, itemID)
				if err != nil {
					return explorerView{}, false, err
				}
				available = append(available, key)
				collections[key] = collection
				continue
			}
			// A field with a collection-like name but a scalar value is kept in
			// the root summary rather than being silently discarded.
			root[key] = valueToken
			continue
		}
		if explorerOmitLargeRootField(artifact, key) {
			if err := discardJSONValue(decoder); err != nil {
				return explorerView{}, false, err
			}
			continue
		}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return explorerView{}, false, err
		}
		root[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return explorerView{}, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return explorerView{}, false, fmt.Errorf("artifact contains trailing data")
		}
		return explorerView{}, false, err
	}

	if requestedCollection != "" {
		if _, ok := collections[requestedCollection]; !ok {
			return explorerView{}, false, fmt.Errorf("unknown explorer collection")
		}
	}
	collectionKey := chooseExplorerCollection(artifact, available, requestedCollection)
	view = explorerView{
		Artifact:             artifact,
		Kind:                 "json",
		Query:                filters.Query,
		Offset:               offset,
		Limit:                limit,
		AvailableCollections: available,
	}
	if collectionKey == "" {
		view.Data = root
		keys := make([]string, 0, len(root))
		for key := range root {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		view.AvailableFields = keys
		return view, false, nil
	}
	collection := collections[collectionKey]
	view.Kind = "collection"
	view.CollectionKey = collectionKey
	view.RootSummary = explorerRootSummary(artifact, collectionKey, available, root)
	view.Total = collection.Total
	if itemID != "" {
		if collection.Matched == nil {
			return explorerView{}, true, nil
		}
		view.ItemID = itemID
		view.Item = collection.Matched.Value
		return view, false, nil
	}
	if offset > collection.Total {
		view.Offset = collection.Total
	}
	view.Items = make([]explorerItemView, 0, len(collection.Items))
	for _, candidate := range collection.Items {
		file, start, finish := explorerLocation(artifact, candidate.Value)
		view.Items = append(view.Items, explorerItemView{
			ID: candidate.ID, Label: explorerLabel(artifact, candidate.ID, candidate.Value),
			File: file, StartLine: start, EndLine: finish, Summary: explorerSummary(artifact, candidate.Value),
		})
	}
	next := view.Offset + len(view.Items)
	if next < collection.Total {
		view.NextOffset = &next
	}
	return view, false, nil
}

func (s *Server) handleExploreArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.mgr.get(id); !ok {
		http.NotFound(w, r)
		return
	}
	name := r.PathValue("name")
	spec, ok := scanArtifactSpecByName[name]
	if !ok || !strings.HasSuffix(spec.Name, ".json") {
		http.NotFound(w, r)
		return
	}
	filters, offset, limit, err := parseExplorerFilters(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	requestedCollection := strings.TrimSpace(r.URL.Query().Get("collection"))
	if len(requestedCollection) > maxExplorerQuery {
		http.Error(w, "collection name is too long", http.StatusBadRequest)
		return
	}
	itemID := strings.TrimSpace(r.URL.Query().Get("item"))
	if len(itemID) > maxExplorerItemID {
		http.Error(w, "item id is too long", http.StatusBadRequest)
		return
	}
	jobDir := filepath.Join(s.outDir, id)
	path := filepath.Join(jobDir, spec.Name)
	f, fi, err := openRegularInRoot(jobDir, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if fi.Size() > maxArtifactBytes {
		http.Error(w, "artifact is too large to explore", http.StatusRequestEntityTooLarge)
		return
	}
	if fi.Size() > maxInMemoryArtifactBytes {
		view, itemMissing, err := exploreLargeArtifact(f, name, filters, offset, limit, requestedCollection, itemID)
		if err != nil {
			if strings.Contains(err.Error(), "unknown explorer collection") {
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				http.Error(w, "artifact is not valid JSON", http.StatusUnprocessableEntity)
			}
			return
		}
		if itemMissing {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(view)
		return
	}
	var data any
	decoder := json.NewDecoder(io.LimitReader(f, maxInMemoryArtifactBytes+1))
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, "artifact is not valid JSON", http.StatusUnprocessableEntity)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "artifact contains trailing data", http.StatusUnprocessableEntity)
		return
	}

	availableCollections := explorerCollectionKeys(name, data)
	if requestedCollection != "" {
		found := false
		for _, key := range availableCollections {
			if key == requestedCollection {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "unknown explorer collection", http.StatusBadRequest)
			return
		}
	}
	collectionKey, collection, isCollection := explorerCollection(name, data, requestedCollection)
	view := explorerView{
		Artifact:             name,
		Kind:                 "json",
		Query:                filters.Query,
		Offset:               offset,
		Limit:                limit,
		AvailableFields:      nil,
		AvailableCollections: availableCollections,
	}
	if !isCollection {
		view.Data = data
		if object, ok := data.(map[string]any); ok {
			keys := make([]string, 0, len(object))
			for key := range object {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			view.AvailableFields = keys
		}
	} else {
		view.Kind = "collection"
		view.CollectionKey = collectionKey
		view.RootSummary = explorerRootSummary(name, collectionKey, availableCollections, data)
		filtered := make([]explorerCollectionItem, 0, len(collection))
		for _, candidate := range collection {
			if explorerMatches(name, candidate.ID, candidate.Value, filters) {
				filtered = append(filtered, candidate)
			}
		}
		view.Total = len(filtered)
		if offset > len(filtered) {
			offset = len(filtered)
			view.Offset = offset
		}
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		if itemID != "" {
			for _, candidate := range filtered {
				if candidate.ID == itemID {
					view.ItemID = itemID
					view.Item = candidate.Value
					break
				}
			}
			if view.Item == nil {
				http.NotFound(w, r)
				return
			}
		} else {
			view.Items = make([]explorerItemView, 0, end-offset)
			for _, candidate := range filtered[offset:end] {
				file, start, finish := explorerLocation(name, candidate.Value)
				view.Items = append(view.Items, explorerItemView{
					ID: candidate.ID, Label: explorerLabel(name, candidate.ID, candidate.Value),
					File: file, StartLine: start, EndLine: finish,
					Summary: explorerSummary(name, candidate.Value),
				})
			}
			if end < len(filtered) {
				next := end
				view.NextOffset = &next
			}
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(view)
}

type llmProviderView struct {
	Name             string
	Type             string
	BaseURL          string
	CredentialStatus string
}

type llmPhaseView struct {
	Phase    string
	Provider string
	Model    string
}

type llmConfigOption struct {
	Name     string
	Selected bool
}

// llmStatusView deliberately contains only provider metadata and credential
// presence. API-key values never leave the process and are not rendered into
// the HTML response.
type llmStatusView struct {
	Available      bool
	ConfigName     string
	Configs        []llmConfigOption
	Providers      []llmProviderView
	Phases         []llmPhaseView
	ShowLegacyKey  bool
	CredentialHint string
}

type indexData struct {
	Jobs         []*jobView
	Repositories []repositoryOption
	LLM          llmStatusView
	CSRF         string
}

func llmCredentialEnvVars(providerType string) []string {
	switch strings.ToLower(strings.TrimSpace(providerType)) {
	case "anthropic":
		return []string{"ANTHROPIC_API_KEY"}
	case "openai":
		return []string{"OPENAI_API_KEY"}
	case "openrouter":
		return []string{"OPENROUTER_API_KEY"}
	case "google":
		return []string{"GOOGLE_API_KEY", "GEMINI_API_KEY"}
	default:
		return nil
	}
}

func llmCredentialStatus(entry config.ProviderEntry, providerType string) string {
	if entry.APIKey != "" {
		return "configured in config.json"
	}
	for _, envName := range llmCredentialEnvVars(providerType) {
		if os.Getenv(envName) != "" {
			return "configured via " + envName
		}
	}
	if strings.EqualFold(strings.TrimSpace(providerType), "bedrock") {
		return "uses AWS credential chain"
	}
	return "not detected"
}

func buildLLMStatus(cfg *config.Config) llmStatusView {
	status := llmStatusView{
		Available:     true, // the built-in VulnFounder config is always available
		ConfigName:    config.DefaultLLMConfigName,
		ShowLegacyKey: true,
		Configs:       []llmConfigOption{{Name: config.DefaultLLMConfigName, Selected: true}},
	}
	if cfg == nil {
		status.Providers = []llmProviderView{{
			Name:             "anthropic",
			Type:             "anthropic",
			CredentialStatus: llmCredentialStatus(config.ProviderEntry{}, "anthropic"),
		}}
		status.CredentialHint = "Legacy mode: configure an Anthropic key with vulnfounder set-api-key, or enter a key for this scan."
		return status
	}

	status.ConfigName = cfg.DefaultLLMName()
	if status.ConfigName == config.LegacyDefaultLLMConfigName {
		status.ConfigName = config.DefaultLLMConfigName
	}
	configNames := cfg.LLMConfigNames()
	sort.Strings(configNames)
	status.Configs = []llmConfigOption{{Name: config.DefaultLLMConfigName, Selected: status.ConfigName == config.DefaultLLMConfigName}}
	selected := status.ConfigName == config.DefaultLLMConfigName
	for _, name := range configNames {
		isSelected := name == status.ConfigName
		selected = selected || isSelected
		status.Configs = append(status.Configs, llmConfigOption{Name: name, Selected: isSelected})
	}
	if !selected {
		// A stale default_llm should not leave the select with no selected
		// option. Python falls back to the built-in config in this situation.
		status.ConfigName = config.DefaultLLMConfigName
		status.Configs[0].Selected = true
	}
	status.ShowLegacyKey = !cfg.HasV2Providers()
	if !cfg.HasV2Providers() {
		status.Providers = []llmProviderView{{
			Name:             "anthropic",
			Type:             "anthropic",
			CredentialStatus: llmCredentialStatus(config.ProviderEntry{APIKey: cfg.APIKey}, "anthropic"),
		}}
		status.CredentialHint = "Legacy mode: configure an Anthropic key with vulnfounder set-api-key, or enter a key for this scan."
		return status
	}

	status.CredentialHint = "Credentials are loaded from the provider configuration or its environment variable; secrets are never shown here."
	phaseSummaries := cfg.LLMPhaseSummaries(status.ConfigName)
	providerNames := make(map[string]struct{})
	for _, phase := range phaseSummaries {
		status.Phases = append(status.Phases, llmPhaseView{
			Phase:    phase.Phase,
			Provider: phase.Provider,
			Model:    phase.Model,
		})
		providerNames[phase.Provider] = struct{}{}
	}
	// The built-in config is defined in Python rather than config.json. If a
	// v2 file exists but leaves default_llm at that built-in, still show the
	// provider that will actually be used.
	if len(providerNames) == 0 && status.ConfigName == config.DefaultLLMConfigName {
		providerNames["anthropic"] = struct{}{}
	}
	names := make([]string, 0, len(providerNames))
	for name := range providerNames {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, found := cfg.GetProvider(name)
		providerType := entry.Type
		if !found && name == "anthropic" {
			providerType = "anthropic"
		}
		if providerType == "" {
			providerType = "custom"
		}
		status.Providers = append(status.Providers, llmProviderView{
			Name:             name,
			Type:             providerType,
			BaseURL:          entry.BaseURL,
			CredentialStatus: llmCredentialStatus(entry, providerType),
		})
	}
	return status
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load()

	jobs := s.mgr.all()
	views := make([]*jobView, 0, len(jobs))
	for _, j := range jobs {
		s.refreshRecoveredJob(j)
		j.mu.Lock()
		v := &jobView{
			ID:           j.ID,
			Repo:         j.Repo,
			StartedAt:    j.StartedAt.Format("2006-01-02 15:04:05"),
			Status:       j.Status,
			HasReport:    j.ReportPath != "",
			HasReportZH:  j.ReportPathZH != "",
			HasSummary:   j.SummaryPath != "",
			HasSummaryZH: j.SummaryPathZH != "",
		}
		j.mu.Unlock()
		views = append(views, v)
	}

	d := indexData{
		Jobs:         views,
		Repositories: s.repositoryOptions(),
		LLM:          buildLLMStatus(cfg),
		CSRF:         s.csrfToken,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplIndex.Execute(w, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleRepositories(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(repositoriesResponse{Repositories: s.repositoryOptions()})
}

// hostHeaderIsLoopback reports whether the request's Host is a loopback name.
// The server binds loopback only, so a non-loopback Host means the request was
// aimed at some other name that DNS-rebound to 127.0.0.1 — reject it. Enforced
// for EVERY route by the securityHeaders middleware (not just mutations), so a
// rebinding page can't read the index/reports/logs either.
func hostHeaderIsLoopback(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	// Accept ANY loopback IP so a server bound to e.g. 127.0.0.2 (hostIsLoopback
	// allows the whole 127.0.0.0/8 for binding) isn't 403'd by its own Host check.
	// A rebound name like "evil.com" is not an IP literal, so it stays rejected.
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// sameOriginOK guards state-changing requests against CSRF: the Host must be
// loopback (also enforced globally by the middleware) and any Origin/
// Sec-Fetch-Site present must be same-origin. Some browser contexts submit a
// normal same-origin form with the opaque Origin value "null"; that value is
// accepted only when Fetch Metadata independently reports same-origin. A null
// Origin without that corroborating signal remains rejected.
func sameOriginOK(r *http.Request) bool {
	if !hostHeaderIsLoopback(r) {
		return false
	}
	sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if sfs == "cross-site" || sfs == "cross-origin" {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if origin == "null" {
			return sfs == "same-origin"
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	switch name {
	case "marked.min.js", "purify.min.js":
		data, err := uifiles.FS.ReadFile("vendor/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
		return
	case "vulnfounder-theme.css", "openant-theme.css":
		// Keep the old asset URL readable for bookmarked pages and older
		// integrations; all embedded pages use the canonical filename.
		assetName := "vulnfounder-theme.css"
		data, err := uifiles.FS.ReadFile(assetName)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
		return
	case "vulnfounder-navigation.js", "openant-navigation.js":
		// The legacy URL is an alias, not a second implementation.
		assetName := "vulnfounder-navigation.js"
		data, err := uifiles.FS.ReadFile(assetName)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if !sameOriginOK(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrfToken)) != 1 {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	repoID := strings.TrimSpace(r.FormValue("repo_id"))
	repo := strings.TrimSpace(r.FormValue("repo"))
	if repoID != "" {
		resolved, ok := s.resolveRepositoryID(repoID)
		if !ok {
			http.Error(w, "unknown or stale repository selection", http.StatusBadRequest)
			return
		}
		// The opaque catalog ID wins over any concurrently tampered free-form
		// value. Manual input is used only when repo_id is empty.
		repo = resolved
	}
	if repo == "" {
		http.Error(w, "repository selection or repo path is required", http.StatusBadRequest)
		return
	}
	scopeManifest := strings.TrimSpace(r.FormValue("scope_manifest"))
	if len(scopeManifest) > 4096 {
		http.Error(w, "scope manifest path is too long", http.StatusBadRequest)
		return
	}
	// A manifest records an absolute repository identity and cannot safely
	// follow a URL clone into the per-job temporary directory. Require a local
	// repository for this opt-in narrowing.
	if scopeManifest != "" && (strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "git@")) {
		http.Error(w, "socket scope manifest requires a local repository path", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(repo, "-") {
		http.Error(w, "repository path/URL must not start with '-'", http.StatusBadRequest)
		return
	}
	// Reject credentials embedded in an http(s) URL: the repo string is logged and
	// persisted verbatim (meta.json, logs.txt, SSE, pipeline_output.json, argv), so
	// userinfo would leak. Fail CLOSED on an unparseable URL too — a malformed
	// credential URL (e.g. bad %-escape) must not slip past into the logs before
	// the later clone guard sees it. Use a git credential helper instead.
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		u, err := url.Parse(repo)
		if err != nil || u.User != nil {
			http.Error(w, "invalid repository URL, or credentials in the URL (use a git credential helper instead)", http.StatusBadRequest)
			return
		}
	}

	languages := r.Form["languages"]
	for _, l := range languages {
		if !supportedLanguages[l] {
			http.Error(w, "unsupported language", http.StatusBadRequest)
			return
		}
	}
	platform, ok := normalizePlatform(r.FormValue("platform"))
	if !ok {
		http.Error(w, "unsupported platform", http.StatusBadRequest)
		return
	}
	cfg, _ := config.Load()
	libraryMode := r.FormValue("library_mode") == "on"
	apiKey := r.FormValue("api_key")
	if apiKey == "" {
		// Fall back to the configured key, mirroring cmd/root.go: a v2
		// llm_providers config deliberately suppresses the legacy key.
		if cfg != nil && !cfg.HasV2Providers() {
			apiKey = cfg.APIKey
		}
	}
	level, ok := normalizeScanLevel(r.FormValue("level"))
	if !ok {
		http.Error(w, "unsupported scan level", http.StatusBadRequest)
		return
	}
	enhanceMode, ok := normalizeEnhanceMode(r.FormValue("enhance_mode"))
	if !ok {
		http.Error(w, "unsupported enhancement mode", http.StatusBadRequest)
		return
	}
	noContext := r.FormValue("no_context") == "on"
	noEnhance := r.FormValue("no_enhance") == "on"
	noReport := r.FormValue("no_report") == "on"
	noSkipTests := r.FormValue("no_skip_tests") == "on"
	allLanguages := r.FormValue("all_languages") == "on"
	multiLanguage := r.FormValue("multi_language") == "on"
	strictLanguages := r.FormValue("strict_languages") == "on"
	if (allLanguages || multiLanguage) && len(languages) > 0 {
		http.Error(w, "all-languages or multi-language cannot be combined with explicit language selection", http.StatusBadRequest)
		return
	}
	minLanguageFiles, ok := normalizeBoundedInt(r.FormValue("min_language_files"), defaultMinLanguageFiles, 1, maxMinLanguageFiles)
	if !ok {
		http.Error(w, fmt.Sprintf("min language files must be between 1 and %d", maxMinLanguageFiles), http.StatusBadRequest)
		return
	}
	minLanguageShare, ok := normalizeMinLanguageShare(r.FormValue("min_language_share"))
	if !ok {
		http.Error(w, "min language share must be between 0 and 1", http.StatusBadRequest)
		return
	}
	limit, ok := normalizeBoundedInt(r.FormValue("limit"), 0, 0, maxScanLimit)
	if !ok {
		http.Error(w, fmt.Sprintf("unit limit must be between 0 and %d", maxScanLimit), http.StatusBadRequest)
		return
	}
	llmConfig, ok := normalizeLLMConfigName(r.FormValue("llm_config"), cfg)
	if !ok {
		http.Error(w, "unknown LLM configuration", http.StatusBadRequest)
		return
	}
	workers, ok := normalizeBoundedInt(r.FormValue("workers"), defaultScanWorkers, 1, maxScanWorkers)
	if !ok {
		http.Error(w, fmt.Sprintf("workers must be between 1 and %d", maxScanWorkers), http.StatusBadRequest)
		return
	}
	backoff, ok := normalizeBoundedInt(r.FormValue("backoff"), defaultScanBackoff, 0, maxScanBackoff)
	if !ok {
		http.Error(w, fmt.Sprintf("backoff must be between 0 and %d seconds", maxScanBackoff), http.StatusBadRequest)
		return
	}
	verify := r.FormValue("verify") == "on"
	llmReachability := r.FormValue("llm_reachability") == "on"
	llmReachabilityMaxCodeBytes := defaultLLMReachabilityMaxCodeBytes
	if llmReachability {
		var valid bool
		llmReachabilityMaxCodeBytes, valid = normalizeLLMReachabilityMaxCodeBytes(r.FormValue("llm_reachability_max_code_bytes"))
		if !valid {
			http.Error(w, fmt.Sprintf("llm reachability code size must be between %d and %d bytes", minLLMReachabilityMaxCodeBytes, maxLLMReachabilityMaxCodeBytes), http.StatusBadRequest)
			return
		}
	}
	dynamicTest := r.FormValue("dynamic_test") == "on"
	dynamicTestMode := strings.TrimSpace(r.FormValue("dynamic_test_mode"))
	if dynamicTestMode == "" {
		dynamicTestMode = "docker"
	}
	if dynamicTestMode != "docker" && dynamicTestMode != "claude-code" {
		http.Error(w, "unsupported dynamic test mode", http.StatusBadRequest)
		return
	}
	if !dynamicTest {
		// The selector is only meaningful when the dynamic stage is enabled. A
		// stale browser value must not alter the normal static pipeline.
		dynamicTestMode = "docker"
	}
	llmCallGraphRecovery := r.FormValue("llm_call_graph_recovery") == "on"
	llmCallGraphIterative := r.FormValue("llm_call_graph_iterative_recovery") == "on"
	llmCallGraphCandidateReview := r.FormValue("llm_call_graph_candidate_review") == "on"
	llmCallGraphProjection := r.FormValue("llm_call_graph_projection") == "on"
	dispatchCodeEvidence := r.FormValue("openharmony_dispatch_code_evidence") == "on"
	clangSemantic := r.FormValue("clang_semantic") == "on"
	clangMaxFiles, ok := normalizeBoundedInt(r.FormValue("clang_max_files"), defaultClangMaxFiles, 1, maxClangMaxFiles)
	if !ok {
		http.Error(w, fmt.Sprintf("clang max files must be between 1 and %d", maxClangMaxFiles), http.StatusBadRequest)
		return
	}
	clangTimeoutSeconds, ok := normalizeBoundedInt(r.FormValue("clang_timeout_seconds"), defaultClangTimeoutSeconds, 1, maxClangTimeoutSeconds)
	if !ok {
		http.Error(w, fmt.Sprintf("clang timeout must be between 1 and %d seconds", maxClangTimeoutSeconds), http.StatusBadRequest)
		return
	}
	clangBatchSize, ok := normalizeBoundedInt(r.FormValue("clang_batch_size"), defaultClangBatchSize, 1, maxClangBatchSize)
	if !ok {
		http.Error(w, fmt.Sprintf("clang batch size must be between 1 and %d", maxClangBatchSize), http.StatusBadRequest)
		return
	}
	clangDependencyRetries, ok := normalizeBoundedInt(r.FormValue("clang_dependency_retries"), defaultClangDependencyRetries, 0, maxClangDependencyRetries)
	if !ok {
		http.Error(w, fmt.Sprintf("clang dependency retries must be between 0 and %d", maxClangDependencyRetries), http.StatusBadRequest)
		return
	}
	clangDefinitionLoadMaxFiles, ok := normalizeBoundedInt(r.FormValue("clang_definition_load_max_files"), defaultClangDefinitionLoadMaxFiles, 0, maxClangDefinitionLoadMaxFiles)
	if !ok {
		http.Error(w, fmt.Sprintf("clang definition load max files must be between 0 and %d", maxClangDefinitionLoadMaxFiles), http.StatusBadRequest)
		return
	}

	// Gate new work at shutdown BEFORE creating any disk/manager state, and
	// register with the WaitGroup under drainMu so wg.Add can never race the
	// shutdown's wg.Wait (draining is set before Wait). Every return path after
	// this Add MUST call wg.Done; the success path hands the count to runJob's
	// deferred wg.Done.
	s.drainMu.Lock()
	if s.draining {
		s.drainMu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	s.wg.Add(1)
	s.drainMu.Unlock()

	id, err := randomID()
	if err != nil {
		s.wg.Done()
		http.Error(w, "failed to generate ID", http.StatusInternalServerError)
		return
	}

	jobDir := filepath.Join(s.outDir, id)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		s.wg.Done()
		http.Error(w, "failed to create job dir", http.StatusInternalServerError)
		return
	}

	// Write meta.json immediately.
	meta := jobMeta{
		ID: id, Repo: repo, StartedAt: time.Now().UTC(), Platform: platform,
		Level: level, NoContext: noContext, NoEnhance: noEnhance, EnhanceMode: enhanceMode,
		ScopeManifest: scopeManifest,
		NoReport:      noReport, NoSkipTests: noSkipTests, AllLanguages: allLanguages,
		MultiLanguage: multiLanguage, MinLanguageFiles: minLanguageFiles,
		MinLanguageShare: minLanguageShare, StrictLanguages: strictLanguages, Limit: limit,
		Languages: languages, Verify: verify, LibraryMode: libraryMode,
		LLMConfig: llmConfig, Workers: workers, Backoff: backoff,
		LLMCallGraphRecovery: llmCallGraphRecovery, LLMCallGraphIterative: llmCallGraphIterative,
		LLMCallGraphCandidateReview: llmCallGraphCandidateReview,
		LLMCallGraphProjection:      llmCallGraphProjection, DispatchCodeEvidence: dispatchCodeEvidence,
		ClangSemantic: clangSemantic, ClangBuildStatus: defaultClangBuildStatus,
		ClangMaxFiles: clangMaxFiles, ClangTimeoutSeconds: clangTimeoutSeconds,
		ClangBatchSize: clangBatchSize, ClangDependencyRetries: clangDependencyRetries,
		ClangDefinitionLoadMaxFiles: clangDefinitionLoadMaxFiles,
		DynamicTest:                 dynamicTest, DynamicTestMode: dynamicTestMode,
	}
	if llmReachability {
		meta.LLMReachability = true
		meta.LLMReachabilityMaxCodeBytes = llmReachabilityMaxCodeBytes
	}
	if data, err := json.Marshal(meta); err == nil {
		_ = os.WriteFile(filepath.Join(jobDir, "meta.json"), data, 0640)
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:                          id,
		Repo:                        repo,
		StartedAt:                   meta.StartedAt,
		Status:                      StatusRunning,
		Cancel:                      cancel,
		ctx:                         ctx,
		apiKey:                      apiKey,
		languages:                   languages,
		platform:                    platform,
		level:                       level,
		noContext:                   noContext,
		scopeManifest:               scopeManifest,
		noEnhance:                   noEnhance,
		enhanceMode:                 enhanceMode,
		noReport:                    noReport,
		noSkipTests:                 noSkipTests,
		allLanguages:                allLanguages,
		multiLanguage:               multiLanguage,
		minLanguageFiles:            minLanguageFiles,
		minLanguageShare:            minLanguageShare,
		strictLanguages:             strictLanguages,
		limit:                       limit,
		llmConfig:                   llmConfig,
		workers:                     workers,
		backoff:                     backoff,
		libraryMode:                 libraryMode,
		verify:                      verify,
		llmReachability:             llmReachability,
		llmReachabilityMaxCodeBytes: llmReachabilityMaxCodeBytes,
		llmCallGraphRecovery:        llmCallGraphRecovery,
		llmCallGraphIterative:       llmCallGraphIterative,
		llmCallGraphCandidateReview: llmCallGraphCandidateReview,
		llmCallGraphProjection:      llmCallGraphProjection,
		dispatchCodeEvidence:        dispatchCodeEvidence,
		clangSemantic:               clangSemantic,
		clangBuildStatus:            defaultClangBuildStatus,
		clangMaxFiles:               clangMaxFiles,
		clangTimeoutSeconds:         clangTimeoutSeconds,
		clangBatchSize:              clangBatchSize,
		clangDependencyRetries:      clangDependencyRetries,
		clangDefinitionLoadMaxFiles: clangDefinitionLoadMaxFiles,
		dynamicTest:                 dynamicTest,
		dynamicTestMode:             dynamicTestMode,
		done:                        make(chan struct{}),
	}
	s.mgr.add(job)
	go s.runJob(job)

	http.Redirect(w, r, "/scan/"+id, http.StatusSeeOther)
}

type scanPageData struct {
	ID   string
	Repo string
	CSRF string
}

func (s *Server) handleScanPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	repo := job.Repo
	job.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplScan.Execute(w, scanPageData{ID: id, Repo: repo, CSRF: s.csrfToken}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleScanLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Resume support: on reconnect EventSource replays the Last-Event-ID header
	// (the 0-based index of the last line it received), so we send only newer
	// lines instead of duplicating the whole log. Indices are stable for the
	// buffer's life (addLog/recoverJobs cap-and-stop, never shift).
	start := 0
	if leid := r.Header.Get("Last-Event-ID"); leid != "" {
		if n, err := strconv.Atoi(leid); err == nil && n >= 0 {
			start = n + 1
		}
	}

	job.mu.Lock()
	initial := make([]string, len(job.LogBuf))
	copy(initial, job.LogBuf)
	initStatus := job.Status
	job.mu.Unlock()

	// Clamp both ends: a Last-Event-ID of MaxInt64 makes start=n+1 overflow
	// negative, which would index initial[<0] and panic; past-end just resumes
	// after everything.
	if start < 0 || start > len(initial) {
		start = len(initial)
	}
	for i := start; i < len(initial); i++ {
		fmt.Fprintf(w, "id: %d\ndata: %s\n\n", i, initial[i])
	}
	sent := len(initial)

	if initStatus != StatusRunning {
		fmt.Fprintf(w, "event: done\ndata: %s\n\n", initStatus)
		if canFlush {
			flusher.Flush()
		}
		return
	}
	if canFlush {
		flusher.Flush()
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}

		job.mu.Lock()
		logs := job.LogBuf
		status := job.Status
		job.mu.Unlock()

		for i := sent; i < len(logs); i++ {
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", i, logs[i])
		}
		sent = len(logs)

		if status != StatusRunning {
			fmt.Fprintf(w, "event: done\ndata: %s\n\n", status)
			if canFlush {
				flusher.Flush()
			}
			return
		}
		if canFlush {
			flusher.Flush()
		}
	}
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.refreshRecoveredJob(job)
	job.mu.Lock()
	rp := job.ReportPath
	if r.URL.Query().Get("lang") == "zh-CN" {
		rp = job.ReportPathZH
	}
	job.mu.Unlock()
	if rp == "" {
		http.NotFound(w, r)
		return
	}
	f, fi, err := openRegularInRoot(filepath.Join(s.outDir, id), rp)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, filepath.Base(rp), fi.ModTime(), f)
}

type summaryData struct {
	ID           string
	MarkdownJSON template.JS // full JSON-encoded string literal (incl. outer quotes)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.refreshRecoveredJob(job)
	job.mu.Lock()
	sp := job.SummaryPath
	if r.URL.Query().Get("lang") == "zh-CN" {
		sp = job.SummaryPathZH
	}
	job.mu.Unlock()
	if sp == "" {
		http.NotFound(w, r)
		return
	}
	f, _, err := openRegularInRoot(filepath.Join(s.outDir, id), sp)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// json.Marshal produces a properly-escaped JS string literal including outer quotes.
	mdJSON, _ := json.Marshal(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplSum.Execute(w, summaryData{
		ID:           id,
		MarkdownJSON: template.JS(mdJSON),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type disclosureInfo struct {
	Name              string               `json:"name"`
	Label             string               `json:"label"`
	URL               string               `json:"url"`
	CVE               string               `json:"cve,omitempty"`
	VulnerabilityType string               `json:"vulnerability_type,omitempty"`
	CWEID             string               `json:"cwe_id,omitempty"`
	CWEName           string               `json:"cwe_name,omitempty"`
	FilePath          string               `json:"file_path,omitempty"`
	Function          string               `json:"function,omitempty"`
	StartLine         int                  `json:"start_line,omitempty"`
	EndLine           int                  `json:"end_line,omitempty"`
	AffectedVersion   string               `json:"affected_version,omitempty"`
	RepairStatus      string               `json:"repair_status,omitempty"`
	Summary           string               `json:"summary,omitempty"`
	SourceToSink      string               `json:"source_to_sink,omitempty"`
	CallChain         []disclosureCallNode `json:"call_chain,omitempty"`
	CallChainCount    int                  `json:"call_chain_count,omitempty"`
	CallChainOmitted  int                  `json:"call_chain_omitted,omitempty"`
	ContextAvailable  bool                 `json:"context_available,omitempty"`
}

// disclosureCallNode is deliberately smaller than report_context.call_chain.
// The list endpoint needs enough information to orient a reviewer, but it must
// not repeat bounded source snippets or a full graph in every disclosure card.
type disclosureCallNode struct {
	Function  string `json:"function,omitempty"`
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Role      string `json:"role,omitempty"`
}

// disclosureMetadata contains the small, list-friendly explanation extracted
// from a generated disclosure markdown file. The full markdown remains
// available through the existing disclosure URL.
type disclosureMetadata struct {
	Label             string
	CVE               string
	VulnerabilityType string
	CWEID             string
	CWEName           string
	FilePath          string
	Function          string
	StartLine         int
	EndLine           int
	AffectedVersion   string
	RepairStatus      string
	Summary           string
	SourceToSink      string
}

func (s *Server) handleDisclosureList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	paths := make([]string, len(job.DisclosurePaths))
	copy(paths, job.DisclosurePaths)
	job.mu.Unlock()
	pipeline := readDisclosurePipeline(filepath.Join(s.outDir, id))

	infos := make([]disclosureInfo, 0, len(paths))
	for _, p := range paths {
		name := filepath.Base(p)
		metadata := disclosureMetadataFromFile(p)
		label := metadata.Label
		if label == "" {
			label = disclosureLabel(name)
		}
		info := disclosureInfo{
			Name:              name,
			Label:             label,
			URL:               "/disclosure/" + id + "/" + name,
			CVE:               metadata.CVE,
			VulnerabilityType: metadata.VulnerabilityType,
			CWEID:             metadata.CWEID,
			CWEName:           metadata.CWEName,
			FilePath:          metadata.FilePath,
			Function:          metadata.Function,
			StartLine:         metadata.StartLine,
			EndLine:           metadata.EndLine,
			AffectedVersion:   metadata.AffectedVersion,
			RepairStatus:      metadata.RepairStatus,
			Summary:           metadata.Summary,
			SourceToSink:      metadata.SourceToSink,
		}
		if finding := disclosureFindingForFile(name, pipeline); finding != nil {
			applyDisclosureFinding(&info, finding, pipeline)
		}
		// A report generated by the current pipeline has an explicit repair
		// status.  Older reports only have the markdown section, so leave the
		// parsed value intact and use a neutral fallback for the UI.
		if info.RepairStatus == "" {
			info.RepairStatus = "unavailable"
		}
		infos = append(infos, info)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(infos)
}

type disclosureData struct {
	ID           string
	Name         string
	MarkdownJSON template.JS
}

func (s *Server) handleDisclosure(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := filepath.Base(r.PathValue("filename")) // sanitize: strip any path components
	if filename == "." || filename == "" {
		http.NotFound(w, r)
		return
	}

	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Verify the file is one of the job's known disclosure paths.
	job.mu.Lock()
	var matchedPath string
	for _, p := range job.DisclosurePaths {
		if filepath.Base(p) == filename {
			matchedPath = p
			break
		}
	}
	job.mu.Unlock()

	if matchedPath == "" {
		http.NotFound(w, r)
		return
	}
	// O_NOFOLLOW read: even a known path must be a regular file within the job dir
	// at read time — refuses a symlink atomically (no check-then-read TOCTOU).
	f, _, err := openRegularInRoot(filepath.Join(s.outDir, id), matchedPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	mdJSON, _ := json.Marshal(string(data))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplDisclosure.Execute(w, disclosureData{
		ID:           id,
		Name:         disclosureLabel(filename),
		MarkdownJSON: template.JS(mdJSON),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// disclosureTitleFromFile reads the first markdown heading from a disclosure
// file and returns the vulnerability title.
// e.g. "# Security Disclosure: Mail Account Credential Theft" → "Mail Account Credential Theft"
// Returns empty string if the title cannot be extracted.
func disclosureTitleFromFile(path string) string {
	// Reject a symlink (Lstat cross-platform; oNoFollow adds unix atomicity) so the
	// title-scan (reached from handleDisclosureList) can't read a symlink target.
	if lfi, err := os.Lstat(path); err != nil || lfi.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			// Strip all leading '#' and whitespace.
			title := strings.TrimSpace(strings.TrimLeft(line, "#"))
			// Strip common "Security Disclosure:" prefix.
			for _, prefix := range []string{
				"Security Disclosure: ",
				"Security Disclosure:",
			} {
				if strings.HasPrefix(title, prefix) {
					return strings.TrimSpace(strings.TrimPrefix(title, prefix))
				}
			}
			return title
		}
	}
	return ""
}

// disclosureLabel converts a disclosure filename to a human-readable label.
// e.g. "DISCLOSURE_01_SQL_INJECTION.md" → "Sql Injection"
var reDisclosurePrefix = regexp.MustCompile(`(?i)^DISCLOSURE_\d+_`)

var (
	reDisclosureCodePath       = regexp.MustCompile("(?m)^`([^`\\n]+)`:\\s*$")
	reDisclosureFunction       = regexp.MustCompile(`(?s)\b([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*(?:const\b[^{}]*)?\{`)
	reDisclosurePythonFunction = regexp.MustCompile(`(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	reDisclosureOrdinal        = regexp.MustCompile(`(?i)^DISCLOSURE_(\d+)_`)
	reDisclosureEvidenceFile   = regexp.MustCompile("(?m)^-\\s+\\*\\*File:\\*\\*\\s+`([^`\\n]+)`\\s+\\(第\\s*(\\d+)(?:\\s*-\\s*(\\d+))?\\s*行")
	reDisclosureEvidenceFunc   = regexp.MustCompile("(?m)^-\\s+\\*\\*Function:\\*\\*\\s+`([^`\\n]+)`")
	reDisclosureRepairStatus   = regexp.MustCompile("(?mi)(?:修复状态|repair\\s+status)\\s*[：:]\\s*`?([^`\\n]+)")
	reDisclosureCWE            = regexp.MustCompile(`(?i)^CWE[- ]?(\d+)\s*(?:\(([^)]*)\))?`)
	reDisclosureCVE            = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
)

const maxDisclosurePipelineBytes = 32 << 20

// readDisclosurePipeline reads only the server-owned pipeline artifact.  It is
// optional: disclosure pages must continue to work for historical scans that
// predate report_context and for scans whose pipeline output was not written.
func readDisclosurePipeline(jobDir string) map[string]any {
	path := filepath.Join(jobDir, "pipeline_output.json")
	f, fi, err := openRegularInRoot(jobDir, path)
	if err != nil || fi == nil || fi.Size() > maxDisclosurePipelineBytes {
		if f != nil {
			_ = f.Close()
		}
		return nil
	}
	defer f.Close()
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(f, maxDisclosurePipelineBytes+1)).Decode(&payload); err != nil {
		return nil
	}
	return payload
}

func disclosureMap(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return object
}

func disclosureScalar(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32)
	case int:
		return strconv.Itoa(typed)
	case int8, int16, int32, int64:
		return fmt.Sprintf("%d", typed)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", typed)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func disclosureInt(value any) int {
	text := disclosureScalar(value)
	if text == "" {
		return 0
	}
	parsed, err := strconv.Atoi(text)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func disclosureFindingForFile(filename string, pipeline map[string]any) map[string]any {
	if pipeline == nil {
		return nil
	}
	values, ok := pipeline["findings"].([]any)
	if !ok {
		return nil
	}
	if match := reDisclosureOrdinal.FindStringSubmatch(filename); len(match) == 2 {
		ordinal, err := strconv.Atoi(match[1])
		if err == nil && ordinal > 0 && ordinal <= len(values) {
			return disclosureMap(values[ordinal-1])
		}
	}
	// A few historical generators did not include a numeric ordinal.  Match a
	// normalized short_name as a best-effort fallback rather than dropping all
	// context for those reports.
	needle := strings.ToUpper(strings.TrimSuffix(filename, filepath.Ext(filename)))
	needle = reDisclosurePrefix.ReplaceAllString(needle, "")
	for _, value := range values {
		finding := disclosureMap(value)
		if finding == nil {
			continue
		}
		name := strings.ToUpper(strings.ReplaceAll(disclosureScalar(finding["short_name"]), " ", "_"))
		if name != "" && name == needle {
			return finding
		}
	}
	return nil
}

func disclosureAffectedVersion(pipeline map[string]any) string {
	if pipeline == nil {
		return ""
	}
	repository := disclosureMap(pipeline["repository"])
	for _, key := range []string{"affected_versions", "version", "release", "release_version"} {
		if value := disclosureScalar(pipeline[key]); value != "" {
			return value
		}
		if repository != nil {
			if value := disclosureScalar(repository[key]); value != "" {
				return value
			}
		}
	}
	if repository != nil {
		if commit := disclosureScalar(repository["commit_sha"]); commit != "" {
			return "commit " + commit
		}
		if branch := disclosureScalar(repository["branch"]); branch != "" {
			return "branch " + branch
		}
		if revision := disclosureScalar(repository["revision"]); revision != "" {
			return revision
		}
	}
	return disclosureScalar(pipeline["revision"])
}

func disclosureRepairStatusFromFix(fix string) string {
	fix = strings.TrimSpace(fix)
	if fix == "" {
		return "unavailable"
	}
	lower := strings.ToLower(fix)
	if strings.Contains(lower, "manual review") || strings.Contains(lower, "requires manual") {
		return "unavailable"
	}
	// A prose recommendation such as "validate the caller" is guidance, not
	// generated patch code.  Treat only a fenced snippet or code-like syntax as
	// generated so the card does not overstate remediation completeness.
	if strings.Contains(fix, "```") ||
		(strings.Contains(fix, ";") && (strings.Contains(fix, "{") || strings.Contains(fix, "}"))) {
		return "generated"
	}
	return "provided"
}

func disclosureSourceToSink(context map[string]any) string {
	if context == nil {
		return ""
	}
	sourceSink := disclosureMap(context["source_to_sink"])
	if sourceSink == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	if entry := disclosureScalar(sourceSink["entry_point"]); entry != "" {
		parts = append(parts, entry)
	}
	if chain, ok := sourceSink["function_route_chain"].([]any); ok {
		for _, value := range chain {
			if route := disclosureScalar(value); route != "" {
				parts = append(parts, route)
			}
			if len(parts) >= 8 {
				break
			}
		}
	}
	if len(parts) == 0 {
		if summary := disclosureScalar(sourceSink["dataflow_summary"]); summary != "" {
			parts = append(parts, summary)
		}
	}
	return disclosureCompactText(strings.Join(parts, " → "), 600)
}

func applyDisclosureFinding(info *disclosureInfo, finding map[string]any, pipeline map[string]any) {
	if info == nil || finding == nil {
		return
	}
	location := disclosureMap(finding["location"])
	if location != nil {
		if value := disclosureScalar(location["file"]); value != "" {
			info.FilePath = value
		}
		if value := disclosureScalar(location["function"]); value != "" {
			info.Function = value
		}
		if value := disclosureInt(location["start_line"]); value > 0 {
			info.StartLine = value
		}
		if value := disclosureInt(location["end_line"]); value > 0 {
			info.EndLine = value
		}
	}
	if info.FilePath == "" {
		if route := disclosureScalar(finding["route_key"]); route != "" {
			parts := strings.SplitN(route, ":", 2)
			info.FilePath = parts[0]
			if info.Function == "" && len(parts) == 2 {
				info.Function = parts[1]
			}
		}
	}
	if info.CWEID == "" {
		info.CWEID = disclosureScalar(finding["cwe_id"])
	}
	if info.CVE == "" {
		for _, key := range []string{"cve", "cve_id", "cve_name", "advisory_id"} {
			if value := disclosureFirstCVE(disclosureScalar(finding[key])); value != "" {
				info.CVE = value
				break
			}
		}
	}
	if info.CWEName == "" {
		info.CWEName = disclosureScalar(finding["cwe_name"])
	}
	if info.VulnerabilityType == "" && info.CWEID != "" {
		info.VulnerabilityType = "CWE-" + info.CWEID
		if info.CWEName != "" {
			info.VulnerabilityType += " (" + info.CWEName + ")"
		}
	}
	if version := disclosureAffectedVersion(pipeline); version != "" {
		// pipeline_output is the authoritative scan revision.  A disclosure
		// generated by an older report phase may still contain a placeholder or
		// stale Affected line, so prefer the structured artifact when available.
		info.AffectedVersion = version
	}
	if info.RepairStatus == "" {
		if repair := disclosureMap(finding["repair"]); repair != nil {
			info.RepairStatus = disclosureScalar(repair["status"])
		}
	}
	if info.RepairStatus == "" {
		info.RepairStatus = disclosureRepairStatusFromFix(disclosureScalar(finding["suggested_fix"]))
	}

	context := disclosureMap(finding["report_context"])
	if context == nil {
		return
	}
	info.ContextAvailable = true
	if info.SourceToSink == "" {
		info.SourceToSink = disclosureSourceToSink(context)
	}
	chain := disclosureMap(context["call_chain"])
	if chain == nil {
		return
	}
	info.CallChainCount = disclosureInt(chain["node_count"])
	info.CallChainOmitted = disclosureInt(chain["omitted_node_count"])
	nodes, ok := chain["nodes"].([]any)
	if !ok {
		return
	}
	const maxNodes = 24
	for _, value := range nodes {
		if len(info.CallChain) >= maxNodes {
			break
		}
		node := disclosureMap(value)
		if node == nil {
			continue
		}
		info.CallChain = append(info.CallChain, disclosureCallNode{
			Function:  disclosureScalar(node["function"]),
			File:      disclosureScalar(node["file"]),
			StartLine: disclosureInt(node["start_line"]),
			EndLine:   disclosureInt(node["end_line"]),
			Role:      disclosureScalar(node["role"]),
		})
	}
	if info.CallChainCount == 0 {
		info.CallChainCount = len(info.CallChain)
	}
}

// disclosureMetadataFromFile reads a bounded amount of a report and extracts
// only presentation metadata. It uses the same symlink protections as the
// existing title reader so a malformed report cannot make the UI read a host
// file through a planted link.
func disclosureMetadataFromFile(path string) disclosureMetadata {
	if lfi, err := os.Lstat(path); err != nil || lfi.Mode()&os.ModeSymlink != 0 || !lfi.Mode().IsRegular() {
		return disclosureMetadata{}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return disclosureMetadata{}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 512<<10))
	if err != nil {
		return disclosureMetadata{}
	}
	return parseDisclosureMetadata(string(data))
}

func parseDisclosureMetadata(markdown string) disclosureMetadata {
	markdown = strings.ReplaceAll(markdown, "\r\n", "\n")
	metadata := disclosureMetadata{
		Label: disclosureTitleFromMarkdown(markdown),
	}
	metadata.CVE = disclosureFirstCVE(markdown)
	for _, line := range strings.Split(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "**Type:**") {
			metadata.VulnerabilityType = strings.TrimSpace(strings.TrimPrefix(trimmed, "**Type:**"))
			if match := reDisclosureCWE.FindStringSubmatch(metadata.VulnerabilityType); len(match) >= 2 {
				metadata.CWEID = match[1]
				if len(match) >= 3 {
					metadata.CWEName = strings.TrimSpace(match[2])
				}
			}
		}
		if strings.HasPrefix(trimmed, "**Affected:**") {
			metadata.AffectedVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "**Affected:**"))
		}
	}

	summary := disclosureMarkdownSection(markdown, "## Summary")
	metadata.Summary = disclosureCompactText(summary, 360)
	vulnerableCode := disclosureMarkdownSection(markdown, "## Vulnerable Code")
	if match := reDisclosureCodePath.FindStringSubmatch(vulnerableCode); len(match) == 2 {
		metadata.FilePath = strings.TrimSpace(match[1])
	}
	code := disclosureFirstCodeFence(vulnerableCode)
	metadata.Function = disclosureFunctionName(code)
	if match := reDisclosureEvidenceFile.FindStringSubmatch(markdown); len(match) >= 3 {
		metadata.FilePath = strings.TrimSpace(match[1])
		metadata.StartLine = disclosureInt(match[2])
		if len(match) >= 4 {
			metadata.EndLine = disclosureInt(match[3])
		}
	}
	if match := reDisclosureEvidenceFunc.FindStringSubmatch(markdown); len(match) == 2 {
		metadata.Function = strings.TrimSpace(match[1])
	}
	fixSection := disclosureMarkdownSection(markdown, "## Suggested Fix")
	if match := reDisclosureRepairStatus.FindStringSubmatch(fixSection); len(match) == 2 {
		metadata.RepairStatus = strings.TrimSpace(match[1])
	}
	if metadata.RepairStatus == "" {
		metadata.RepairStatus = disclosureRepairStatusFromFix(fixSection)
	}
	for _, line := range strings.Split(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range []string{"- **Entry point:**", "- **Data-flow summary:**", "- **Function route chain:**"} {
			if strings.HasPrefix(trimmed, prefix) {
				metadata.SourceToSink = disclosureCompactText(strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)), 600)
				break
			}
		}
		if metadata.SourceToSink != "" {
			break
		}
	}
	return metadata
}

// disclosureFirstCVE extracts a canonical CVE identifier from a structured
// finding field. Reports may contain prose around the identifier, so return
// only the identifier rather than exposing the whole field in the list API.
func disclosureFirstCVE(value string) string {
	if match := reDisclosureCVE.FindString(value); match != "" {
		return strings.ToUpper(match)
	}
	return ""
}

func disclosureTitleFromMarkdown(markdown string) string {
	for _, line := range strings.Split(markdown, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		title := strings.TrimSpace(strings.TrimLeft(line, "#"))
		for _, prefix := range []string{"Security Disclosure: ", "Security Disclosure:"} {
			if strings.HasPrefix(title, prefix) {
				return strings.TrimSpace(strings.TrimPrefix(title, prefix))
			}
		}
		return title
	}
	return ""
}

func disclosureMarkdownSection(markdown, heading string) string {
	start := strings.Index(markdown, heading)
	if start < 0 {
		return ""
	}
	section := markdown[start+len(heading):]
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	return strings.TrimSpace(section)
}

func disclosureFirstCodeFence(markdown string) string {
	start := strings.Index(markdown, "```")
	if start < 0 {
		return ""
	}
	contentStart := strings.Index(markdown[start+3:], "\n")
	if contentStart < 0 {
		return ""
	}
	contentStart += start + 3 + 1
	end := strings.Index(markdown[contentStart:], "```")
	if end < 0 {
		return ""
	}
	return markdown[contentStart : contentStart+end]
}

func disclosureFunctionName(code string) string {
	for _, match := range reDisclosureFunction.FindAllStringSubmatch(code, -1) {
		if len(match) != 2 {
			continue
		}
		name := match[1]
		switch name {
		case "if", "for", "while", "switch", "catch":
			continue
		default:
			return name
		}
	}
	if match := reDisclosurePythonFunction.FindStringSubmatch(code); len(match) == 2 {
		return match[1]
	}
	return ""
}

func disclosureCompactText(text string, maxRunes int) string {
	text = strings.Join(strings.Fields(text), " ")
	if maxRunes <= 0 {
		return text
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}

func disclosureLabel(filename string) string {
	name := strings.TrimSuffix(filename, ".md")
	name = reDisclosurePrefix.ReplaceAllString(name, "")
	words := strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '-' })
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, " ")
}

// findDisclosures returns absolute paths to all .md files in the disclosures
// subdirectory of outDir.
func findDisclosures(outDir string) []string {
	discDir := filepath.Join(outDir, "report", "disclosures")
	entries, err := os.ReadDir(discDir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		p := filepath.Join(discDir, e.Name())
		// Skip symlinks: a disclosure is a scan-produced .md file, never a link
		// out of the job dir (which could point at a host secret).
		if !isRegularNoSymlink(outDir, p) {
			continue
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if !sameOriginOK(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrfToken)) != 1 {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if !jobIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	job, ok := s.mgr.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.mu.Lock()
	if job.Cancel != nil {
		job.Cancel()
	}
	done := job.done
	job.mu.Unlock()

	// Wait (bounded) for the runner to stop touching the job dir before removing
	// it, so a late report/log write can't recreate the deleted directory and
	// resurrect the job on restart. Recovered jobs have no runner (done == nil).
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}

	s.mgr.remove(id)
	_ = os.RemoveAll(filepath.Join(s.outDir, id))
	w.WriteHeader(http.StatusNoContent)
}

// buildScanArgs translates the persisted Web options to the scanner's argv.
// Keeping this mapping in one pure helper makes it auditable and prevents a UI
// checkbox from silently becoming metadata that never reaches Python.
func buildScanArgs(job *Job, outDir, localPath string, isURL bool) []string {
	args := []string{"scan", "--output", outDir}
	if len(job.languages) == 1 {
		args = append(args, "--language", job.languages[0])
	} else if len(job.languages) > 1 {
		args = append(args, "--languages", strings.Join(job.languages, ","))
	}
	args = append(args, platformArgs(job.platform)...)
	if job.level != "" && job.level != defaultScanLevel {
		args = append(args, "--level", job.level)
	}
	if job.noContext {
		args = append(args, "--no-context")
	}
	if job.scopeManifest != "" {
		args = append(args, "--scope-manifest", job.scopeManifest)
	}
	if job.noEnhance {
		args = append(args, "--no-enhance")
	} else if job.enhanceMode != "" && job.enhanceMode != defaultEnhanceMode {
		args = append(args, "--enhance-mode", job.enhanceMode)
	}
	if job.noReport {
		args = append(args, "--no-report")
	}
	if job.noSkipTests {
		args = append(args, "--no-skip-tests")
	}
	if job.allLanguages {
		args = append(args, "--all-languages")
	}
	if job.multiLanguage {
		args = append(args, "--multi-language")
	}
	if job.minLanguageFiles != 0 && job.minLanguageFiles != defaultMinLanguageFiles {
		args = append(args, "--min-language-files", strconv.Itoa(job.minLanguageFiles))
	}
	if job.minLanguageShare != defaultMinLanguageShare {
		args = append(args, "--min-language-share", strconv.FormatFloat(job.minLanguageShare, 'f', -1, 64))
	}
	if job.strictLanguages {
		args = append(args, "--strict-languages")
	}
	if job.limit > 0 {
		args = append(args, "--limit", strconv.Itoa(job.limit))
	}
	if job.llmConfig != "" {
		args = append(args, "--llm-config", job.llmConfig)
	}
	if job.workers != 0 && job.workers != defaultScanWorkers {
		args = append(args, "--workers", strconv.Itoa(job.workers))
	}
	if job.backoff != defaultScanBackoff {
		args = append(args, "--backoff", strconv.Itoa(job.backoff))
	}
	if job.verify {
		args = append(args, "--verify")
	}
	if job.llmReachability {
		args = append(args, "--llm-reachability")
		maxCodeBytes := job.llmReachabilityMaxCodeBytes
		if maxCodeBytes == 0 {
			maxCodeBytes = defaultLLMReachabilityMaxCodeBytes
		}
		if maxCodeBytes != defaultLLMReachabilityMaxCodeBytes {
			args = append(args, "--llm-reachability-max-code-bytes", strconv.Itoa(maxCodeBytes))
		}
	}
	if job.llmCallGraphRecovery {
		args = append(args, "--llm-call-graph-recovery")
	}
	if job.llmCallGraphIterative {
		args = append(args, "--llm-call-graph-iterative-recovery")
	}
	if job.llmCallGraphCandidateReview {
		args = append(args, "--llm-call-graph-candidate-review")
	}
	if job.llmCallGraphProjection {
		args = append(args, "--llm-call-graph-projection")
	}
	if job.dispatchCodeEvidence {
		args = append(args, "--openharmony-dispatch-code-evidence")
	}
	if job.clangSemantic {
		args = append(args, "--clang-semantic")
		buildStatus := job.clangBuildStatus
		if buildStatus == "" {
			buildStatus = defaultClangBuildStatus
		}
		maxFiles := job.clangMaxFiles
		if maxFiles == 0 {
			maxFiles = defaultClangMaxFiles
		}
		timeoutSeconds := job.clangTimeoutSeconds
		if timeoutSeconds == 0 {
			timeoutSeconds = defaultClangTimeoutSeconds
		}
		batchSize := job.clangBatchSize
		if batchSize == 0 {
			batchSize = defaultClangBatchSize
		}
		dependencyRetries := job.clangDependencyRetries
		definitionLoadMaxFiles := job.clangDefinitionLoadMaxFiles
		args = append(args,
			"--clang-build-status", buildStatus,
			"--clang-max-files", strconv.Itoa(maxFiles),
			"--clang-timeout-seconds", strconv.Itoa(timeoutSeconds),
			"--clang-batch-size", strconv.Itoa(batchSize),
			"--clang-dependency-retries", strconv.Itoa(dependencyRetries),
			"--clang-definition-load-max-files", strconv.Itoa(definitionLoadMaxFiles),
		)
	}
	if job.dynamicTest {
		if job.dynamicTestMode == "claude-code" {
			if !job.noReport {
				args = append(args, "--no-report")
			}
		} else {
			args = append(args, "--dynamic-test")
		}
	}
	if job.libraryMode {
		args = append(args, "--library-mode")
	}
	if isURL {
		args = append(args, "--repo-url", job.Repo)
	}
	return append(args, "--", localPath)
}

// ─── Background job runner ─────────────────────────────────────────────────

func (s *Server) runJob(job *Job) {
	defer s.wg.Done()
	// Closed last (after the cleanup defer below) so handleDeleteScan can wait
	// for this goroutine to stop writing the job dir before it RemoveAll's it —
	// otherwise a late report/log write recreates the deleted directory.
	defer close(job.done)

	outDir := filepath.Join(s.outDir, job.ID)

	defer func() {
		// Panic recovery — log rather than silently dropping the goroutine.
		if r := recover(); r != nil {
			job.addLog(fmt.Sprintf("[error] internal panic: %v", r))
		}
		// Any path that leaves the job still "running" here is a cancellation
		// (delete/shutdown) or a recovered panic; mark it terminal so an open SSE
		// stream receives a done event and stops instead of ticking forever.
		job.mu.Lock()
		if job.Status == StatusRunning {
			job.Status = StatusError
		}
		job.mu.Unlock()
		// Persist full log buffer to logs.txt.
		job.mu.Lock()
		logData := strings.Join(job.LogBuf, "\n") + "\n"
		job.mu.Unlock()
		_ = os.WriteFile(filepath.Join(outDir, "logs.txt"), []byte(logData), 0640)
	}()

	// Acquire a run slot, but abort promptly if the job was cancelled/deleted
	// while queued rather than parking on the semaphore until a slot frees.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-job.ctx.Done():
		return
	}

	job.addLog("→ Starting scan of " + job.Repo)

	// Determine local path: clone if URL, use directly if local path.
	localPath := job.Repo
	isURL := strings.HasPrefix(job.Repo, "https://") ||
		strings.HasPrefix(job.Repo, "http://") ||
		strings.HasPrefix(job.Repo, "git@")

	if isURL {
		cloneDir := filepath.Join(outDir, "repo")
		job.addLog("[clone] Cloning " + job.Repo + "…")
		if err := cloneRepo(job.ctx, job.Repo, cloneDir, job.addLog); err != nil {
			if job.ctx.Err() == nil {
				job.addLog("[clone] Error: " + err.Error())
				job.setError()
			}
			return
		}
		localPath = cloneDir
	}

	args := buildScanArgs(job, outDir, localPath, isURL)

	job.addLog("→ Running: python -m vulnfounder " + strings.Join(args, " "))

	stdout, exitCode, err := python.InvokeCtxCapture(job.ctx, s.pythonPath, args, "", job.apiKey, job.addLog)
	if job.ctx.Err() != nil {
		return // cancelled — don't mark error
	}
	if err != nil {
		job.addLog("[error] scan failed to start: " + err.Error())
		job.setError()
		return
	}
	// Exit code 1 means "scan succeeded but found vulnerabilities" (like grep).
	// Exit code 2+ means actual failure. The CLI writes the reason as a JSON
	// envelope on stdout (stderr may be empty), so surface it to the UI.
	if exitCode >= 2 || exitCode < 0 {
		if msgs := envelopeErrors(stdout); len(msgs) > 0 {
			for _, m := range msgs {
				job.addLog("[error] " + m)
			}
		} else {
			job.addLog(fmt.Sprintf("[error] scan exited with code %d", exitCode))
		}
		job.setError()
		return
	}

	// Patch pipeline_output.json with the original repo URL.
	patchPipelineOutput(outDir, job.Repo, job.addLog)

	if job.dynamicTest && job.dynamicTestMode == "claude-code" {
		job.addLog("[dynamic-test] Preparing Claude Code task workspace…")
		if err := s.prepareAndRunClaudeCode(job, outDir, localPath); err != nil {
			if job.ctx.Err() != nil {
				return
			}
			job.addLog("[dynamic-test] Task preparation failed: " + err.Error())
			job.setError()
			return
		}
		if job.ctx.Err() != nil {
			return
		}
	}
	if job.noReport {
		// The scanner itself honors --no-report, but the Web runner normally
		// performs a post-scan report fallback (including the Chinese report).
		// Do not silently undo the operator's explicit choice by generating a
		// report here; the scan artifacts remain available in the stage viewer.
		job.addLog("[report] 已按执行选项跳过报告生成（--no-report）")
		job.setDone("", "", "", "", nil)
		return
	}

	// Locate or generate report.html.
	reportPath := filepath.Join(outDir, "report.html")
	if !fileExists(reportPath) {
		// Scan step may have placed it in a subdirectory.
		for _, alt := range []string{
			filepath.Join(outDir, "final-reports", "report.html"),
			filepath.Join(outDir, "final-reports", "report-reskin.html"),
		} {
			if fileExists(alt) {
				if data, err := os.ReadFile(alt); err == nil {
					_ = os.WriteFile(reportPath, data, 0640)
				}
				break
			}
		}
	}
	reportPathZH := localizedOutputPath(reportPath, "zh-CN")

	// If either locale is missing, try explicit report generation (non-fatal).
	if !fileExists(reportPath) || !fileExists(reportPathZH) {
		if err := s.generateHTMLReport(job.ctx, outDir, reportPath, job.apiKey, job.addLog); err != nil {
			if job.ctx.Err() != nil {
				return
			}
			job.addLog("[report] Warning: " + err.Error())
			// Continue — mark done only if we found something.
		}
	}

	if job.ctx.Err() != nil {
		return
	}
	if !fileExists(reportPath) {
		job.addLog("[error] no report.html produced; marking scan as error")
		job.setError()
		return
	}

	// Markdown summary: prefer the one the scan already produced (the pipeline
	// writes report/SUMMARY_REPORT.md by default) to avoid a second LLM-billed
	// summary of the same results. Only generate if the scan produced none.
	summaryPath := ""
	for _, sp := range []string{
		filepath.Join(outDir, "report", "SUMMARY_REPORT.md"),
		filepath.Join(outDir, "SUMMARY_REPORT.md"),
	} {
		if fileExists(sp) {
			summaryPath = sp
			break
		}
	}
	if summaryPath == "" {
		// Non-fatal — requires API key / LLM.
		sp := filepath.Join(outDir, "SUMMARY_REPORT.md")
		if err := s.generateSummaryLocalized(job.ctx, outDir, sp, job.apiKey, job.addLog, "en"); err != nil {
			if job.ctx.Err() != nil {
				return
			}
			job.addLog("[report] Warning: summary not generated: " + err.Error())
		} else {
			summaryPath = sp
		}
	}

	// Always attempt the additive Chinese summary after the English path is
	// available. A failure is non-fatal: the English report remains usable and
	// the scan is still recorded as completed.
	summaryPathZH := ""
	if summaryPath != "" {
		candidate := localizedOutputPath(summaryPath, "zh-CN")
		if fileExists(candidate) {
			summaryPathZH = candidate
		} else if err := s.generateSummaryLocalized(job.ctx, outDir, candidate, job.apiKey, job.addLog, "zh-CN"); err != nil {
			if job.ctx.Err() != nil {
				return
			}
			job.addLog("[report] Warning: Chinese summary not generated: " + err.Error())
		} else {
			summaryPathZH = candidate
		}
	}

	disclosurePaths := findDisclosures(outDir)
	if !fileExists(reportPathZH) {
		reportPathZH = ""
	}

	job.setDone(reportPath, summaryPath, reportPathZH, summaryPathZH, disclosurePaths)
}

// envelopeErrors extracts the errors[] from the CLI's JSON result envelope,
// which is printed to stdout on failure (e.g. {"status":"error","errors":[...]}).
// It scans lines bottom-up for the last well-formed envelope carrying errors,
// tolerating non-JSON log noise on the same stream.
func envelopeErrors(stdout string) []string {
	lines := strings.Split(stdout, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var env struct {
			Status string   `json:"status"`
			Errors []string `json:"errors"`
		}
		if err := json.Unmarshal([]byte(line), &env); err == nil && len(env.Errors) > 0 {
			return env.Errors
		}
	}
	return nil
}

// cloneRepo runs git clone --depth 1 and streams stderr to onLog.
// Cloud metadata endpoints that are not otherwise loopback/link-local and so
// need blocking as specific literals: AWS's IPv6 IMDS (a ULA address, and ULA is
// otherwise the IPv6 equivalent of RFC1918 which we allow) and Alibaba Cloud's
// ECS metadata service (a public RFC6598 shared-space address). Both are SSRF
// targets, never a real repository.
var (
	awsIPv6IMDS = net.ParseIP("fd00:ec2::254")
	alibabaIMDS = net.ParseIP("100.100.100.200")
)

// ipBlocked reports whether ip is an SSRF-sensitive target that is never a
// legitimate remote repository: loopback, link-local (which includes the
// 169.254.169.254 IMDS endpoint), unspecified, or a cloud-metadata literal.
// RFC1918 and general IPv6 ULA private ranges stay allowed so internal git
// servers remain scannable (the deliberate policy of the original guard).
func ipBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() ||
		ip.Equal(awsIPv6IMDS) || ip.Equal(alibabaIMDS)
}

// scpHost extracts the host from an scp-style git address, "[user@]host:path" or
// the bracketed IPv6 form "[user@][::1]:path". ssh connects to the host after the
// LAST userinfo '@', so a smuggled extra userinfo like "git@evil@127.0.0.1" must
// resolve to "127.0.0.1", not "evil@127.0.0.1" (which would dodge the guard and
// let ssh still reach loopback). Returns "" when no host can be determined.
func scpHost(repo string) string {
	s := strings.TrimPrefix(repo, "git@")
	// The host region begins after the last userinfo '@' that precedes the host.
	// Userinfo contains no ':' or '[', so bound the search at the first of those
	// (the path separator, or the start of a bracketed IPv6 literal).
	limit := len(s)
	if c := strings.IndexByte(s, ':'); c >= 0 && c < limit {
		limit = c
	}
	if b := strings.IndexByte(s, '['); b >= 0 && b < limit {
		limit = b
	}
	if a := strings.LastIndexByte(s[:limit], '@'); a >= 0 {
		s = s[a+1:]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 1 {
			return s[1:i]
		}
		return ""
	}
	return strings.SplitN(s, ":", 2)[0]
}

// fieldCandidates returns EVERY numeric value a resolver might read one
// inet_aton-style field as. Go's net.ParseIP rejects these forms; git/libcurl
// (via the platform resolver) accept them, but the platforms disagree on
// leading-zero fields: glibc reads them as octal, while macOS/BSD getaddrinfo
// reads a leading-zero dotted field as DECIMAL (e.g. "0127" -> 127, not octal
// 87). To match what git could actually dial on ANY platform we must consider
// both. Returns octal AND decimal for a leading-zero field, hex for 0x, decimal
// otherwise; empty slice if the field parses under none of those. Uses big.Int
// so a bare integer larger than 2^64 (which libcurl still wraps mod 2^32) is
// represented rather than overflowing strconv and slipping through.
func fieldCandidates(s string) []*big.Int {
	parse := func(str string, base int) (*big.Int, bool) {
		if str == "" {
			return nil, false
		}
		v, ok := new(big.Int).SetString(str, base)
		return v, ok && v.Sign() >= 0
	}
	switch {
	case len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'):
		if v, ok := parse(s[2:], 16); ok {
			return []*big.Int{v}
		}
		return nil
	case len(s) >= 2 && s[0] == '0':
		var out []*big.Int
		if v, ok := parse(s[1:], 8); ok {
			out = append(out, v) // glibc: octal
		}
		if v, ok := parse(s, 10); ok {
			out = append(out, v) // macOS/BSD: decimal (leading zero ignored)
		}
		return out
	default:
		if v, ok := parse(s, 10); ok {
			return []*big.Int{v}
		}
		return nil
	}
}

// packLegacyIPv4 packs 1–4 inet_aton field values into an IPv4 address, honoring
// the short-form packing (a.b -> a.(24-bit b), etc.) and the bare-integer mod-2^32
// wrap. Returns nil if a multi-part field exceeds its slot.
func packLegacyIPv4(vals []*big.Int) net.IP {
	lim := func(v *big.Int, max uint64) bool { return v.Cmp(new(big.Int).SetUint64(max)) > 0 }
	u := func(v *big.Int) uint64 { return v.Uint64() }
	var n uint64
	switch len(vals) {
	case 1:
		// A bare integer addresses all 32 bits; C inet_aton wraps a too-large
		// value mod 2^32 (e.g. 4294967296 -> 0.0.0.0, or 2^64+X -> X mod 2^32),
		// so take the low 32 bits to match what git resolves.
		n = new(big.Int).And(vals[0], big.NewInt(0xffffffff)).Uint64()
	case 2: // a.b -> a.(24-bit b)
		if lim(vals[0], 0xff) || lim(vals[1], 0xffffff) {
			return nil
		}
		n = u(vals[0])<<24 | u(vals[1])
	case 3: // a.b.c -> a.b.(16-bit c)
		if lim(vals[0], 0xff) || lim(vals[1], 0xff) || lim(vals[2], 0xffff) {
			return nil
		}
		n = u(vals[0])<<24 | u(vals[1])<<16 | u(vals[2])
	case 4:
		if lim(vals[0], 0xff) || lim(vals[1], 0xff) || lim(vals[2], 0xff) || lim(vals[3], 0xff) {
			return nil
		}
		n = u(vals[0])<<24 | u(vals[1])<<16 | u(vals[2])<<8 | u(vals[3])
	default:
		return nil
	}
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// parseLegacyIPv4Candidates parses the non-canonical IPv4 forms that inet_aton
// (and thus git/libcurl) accept but net.ParseIP rejects — bare 32-bit integers
// and dotted 1–4-part forms with decimal/octal/hex fields, incl. short forms like
// "127.1" — and returns EVERY address the host could resolve to across resolver
// platforms (the cross-product of each field's candidate readings). Empty when
// host is not such a legacy numeric address (e.g. a real DNS name), so callers
// fall through to name resolution. Callers must block if ANY candidate is
// sensitive (the reachability-safe superset).
func parseLegacyIPv4Candidates(host string) []net.IP {
	if host == "" {
		return nil
	}
	// Fast reject: a legacy numeric host is only digits, dots, and hex letters.
	// Real hostnames carry other letters/hyphens and fall through to DNS.
	for _, r := range host {
		isDigit := r >= '0' && r <= '9'
		isHex := (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isDigit && !isHex && r != '.' && r != 'x' && r != 'X' {
			return nil
		}
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return nil
	}
	// Per-field candidate values, then cross-product into whole-address vals.
	combos := [][]*big.Int{{}}
	for _, p := range parts {
		cands := fieldCandidates(p)
		if len(cands) == 0 {
			return nil
		}
		var next [][]*big.Int
		for _, combo := range combos {
			for _, v := range cands {
				n := append(append([]*big.Int{}, combo...), v)
				next = append(next, n)
			}
		}
		combos = next
	}
	var ips []net.IP
	for _, vals := range combos {
		if ip := packLegacyIPv4(vals); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// repoHostBlocked reports whether a repo URL points at a loopback, link-local,
// unspecified, or cloud-metadata address — an SSRF target that is never a
// legitimate remote repository. Private (RFC1918 / IPv6 ULA) hosts are allowed
// so internal git servers can still be scanned.
//
// It matches what git/libcurl will actually connect to, not just what
// net.ParseIP recognizes: canonical literals, the legacy numeric IPv4 encodings
// inet_aton accepts (decimal/octal/hex/short forms), the "localhost"/FQDN-root
// spellings, and — for genuine DNS names — every resolved address. A name that
// rebinds to a sensitive address in the window between this check and the clone
// remains out of scope; the redirect vector is closed separately by disabling
// git HTTP redirects in cloneRepo.
func repoHostBlocked(ctx context.Context, repo string) bool {
	var host string
	if strings.HasPrefix(repo, "git@") {
		host = scpHost(repo)
	} else {
		// An http(s) URL we will hand to git. Fail closed on anything git/libcurl
		// parses differently than Go: a backslash libcurl reads as '/', or a
		// malformed userinfo that makes url.Parse error while git salvages a
		// trailing host (e.g. "http://example.com\@127.0.0.1/" reaches 127.0.0.1).
		if strings.Contains(repo, `\`) {
			return true
		}
		u, err := url.Parse(repo)
		if err != nil || u.Host == "" {
			return true
		}
		host = u.Hostname()
	}
	if host == "" {
		return false
	}
	host = strings.TrimSpace(host)       // an scp host like "127.0.0.1 :x" can carry a trailing space
	host = strings.TrimSuffix(host, ".") // FQDN-root form: "localhost.", "127.0.0.1."
	// A non-ASCII host is anomalous for git — real IDN hosts arrive punycode
	// (xn--, ASCII). A libidn2-linked git/libcurl applies UTS-46 mapping
	// (fullwidth digits and the U+3002/FF0E/FF61 label separators -> ASCII), so a
	// raw-unicode host like "127。0。0。1" could dial 127.0.0.1 while Go's resolver
	// NXDOMAINs and the numeric guard never sees ASCII digits. Fail closed.
	for _, r := range host {
		if r > 127 {
			return true
		}
	}
	// "localhost" and, per RFC 6761, any *.localhost name resolve to loopback on
	// common Linux setups (systemd-resolved), while Go's pure-Go resolver may
	// NXDOMAIN it — so block the whole .localhost TLD, not just the bare label.
	if lower := strings.ToLower(host); lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	// Strip an IPv6 zone id before ParseIP, which returns nil for zoned literals
	// (e.g. "fe80::1%eth0", "::1%lo0", "fd00:ec2::254%eth0"). git/libcurl accept
	// the bracketed form "[fe80::1%25eth0]" and dial the address, so the zone must
	// not hide a loopback/link-local/metadata target.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ipBlocked(ip)
	}
	// Non-canonical numeric literal (parseable by inet_aton — decimal/octal/hex/
	// short-form/wrap — but rejected by net.ParseIP): BLOCK unconditionally. No
	// legitimate repository is hosted at a form like 0127.0.0.1 or 2130706433;
	// real hosts are canonical IPs (handled above, incl. RFC1918 internal
	// servers) or DNS names (below). Blocking the whole non-canonical-numeric
	// class is encoding-proof — it does not depend on matching what any resolver
	// reads a given encoding as, which is where each prior round found a bypass.
	if len(parseLegacyIPv4Candidates(host)) > 0 {
		return true
	}
	// A DNS name: resolve and block if ANY resolved address is sensitive.
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil {
		return false // unresolvable — git will fail on its own; not our block
	}
	for _, a := range addrs {
		if ipBlocked(a.IP) {
			return true
		}
	}
	return false
}

func cloneRepo(ctx context.Context, repo, dest string, onLog func(string)) error {
	if !(strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "git@")) {
		return fmt.Errorf("unsupported repository URL scheme")
	}
	if repoHostBlocked(ctx, repo) {
		return fmt.Errorf("refusing to clone from a loopback, link-local, or metadata address")
	}
	// Bound the clone in time so a hostile remote that streams forever can't hold a
	// scan slot indefinitely (the parent ctx is cancel-only). Disk size is not
	// bounded here — a huge working tree is a documented limitation for a
	// local, user-chosen scan target.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=user",
		// Do not follow HTTP redirects: an allowed public host could otherwise
		// 302 the clone to a loopback/metadata URL that repoHostBlocked never saw.
		"-c", "http.followRedirects=false",
		"clone", "--depth", "1", "--", repo, dest)
	// Run git in its own process group and SIGKILL the whole group on cancel, so
	// helpers (git-remote-https, ssh) are killed too — matching the python path
	// rather than leaving them to die indirectly on EPIPE. (unix; no-op elsewhere)
	setProcGroupKill(cmd)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long remote: sideband lines
	for sc.Scan() {
		onLog("[clone] " + sc.Text())
	}
	// Drain any remainder (an over-long line stops Scan) so a malicious git
	// server cannot wedge cmd.Wait() by filling the stderr pipe.
	_, _ = io.Copy(io.Discard, stderr)
	return cmd.Wait()
}

// patchPipelineOutput updates the repository.url field in pipeline_output.json.
func patchPipelineOutput(outDir, repo string, onLog func(string)) {
	path := filepath.Join(outDir, "pipeline_output.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // file doesn't exist, skip silently
	}
	// UseNumber so large integer fields (e.g. a CWE id) round-trip exactly rather
	// than being coerced to float64 and losing precision on rewrite.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return
	}
	if repoField, ok := obj["repository"]; ok {
		if repoMap, ok := repoField.(map[string]any); ok {
			repoMap["url"] = repo
		}
	}
	patched, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, patched, 0640); err != nil {
		onLog("[report] Warning: could not patch pipeline_output.json: " + err.Error())
	}
}

// generateHTMLReport uses `python -m vulnfounder report-data` to get pre-computed
// report JSON, then renders it with Go's embedded HTML template — the same
// pipeline the `vulnfounder report -f html` CLI command uses.
func (s *Server) generateHTMLReport(ctx context.Context, outDir, reportPath, apiKey string, onLog func(string)) error {
	resultsPath := findResultsFile(outDir)
	if resultsPath == "" {
		return fmt.Errorf("no results file found in %s", outDir)
	}
	reportPathZH := localizedOutputPath(reportPath, "zh-CN")
	for _, locale := range []string{"en", "zh-CN"} {
		outputPath := reportPath
		if locale == "zh-CN" {
			outputPath = reportPathZH
		}
		if fileExists(outputPath) {
			continue
		}

		args := []string{"report-data", resultsPath}
		if ds := findDatasetFile(outDir); ds != "" {
			args = append(args, "--dataset", ds)
		}
		if locale != "en" {
			args = append(args, "--language", locale)
		}

		onLog("[report] Generating HTML report (" + locale + ")…")
		stdout, exitCode, err := python.InvokeCtxCapture(ctx, s.pythonPath, args, "", apiKey, func(line string) {
			onLog("[report] " + line)
		})
		if err != nil {
			return err
		}
		if exitCode != 0 {
			return fmt.Errorf("report-data (%s) exited with code %d", locale, exitCode)
		}

		var envelope types.Envelope
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &envelope); err != nil {
			return fmt.Errorf("parse report-data (%s) output: %w", locale, err)
		}
		if envelope.Status != "success" {
			if len(envelope.Errors) > 0 {
				return fmt.Errorf("report-data (%s): %s", locale, envelope.Errors[0])
			}
			return fmt.Errorf("report-data (%s) returned status %q", locale, envelope.Status)
		}

		dataBytes, err := json.Marshal(envelope.Data)
		if err != nil {
			return fmt.Errorf("marshal report data (%s): %w", locale, err)
		}
		var reportData report.ReportData
		if err := json.Unmarshal(dataBytes, &reportData); err != nil {
			return fmt.Errorf("parse report data (%s): %w", locale, err)
		}
		reportData.Locale = locale
		if err := report.GenerateReskinLocalized(reportData, outputPath, locale); err != nil {
			return fmt.Errorf("render HTML (%s): %w", locale, err)
		}
	}
	return nil
}

// localizedOutputPath inserts a locale suffix before the extension while
// keeping the historical English filename stable.
func localizedOutputPath(path, locale string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + "." + locale
	}
	return strings.TrimSuffix(path, ext) + "." + locale + ext
}

// generateSummary runs `python -m vulnfounder report --format summary` to produce
// SUMMARY_REPORT.md.  This step makes LLM calls so it requires an API key.
func (s *Server) generateSummary(ctx context.Context, outDir, outputPath, apiKey string, onLog func(string)) error {
	return s.generateSummaryLocalized(ctx, outDir, outputPath, apiKey, onLog, "en")
}

func (s *Server) generateSummaryLocalized(ctx context.Context, outDir, outputPath, apiKey string, onLog func(string), locale string) error {
	resultsPath := findResultsFile(outDir)
	if resultsPath == "" {
		return fmt.Errorf("no results file found in %s", outDir)
	}

	args := []string{"report", resultsPath, "--format", "summary", "--output", outputPath}
	if locale != "" && locale != "en" {
		args = append(args, "--language", locale)
	}
	if po := filepath.Join(outDir, "pipeline_output.json"); fileExists(po) {
		args = append(args, "--pipeline-output", po)
	}

	onLog("[report] Generating Markdown summary (" + locale + ")…")
	exitCode, err := python.InvokeCtx(ctx, s.pythonPath, args, "", apiKey, func(line string) {
		onLog("[report] " + line)
	})
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("summary generation exited with code %d", exitCode)
	}
	if !fileExists(outputPath) {
		return fmt.Errorf("summary file not produced at %s", outputPath)
	}
	return nil
}

// findResultsFile locates the primary results JSON in the output directory.
func findResultsFile(outDir string) string {
	for _, name := range []string{
		"results_verified.json",
		"results_analyzed.json",
		"results.json",
	} {
		p := filepath.Join(outDir, name)
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// findDatasetFile locates the best available dataset JSON in the output directory.
// Prefers the enhanced dataset; falls back to the original parsed dataset.
func findDatasetFile(outDir string) string {
	for _, name := range []string{
		"dataset_enhanced.json",
		"dataset.json",
	} {
		p := filepath.Join(outDir, name)
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// withinRoot reports whether path's fully-resolved location stays inside root's
// fully-resolved location (catches a parent-component symlink or a swapped root).
func withinRoot(root, path string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isRegularNoSymlink reports whether path is a regular file, not a symlink, whose
// resolved location is within root. Used at ENUMERATION time (findDisclosures) to
// keep symlinks out of the served allowlist.
func isRegularNoSymlink(root, path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return false
	}
	return withinRoot(root, path)
}

// openRegularInRoot opens a file for reading with O_NOFOLLOW so a symlink at the
// final component is refused ATOMICALLY (closing the check-then-read TOCTOU that
// a plain Lstat-then-open leaves open), verifies it's a regular file, and
// confirms containment within root. The job output dir holds files derived from
// an untrusted scanned repo, so no served file may be a symlink to a host secret.
func openRegularInRoot(root, path string) (*os.File, os.FileInfo, error) {
	// Reject a leaf symlink cross-platform (Lstat); on unix oNoFollow also makes
	// the open itself refuse it, closing the check-then-open TOCTOU.
	if lfi, err := os.Lstat(path); err != nil || lfi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("not a regular file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("not a regular file")
	}
	if !withinRoot(root, path) {
		f.Close()
		return nil, nil, fmt.Errorf("path escapes job root")
	}
	return f, fi, nil
}

// randomID generates a 16-character cryptographically random hex string.
func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
