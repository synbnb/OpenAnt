// Package server implements the OpenAnt web UI HTTP server.
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

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/python"
	"github.com/knostic/open-ant-cli/internal/report"
	"github.com/knostic/open-ant-cli/internal/types"
	uifiles "github.com/knostic/open-ant-cli/ui"
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
	LLMReachability             bool      `json:"llm_reachability,omitempty"`
	LLMReachabilityMaxCodeBytes int       `json:"llm_reachability_max_code_bytes,omitempty"`
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
	libraryMode                 bool
	verify                      bool
	llmReachability             bool
	llmReachabilityMaxCodeBytes int
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
	pythonPath        string
	outDir            string
	mgr               *manager
	tmplIndex         *template.Template
	tmplScan          *template.Template
	tmplArtifact      *template.Template
	tmplSum           *template.Template
	tmplDisclosure    *template.Template
	tmplSourceLocator *template.Template
	sem               chan struct{}
	csrfToken         string
	sourceLocatorMu   sync.Mutex     // serializes Web source-locator mutations, including deletion
	wg                sync.WaitGroup // tracks in-flight runJob goroutines for shutdown
	shutdownDone      chan struct{}  // closed once cancel+drain completes
	drainMu           sync.Mutex     // guards draining; makes wg.Add happen-before wg.Wait
	draining          bool           // set at shutdown so no new job is added after Wait starts
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

	// Per-instance CSRF synchronizer token: 32 hex chars from crypto/rand,
	// stable for the server's lifetime and embedded in served pages.
	tokBytes := make([]byte, 16)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}

	s := &Server{
		pythonPath:        pythonPath,
		outDir:            outDir,
		mgr:               newManager(outDir),
		tmplIndex:         tmplIndex,
		tmplScan:          tmplScan,
		tmplArtifact:      tmplArtifact,
		tmplSum:           tmplSum,
		tmplDisclosure:    tmplDisclosure,
		tmplSourceLocator: tmplSourceLocator,
		sem:               make(chan struct{}, 4),
		csrfToken:         hex.EncodeToString(tokBytes),
		shutdownDone:      make(chan struct{}),
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
				job.llmReachability = m.LLMReachability
				job.llmReachabilityMaxCodeBytes = m.LLMReachabilityMaxCodeBytes
				if job.llmReachabilityMaxCodeBytes == 0 {
					job.llmReachabilityMaxCodeBytes = defaultLLMReachabilityMaxCodeBytes
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

		// Determine status from presence of the stable English report path.
		reportPath := filepath.Join(jobDir, "report.html")
		if _, err := os.Stat(reportPath); err == nil {
			job.Status = StatusDone
			job.ReportPath = reportPath
			zhReportPath := filepath.Join(jobDir, "report.zh-CN.html")
			if isRegularNoSymlink(jobDir, zhReportPath) {
				job.ReportPathZH = zhReportPath
			}
			// Look for summary.
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
			// Look for disclosure reports.
			job.DisclosurePaths = findDisclosures(jobDir)
		} else {
			job.Status = StatusError
		}

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
	mux.HandleFunc("GET /source-locator/sessions", s.handleSourceLocatorSessions)
	mux.HandleFunc("POST /source-locator/sessions", s.handleSourceLocatorCreate)
	mux.HandleFunc("GET /source-locator/sessions/{id}", s.handleSourceLocatorStatus)
	mux.HandleFunc("GET /source-locator/sessions/{id}/handoff", s.handleSourceLocatorHandoff)
	mux.HandleFunc("GET /source-locator/sessions/{id}/events/snapshot", s.handleSourceLocatorEventSnapshot)
	mux.HandleFunc("GET /source-locator/sessions/{id}/events", s.handleSourceLocatorEvents)
	mux.HandleFunc("POST /source-locator/sessions/{id}/message", s.handleSourceLocatorMessage)
	mux.HandleFunc("POST /source-locator/sessions/{id}/advance", s.handleSourceLocatorAdvance)
	mux.HandleFunc("POST /source-locator/sessions/{id}/approve", s.handleSourceLocatorApprove)
	mux.HandleFunc("POST /source-locator/sessions/{id}/reject", s.handleSourceLocatorReject)
	mux.HandleFunc("POST /source-locator/sessions/{id}/cancel", s.handleSourceLocatorCancel)
	mux.HandleFunc("DELETE /source-locator/sessions/{id}", s.handleSourceLocatorDelete)
	mux.HandleFunc("GET /source-locator/sessions/{id}/artifact/{name...}", s.handleSourceLocatorArtifact)
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
	defaultLLMReachabilityMaxCodeBytes = 1500
	minLLMReachabilityMaxCodeBytes     = 256
	maxLLMReachabilityMaxCodeBytes     = 32768
)

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
	// travels with an OpenAnt checkout and does not depend on ~/.openant state.
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
	// `openant init`. The manager already orders jobs newest-first.
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
		return "", fmt.Errorf("refusing to bind %q: the OpenAnt web UI is local-only and must listen on a loopback address (127.0.0.1 or localhost)", addr)
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
		_ = srv.Close()   // stop listening + drop conns immediately (an open SSE stream
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
// stages are marked not_requested only when the corresponding form option was
// not selected.
func requestedPipelineStep(id string, verify, llmReachability, dynamicTest bool) bool {
	switch id {
	case "llm-reachability":
		return llmReachability
	case "verify":
		return verify
	case "dynamic-test":
		return dynamicTest
	default:
		return true
	}
}

func normalizePipelineStatus(status string) string {
	switch status {
	case "success", "skipped", "error", "running", "pending":
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
	llmReachability := job.llmReachability
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
		} else if !requestedPipelineStep(spec.ID, verify, llmReachability, dynamicTest) {
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
	{Name: "llm_reachability.json", Label: "LLM reachability signals", Category: "reachability", Stage: "llm-reachability", Description: "Model-proposed entry-point, external-input, and cross-process signals with confidence and application results."},
	{Name: "results.json", Label: "Stage 1 analysis results", Category: "results", Stage: "analyze", Description: "Candidate vulnerabilities emitted by the primary analysis before attacker-path verification."},
	{Name: "results_verified.json", Label: "Stage 2 verified results", Category: "results", Stage: "verify", Description: "Candidate findings annotated with verification verdicts, exploit paths, confidence, and rejection reasons."},
	{Name: "dynamic_test_results.json", Label: "Dynamic-test results", Category: "dynamic-test", Stage: "dynamic-test", Description: "Structured observations from isolated runtime checks for selected findings."},
	{Name: "dynamic_test_results.md", Label: "Dynamic-test report", Category: "dynamic-test", Stage: "dynamic-test", Description: "Human-readable account of dynamic-test setup, execution, observations, and limitations."},
	{Name: "pipeline_results.json", Label: "Pipeline stage results", Category: "results", Stage: "build-output", Description: "Intermediate pipeline result containing stage success and stage-level outputs."},
	{Name: "scan_results.json", Label: "Raw scan results", Category: "results", Stage: "parse", Description: "Raw scan result containing scanned files, scope, counters, and scan time."},
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

// llmStatusView deliberately contains only provider metadata and credential
// presence. API-key values never leave the process and are not rendered into
// the HTML response.
type llmStatusView struct {
	Available      bool
	ConfigName     string
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
		Available:     true, // the built-in openant-default config is always available
		ConfigName:    "openant-default",
		ShowLegacyKey: true,
	}
	if cfg == nil {
		status.Providers = []llmProviderView{{
			Name:             "anthropic",
			Type:             "anthropic",
			CredentialStatus: llmCredentialStatus(config.ProviderEntry{}, "anthropic"),
		}}
		status.CredentialHint = "Legacy mode: configure an Anthropic key with openant set-api-key, or enter a key for this scan."
		return status
	}

	status.ConfigName = cfg.DefaultLLMName()
	status.ShowLegacyKey = !cfg.HasV2Providers()
	if !cfg.HasV2Providers() {
		status.Providers = []llmProviderView{{
			Name:             "anthropic",
			Type:             "anthropic",
			CredentialStatus: llmCredentialStatus(config.ProviderEntry{APIKey: cfg.APIKey}, "anthropic"),
		}}
		status.CredentialHint = "Legacy mode: configure an Anthropic key with openant set-api-key, or enter a key for this scan."
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
	if len(providerNames) == 0 && status.ConfigName == "openant-default" {
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
	default:
		http.NotFound(w, r)
		return
	}
	data, err := uifiles.FS.ReadFile("vendor/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
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
	libraryMode := r.FormValue("library_mode") == "on"
	apiKey := r.FormValue("api_key")
	if apiKey == "" {
		// Fall back to the configured key, mirroring cmd/root.go: a v2
		// llm_providers config deliberately suppresses the legacy key.
		if cfg, _ := config.Load(); cfg != nil && !cfg.HasV2Providers() {
			apiKey = cfg.APIKey
		}
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
		DynamicTest: dynamicTest, DynamicTestMode: dynamicTestMode,
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
		libraryMode:                 libraryMode,
		verify:                      verify,
		llmReachability:             llmReachability,
		llmReachabilityMaxCodeBytes: llmReachabilityMaxCodeBytes,
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
	Name              string `json:"name"`
	Label             string `json:"label"`
	URL               string `json:"url"`
	VulnerabilityType string `json:"vulnerability_type,omitempty"`
	FilePath          string `json:"file_path,omitempty"`
	Function          string `json:"function,omitempty"`
	Summary           string `json:"summary,omitempty"`
}

// disclosureMetadata contains the small, list-friendly explanation extracted
// from a generated disclosure markdown file. The full markdown remains
// available through the existing disclosure URL.
type disclosureMetadata struct {
	Label             string
	VulnerabilityType string
	FilePath          string
	Function          string
	Summary           string
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

	infos := make([]disclosureInfo, 0, len(paths))
	for _, p := range paths {
		name := filepath.Base(p)
		metadata := disclosureMetadataFromFile(p)
		label := metadata.Label
		if label == "" {
			label = disclosureLabel(name)
		}
		infos = append(infos, disclosureInfo{
			Name:              name,
			Label:             label,
			URL:               "/disclosure/" + id + "/" + name,
			VulnerabilityType: metadata.VulnerabilityType,
			FilePath:          metadata.FilePath,
			Function:          metadata.Function,
			Summary:           metadata.Summary,
		})
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
)

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
	for _, line := range strings.Split(markdown, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "**Type:**") {
			metadata.VulnerabilityType = strings.TrimSpace(strings.TrimPrefix(trimmed, "**Type:**"))
			break
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
	return metadata
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

	// Build scan args.
	args := []string{"scan", "--output", outDir}
	// Language selection mirrors the CLI. No selection = the auto default: every
	// detected language above the size threshold (NOT just the dominant one — see
	// core/language_selection.py select_languages). One selection = --language;
	// several = --languages (a subset). The CLI's --all-languages mode (also scan
	// below-threshold trivial languages) is intentionally not exposed — auto covers
	// the common case.
	if len(job.languages) == 1 {
		args = append(args, "--language", job.languages[0])
	} else if len(job.languages) > 1 {
		args = append(args, "--languages", strings.Join(job.languages, ","))
	}
	// The historical Web UI invocation used the scanner's implicit auto mode.
	// Keep that exact argv for auto, while allowing an explicit generic or
	// OpenHarmony selection to reach the Python CLI.
	args = append(args, platformArgs(job.platform)...)
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
	if job.dynamicTest {
		if job.dynamicTestMode == "claude-code" {
			// Claude Code needs a live pause between static analysis and report
			// generation. The Web runner prepares the task and resumes reporting
			// after the PTY session ends.
			args = append(args, "--no-report")
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
	args = append(args, "--", localPath)

	job.addLog("→ Running: python -m openant " + strings.Join(args, " "))

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

// generateHTMLReport uses `python -m openant report-data` to get pre-computed
// report JSON, then renders it with Go's embedded HTML template — the same
// pipeline the `openant report -f html` CLI command uses.
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

// generateSummary runs `python -m openant report --format summary` to produce
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
