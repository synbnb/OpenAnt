package server

// HTTP bridge for device dynamic testing driven by scan intermediates.
// The Python core owns the scan-artifact listing, the Stage1 conversion, the
// contract compiler and the device run; this layer only enforces loopback /
// CSRF / body limits, keeps run artifacts inside the server-owned output
// directory, and projects the JSON to the page.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/python"
)

const scanArtifactInvokeTimeout = 45 * time.Minute

const (
	scanArtifactMaxProgressBytes = 16 << 20
	scanArtifactMaxLedgerBytes   = 64 << 20
	scanArtifactMaxResultBytes   = 32 << 20
	scanArtifactMaxRuns          = 1024
)

type scanArtifactPageData struct {
	CSRF string
}

func (s *Server) scanArtifactRoot() (string, error) {
	base, err := filepath.Abs(s.outDir)
	if err != nil || strings.TrimSpace(base) == "" {
		return "", errors.New("Web 输出目录不可用")
	}
	if err := os.MkdirAll(base, 0750); err != nil {
		return "", fmt.Errorf("创建 Web 输出目录失败：%w", err)
	}
	root := filepath.Join(base, "scan-artifact")
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("scan-artifact 目录不能是符号链接")
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		return "", fmt.Errorf("创建 scan-artifact 目录失败：%w", err)
	}
	return root, nil
}

func scanArtifactJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleScanArtifactIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplScanArtifact.Execute(w, scanArtifactPageData{CSRF: s.csrfToken}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// scanArtifactMutationOK mirrors socketScopeMutationOK: same-origin + CSRF.
func (s *Server) scanArtifactMutationOK(w http.ResponseWriter, r *http.Request) bool {
	if !sameOriginOK(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if token == "" {
		if err := r.ParseForm(); err == nil {
			token = strings.TrimSpace(r.FormValue("csrf"))
		}
	}
	if subtleConstantTimeCompare(token, s.csrfToken) != 1 {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) invokeScanArtifact(ctx context.Context, args []string) (map[string]any, int, error) {
	ctx, cancel := context.WithTimeout(ctx, scanArtifactInvokeTimeout)
	defer cancel()
	stdout, exitCode, err := python.InvokeCtxCapture(ctx, s.pythonPath, args, "", "", nil)
	if err != nil {
		return nil, exitCode, err
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload); err != nil {
		return nil, exitCode, fmt.Errorf("decode scan-artifact JSON: %w", err)
	}
	return payload, exitCode, nil
}

// scanArtifactRunDir returns the per-run artifact directory <outDir>/scan-artifact/runs/<run_id>.
func (s *Server) scanArtifactRunDir(runID string) (string, error) {
	root, err := s.scanArtifactRoot()
	if err != nil {
		return "", err
	}
	if !scanArtifactRunIDOK(runID) {
		return "", errors.New("run_id 不是安全标识")
	}
	runDir := filepath.Join(root, "runs", runID)
	if info, err := os.Lstat(runDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("run 目录不能是符号链接")
	}
	return runDir, nil
}

// scanArtifactRunIDOK mirrors deviceSocketAssetRunIDRe: safe directory names only.
func scanArtifactRunIDOK(s string) bool {
	return scanArtifactRunIDRe.MatchString(s)
}

var scanArtifactRunIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,96}$`)

// scanArtifactDeliverableOK restricts downloadable deliverable names: the
// exp_package fixed set (plus signed-hap style suffixes), no separators — the
// name is joined onto the server-owned deliverables dir, so path traversal
// must be impossible by construction.
var scanArtifactDeliverableRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var scanArtifactDeliverableNames = map[string]bool{
	"poc.hap":              true,
	"exp.hap":              true,
	"contract_poc.json":    true,
	"contract_exp.json":    true,
	"evidence_exp.json":    true,
	"README.md":            true,
	"poc_source_Index.ets": true,
	"exp_source_Index.ets": true,
}

// handleScanArtifactRunDeliverables lists one run's deliverables directory
// (read-only). Empty list when the run has none (not CONFIRMED / older run).
func (s *Server) handleScanArtifactRunDeliverables(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if !scanArtifactRunIDOK(runID) {
		http.NotFound(w, r)
		return
	}
	runDir, err := s.scanArtifactRunDir(runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	deliverDir := filepath.Join(runDir, "deliverables")
	entries, err := os.ReadDir(deliverDir)
	if err != nil {
		if os.IsNotExist(err) {
			scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "files": []any{}})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	files := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !scanArtifactDeliverableRe.MatchString(e.Name()) || !scanArtifactDeliverableNames[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		files = append(files, map[string]any{
			"name":  e.Name(),
			"bytes": info.Size(),
			"url":   "/scan-artifact/runs/" + runID + "/deliverables/" + e.Name(),
		})
	}
	scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "files": files})
}

// handleScanArtifactRunDeliverable serves one deliverable file for download.
// The name must be in the allowlist, so the joined path stays inside the
// server-owned run directory (no traversal; symlink + non-regular refused).
func (s *Server) handleScanArtifactRunDeliverable(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	name := strings.TrimSpace(r.PathValue("name"))
	if !scanArtifactRunIDOK(runID) || !scanArtifactDeliverableNames[name] || !scanArtifactDeliverableRe.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	runDir, err := s.scanArtifactRunDir(runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	root, err := s.scanArtifactRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, _, err := openRegularInRoot(root, filepath.Join(runDir, "deliverables", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	contentType := "application/octet-stream"
	switch {
	case strings.HasSuffix(name, ".json"):
		contentType = "application/json; charset=utf-8"
	case strings.HasSuffix(name, ".md"):
		contentType = "text/markdown; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = io.Copy(w, f)
}

// scanArtifactJob tracks one background dynamic-test run observed by the page.
type scanArtifactJob struct {
	RunID     string             `json:"run_id"`
	Sample    string             `json:"sample,omitempty"`
	ScanID    string             `json:"scan_id,omitempty"`
	Serial    string             `json:"device_serial,omitempty"`
	Status    string             `json:"status"`
	Error     string             `json:"error,omitempty"`
	StartedAt time.Time          `json:"started_at"`
	EndedAt   time.Time          `json:"ended_at,omitempty"`
	Cancel    context.CancelFunc `json:"-"`
}

func (s *Server) registerScanArtifactJob(job *scanArtifactJob) {
	if job == nil || job.RunID == "" {
		return
	}
	s.scanArtifactJobsMu.Lock()
	defer s.scanArtifactJobsMu.Unlock()
	if s.scanArtifactJobs == nil {
		s.scanArtifactJobs = make(map[string]*scanArtifactJob)
	}
	if len(s.scanArtifactJobs) >= scanArtifactMaxRuns {
		for id, old := range s.scanArtifactJobs {
			if old != nil && old.Status != "running" {
				delete(s.scanArtifactJobs, id)
				if len(s.scanArtifactJobs) < scanArtifactMaxRuns {
					break
				}
			}
		}
	}
	s.scanArtifactJobs[job.RunID] = job
}

func (s *Server) scanArtifactJob(runID string) (scanArtifactJob, bool) {
	s.scanArtifactJobsMu.RLock()
	defer s.scanArtifactJobsMu.RUnlock()
	job, ok := s.scanArtifactJobs[runID]
	if !ok || job == nil {
		return scanArtifactJob{}, false
	}
	copy := *job
	copy.Cancel = nil
	return copy, true
}

func (s *Server) finishScanArtifactJob(runID, status, message string) {
	s.scanArtifactJobsMu.Lock()
	defer s.scanArtifactJobsMu.Unlock()
	if job := s.scanArtifactJobs[runID]; job != nil {
		job.Status = status
		job.Error = message
		job.EndedAt = time.Now().UTC()
	}
}

func (s *Server) cancelScanArtifactJobs() {
	s.scanArtifactJobsMu.RLock()
	defer s.scanArtifactJobsMu.RUnlock()
	for _, job := range s.scanArtifactJobs {
		if job != nil && job.Cancel != nil && job.Status == "running" {
			job.Cancel()
		}
	}
}

// scanArtifactTerminal reports whether a run status is final.
func scanArtifactTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed", "suspected", "not_reproduced", "inconclusive", "error",
		"cancelled", "complete", "failed":
		return true
	default:
		return false
	}
}

// readScanArtifactJSONL reads a bounded JSONL file inside the run directory,
// tolerating a partial trailing line (the Python side appends as it runs).
func readScanArtifactJSONL(root, path string, maxBytes int64) ([]map[string]any, error) {
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return []map[string]any{}, nil
	}
	f, fi, err := openRegularInRoot(root, path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	defer f.Close()
	if fi.Size() > maxBytes {
		return nil, errors.New("进度产物超过大小上限")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil || row == nil {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// scanArtifactRunStatus projects the on-disk run state (result.json when the
// Python worker finished, else the in-memory job) for the status endpoint and
// the SSE terminal check.
func (s *Server) scanArtifactRunStatus(runID string) (map[string]any, bool, error) {
	root, err := s.scanArtifactRoot()
	if err != nil {
		return nil, false, err
	}
	runDir := filepath.Join(root, "runs", runID)
	job, hasJob := s.scanArtifactJob(runID)
	// result.json exists once the Python worker finished (written by Go, from
	// the worker's stdout envelope). It is the authoritative terminal state.
	if payload, readErr := scanArtifactReadResult(root, filepath.Join(runDir, "result.json")); readErr == nil {
		status := strings.TrimSpace(fmt.Sprint(payload["run_status"]))
		if status == "" {
			status = "complete"
		}
		payload["run_id"] = runID
		payload["status"] = status
		payload["terminal"] = true
		return payload, true, nil
	} else if !os.IsNotExist(readErr) && hasJob {
		// unreadable result.json on a live job: fall through to job metadata
		_ = readErr
	}
	if !hasJob {
		return nil, false, os.ErrNotExist
	}
	return map[string]any{
		"run_id":     runID,
		"status":     job.Status,
		"sample":     job.Sample,
		"scan_id":    job.ScanID,
		"device":     job.Serial,
		"started_at": job.StartedAt,
		"ended_at":   job.EndedAt,
		"error":      job.Error,
	}, true, nil
}

// scanArtifactReadResult reads result.json with the same containment guarantees
// as the other served artifacts.
func scanArtifactReadResult(root, path string) (map[string]any, error) {
	f, fi, err := openRegularInRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > scanArtifactMaxResultBytes {
		return nil, errors.New("结果 JSON 超过大小上限")
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(f, scanArtifactMaxResultBytes+1)).Decode(&payload); err != nil {
		return nil, err
	}
	if payload == nil {
		payload = map[string]any{}
	}
	return payload, nil
}

// handleScanArtifactRunEvents streams live progress (progress.jsonl +
// ledger.jsonl rows appended by the Python worker) as SSE events until the run
// reaches a terminal state (result.json present or the in-memory job ended).
func (s *Server) handleScanArtifactRunEvents(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if !scanArtifactRunIDOK(runID) {
		http.NotFound(w, r)
		return
	}
	root, err := s.scanArtifactRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runDir := filepath.Join(root, "runs", runID)
	progressSeen, ledgerSeen := 0, 0
	if raw := strings.TrimSpace(r.Header.Get("Last-Event-ID")); raw != "" {
		// "progress:<n>:<m>" or "done" — replay cursor for both streams.
		if _, rest, ok := strings.Cut(raw, ":"); ok {
			parts := strings.SplitN(rest, ":", 2)
			p, errP := strconv.Atoi(parts[0])
			l, errL := strconv.Atoi(parts[1])
			if errP == nil && errL == nil && p >= 0 && l >= 0 {
				progressSeen, ledgerSeen = p, l
			}
		}
	}
	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = io.WriteString(w, "retry: 1500\n\n")
	if canFlush {
		flusher.Flush()
	}
	sendRows := func(rows []map[string]any, seen *int, name string) {
		for ; *seen < len(rows); *seen++ {
			payload, marshalErr := json.Marshal(rows[*seen])
			if marshalErr != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "id: progress:%d:%d\nevent: %s\ndata: %s\n\n", progressSeen, ledgerSeen, name, payload)
		}
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		progressRows, pErr := readScanArtifactJSONL(root, filepath.Join(runDir, "progress.jsonl"), scanArtifactMaxProgressBytes)
		ledgerRows, lErr := readScanArtifactJSONL(root, filepath.Join(runDir, "ledger.jsonl"), scanArtifactMaxLedgerBytes)
		if pErr == nil && lErr == nil && (len(progressRows) > progressSeen || len(ledgerRows) > ledgerSeen) {
			// progress.jsonl carries the coarse phases; ledger.jsonl the per-command
			// records. Emit ledger first so a phase lands after its commands.
			sendRows(ledgerRows, &ledgerSeen, "device-cmd")
			sendRows(progressRows, &progressSeen, "progress")
			if canFlush {
				flusher.Flush()
			}
		}
		status, found, statusErr := s.scanArtifactRunStatus(runID)
		if statusErr == nil && found {
			state := strings.ToLower(strings.TrimSpace(fmt.Sprint(status["status"])))
			if scanArtifactTerminal(state) {
				payload, _ := json.Marshal(map[string]any{"status": state, "run": status})
				_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", payload)
				if canFlush {
					flusher.Flush()
				}
				return
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

// handleScanArtifactRunStatus returns the current run state (job metadata plus
// result.json when the run finished). Read-only.
func (s *Server) handleScanArtifactRunStatus(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if !scanArtifactRunIDOK(runID) {
		http.NotFound(w, r)
		return
	}
	data, found, err := s.scanArtifactRunStatus(runID)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "run": data, "found": found})
}

// handleScanArtifactRunResult serves the finished run's result.json (or the
// latest progress snapshot while running) so the detail page can render the
// full evidence view after a reload.
func (s *Server) handleScanArtifactRunResult(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if !scanArtifactRunIDOK(runID) {
		http.NotFound(w, r)
		return
	}
	root, err := s.scanArtifactRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runDir := filepath.Join(root, "runs", runID)
	if payload, readErr := scanArtifactReadResult(root, filepath.Join(runDir, "result.json")); readErr == nil {
		scanArtifactJSON(w, http.StatusOK, payload)
		return
	}
	http.NotFound(w, r)
}

// handleScanArtifactRounds lists scan-artifact rounds, or webui scans when no
// result_dir is given (read-only listing).
func (s *Server) handleScanArtifactRounds(w http.ResponseWriter, r *http.Request) {
	resultDir := strings.TrimSpace(r.URL.Query().Get("result_dir"))
	if resultDir == "" {
		// No dir selected: list the webui scans for the picker form.
		args := []string{"scan-artifact", "list"}
		if d := strings.TrimSpace(r.URL.Query().Get("webui_dir")); d != "" && len(d) <= 4096 {
			args = append(args, "--webui-dir", d)
		}
		payload, _, err := s.invokeScanArtifact(r.Context(), args)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		scanArtifactJSON(w, http.StatusOK, payload)
		return
	}
	if len(resultDir) > 4096 {
		http.Error(w, "result_dir too long", http.StatusBadRequest)
		return
	}
	payload, _, err := s.invokeScanArtifact(r.Context(), []string{
		"scan-artifact", "list", "--result-dir", resultDir,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	scanArtifactJSON(w, http.StatusOK, payload)
}

// handleScanArtifactEntries lists one scan's testable entries (read-only).
// Two input modes: webui scan (scan_id) or legacy aggregate dir (result_dir+round).
func (s *Server) handleScanArtifactEntries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	resultDir := strings.TrimSpace(q.Get("result_dir"))
	scanID := strings.ToLower(strings.TrimSpace(q.Get("scan_id")))
	round := strings.TrimSpace(q.Get("round"))
	if scanID != "" {
		if len(scanID) > 64 || !scanArtifactScanIDOK(scanID) {
			http.Error(w, "scan_id must be a hex scan ID", http.StatusBadRequest)
			return
		}
	} else if resultDir == "" || len(resultDir) > 4096 || round == "" || len(round) > 8 {
		http.Error(w, "result_dir+round or scan_id are required", http.StatusBadRequest)
		return
	}
	var args []string
	if scanID != "" {
		args = []string{"scan-artifact", "list", "--scan-id", scanID}
		if d := strings.TrimSpace(q.Get("webui_dir")); d != "" && len(d) <= 4096 {
			args = append(args, "--webui-dir", d)
		}
	} else {
		args = []string{"scan-artifact", "list", "--result-dir", resultDir, "--round", round}
	}
	if f := strings.TrimSpace(q.Get("finding")); f == "vulnerable" || f == "inconclusive" {
		args = append(args, "--finding", f)
	}
	if repo := strings.TrimSpace(q.Get("repository")); repo != "" && len(repo) <= 256 {
		args = append(args, "--repository", repo)
	}
	payload, _, err := s.invokeScanArtifact(r.Context(), args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	scanArtifactJSON(w, http.StatusOK, payload)
}

// handleScanArtifactRun starts the device dynamic test for one entry as a
// background job and returns the run ID immediately. This is a mutation: CSRF +
// same-origin apply, all artifacts land inside the server-owned scan-artifact
// directory, and the device serial must be given explicitly (the bridge never
// picks a board implicitly). Progress is observed via the SSE events endpoint.
func (s *Server) handleScanArtifactRun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if !s.scanArtifactMutationOK(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	resultDir := strings.TrimSpace(r.FormValue("result_dir"))
	scanID := strings.ToLower(strings.TrimSpace(r.FormValue("scan_id")))
	round := strings.TrimSpace(r.FormValue("round"))
	sample := strings.TrimSpace(r.FormValue("sample"))
	serial := strings.TrimSpace(r.FormValue("device"))
	// Two input modes: webui scan (--scan-id) or legacy aggregate dir
	// (--result-dir + --round). Exactly one must be selected.
	if scanID != "" {
		if len(scanID) > 64 || !scanArtifactScanIDOK(scanID) {
			http.Error(w, "scan_id must be a hex scan ID", http.StatusBadRequest)
			return
		}
		if resultDir != "" {
			http.Error(w, "pass either scan_id or result_dir, not both", http.StatusBadRequest)
			return
		}
	} else {
		if resultDir == "" || len(resultDir) > 4096 {
			http.Error(w, "result_dir is required (or pass scan_id)", http.StatusBadRequest)
			return
		}
		if !isDigits(round) || len(round) > 8 {
			http.Error(w, "round must be numeric", http.StatusBadRequest)
			return
		}
	}
	if sample == "" || len(sample) > 160 || !scanArtifactSampleOK(sample) {
		http.Error(w, "sample must be an identifier (finding id or unit path)", http.StatusBadRequest)
		return
	}
	if serial == "" || len(serial) > 128 {
		http.Error(w, "device serial is required", http.StatusBadRequest)
		return
	}

	// Gate new work at shutdown BEFORE creating any state, mirroring
	// handleStartScan's drain protocol (wg.Add cannot race wg.Wait).
	s.drainMu.Lock()
	if s.draining {
		s.drainMu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	s.wg.Add(1)
	s.drainMu.Unlock()
	// Every return path after this Add MUST call wg.Done.

	root, err := s.scanArtifactRoot()
	if err != nil {
		s.wg.Done()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runID, err := randomID()
	if err != nil {
		s.wg.Done()
		http.Error(w, "failed to generate run ID", http.StatusInternalServerError)
		return
	}
	runDir := filepath.Join(root, "runs", runID)
	if err := os.MkdirAll(runDir, 0750); err != nil {
		s.wg.Done()
		http.Error(w, "failed to create run dir", http.StatusInternalServerError)
		return
	}
	progressPath := filepath.Join(runDir, "progress.jsonl")
	ledgerPath := filepath.Join(runDir, "ledger.jsonl")

	args := []string{
		"scan-artifact", "run",
		"--sample", sample,
		"--device", serial,
		"--ledger", ledgerPath,
		"--progress-file", progressPath,
	}
	if scanID != "" {
		args = append(args, "--scan-id", scanID)
		if webuiDir := strings.TrimSpace(r.FormValue("webui_dir")); webuiDir != "" && len(webuiDir) <= 4096 {
			args = append(args, "--webui-dir", webuiDir)
		}
	} else {
		args = append(args, "--result-dir", resultDir, "--round", round)
	}
	if hdc := strings.TrimSpace(r.FormValue("hdc")); hdc != "" && len(hdc) <= 1024 {
		args = append(args, "--hdc", hdc)
	}
	if repoRoot := strings.TrimSpace(r.FormValue("repo_root")); repoRoot != "" && len(repoRoot) <= 4096 {
		args = append(args, "--repo-root", repoRoot)
	}

	// The browser must not hold the POST connection open while the pipeline
	// compiles contracts and drives the board. The worker gets a detached
	// context with the stage deadline; progress flows through progress.jsonl /
	// ledger.jsonl and the SSE endpoint.
	ctx, cancel := context.WithTimeout(context.Background(), scanArtifactInvokeTimeout)
	s.registerScanArtifactJob(&scanArtifactJob{
		RunID: runID, Sample: sample, ScanID: scanID, Serial: serial,
		Status: "running", StartedAt: time.Now().UTC(), Cancel: cancel,
	})
	go func() {
		defer cancel()
		defer s.wg.Done()
		stdout, exitCode, invokeErr := python.InvokeCtxCapture(ctx, s.pythonPath, args, "", "", nil)
		runStatus := "complete"
		errMsg := ""
		var payload map[string]any
		if invokeErr != nil && ctx.Err() != nil {
			runStatus = "cancelled"
			errMsg = "运行已取消"
		} else if invokeErr != nil {
			runStatus = "error"
			errMsg = invokeErr.Error()
		} else {
			// Exit 1 means "confirmed device effect" — a successful result, not
			// an error. Exit 2 means the pipeline failed and stdout carries
			// {"status":"error",...}.
			if strings.TrimSpace(stdout) != "" {
				_ = json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload)
			}
			switch {
			case payload != nil && payload["status"] == "error":
				runStatus = "error"
				if errs, ok := payload["errors"].([]any); ok && len(errs) > 0 {
					errMsg = fmt.Sprint(errs[0])
				} else {
					errMsg = "worker 返回错误"
				}
			case exitCode == 1:
				// Exit 1 mirrors dynamic-test: a CONFIRMED device effect is a
				// finding, not a failure.
				runStatus = "complete"
			case exitCode != 0:
				runStatus = "error"
				errMsg = fmt.Sprintf("worker 退出码 %d", exitCode)
			}
		}
		if payload == nil {
			payload = map[string]any{"status": "error", "errors": []string{errMsg}}
		}
		payload["run_status"] = runStatus
		payload["run_error"] = errMsg
		payload["run_id"] = runID
		if data, err := json.MarshalIndent(payload, "", "  "); err == nil {
			_ = os.WriteFile(filepath.Join(runDir, "result.json"), data, 0640)
		}
		s.finishScanArtifactJob(runID, runStatus, errMsg)
	}()
	scanArtifactJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"run_id":     runID,
		"sample":     sample,
		"scan_id":    scanID,
		"device":     serial,
		"events_url": "/scan-artifact/runs/" + runID + "/events",
		"status_url": "/scan-artifact/runs/" + runID,
		"result_url": "/scan-artifact/runs/" + runID + "/result",
		"message":    "动态测试已在后台启动；请通过 events 查看实时进度",
	})
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// handleScanArtifactDevices lists currently connected HDC devices so the page
// can offer a picker instead of a free-text serial field. Read-only: runs
// `hdc list targets` (hdc binary resolved like the Python core: env override,
// PATH, then the bundled toolchain).
func (s *Server) handleScanArtifactDevices(w http.ResponseWriter, r *http.Request) {
	hdc := strings.TrimSpace(r.URL.Query().Get("hdc"))
	if hdc == "" {
		hdc = resolveHDCBinary()
	}
	if hdc == "" || filepath.Base(hdc) != "hdc" {
		scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "devices": []any{}, "error": "hdc not found"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, hdc, "list", "targets").Output()
	devices := []map[string]string{}
	if err != nil {
		scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "devices": devices, "error": err.Error()})
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[Empty]") || strings.Contains(line, "Cannot find") {
			continue
		}
		// Serial is the first token; some hdc versions append a state suffix.
		serial := strings.Fields(line)[0]
		if len(serial) > 128 || !scanArtifactSampleOK(serial) {
			continue
		}
		devices = append(devices, map[string]string{"serial": serial})
	}
	scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "devices": devices})
}

// resolveHDCBinary mirrors the Python core's resolve order (env override →
// PATH → bundled toolchain) without accepting arbitrary user paths.
func resolveHDCBinary() string {
	for _, env := range []string{"VULNFOUNDER_HDC", "OPENANT_HDC"} {
		if p := strings.TrimSpace(os.Getenv(env)); p != "" && filepath.Base(p) == "hdc" {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath("hdc"); err == nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, "harmonyos-sdk", "openharmony", "9", "toolchains", "hdc")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// scanArtifactSampleOK restricts the sample id to identifier shapes
// (letters, digits, dash, underscore, and for webui unit paths a colon and
// slash) so it cannot smuggle CLI flags.
func scanArtifactSampleOK(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':', c == '/':
		default:
			return false
		}
	}
	return true
}

// scanArtifactScanIDOK restricts webui scan IDs to the hex job-ID shape.
func scanArtifactScanIDOK(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'f', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}
