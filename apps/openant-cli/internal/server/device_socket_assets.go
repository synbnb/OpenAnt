package server

// HTTP boundary for device-scoped Socket asset discovery.  The Python worker
// owns the Agentic Loop and snapshot schema; Go owns loopback/CSRF checks,
// request bounds, artifact containment and the browser-facing JSON contract.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/knostic/open-ant-cli/internal/python"
)

const deviceSocketAssetInvokeTimeout = 35 * time.Minute

const (
	deviceSocketAssetMaxTraceBytes    = 16 << 20
	deviceSocketAssetMaxEvidenceBytes = 16 << 20
	deviceSocketAssetMaxCommandBytes  = 64 << 20
	deviceSocketAssetMaxSnapshotBytes = 32 << 20
	deviceSocketAssetMaxRuns          = 2048
)

var deviceSocketAssetArtifactAllowlist = map[string]bool{
	"latest.json":                     true,
	"socket_inventory_plan.json":      true,
	"socket_inventory_trace.jsonl":    true,
	"socket_inventory_evidence.json":  true,
	"socket_inventory_commands.jsonl": true,
	"socket_inventory_worker.log":     true,
}

var deviceSocketAssetNameRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,160}$`)
var deviceSocketAssetRunIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,96}$`)

type deviceSocketAssetJob struct {
	RunID      string             `json:"run_id"`
	Serial     string             `json:"device_serial,omitempty"`
	TaskGoal   string             `json:"task_goal,omitempty"`
	Status     string             `json:"status"`
	Error      string             `json:"error,omitempty"`
	StartedAt  time.Time          `json:"started_at"`
	EndedAt    time.Time          `json:"ended_at,omitempty"`
	Cancel     context.CancelFunc `json:"-"`
	WorkerLogs []string           `json:"worker_logs,omitempty"`
	LogBytes   int                `json:"-"`
}

func (s *Server) registerDeviceSocketAssetJob(job *deviceSocketAssetJob) {
	if job == nil || job.RunID == "" {
		return
	}
	s.deviceSocketJobsMu.Lock()
	defer s.deviceSocketJobsMu.Unlock()
	if s.deviceSocketJobs == nil {
		s.deviceSocketJobs = make(map[string]*deviceSocketAssetJob)
	}
	// Keep the in-memory table bounded.  On-disk run artifacts remain the
	// durable history; old terminal entries are only an acceleration cache for
	// a page that is currently open.
	if len(s.deviceSocketJobs) >= deviceSocketAssetMaxRuns {
		for id, old := range s.deviceSocketJobs {
			if old != nil && old.Status != "running" {
				delete(s.deviceSocketJobs, id)
				if len(s.deviceSocketJobs) < deviceSocketAssetMaxRuns {
					break
				}
			}
		}
	}
	s.deviceSocketJobs[job.RunID] = job
}

func (s *Server) deviceSocketAssetJob(runID string) (deviceSocketAssetJob, bool) {
	s.deviceSocketJobsMu.RLock()
	defer s.deviceSocketJobsMu.RUnlock()
	job, ok := s.deviceSocketJobs[runID]
	if !ok || job == nil {
		return deviceSocketAssetJob{}, false
	}
	copy := *job
	copy.Cancel = nil
	return copy, true
}

func (s *Server) finishDeviceSocketAssetJob(runID, status, message string) {
	s.deviceSocketJobsMu.Lock()
	defer s.deviceSocketJobsMu.Unlock()
	if job := s.deviceSocketJobs[runID]; job != nil {
		job.Status = status
		job.Error = message
		job.EndedAt = time.Now().UTC()
	}
}

func (s *Server) cancelDeviceSocketAssetJobs() {
	s.deviceSocketJobsMu.RLock()
	defer s.deviceSocketJobsMu.RUnlock()
	for _, job := range s.deviceSocketJobs {
		if job != nil && job.Cancel != nil && job.Status == "running" {
			job.Cancel()
		}
	}
}

func (s *Server) appendDeviceSocketAssetLog(runID, line string) {
	line = strings.ReplaceAll(strings.ReplaceAll(line, "\x00", ""), "\r", "")
	line = strings.TrimRight(line, "\n")
	if line == "" {
		return
	}
	s.deviceSocketJobsMu.Lock()
	job := s.deviceSocketJobs[runID]
	if job != nil && job.LogBytes < 4<<20 && len(job.WorkerLogs) < 4000 {
		remaining := (4 << 20) - job.LogBytes
		if len(line) > remaining {
			line = line[:remaining]
		}
		job.WorkerLogs = append(job.WorkerLogs, line)
		job.LogBytes += len(line)
	}
	s.deviceSocketJobsMu.Unlock()
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		return
	}
	runDir, _, err := findDeviceSocketAssetRun(root, runID)
	if err != nil {
		return
	}
	path := filepath.Join(runDir, "socket_inventory_worker.log")
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return
	}
	if handle, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|oNoFollow, 0600); openErr == nil {
		// Keep the durable log bounded as well as the in-memory view.  The
		// Python trace/command artifacts retain the structured details; this
		// stderr mirror is only a live diagnostic stream.
		if info, statErr := handle.Stat(); statErr == nil && info.Size() < 4<<20 {
			remaining := int64(4<<20) - info.Size()
			entry := []byte(line + "\n")
			if int64(len(entry)) > remaining {
				entry = entry[:remaining]
			}
			_, _ = handle.Write(entry)
		}
		_ = handle.Close()
	}
}

func (s *Server) deviceSocketAssetRoot() (string, error) {
	if strings.TrimSpace(s.outDir) == "" {
		return "", errors.New("Web 输出目录未配置")
	}
	base, err := filepath.Abs(s.outDir)
	if err != nil {
		return "", fmt.Errorf("解析 Web 输出目录失败：%w", err)
	}
	if info, lstatErr := os.Lstat(base); lstatErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("Web 输出目录不能是符号链接或普通文件")
		}
	} else if os.IsNotExist(lstatErr) {
		if err := os.MkdirAll(base, 0750); err != nil {
			return "", fmt.Errorf("创建 Web 输出目录失败：%w", err)
		}
	} else {
		return "", fmt.Errorf("检查 Web 输出目录失败：%w", lstatErr)
	}
	root := filepath.Join(base, "device-socket-assets")
	if info, lstatErr := os.Lstat(root); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("device-socket-assets 目录不能是符号链接")
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		return "", fmt.Errorf("创建设备资产目录失败：%w", err)
	}
	return root, nil
}

func writeDeviceSocketAssetResult(w http.ResponseWriter, result *python.InvokeResult, err error) {
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadGateway, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if result == nil {
		sourceLocatorJSON(w, http.StatusBadGateway, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"设备资产 worker 没有返回结果"}})
		return
	}
	status := http.StatusOK
	if result.Envelope.Status == "error" {
		status = http.StatusBadRequest
	}
	sourceLocatorJSON(w, status, result.Envelope)
}

func (s *Server) invokeDeviceSocketAsset(r *http.Request, args []string) (*python.InvokeResult, error) {
	ctx, cancel := context.WithTimeout(r.Context(), deviceSocketAssetInvokeTimeout)
	defer cancel()
	return s.invokeDeviceSocketAssetContext(ctx, args)
}

func (s *Server) invokeDeviceSocketAssetContext(ctx context.Context, args []string, onLog ...func(string)) (*python.InvokeResult, error) {
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		return nil, err
	}
	args = append(args, "--root", root)
	var callback func(string)
	if len(onLog) > 0 {
		callback = onLog[0]
	}
	return python.InvokeDeviceSocketInventory(ctx, s.pythonPath, args, "", callback)
}

func deviceSocketAssetRunID(runID string) bool {
	return deviceSocketAssetRunIDRe.MatchString(strings.TrimSpace(runID))
}

// findDeviceSocketAssetRun locates a run without trusting the hashed device
// directory name supplied by a browser.  The run ID is validated, every path
// component is checked with Lstat, and the result is required to stay below
// the server-owned asset root.
func findDeviceSocketAssetRun(root, runID string) (runDir, deviceDir string, err error) {
	if !deviceSocketAssetRunID(runID) {
		return "", "", errors.New("设备资产 run_id 不是安全标识")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "." || entry.Name() == ".." {
			continue
		}
		device := filepath.Join(root, entry.Name())
		if info, lerr := os.Lstat(device); lerr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		candidate := filepath.Join(device, "runs", strings.TrimSpace(runID))
		info, lerr := os.Lstat(candidate)
		if lerr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !withinRoot(root, candidate) {
			continue
		}
		return candidate, device, nil
	}
	return "", "", os.ErrNotExist
}

func readDeviceSocketAssetJSON(root, path string, maxBytes int64) (map[string]any, error) {
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return nil, os.ErrNotExist
	}
	f, fi, err := openRegularInRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > maxBytes {
		return nil, errors.New("设备资产 JSON 产物超过大小上限")
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(f, maxBytes+1)).Decode(&payload); err != nil {
		return nil, err
	}
	if payload == nil {
		payload = map[string]any{}
	}
	return payload, nil
}

func readDeviceSocketAssetJSONL(root, path string, maxBytes int64) ([]map[string]any, error) {
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
		return nil, errors.New("设备资产 JSONL 产物超过大小上限")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("设备资产 JSONL 产物超过大小上限")
	}
	rows := make([]map[string]any, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil || value == nil {
			// An atomically replaced file should never contain a partial line.  A
			// malformed line is ignored in the status view so one damaged record
			// cannot hide the rest of an auditable run.
			continue
		}
		rows = append(rows, value)
	}
	return rows, nil
}

func readDeviceSocketAssetText(root, path string, maxBytes int64) ([]string, error) {
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return []string{}, nil
	}
	f, fi, err := openRegularInRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > maxBytes {
		return nil, errors.New("设备资产日志超过大小上限")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("设备资产日志超过大小上限")
	}
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(data), "\r", ""), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []string{}, nil
	}
	return lines, nil
}

func compactDeviceSocketAssetCommands(rows []map[string]any) []map[string]any {
	const maxOutput = 48 << 10
	for _, row := range rows {
		for _, key := range []string{"stdout", "stderr"} {
			value, ok := row[key].(string)
			if !ok || len(value) <= maxOutput {
				continue
			}
			row[key] = value[:maxOutput] + " …[Web 展示截断；完整内容见命令产物]"
			row[key+"_web_truncated"] = true
		}
	}
	return rows
}

func deviceSocketAssetTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "complete", "partial", "incomplete", "error", "failed", "cancelled":
		return true
	default:
		return false
	}
}

func deviceSocketAssetPlanStatus(plan map[string]any) string {
	if value, ok := plan["status"].(string); ok && strings.TrimSpace(value) != "" {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return "running"
}

func (s *Server) deviceSocketAssetRunData(runID string) (map[string]any, bool, error) {
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		return nil, false, err
	}
	runDir, deviceDir, findErr := findDeviceSocketAssetRun(root, runID)
	job, hasJob := s.deviceSocketAssetJob(runID)
	if findErr != nil {
		if !hasJob {
			return nil, false, findErr
		}
		return map[string]any{
			"run_id":        runID,
			"status":        job.Status,
			"device_serial": job.Serial,
			"task_goal":     job.TaskGoal,
			"started_at":    job.StartedAt,
			"ended_at":      job.EndedAt,
			"error":         job.Error,
			"phase":         "worker_starting",
			"task_tree":     map[string]any{},
			"trace":         []any{},
			"evidence":      []any{},
			"commands":      []any{},
		}, true, nil
	}
	plan, planErr := readDeviceSocketAssetJSON(root, filepath.Join(runDir, "socket_inventory_plan.json"), deviceSocketAssetMaxTraceBytes)
	if planErr != nil && !os.IsNotExist(planErr) {
		return nil, false, planErr
	}
	trace, traceErr := readDeviceSocketAssetJSONL(root, filepath.Join(runDir, "socket_inventory_trace.jsonl"), deviceSocketAssetMaxTraceBytes)
	if traceErr != nil {
		return nil, false, traceErr
	}
	evidencePayload, evidenceErr := readDeviceSocketAssetJSON(root, filepath.Join(runDir, "socket_inventory_evidence.json"), deviceSocketAssetMaxEvidenceBytes)
	if evidenceErr != nil && !os.IsNotExist(evidenceErr) {
		return nil, false, evidenceErr
	}
	evidence := []any{}
	if raw, ok := evidencePayload["evidence"].([]any); ok {
		evidence = raw
	}
	commands, commandErr := readDeviceSocketAssetJSONL(root, filepath.Join(runDir, "socket_inventory_commands.jsonl"), deviceSocketAssetMaxCommandBytes)
	if commandErr != nil {
		return nil, false, commandErr
	}
	// Older runs predate the progress schema and therefore do not have the
	// count fields in their plan.  Derive those counters from the same
	// artifacts so the historical view remains as informative as a new run.
	traceCount := plan["trace_count"]
	if traceCount == nil {
		traceCount = len(trace)
	}
	evidenceCount := plan["evidence_count"]
	if evidenceCount == nil {
		evidenceCount = len(evidence)
	}
	commandCount := plan["command_count"]
	if commandCount == nil {
		commandCount = len(commands)
	}
	observedEndpointCount := plan["observed_endpoint_count"]
	if observedEndpointCount == nil {
		if endpoints, ok := plan["observed_endpoints"].([]any); ok {
			observedEndpointCount = len(endpoints)
		} else {
			observedEndpointCount = 0
		}
	}
	workerLogs, workerLogErr := readDeviceSocketAssetText(root, filepath.Join(runDir, "socket_inventory_worker.log"), 4<<20)
	if workerLogErr != nil {
		workerLogs = []string{}
	}
	data := map[string]any{
		"run_id":                    runID,
		"status":                    deviceSocketAssetPlanStatus(plan),
		"device_serial":             plan["device_serial"],
		"task_goal":                 plan["task_goal"],
		"task_scope":                plan["task_scope"],
		"socket_inventory_required": plan["socket_inventory_required"],
		"task_summary":              plan["task_summary"],
		"task_findings":             plan["task_findings"],
		"provider":                  plan["provider"],
		"model":                     plan["model"],
		"phase":                     plan["phase"],
		"plan":                      plan,
		"task_tree":                 plan["task_tree"],
		"rag":                       plan["rag"],
		"rounds":                    plan["rounds"],
		"command_count":             commandCount,
		"evidence_count":            evidenceCount,
		"trace_count":               traceCount,
		"observed_endpoint_count":   observedEndpointCount,
		"observed_endpoints":        plan["observed_endpoints"],
		// The final asset list intentionally excludes CONNECTED and anonymous
		// rows.  Forward the separate exhaustive observation view as-is so the
		// Web UI can display every socket record collected from netstat/proc.
		"socket_record_count":     plan["socket_record_count"],
		"socket_record_summary":   plan["socket_record_summary"],
		"observed_socket_records": plan["observed_socket_records"],
		"last_event":              plan["last_event"],
		"error":                   plan["error"],
		"trace":                   trace,
		"evidence":                evidence,
		"commands":                compactDeviceSocketAssetCommands(commands),
		"worker_logs":             workerLogs,
		"artifacts": map[string]string{
			"socket_inventory_plan.json":      "/device-socket-assets/runs/" + runID + "/artifact/socket_inventory_plan.json",
			"socket_inventory_trace.jsonl":    "/device-socket-assets/runs/" + runID + "/artifact/socket_inventory_trace.jsonl",
			"socket_inventory_evidence.json":  "/device-socket-assets/runs/" + runID + "/artifact/socket_inventory_evidence.json",
			"socket_inventory_commands.jsonl": "/device-socket-assets/runs/" + runID + "/artifact/socket_inventory_commands.jsonl",
			"socket_inventory_worker.log":     "/device-socket-assets/runs/" + runID + "/artifact/socket_inventory_worker.log",
		},
	}
	// The final snapshot is outside the run directory by design.  Load it only
	// when present so assets are visible as soon as the terminal snapshot lands.
	snapshotPath := filepath.Join(deviceDir, "snapshots", "socket_inventory_"+runID+".json")
	if snapshot, snapshotErr := readDeviceSocketAssetJSON(root, snapshotPath, deviceSocketAssetMaxSnapshotBytes); snapshotErr == nil {
		for _, key := range []string{"assets", "asset_count", "listening_count", "observed_non_listening", "coverage", "notes", "missing_fields", "task_goal", "task_scope", "socket_inventory_required", "task_summary", "task_findings", "socket_record_count", "socket_record_summary", "observed_socket_records", "generated_at", "latest_updated"} {
			if value, ok := snapshot[key]; ok {
				data[key] = value
			}
		}
	}
	if hasJob {
		// The on-disk plan is authoritative once it exists; job metadata fills
		// the short interval before the Python worker creates that plan.
		if data["device_serial"] == nil || strings.TrimSpace(fmt.Sprint(data["device_serial"])) == "" {
			data["device_serial"] = job.Serial
		}
		if len(workerLogs) == 0 && len(job.WorkerLogs) > 0 {
			data["worker_logs"] = append([]string(nil), job.WorkerLogs...)
		}
		if job.Status != "running" && !deviceSocketAssetTerminal(data["status"].(string)) {
			data["status"] = job.Status
		}
	}
	return data, true, nil
}

func (s *Server) handleDeviceSocketAssetIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.tmplDeviceSocketAssets == nil {
		http.Error(w, "设备 Socket 资产页面未初始化", http.StatusInternalServerError)
		return
	}
	if err := s.tmplDeviceSocketAssets.Execute(w, struct{ CSRF string }{CSRF: s.csrfToken}); err != nil {
		http.Error(w, "设备 Socket 资产页面渲染失败", http.StatusInternalServerError)
	}
}

func (s *Server) handleDeviceSocketAssetSnapshots(w http.ResponseWriter, r *http.Request) {
	result, err := s.invokeDeviceSocketAsset(r, []string{"list"})
	writeDeviceSocketAssetResult(w, result, err)
}

func (s *Server) handleDeviceSocketAssetScan(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	consent, err := sourceLocatorBool(fields, "consent", false)
	if err != nil || !consent {
		if err == nil {
			err = errors.New("开始设备资产侦查前必须明确确认设备只读命令授权")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	serial, err := sourceLocatorString(fields, "device_serial", 128)
	if err != nil || (serial != "" && !exposureSurfaceSerialRe.MatchString(serial)) {
		if err == nil {
			err = errors.New("device_serial 不是安全标识")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	taskGoal, err := sourceLocatorString(fields, "task_goal", 4096)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	llmConfig, err := sourceLocatorLLMConfig(fields)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	ragMode, err := sourceLocatorString(fields, "rag_mode", 16)
	if err != nil || (ragMode != "" && ragMode != "local" && ragMode != "off") {
		if err == nil {
			err = errors.New("rag_mode 只能是 local 或 off")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if ragMode == "" {
		ragMode = "local"
	}
	asyncRequested := r.URL.Query().Get("async") == "1" || strings.EqualFold(r.URL.Query().Get("async"), "true")
	if _, hasAsync := fields["async"]; hasAsync {
		asyncRequested, err = sourceLocatorBool(fields, "async", asyncRequested)
		if err != nil {
			sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
			return
		}
	}
	maxRounds, err := sourceLocatorInt(fields, "max_rounds", 1, 32)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	maxCommands, err := sourceLocatorInt(fields, "max_commands", 1, 128)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	maxWall, err := sourceLocatorInt(fields, "max_wall_seconds", 1, 30*60)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	timeout, err := sourceLocatorInt(fields, "command_timeout_seconds", 1, 300)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	runID, err := newDeviceSocketAssetRunID()
	if err != nil {
		sourceLocatorJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"生成设备资产 run_id 失败"}})
		return
	}
	args := []string{"scan", "--run-id", runID, "--rag-mode", ragMode, "--max-rounds", strconv.Itoa(valueOr(maxRounds, 24)), "--max-commands", strconv.Itoa(valueOr(maxCommands, 96)), "--max-wall-seconds", strconv.Itoa(valueOr(maxWall, 20*60)), "--command-timeout-seconds", strconv.Itoa(valueOr(timeout, 30))}
	if serial != "" {
		args = append(args, "--device-serial", serial)
	}
	if llmConfig != "" {
		args = append(args, "--llm-config", llmConfig)
	}
	// The Python provider normalizes an empty value to the backwards-compatible
	// default.  Forward the field explicitly so a custom user objective is
	// preserved in the CLI invocation, checkpoint and audit trail.
	args = append(args, "--task-goal", taskGoal)
	if !asyncRequested {
		result, invokeErr := s.invokeDeviceSocketAsset(r, args)
		writeDeviceSocketAssetResult(w, result, invokeErr)
		return
	}
	// The browser must not hold the POST connection open while the model is
	// thinking or HDC is collecting evidence.  The worker receives a detached
	// context with its own stage deadline; all progress is observed through the
	// run files and SSE endpoint below.
	if _, err := s.deviceSocketAssetRoot(); err != nil {
		sourceLocatorJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), deviceSocketAssetInvokeTimeout)
	s.registerDeviceSocketAssetJob(&deviceSocketAssetJob{RunID: runID, Serial: serial, TaskGoal: taskGoal, Status: "running", StartedAt: time.Now().UTC(), Cancel: cancel})
	go func() {
		defer cancel()
		result, invokeErr := s.invokeDeviceSocketAssetContext(ctx, args, func(line string) {
			s.appendDeviceSocketAssetLog(runID, line)
		})
		if invokeErr != nil {
			s.finishDeviceSocketAssetJob(runID, "error", invokeErr.Error())
			return
		}
		if result == nil {
			s.finishDeviceSocketAssetJob(runID, "error", "设备资产 worker 没有返回结果")
			return
		}
		if result.Envelope.Status == "error" {
			message := strings.Join(result.Envelope.Errors, "; ")
			if message == "" {
				message = "设备资产 worker 返回错误"
			}
			s.finishDeviceSocketAssetJob(runID, "error", message)
			return
		}
		status := "complete"
		if data, ok := result.Envelope.Data.(map[string]any); ok {
			if candidate, ok := data["status"].(string); ok && strings.TrimSpace(candidate) != "" {
				status = strings.ToLower(strings.TrimSpace(candidate))
			}
		}
		s.finishDeviceSocketAssetJob(runID, status, "")
	}()
	sourceLocatorJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data": map[string]any{
			"status":        "running",
			"run_id":        runID,
			"device_serial": serial,
			"task_goal":     taskGoal,
			"events_url":    "/device-socket-assets/runs/" + runID + "/events",
			"status_url":    "/device-socket-assets/runs/" + runID,
			"message":       "Agent 已在后台启动；请通过 events/status 查看实时任务树和证据",
		},
		"errors": []string{},
	})
}

func newDeviceSocketAssetRunID() (string, error) {
	random, err := randomID()
	if err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405000000Z") + "-" + random[:6], nil
}

func (s *Server) handleDeviceSocketAssetRun(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if !deviceSocketAssetRunID(runID) {
		http.NotFound(w, r)
		return
	}
	data, found, err := s.deviceSocketAssetRunData(runID)
	if err != nil {
		if !found && os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		sourceLocatorJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": data, "errors": []string{}})
}

func (s *Server) handleDeviceSocketAssetRuns(w http.ResponseWriter, r *http.Request) {
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		sourceLocatorJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	rows := make([]map[string]any, 0, 64)
	seen := make(map[string]bool)
	if entries, readErr := os.ReadDir(root); readErr == nil {
		for _, entry := range entries {
			if len(rows) >= deviceSocketAssetMaxRuns || !entry.IsDir() {
				break
			}
			device := filepath.Join(root, entry.Name())
			if info, lerr := os.Lstat(device); lerr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				continue
			}
			runs := filepath.Join(device, "runs")
			runEntries, lerr := os.ReadDir(runs)
			if lerr != nil {
				continue
			}
			for _, runEntry := range runEntries {
				if len(rows) >= deviceSocketAssetMaxRuns || !runEntry.IsDir() || !deviceSocketAssetRunID(runEntry.Name()) || seen[runEntry.Name()] {
					continue
				}
				seen[runEntry.Name()] = true
				plan, planErr := readDeviceSocketAssetJSON(root, filepath.Join(runs, runEntry.Name(), "socket_inventory_plan.json"), deviceSocketAssetMaxTraceBytes)
				if planErr != nil && !os.IsNotExist(planErr) {
					continue
				}
				// Plans written by older workers do not carry the live counters.
				// Derive missing values from the same run artifacts so a historical
				// session is not shown as having zero intermediate activity.
				traceCount := plan["trace_count"]
				if traceCount == nil {
					if traceRows, traceReadErr := readDeviceSocketAssetJSONL(root, filepath.Join(runs, runEntry.Name(), "socket_inventory_trace.jsonl"), deviceSocketAssetMaxTraceBytes); traceReadErr == nil {
						traceCount = len(traceRows)
					}
				}
				commandCount := plan["command_count"]
				if commandCount == nil {
					if commandRows, commandReadErr := readDeviceSocketAssetJSONL(root, filepath.Join(runs, runEntry.Name(), "socket_inventory_commands.jsonl"), deviceSocketAssetMaxCommandBytes); commandReadErr == nil {
						commandCount = len(commandRows)
					}
				}
				evidenceCount := plan["evidence_count"]
				if evidenceCount == nil {
					if evidencePayload, evidenceReadErr := readDeviceSocketAssetJSON(root, filepath.Join(runs, runEntry.Name(), "socket_inventory_evidence.json"), deviceSocketAssetMaxEvidenceBytes); evidenceReadErr == nil {
						if evidenceRows, ok := evidencePayload["evidence"].([]any); ok {
							evidenceCount = len(evidenceRows)
						}
					}
				}
				observedEndpointCount := plan["observed_endpoint_count"]
				if observedEndpointCount == nil {
					if endpointRows, ok := plan["observed_endpoints"].([]any); ok {
						observedEndpointCount = len(endpointRows)
					}
				}
				socketRecordCount := plan["socket_record_count"]
				rows = append(rows, map[string]any{
					"run_id":                  runEntry.Name(),
					"device_serial":           plan["device_serial"],
					"task_goal":               plan["task_goal"],
					"task_scope":              plan["task_scope"],
					"status":                  deviceSocketAssetPlanStatus(plan),
					"generated_at":            plan["generated_at"],
					"rounds":                  plan["rounds"],
					"command_count":           commandCount,
					"evidence_count":          evidenceCount,
					"trace_count":             traceCount,
					"observed_endpoint_count": observedEndpointCount,
					"socket_record_count":     socketRecordCount,
				})
			}
		}
	}
	// Include a run that has not yet created its device directory (for example,
	// while HDC/model preflight is still starting).
	s.deviceSocketJobsMu.RLock()
	for id, job := range s.deviceSocketJobs {
		if len(rows) >= deviceSocketAssetMaxRuns || seen[id] || job == nil {
			continue
		}
		seen[id] = true
		rows = append(rows, map[string]any{
			"run_id": id, "device_serial": job.Serial, "status": job.Status,
			"task_goal":  job.TaskGoal,
			"started_at": job.StartedAt, "ended_at": job.EndedAt, "error": job.Error,
		})
	}
	s.deviceSocketJobsMu.RUnlock()
	// Newest runs first; timestamps are ISO strings and therefore sort
	// lexicographically for the provider's UTC format.
	sort.SliceStable(rows, func(i, j int) bool {
		left := fmt.Sprint(rows[i]["generated_at"])
		if left == "<nil>" || left == "" {
			left = fmt.Sprint(rows[i]["started_at"])
		}
		right := fmt.Sprint(rows[j]["generated_at"])
		if right == "<nil>" || right == "" {
			right = fmt.Sprint(rows[j]["started_at"])
		}
		return left > right
	})
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": map[string]any{"runs": rows}, "errors": []string{}})
}

type deviceSocketAssetTraceEvent struct {
	SchemaVersion string         `json:"schema_version"`
	Seq           int            `json:"seq"`
	Event         string         `json:"event"`
	CreatedAt     string         `json:"created_at"`
	Details       map[string]any `json:"details"`
}

func (s *Server) handleDeviceSocketAssetRunEvents(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if !deviceSocketAssetRunID(runID) {
		http.NotFound(w, r)
		return
	}
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	after := 0
	if raw := strings.TrimSpace(r.Header.Get("Last-Event-ID")); raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || parsed < 0 || parsed > int64(^uint(0)>>1) {
			http.Error(w, "invalid Last-Event-ID", http.StatusBadRequest)
			return
		}
		after = int(parsed)
	}
	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = io.WriteString(w, "retry: 1000\n\n")
	if canFlush {
		flusher.Flush()
	}
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		default:
		}
		runDir, _, findErr := findDeviceSocketAssetRun(root, runID)
		if findErr == nil {
			rows, readErr := readDeviceSocketAssetJSONL(root, filepath.Join(runDir, "socket_inventory_trace.jsonl"), deviceSocketAssetMaxTraceBytes)
			if readErr != nil {
				_, _ = fmt.Fprintf(w, "event: error\ndata: %q\n\n", readErr.Error())
				if canFlush {
					flusher.Flush()
				}
				return
			}
			for _, row := range rows {
				seq, ok := row["seq"].(float64)
				if !ok || int(seq) <= after {
					continue
				}
				payload, marshalErr := json.Marshal(row)
				if marshalErr != nil {
					continue
				}
				seqInt := int(seq)
				_, _ = fmt.Fprintf(w, "id: %d\nevent: device-socket\ndata: %s\n\n", seqInt, payload)
				after = seqInt
			}
			if canFlush {
				flusher.Flush()
			}
		}
		data, found, dataErr := s.deviceSocketAssetRunData(runID)
		if dataErr == nil && found {
			state := fmt.Sprint(data["status"])
			if deviceSocketAssetTerminal(state) {
				_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", state)
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

func (s *Server) handleDeviceSocketAssetRunArtifact(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	name := strings.TrimSpace(r.PathValue("name"))
	if !deviceSocketAssetRunID(runID) || !deviceSocketAssetArtifactAllowlist[name] || !deviceSocketAssetNameRe.MatchString(name) || name == "latest.json" {
		http.NotFound(w, r)
		return
	}
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runDir, _, err := findDeviceSocketAssetRun(root, runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, fi, err := openRegularInRoot(root, filepath.Join(runDir, name))
	if err != nil || fi.Size() > deviceSocketAssetMaxCommandBytes {
		if f != nil {
			_ = f.Close()
		}
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	contentType := "application/octet-stream"
	if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".jsonl") {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, io.LimitReader(f, deviceSocketAssetMaxCommandBytes))
}

func valueOr(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func (s *Server) handleDeviceSocketAssetSnapshot(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if serial == "" || !exposureSurfaceSerialRe.MatchString(serial) {
		http.NotFound(w, r)
		return
	}
	result, err := s.invokeDeviceSocketAsset(r, []string{"status", "--device-serial", serial})
	writeDeviceSocketAssetResult(w, result, err)
}

func (s *Server) handleDeviceSocketAssetArtifact(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	name := r.PathValue("name")
	if serial == "" || !exposureSurfaceSerialRe.MatchString(serial) || !deviceSocketAssetArtifactAllowlist[name] || !deviceSocketAssetNameRe.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	root, err := s.deviceSocketAssetRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// DeviceSocketAssetStore hashes the serial to a fixed directory.  Compute
	// the same key here without trusting a path supplied by the browser.
	// Keep this tiny implementation in Go to avoid exposing arbitrary paths.
	// The Python endpoint remains the source of truth for the snapshot itself.
	keyBytes := sha256.Sum256([]byte(serial))
	deviceDir := filepath.Join(root, fmt.Sprintf("%x", keyBytes[:])[:32])
	path := filepath.Join(deviceDir, "latest.json")
	if name != "latest.json" {
		// The latest snapshot records artifact paths; serving run artifacts is
		// intentionally omitted until an explicit run-id API is requested.
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, io.LimitReader(f, 8<<20))
}
