package server

// HTTP boundary for the standalone OpenHarmony device exposure-surface stage.
// The Python side owns target normalization, read-only HDC probing and the
// persisted result schema. Go owns the loopback API, CSRF protection, SSE
// replay and the artifact allowlist.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knostic/open-ant-cli/internal/python"
)

const (
	maxExposureSurfaceArtifactBytes  = 4 << 20
	maxExposureSurfaceEventLineBytes = 64 << 10
	maxExposureSurfaceEventFileBytes = 16 << 20
	exposureSurfaceInvokeTimeout     = 10 * time.Minute
)

var (
	exposureSurfaceSessionIDRe = regexp.MustCompile(`^exp_[A-Za-z0-9_-]{8,64}$`)
	exposureSurfaceSerialRe    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	exposureSurfaceBatchIDRe   = regexp.MustCompile(`^batch_[A-Za-z0-9_-]{8,64}$`)
)

var exposureSurfaceTerminalStates = map[string]bool{
	"DONE": true, "PARTIAL": true, "OFFLINE": true, "NOT_FOUND": true,
	"PERMISSION_DENIED": true, "CANCELLED": true, "FAILED": true,
}

var exposureSurfaceArtifactAllowlist = map[string]bool{
	"exposure_surface.json":        true,
	"exposure_surface.report.json": true,
	"exposure_evidence.json":       true,
	"exposure_llm_extraction.json": true,
	"exposure_agent_plan.json":     true,
	"exposure_agent_trace.jsonl":   true,
	"exposure_agent_evidence.json": true,
	"exposure_commands.jsonl":      true,
	"device_snapshot.json":         true,
	"exposure_surface.md":          true,
	"exposure_start_action.json":   true,
}

func (s *Server) exposureSurfaceRoot() (string, error) {
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
	root := filepath.Join(base, "exposure-surface")
	if info, lstatErr := os.Lstat(root); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("exposure-surface 目录不能是符号链接")
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		return "", fmt.Errorf("创建 exposure-surface 目录失败：%w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("exposure-surface 目录不是安全的普通目录")
	}
	return root, nil
}

func exposureSurfaceSafeSessionPath(root, sessionID string) (string, error) {
	if !exposureSurfaceSessionIDRe.MatchString(sessionID) {
		return "", errors.New("无效的暴露面 session ID")
	}
	path := filepath.Join(root, sessionID)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("session 路径越界")
	}
	if info, lstatErr := os.Lstat(path); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("session 目录不能是符号链接")
	}
	return path, nil
}

func exposureSurfaceExistingSession(root, sessionID string) (string, error) {
	path, err := exposureSurfaceSafeSessionPath(root, sessionID)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("session 目录不是普通目录")
	}
	return path, nil
}

func exposureSurfaceString(fields sourceLocatorRequestFields, key string, max int) (string, error) {
	value, ok := fields[key]
	if !ok || value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s 必须是字符串", key)
	}
	text = strings.TrimSpace(text)
	if len(text) > max {
		return "", fmt.Errorf("%s 超过长度上限 %d", key, max)
	}
	if strings.IndexByte(text, 0) >= 0 {
		return "", fmt.Errorf("%s 包含控制字符", key)
	}
	return text, nil
}

// exposureSurfaceTarget accepts both the legacy single-string target and the
// structured network form used by API clients.  The final value is still
// normalized by Python, so this helper only assembles an unambiguous display
// string; it never creates a shell command.
func exposureSurfaceTarget(fields sourceLocatorRequestFields) (string, error) {
	target, err := exposureSurfaceString(fields, "target", 512)
	if err != nil {
		return "", err
	}
	mode, err := exposureSurfaceString(fields, "target_mode", 16)
	if err != nil {
		return "", err
	}
	if mode == "" || strings.EqualFold(mode, "unix") {
		return target, nil
	}
	mode = strings.ToLower(mode)
	if mode != "tcp" && mode != "udp" {
		return "", errors.New("target_mode 只能是 unix、tcp 或 udp")
	}
	address, err := exposureSurfaceString(fields, "network_address", 128)
	if err != nil {
		return "", err
	}
	if address == "" {
		return "", errors.New("network_address 不能为空")
	}
	port, err := sourceLocatorInt(fields, "network_port", 1, 65535)
	if err != nil {
		return "", err
	}
	if port == 0 {
		return "", errors.New("network_port 不能为空")
	}
	process, err := exposureSurfaceString(fields, "network_process", 128)
	if err != nil {
		return "", err
	}
	endpointAddress := address
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		endpointAddress = "[" + address + "]"
	}
	parts := make([]string, 0, 3)
	if process != "" {
		parts = append(parts, process)
	}
	parts = append(parts, strings.ToUpper(mode), fmt.Sprintf("%s:%d", endpointAddress, port))
	return strings.Join(parts, " "), nil
}

func writeExposureSurfaceResult(w http.ResponseWriter, result *python.InvokeResult, err error) {
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadGateway, map[string]any{
			"status": "error", "data": map[string]any{}, "errors": []string{err.Error()},
		})
		return
	}
	if result == nil {
		sourceLocatorJSON(w, http.StatusBadGateway, map[string]any{
			"status": "error", "data": map[string]any{}, "errors": []string{"暴露面 worker 没有返回结果"},
		})
		return
	}
	status := http.StatusOK
	if result.Envelope.Status == "error" {
		status = http.StatusBadRequest
	}
	sourceLocatorJSON(w, status, result.Envelope)
}

func (s *Server) invokeExposureSurface(r *http.Request, args []string) (*python.InvokeResult, error) {
	root, err := s.exposureSurfaceRoot()
	if err != nil {
		return nil, err
	}
	args = append(args, "--root", root)
	ctx, cancel := context.WithTimeout(r.Context(), exposureSurfaceInvokeTimeout)
	defer cancel()
	return python.InvokeExposureSurface(ctx, s.pythonPath, args, "", nil)
}

func (s *Server) invokeExposureSurfaceMutation(r *http.Request, args []string) (*python.InvokeResult, error) {
	s.exposureSurfaceMu.Lock()
	defer s.exposureSurfaceMu.Unlock()
	return s.invokeExposureSurface(r, args)
}

func (s *Server) ensureExposureSurfaceSession(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	root, err := s.exposureSurfaceRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if _, err := exposureSurfaceExistingSession(root, sessionID); err != nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (s *Server) handleExposureSurfaceIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page embeds the current UI bundle directly. Prevent a browser from
	// retaining an older script after a Web restart or UI upgrade.
	w.Header().Set("Cache-Control", "no-store")
	if s.tmplExposureSurface == nil {
		http.Error(w, "暴露面识别页面未初始化", http.StatusInternalServerError)
		return
	}
	if err := s.tmplExposureSurface.Execute(w, struct{ CSRF string }{CSRF: s.csrfToken}); err != nil {
		http.Error(w, "暴露面识别页面渲染失败", http.StatusInternalServerError)
	}
}

func (s *Server) handleExposureSurfaceSessions(w http.ResponseWriter, r *http.Request) {
	result, err := s.invokeExposureSurface(r, []string{"list"})
	writeExposureSurfaceResult(w, result, err)
}

func (s *Server) handleExposureSurfaceCreate(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	target, err := exposureSurfaceTarget(fields)
	if err != nil || target == "" {
		if err == nil {
			err = errors.New("target 不能为空")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	serial, err := exposureSurfaceString(fields, "device_serial", 128)
	if err != nil || (serial != "" && !exposureSurfaceSerialRe.MatchString(serial)) {
		if err == nil {
			err = errors.New("device_serial 不是安全标识")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	llmAssist, err := sourceLocatorBool(fields, "llm_assist", false)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	executionMode, err := exposureSurfaceString(fields, "mode", 16)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if executionMode == "" {
		executionMode = "fixed"
	}
	if executionMode != "fixed" && executionMode != "agentic" {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"mode 只能是 fixed 或 agentic"}})
		return
	}
	allowModelCommands, err := sourceLocatorBool(fields, "allow_model_commands", false)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	ragMode, err := exposureSurfaceString(fields, "rag_mode", 16)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if ragMode == "" {
		ragMode = "local"
	}
	if ragMode != "off" && ragMode != "local" {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"rag_mode 只能是 off 或 local"}})
		return
	}
	maxRounds, err := sourceLocatorInt(fields, "max_rounds", 1, 20)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	maxCommands, err := sourceLocatorInt(fields, "max_commands", 1, 100)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	sessionID, err := exposureSurfaceString(fields, "session_id", 80)
	if err != nil || (sessionID != "" && !exposureSurfaceSessionIDRe.MatchString(sessionID)) {
		if err == nil {
			err = errors.New("session_id 不是安全标识")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	batchID, err := exposureSurfaceString(fields, "batch_id", 80)
	if err != nil || (batchID != "" && !exposureSurfaceBatchIDRe.MatchString(batchID)) {
		if err == nil {
			err = errors.New("batch_id 不是安全的批次标识")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	batchIndex, err := sourceLocatorInt(fields, "batch_index", 1, 32)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	batchTotal, err := sourceLocatorInt(fields, "batch_total", 1, 32)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if batchID == "" && (batchIndex != 0 || batchTotal != 0) {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"batch_index 和 batch_total 必须与 batch_id 一起提供"}})
		return
	}
	if batchID != "" && (batchIndex == 0 || batchTotal == 0 || batchIndex > batchTotal) {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"批次序号必须满足 1 ≤ batch_index ≤ batch_total ≤ 32"}})
		return
	}
	args := []string{"create", target}
	if serial != "" {
		args = append(args, "--device-serial", serial)
	}
	if llmAssist {
		args = append(args, "--llm-assist")
	}
	if executionMode != "fixed" {
		args = append(args, "--mode", executionMode)
	}
	if allowModelCommands {
		args = append(args, "--allow-model-commands")
	}
	if ragMode != "local" {
		args = append(args, "--rag-mode", ragMode)
	}
	if maxRounds != 0 {
		args = append(args, "--max-rounds", strconv.Itoa(maxRounds))
	}
	if maxCommands != 0 {
		args = append(args, "--max-commands", strconv.Itoa(maxCommands))
	}
	if batchID != "" {
		args = append(args, "--batch-id", batchID, "--batch-index", strconv.Itoa(batchIndex), "--batch-total", strconv.Itoa(batchTotal))
	}
	if sessionID != "" {
		args = append(args, "--session-id", sessionID)
	}
	result, invokeErr := s.invokeExposureSurfaceMutation(r, args)
	writeExposureSurfaceResult(w, result, invokeErr)
}

func (s *Server) handleExposureSurfaceStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.ensureExposureSurfaceSession(w, r, id) {
		return
	}
	result, err := s.invokeExposureSurface(r, []string{"status", id})
	writeExposureSurfaceResult(w, result, err)
}

func (s *Server) handleExposureSurfaceStart(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureExposureSurfaceSession(w, r, id) {
		return
	}
	result, invokeErr := s.invokeExposureSurfaceMutation(r, []string{"start", id})
	writeExposureSurfaceResult(w, result, invokeErr)
}

func (s *Server) handleExposureSurfaceStartService(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureExposureSurfaceSession(w, r, id) {
		return
	}
	optionID, err := exposureSurfaceString(fields, "option_id", 80)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	args := []string{"start-service", id}
	if optionID != "" {
		args = append(args, "--option-id", optionID)
	}
	result, invokeErr := s.invokeExposureSurfaceMutation(r, args)
	writeExposureSurfaceResult(w, result, invokeErr)
}

func (s *Server) handleExposureSurfaceSkipStart(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureExposureSurfaceSession(w, r, id) {
		return
	}
	reason, err := exposureSurfaceString(fields, "reason", 512)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	args := []string{"skip-start", id}
	if reason != "" {
		args = append(args, "--reason", reason)
	}
	result, invokeErr := s.invokeExposureSurfaceMutation(r, args)
	writeExposureSurfaceResult(w, result, invokeErr)
}

func (s *Server) handleExposureSurfaceCancel(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureExposureSurfaceSession(w, r, id) {
		return
	}
	reason, err := exposureSurfaceString(fields, "reason", 512)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	args := []string{"cancel", id}
	if reason != "" {
		args = append(args, "--reason", reason)
	}
	result, invokeErr := s.invokeExposureSurfaceMutation(r, args)
	writeExposureSurfaceResult(w, result, invokeErr)
}

func (s *Server) handleExposureSurfaceDelete(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !exposureSurfaceSessionIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	if !s.ensureExposureSurfaceSession(w, r, id) {
		return
	}
	result, invokeErr := s.invokeExposureSurfaceMutation(r, []string{"delete", id})
	writeExposureSurfaceResult(w, result, invokeErr)
}

func readExposureSurfaceState(root, sessionID string) string {
	path, err := exposureSurfaceSafeSessionPath(root, sessionID)
	if err != nil {
		return ""
	}
	f, _, err := openRegularInRoot(root, filepath.Join(path, "session.json"))
	if err != nil {
		return ""
	}
	defer f.Close()
	var payload struct {
		State string `json:"state"`
	}
	if json.NewDecoder(io.LimitReader(f, maxExposureSurfaceArtifactBytes)).Decode(&payload) != nil {
		return ""
	}
	return payload.State
}

type exposureSurfaceEvent struct {
	SchemaVersion string         `json:"schema_version"`
	Seq           int            `json:"seq"`
	SessionID     string         `json:"session_id"`
	Type          string         `json:"type"`
	State         string         `json:"state"`
	SummaryZH     string         `json:"summary_zh"`
	Artifact      string         `json:"artifact"`
	EvidenceIDs   []string       `json:"evidence_ids"`
	Details       map[string]any `json:"details"`
	CreatedAt     string         `json:"created_at"`
}

func (e exposureSurfaceEvent) validFor(sessionID string, expected int) bool {
	return e.SchemaVersion == "openant.exposure-surface.event.v1" && e.Seq == expected &&
		e.SessionID == sessionID && e.Type != "" && e.State != "" && e.SummaryZH != "" && e.CreatedAt != ""
}

func readExposureSurfaceEvents(root, sessionID string, after int) ([]exposureSurfaceEvent, int, error) {
	if after < 0 || !exposureSurfaceSessionIDRe.MatchString(sessionID) {
		return nil, after, errors.New("事件参数无效")
	}
	path, err := exposureSurfaceSafeSessionPath(root, sessionID)
	if err != nil {
		return nil, after, err
	}
	f, fi, err := openRegularInRoot(root, filepath.Join(path, "events.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, after, nil
		}
		return nil, after, err
	}
	defer f.Close()
	if fi.Size() > maxExposureSurfaceEventFileBytes {
		return nil, after, errors.New("事件文件超过大小上限")
	}
	reader := bufio.NewReader(io.LimitReader(f, maxExposureSurfaceEventFileBytes))
	events := []exposureSurfaceEvent{}
	last := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > maxExposureSurfaceEventLineBytes {
			return nil, last, errors.New("单条事件超过大小上限")
		}
		raw := strings.TrimSpace(string(line))
		if raw == "" {
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, last, readErr
			}
			continue
		}
		var event exposureSurfaceEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			if readErr == io.EOF {
				break
			}
			return nil, last, errors.New("事件记录不是有效 JSON")
		}
		if !event.validFor(sessionID, last+1) {
			return nil, last, errors.New("事件记录序号、session 或 schema 无效")
		}
		last = event.Seq
		if event.Seq > after {
			events = append(events, event)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, last, readErr
		}
	}
	return events, last, nil
}

func formatExposureSurfaceSSEEvent(event exposureSurfaceEvent) string {
	payload, err := json.Marshal(event)
	if err != nil {
		return ""
	}
	return "id: " + strconv.Itoa(event.Seq) + "\nevent: exposure\ndata: " + string(payload) + "\n\n"
}

func (s *Server) handleExposureSurfaceEventSnapshot(w http.ResponseWriter, r *http.Request) {
	root, err := s.exposureSurfaceRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if _, err := exposureSurfaceExistingSession(root, id); err != nil {
		http.NotFound(w, r)
		return
	}
	events, last, err := readExposureSurfaceEvents(root, id, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": map[string]any{"events": events, "last_seq": last}, "errors": []string{}})
}

func (s *Server) handleExposureSurfaceEvents(w http.ResponseWriter, r *http.Request) {
	root, err := s.exposureSurfaceRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if _, err := exposureSurfaceExistingSession(root, id); err != nil {
		http.NotFound(w, r)
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
	initial, last, err := readExposureSurfaceEvents(root, id, after)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	flusher, canFlush := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = io.WriteString(w, "retry: 1000\n\n")
	for _, event := range initial {
		_, _ = io.WriteString(w, formatExposureSurfaceSSEEvent(event))
	}
	if canFlush {
		flusher.Flush()
	}
	if exposureSurfaceTerminalStates[readExposureSurfaceState(root, id)] {
		_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", readExposureSurfaceState(root, id))
		if canFlush {
			flusher.Flush()
		}
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
		events, current, readErr := readExposureSurfaceEvents(root, id, last)
		if readErr != nil {
			_, _ = fmt.Fprintf(w, "event: error\ndata: %q\n\n", readErr.Error())
			if canFlush {
				flusher.Flush()
			}
			return
		}
		for _, event := range events {
			_, _ = io.WriteString(w, formatExposureSurfaceSSEEvent(event))
		}
		last = current
		if len(events) > 0 && canFlush {
			flusher.Flush()
		}
		state := readExposureSurfaceState(root, id)
		if exposureSurfaceTerminalStates[state] {
			_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", state)
			if canFlush {
				flusher.Flush()
			}
			return
		}
	}
}

func (s *Server) handleExposureSurfaceArtifact(w http.ResponseWriter, r *http.Request) {
	root, err := s.exposureSurfaceRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionDir, err := exposureSurfaceExistingSession(root, r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if !exposureSurfaceArtifactAllowlist[name] || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	sessionFile, _, openErr := openRegularInRoot(root, filepath.Join(sessionDir, "session.json"))
	if openErr != nil {
		http.NotFound(w, r)
		return
	}
	var session struct {
		Artifacts map[string]string `json:"artifacts"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(sessionFile, maxExposureSurfaceArtifactBytes)).Decode(&session)
	_ = sessionFile.Close()
	if decodeErr != nil || session.Artifacts == nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := session.Artifacts[name]; !ok {
		http.NotFound(w, r)
		return
	}
	f, fi, openErr := openRegularInRoot(root, filepath.Join(sessionDir, name))
	if openErr != nil || fi.Size() > maxExposureSurfaceArtifactBytes {
		if f != nil {
			_ = f.Close()
		}
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".jsonl") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	}
	http.ServeContent(w, r, name, fi.ModTime(), f)
}
