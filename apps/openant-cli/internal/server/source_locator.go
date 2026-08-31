package server

// HTTP boundary for the OpenHarmony source locator.  The Go server owns the
// loopback/CSRF/SSE protocol and invokes one fixed Python source-locator
// operation at a time; OpenGrok, Manifest and Git policy remain in Python.

import (
	"bytes"
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
	maxSourceLocatorRequestBytes  = 128 << 10
	maxSourceLocatorArtifactBytes = 4 << 20
	// A single source-locator stage may perform a bounded remote search or a
	// confirmed Git fetch.  The browser receives progress through SSE, so keep
	// the request alive long enough for those operations instead of imposing the
	// 30-second scan timeout used by small metadata calls.
	sourceLocatorInvokeTimeout = 10 * time.Minute
)

var sourceLocatorSessionIDRe = regexp.MustCompile(`^loc_[A-Za-z0-9_-]{8,64}$`)
var sourceLocatorLLMConfigRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var sourceLocatorRevisionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@+~-]{0,127}$`)

var sourceLocatorTerminalStates = map[string]bool{
	"DONE": true, "PARTIAL": true, "NEEDS_REVIEW": true,
	"OPENGROK_UNAVAILABLE": true, "VERSION_MISMATCH": true,
	"CLONE_FAILED": true, "POST_CLONE_VERIFY_FAILED": true,
	"CANCELLED": true, "FAILED": true,
}

type sourceLocatorRequestFields map[string]any

func (s *Server) sourceLocatorRoot() (string, error) {
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
	root := filepath.Join(base, "source-locator")
	if info, lstatErr := os.Lstat(root); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source-locator 目录不能是符号链接")
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		return "", fmt.Errorf("创建 source-locator 目录失败：%w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source-locator 目录不是安全的普通目录")
	}
	return root, nil
}

func sourceLocatorSafeSessionPath(root, sessionID string) (string, error) {
	if !sourceLocatorSessionIDRe.MatchString(sessionID) {
		return "", errors.New("无效的 source-locator session ID")
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

func sourceLocatorExistingSession(root, sessionID string) (string, error) {
	path, err := sourceLocatorSafeSessionPath(root, sessionID)
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

func readSourceLocatorFields(r *http.Request) (sourceLocatorRequestFields, error) {
	fields := sourceLocatorRequestFields{}
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if contentType == "application/json" || contentType == "" {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxSourceLocatorRequestBytes+1))
		if err != nil {
			return nil, fmt.Errorf("读取请求失败：%w", err)
		}
		if len(body) > maxSourceLocatorRequestBytes {
			return nil, errors.New("请求体超过大小上限")
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return fields, nil
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&fields); err != nil {
			return nil, fmt.Errorf("请求 JSON 无效：%w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, errors.New("请求必须只包含一个 JSON 对象")
		}
		return fields, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("解析表单失败：%w", err)
	}
	for key, values := range r.Form {
		if len(values) > 0 {
			fields[key] = values[0]
		}
	}
	return fields, nil
}

func sourceLocatorString(fields sourceLocatorRequestFields, key string, max int) (string, error) {
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
	return text, nil
}

// sourceLocatorInt accepts both a form-encoded string and a JSON number.  The
// browser currently sends a string, but accepting a bounded JSON integer keeps
// the API contract unsurprising for CLI/API clients without converting
// floating-point values or silently truncating malformed input.
func sourceLocatorInt(fields sourceLocatorRequestFields, key string, min, max int) (int, error) {
	value, ok := fields[key]
	if !ok || value == nil {
		return 0, nil
	}
	var raw string
	switch typed := value.(type) {
	case string:
		raw = strings.TrimSpace(typed)
	case json.Number:
		raw = string(typed)
	default:
		return 0, fmt.Errorf("%s 必须是整数", key)
	}
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s 必须是 %d 到 %d 的整数", key, min, max)
	}
	return parsed, nil
}

// sourceLocatorBool accepts a JSON boolean as well as the string form used by
// form clients.  It deliberately rejects numbers and arbitrary truthy values
// so the LLM switch cannot be enabled accidentally by malformed input.
func sourceLocatorBool(fields sourceLocatorRequestFields, key string, defaultValue bool) (bool, error) {
	value, ok := fields[key]
	if !ok || value == nil {
		return defaultValue, nil
	}
	switch typed := value.(type) {
	case bool:
		return typed, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "on":
			return true, nil
		case "false", "0", "no", "off":
			return false, nil
		default:
			return false, fmt.Errorf("%s 必须是布尔值", key)
		}
	default:
		return false, fmt.Errorf("%s 必须是布尔值", key)
	}
}

func sourceLocatorLLMConfig(fields sourceLocatorRequestFields) (string, error) {
	value, err := sourceLocatorString(fields, "llm_config", 128)
	if err != nil {
		return "", err
	}
	if value != "" && !sourceLocatorLLMConfigRe.MatchString(value) {
		return "", errors.New("llm_config 只能包含字母、数字、点、下划线和连字符")
	}
	return value, nil
}

func sourceLocatorRevision(fields sourceLocatorRequestFields) (string, error) {
	value, err := sourceLocatorString(fields, "revision", 128)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("revision 不能为空")
	}
	if !sourceLocatorRevisionRe.MatchString(value) || value == "unknown" || strings.Contains(value, "..") || strings.Contains(value, "//") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, ".lock") {
		return "", errors.New("revision 不是安全的远程版本标识")
	}
	return value, nil
}

func (s *Server) sourceLocatorMutationAllowed(w http.ResponseWriter, r *http.Request, fields sourceLocatorRequestFields) bool {
	if !sameOriginOK(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if token == "" {
		if value, ok := fields["csrf"].(string); ok {
			token = strings.TrimSpace(value)
		}
	}
	if subtleConstantTimeCompare(token, s.csrfToken) != 1 {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// Kept local to this file to make all source-locator mutations visibly use a
// constant-time comparison without duplicating byte conversion at call sites.
func subtleConstantTimeCompare(left, right string) int {
	if len(left) != len(right) {
		return 0
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	if diff == 0 {
		return 1
	}
	return 0
}

func sourceLocatorJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeSourceLocatorResult(w http.ResponseWriter, result *python.InvokeResult, err error) {
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadGateway, map[string]any{
			"status": "error", "data": map[string]any{}, "errors": []string{err.Error()},
		})
		return
	}
	status := http.StatusOK
	if result == nil || result.Envelope.Status == "error" {
		status = http.StatusBadRequest
	}
	if result == nil {
		sourceLocatorJSON(w, http.StatusBadGateway, map[string]any{
			"status": "error", "data": map[string]any{}, "errors": []string{"定位 worker 没有返回结果"},
		})
		return
	}
	sourceLocatorJSON(w, status, result.Envelope)
}

func (s *Server) invokeSourceLocator(r *http.Request, args []string) (*python.InvokeResult, error) {
	root, err := s.sourceLocatorRoot()
	if err != nil {
		return nil, err
	}
	args = append(args, "--root", root)
	ctx, cancel := context.WithTimeout(r.Context(), sourceLocatorInvokeTimeout)
	defer cancel()
	return python.InvokeSourceLocator(ctx, s.pythonPath, args, "", nil)
}

// invokeSourceLocatorMutation serializes all Web-side session mutations.  A
// delete must not race an advance/reject/cancel request whose Python process
// may still be writing session.json or an artifact.
func (s *Server) invokeSourceLocatorMutation(r *http.Request, args []string) (*python.InvokeResult, error) {
	s.sourceLocatorMu.Lock()
	defer s.sourceLocatorMu.Unlock()
	return s.invokeSourceLocator(r, args)
}

func (s *Server) ensureSourceLocatorSession(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	root, err := s.sourceLocatorRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if _, err := sourceLocatorExistingSession(root, sessionID); err != nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (s *Server) handleSourceLocatorIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s.tmplSourceLocator == nil {
		http.Error(w, "源码定位页面未初始化", http.StatusInternalServerError)
		return
	}
	if err := s.tmplSourceLocator.Execute(w, struct{ CSRF string }{CSRF: s.csrfToken}); err != nil {
		// The response may already have begun, so keep the error text generic and
		// avoid leaking template internals to a browser.
		http.Error(w, "源码定位页面渲染失败", http.StatusInternalServerError)
	}
}

func (s *Server) handleSourceLocatorSessions(w http.ResponseWriter, r *http.Request) {
	result, err := s.invokeSourceLocator(r, []string{"list"})
	writeSourceLocatorResult(w, result, err)
}

func (s *Server) handleSourceLocatorCreate(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	target, err := sourceLocatorString(fields, "target", 4096)
	if err != nil || target == "" {
		if err == nil {
			err = errors.New("target 不能为空")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	args := []string{"create", target}
	for _, key := range []string{"target_revision", "session_id"} {
		value, stringErr := sourceLocatorString(fields, key, 256)
		if stringErr != nil {
			sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{stringErr.Error()}})
			return
		}
		if value != "" {
			args = append(args, "--"+strings.ReplaceAll(key, "_", "-"), value)
		}
	}
	if budget, ok := fields["budget"]; ok && budget != nil {
		encoded, marshalErr := json.Marshal(budget)
		if marshalErr != nil {
			sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"budget 必须是 JSON 对象"}})
			return
		}
		args = append(args, "--budget-json", string(encoded))
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, args)
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	root, rootErr := s.sourceLocatorRoot()
	if rootErr != nil {
		http.Error(w, rootErr.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := sourceLocatorExistingSession(root, id); err != nil {
		http.NotFound(w, r)
		return
	}
	result, err := s.invokeSourceLocator(r, []string{"status", id})
	writeSourceLocatorResult(w, result, err)
}

// handleSourceLocatorHandoff exposes only the verified, DONE-session handoff.
// Static scan options are deliberately not inferred here; the caller may use
// primary_analysis_repo to prefill the normal scan form and choose its own
// language/platform/LLM settings.
func (s *Server) handleSourceLocatorHandoff(w http.ResponseWriter, r *http.Request) {
	root, rootErr := s.sourceLocatorRoot()
	if rootErr != nil {
		http.Error(w, rootErr.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if _, err := sourceLocatorExistingSession(root, id); err != nil {
		http.NotFound(w, r)
		return
	}
	result, err := s.invokeSourceLocator(r, []string{"handoff", id})
	writeSourceLocatorResult(w, result, err)
}

// handleSourceLocatorEventSnapshot returns a finite JSON event history for
// page refreshes.  The sibling /events endpoint is deliberately a long-lived
// SSE stream; using it as a fetch() JSON source leaves a browser request open
// forever whenever the session is still non-terminal.
func (s *Server) handleSourceLocatorEventSnapshot(w http.ResponseWriter, r *http.Request) {
	root, rootErr := s.sourceLocatorRoot()
	if rootErr != nil {
		http.Error(w, rootErr.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if _, err := sourceLocatorExistingSession(root, id); err != nil {
		http.NotFound(w, r)
		return
	}
	events, last, err := readSourceLocatorEvents(root, id, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data": map[string]any{
			"events":   events,
			"last_seq": last,
		},
		"errors": []string{},
	})
}

func (s *Server) handleSourceLocatorEvents(w http.ResponseWriter, r *http.Request) {
	root, err := s.sourceLocatorRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := sourceLocatorExistingSession(root, r.PathValue("id")); err != nil {
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
	initial, last, err := readSourceLocatorEvents(root, r.PathValue("id"), after)
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
		_, _ = io.WriteString(w, formatSourceLocatorSSEEvent(event))
	}
	if canFlush {
		flusher.Flush()
	}
	if state := readSourceLocatorState(root, r.PathValue("id")); sourceLocatorTerminalStates[state] {
		_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", state)
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
		events, current, readErr := readSourceLocatorEvents(root, r.PathValue("id"), last)
		if readErr != nil {
			_, _ = fmt.Fprintf(w, "event: error\ndata: %q\n\n", readErr.Error())
			if canFlush {
				flusher.Flush()
			}
			return
		}
		for _, event := range events {
			_, _ = io.WriteString(w, formatSourceLocatorSSEEvent(event))
		}
		last = current
		if len(events) > 0 && canFlush {
			flusher.Flush()
		}
		if state := readSourceLocatorState(root, r.PathValue("id")); sourceLocatorTerminalStates[state] {
			_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", state)
			if canFlush {
				flusher.Flush()
			}
			return
		}
	}
}

func readSourceLocatorState(root, sessionID string) string {
	sessionDir, err := sourceLocatorSafeSessionPath(root, sessionID)
	if err != nil {
		return ""
	}
	path := filepath.Join(sessionDir, "session.json")
	f, _, err := openRegularInRoot(root, path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var payload struct {
		State string `json:"state"`
	}
	if json.NewDecoder(io.LimitReader(f, maxSourceLocatorArtifactBytes)).Decode(&payload) != nil {
		return ""
	}
	return payload.State
}

func (s *Server) handleSourceLocatorMessage(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureSourceLocatorSession(w, r, id) {
		return
	}
	message, err := sourceLocatorString(fields, "message", 4096)
	if err != nil || message == "" {
		if err == nil {
			err = errors.New("message 不能为空")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, []string{"message", id, "--message", message})
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorAdvance(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureSourceLocatorSession(w, r, id) {
		return
	}
	maxSteps := 1
	if parsed, parseErr := sourceLocatorInt(fields, "max_steps", 1, 32); parseErr != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{parseErr.Error()}})
		return
	} else if parsed != 0 {
		maxSteps = parsed
	}
	llmSearch, boolErr := sourceLocatorBool(fields, "llm_search", false)
	if boolErr != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{boolErr.Error()}})
		return
	}
	llmConfig, configErr := sourceLocatorLLMConfig(fields)
	if configErr != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{configErr.Error()}})
		return
	}
	args := []string{"advance", id, "--max-steps", strconv.Itoa(maxSteps)}
	if llmSearch {
		args = append(args, "--llm-search")
		if llmConfig != "" {
			args = append(args, "--llm-config", llmConfig)
		}
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, args)
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorApprove(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	if !s.ensureSourceLocatorSession(w, r, r.PathValue("id")) {
		return
	}
	args := []string{"confirm", r.PathValue("id")}
	if value, stringErr := sourceLocatorString(fields, "confirmation_id", 256); stringErr != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{stringErr.Error()}})
		return
	} else if value != "" {
		args = append(args, "--confirmation-id", value)
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, args)
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorSelectVersion(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !s.ensureSourceLocatorSession(w, r, id) {
		return
	}
	revision, err := sourceLocatorRevision(fields)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	args := []string{"select-version", id, "--revision", revision}
	if value, stringErr := sourceLocatorString(fields, "confirmation_id", 256); stringErr != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{stringErr.Error()}})
		return
	} else if value != "" {
		args = append(args, "--confirmation-id", value)
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, args)
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorReject(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	if !s.ensureSourceLocatorSession(w, r, r.PathValue("id")) {
		return
	}
	reason, err := sourceLocatorString(fields, "reason", 1024)
	if err != nil || reason == "" {
		if err == nil {
			err = errors.New("reason 不能为空")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	args := []string{"reject", r.PathValue("id"), "--reason", reason}
	for _, key := range []string{"exclude_path", "exclude_repo", "required_role"} {
		if value, stringErr := sourceLocatorString(fields, key, 2048); stringErr != nil {
			sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{stringErr.Error()}})
			return
		} else if value != "" {
			args = append(args, "--"+strings.ReplaceAll(key, "_", "-"), value)
		}
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, args)
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorCancel(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	if !s.ensureSourceLocatorSession(w, r, r.PathValue("id")) {
		return
	}
	reason, stringErr := sourceLocatorString(fields, "reason", 512)
	if stringErr != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{stringErr.Error()}})
		return
	}
	args := []string{"cancel", r.PathValue("id")}
	if reason != "" {
		args = append(args, "--reason", reason)
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, args)
	writeSourceLocatorResult(w, result, invokeErr)
}

// handleSourceLocatorDelete removes exactly one locator session directory.
// The Python store validates the ID and deletion boundary again; this HTTP
// check keeps malformed or missing sessions from reaching the subprocess.
func (s *Server) handleSourceLocatorDelete(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.sourceLocatorMutationAllowed(w, r, fields) {
		return
	}
	id := r.PathValue("id")
	if !sourceLocatorSessionIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	if !s.ensureSourceLocatorSession(w, r, id) {
		return
	}
	result, invokeErr := s.invokeSourceLocatorMutation(r, []string{"delete", id})
	writeSourceLocatorResult(w, result, invokeErr)
}

func (s *Server) handleSourceLocatorArtifact(w http.ResponseWriter, r *http.Request) {
	root, err := s.sourceLocatorRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	sessionDir, err := sourceLocatorExistingSession(root, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	// Only artifacts explicitly declared in session.json may be served.
	sessionFile, _, openErr := openRegularInRoot(root, filepath.Join(sessionDir, "session.json"))
	if openErr != nil {
		http.NotFound(w, r)
		return
	}
	var session struct {
		Artifacts map[string]string `json:"artifacts"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(sessionFile, maxSourceLocatorArtifactBytes)).Decode(&session)
	_ = sessionFile.Close()
	if decodeErr != nil {
		http.NotFound(w, r)
		return
	}
	if _, ok := session.Artifacts[name]; !ok {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(sessionDir, filepath.FromSlash(name))
	f, fi, openErr := openRegularInRoot(root, path)
	if openErr != nil || fi.Size() > maxSourceLocatorArtifactBytes {
		if f != nil {
			_ = f.Close()
		}
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if strings.HasSuffix(strings.ToLower(name), ".json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	http.ServeContent(w, r, filepath.Base(name), fi.ModTime(), f)
}
