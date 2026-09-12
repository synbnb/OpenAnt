package server

// HTTP bridge for agentic socket-guided scan scope discovery.  The
// Python core owns normalization and source evidence; this layer only applies
// loopback/CSRF/body limits and persists the user-confirmed manifest.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knostic/open-ant-cli/internal/python"
)

const socketScopeInvokeTimeout = 10 * time.Minute

type socketScopePageData struct {
	CSRF string
}

func (s *Server) socketScopeRoot() (string, error) {
	base, err := filepath.Abs(s.outDir)
	if err != nil || strings.TrimSpace(base) == "" {
		return "", errors.New("Web 输出目录不可用")
	}
	if err := os.MkdirAll(base, 0750); err != nil {
		return "", fmt.Errorf("创建 Web 输出目录失败：%w", err)
	}
	root := filepath.Join(base, "socket-scope")
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("socket-scope 目录不能是符号链接")
	}
	if err := os.MkdirAll(root, 0750); err != nil {
		return "", fmt.Errorf("创建 socket-scope 目录失败：%w", err)
	}
	return root, nil
}

func socketScopeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleSocketScopeIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmplSocketScope.Execute(w, socketScopePageData{CSRF: s.csrfToken}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) socketScopeMutationOK(w http.ResponseWriter, r *http.Request) bool {
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

func (s *Server) invokeSocketScope(ctx context.Context, args []string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, socketScopeInvokeTimeout)
	defer cancel()
	stdout, exitCode, err := python.InvokeCtxCapture(ctx, s.pythonPath, args, "", "", nil)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("socket scope worker exited with code %d", exitCode)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload); err != nil {
		return nil, fmt.Errorf("decode socket scope JSON: %w", err)
	}
	if status, _ := payload["status"].(string); status == "error" {
		return nil, fmt.Errorf("socket scope discovery failed: %v", payload["errors"])
	}
	return payload, nil
}

func (s *Server) handleSocketScopeDiscover(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if !s.socketScopeMutationOK(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	repo := strings.TrimSpace(r.FormValue("repo"))
	target := strings.TrimSpace(r.FormValue("target"))
	if repo == "" || target == "" || len(repo) > 4096 || len(target) > 1024 {
		http.Error(w, "repo and target are required", http.StatusBadRequest)
		return
	}
	root, err := s.socketScopeRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id, err := randomID()
	if err != nil {
		http.Error(w, "failed to generate scope ID", http.StatusInternalServerError)
		return
	}
	dir := filepath.Join(root, "scope_"+id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		http.Error(w, "failed to create scope directory", http.StatusInternalServerError)
		return
	}
	manifest := filepath.Join(dir, "scan_scope.json")
	args := []string{
		"socket-scope", "discover", "--repo", repo, "--target", target, "--output", manifest,
	}
	// Socket scope discovery is always an agentic LLM exploration.  The model
	// itself proposes and orders service-directory candidates; this bridge does
	// not run a deterministic ranking pass.
	if configName := strings.TrimSpace(r.FormValue("llm_config")); configName != "" && len(configName) <= 256 {
		args = append(args, "--llm-config", configName)
	}
	payload, err := s.invokeSocketScope(r.Context(), args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Return the manifest path explicitly so the confirmation request cannot
	// substitute a path outside the server-owned scope directory.
	payload["manifest_path"] = manifest
	socketScopeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleSocketScopeSelect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if !s.socketScopeMutationOK(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	manifest := strings.TrimSpace(r.FormValue("manifest"))
	candidateID := strings.TrimSpace(r.FormValue("candidate_id"))
	root, err := s.socketScopeRoot()
	if err != nil || manifest == "" || candidateID == "" {
		http.Error(w, "manifest and candidate_id are required", http.StatusBadRequest)
		return
	}
	manifestAbs, err := filepath.Abs(manifest)
	if err != nil {
		http.Error(w, "invalid manifest", http.StatusBadRequest)
		return
	}
	if !isRegularNoSymlink(root, manifestAbs) {
		http.Error(w, "manifest must be a regular file inside socket-scope output", http.StatusBadRequest)
		return
	}
	if rel, err := filepath.Rel(root, manifestAbs); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "manifest is outside socket-scope output", http.StatusBadRequest)
		return
	}
	payload, err := s.invokeSocketScope(r.Context(), []string{
		"socket-scope", "select", manifestAbs, "--candidate-id", candidateID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	payload["manifest_path"] = manifestAbs
	socketScopeJSON(w, http.StatusOK, payload)
}
