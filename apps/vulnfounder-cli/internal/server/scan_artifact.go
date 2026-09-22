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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	scanArtifactMaxHistory       = 256
)

// scanArtifactRunArtifactSpecs is deliberately an allowlist rather than a
// directory browser.  A dynamic-test run may contain generated HAPs, signing
// material and temporary build files; the Web UI only needs the small,
// human-auditable snapshots below.  Returning unavailable entries as well as
// available ones lets the page explain what is still being produced instead of
// showing an empty panel while the worker is running.
var scanArtifactRunArtifactSpecs = map[string]struct {
	label       string
	description string
	kind        string
	maxBytes    int64
}{
	"bridge.json":          {"输入桥接快照", "扫描条目如何转换为动态测试输入。", "json", 4 << 20},
	"finding_adapter.json": {"漏洞适配结果", "漏洞类型、危险操作点和入口线索的适配结果。", "json", 8 << 20},
	"entry_discovery.json": {"入口发现结果", "协议匹配前 Agent Loop 找到的设备入口与待补证据。", "json", 8 << 20},
	"device_fingerprint.json": {"设备前置确认", "本轮只读采集的设备版本、服务端点、进程身份与环境结论。", "json", 32 << 20},
	"protocol_evidence.json": {"协议源码证据", "当前路由源码中提取的接收、端点、分帧、分派和校验线索。", "json", 16 << 20},
	"compile_summary.json": {"契约编译摘要", "侦查、校验和编译状态的中间摘要。", "json", 16 << 20},
	"contract.json":        {"设备测试契约", "最终交给 HAP 载荷和设备执行器的结构化契约。", "json", 16 << 20},
	"verdict.json":         {"判定快照", "可达性、影响力和效果观察的阶段性判定。", "json", 16 << 20},
	"run_record.json":      {"设备验证记录", "设备命令、预言机和效果证据的完整记录。", "json", 32 << 20},
	"progress.jsonl":       {"阶段事件日志", "入口发现、侦查、阶段状态和交付物事件。", "jsonl", 16 << 20},
	"ledger.jsonl":         {"设备命令账本", "按时间排序的 HDC 命令、返回码和输出摘要。", "jsonl", 64 << 20},
	"hdc_commands.json":    {"HDC 命令快照", "运行器保存的设备命令结构化快照；如不存在则以 ledger.jsonl 为准。", "json", 16 << 20},
	"result.json":          {"最终运行结果", "动态测试最终结果及全部可追溯字段。", "json", 32 << 20},
	"cli.log":              {"动态测试 CLI 原始日志", "入口发现、契约编译和设备验证 worker 的原始 JSON/文本输出；用于复核命令与决策来源。", "text", 32 << 20},
}

// Manual replay files have a timestamp in their name.  They are explicitly
// allowlisted by prefix and filename shape; arbitrary files in a run directory
// must never become browser-readable.
var scanArtifactManualReplayRe = regexp.MustCompile(`^manual_replay_[0-9]{8,20}\.(md|txt)$`)

func scanArtifactRunArtifactSpec(name string) (struct {
	label       string
	description string
	kind        string
	maxBytes    int64
}, bool) {
	if spec, ok := scanArtifactRunArtifactSpecs[name]; ok {
		return spec, true
	}
	if scanArtifactManualReplayRe.MatchString(name) {
		return struct {
			label       string
			description string
			kind        string
			maxBytes    int64
		}{"手工复核记录", "人工复核时使用的安装、触发、设备观测和结论记录。", "text", 8 << 20}, true
	}
	return struct {
		label       string
		description string
		kind        string
		maxBytes    int64
	}{}, false
}

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
	// 动态测试结果页包含随运行变化的交付物清单。禁止浏览器复用旧 HTML，
	// 否则新生成的 PoC 入口可能仍加载旧版脚本。
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmplScanArtifact.Execute(w, scanArtifactPageData{CSRF: s.csrfToken}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleScanArtifactHistoryIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmplScanArtifactHistory.Execute(w, scanArtifactPageData{CSRF: s.csrfToken}); err != nil {
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
	"poc.hap":                  true,
	"exp.hap":                  true,
	"contract_poc.json":        true,
	"contract_exp.json":        true,
	"evidence_exp.json":        true,
	"README.md":                true,
	"poc_source_Index.ets":     true,
	"exp_source_Index.ets":     true,
	"poc_source.zip":           true,
	"exp_source.zip":           true,
	"poc_source_manifest.json": true,
	"exp_source_manifest.json": true,
}

const (
	scanArtifactSourceMaxFiles = 512
	scanArtifactSourceMaxBytes = 16 << 20
)

var scanArtifactSourceKindRe = regexp.MustCompile(`^(poc|exp)$`)

func scanArtifactSourceRoot(runDir, kind string) string {
	return filepath.Join(runDir, "deliverables", kind+"_source")
}

func scanArtifactSourcePath(raw string) (string, error) {
	pathValue := strings.TrimSpace(raw)
	if decoded, err := url.PathUnescape(pathValue); err == nil {
		pathValue = decoded
	}
	pathValue = strings.ReplaceAll(pathValue, "\\", "/")
	if pathValue == "" || strings.ContainsRune(pathValue, '\x00') || strings.HasPrefix(pathValue, "/") {
		return "", errors.New("源码路径无效")
	}
	clean := filepath.Clean(filepath.FromSlash(pathValue))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", errors.New("源码路径越界")
	}
	return clean, nil
}

func scanArtifactSourcePreviewable(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == "" || ext == ".ets" || ext == ".ts" || ext == ".js" || ext == ".json" ||
		ext == ".json5" || ext == ".yaml" || ext == ".yml" || ext == ".md" || ext == ".txt" ||
		ext == ".d.ts" || ext == ".xml" || ext == ".gn" || ext == ".gni" ||
		ext == ".hvigor" || ext == ".toml"
}

// handleScanArtifactRunSource lists files in the sanitized PoC/Exp source
// snapshot. It deliberately exposes relative paths only; the source archive and
// manifest remain available through the regular deliverable endpoint.
func (s *Server) handleScanArtifactRunSource(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	kind := strings.TrimSpace(r.PathValue("kind"))
	if !scanArtifactRunIDOK(runID) || !scanArtifactSourceKindRe.MatchString(kind) {
		http.NotFound(w, r)
		return
	}
	runDir, err := s.scanArtifactRunDir(runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sourceRoot := scanArtifactSourceRoot(runDir, kind)
	if !isDirectoryNoSymlink(sourceRoot) {
		scanArtifactJSON(w, http.StatusOK, map[string]any{
			"status": "success", "run_id": runID, "kind": kind, "files": []any{},
			"archive_url": "/scan-artifact/runs/" + runID + "/deliverables/" + kind + "_source.zip",
		})
		return
	}
	files := make([]map[string]any, 0)
	var total int64
	err = filepath.WalkDir(sourceRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if len(files) >= scanArtifactSourceMaxFiles || total >= scanArtifactSourceMaxBytes {
			return filepath.SkipDir
		}
		if path != sourceRoot && d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || path == sourceRoot {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || !info.Mode().IsRegular() || info.Size() > scanArtifactSourceMaxBytes-total {
			return nil
		}
		rel, relErr := filepath.Rel(sourceRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		files = append(files, map[string]any{
			"path": rel, "bytes": info.Size(), "previewable": scanArtifactSourcePreviewable(rel),
			"url": "/scan-artifact/runs/" + runID + "/deliverables/source/" + kind + "/" + escapeSourcePath(rel),
		})
		total += info.Size()
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i]["path"].(string) < files[j]["path"].(string) })
	scanArtifactJSON(w, http.StatusOK, map[string]any{
		"status": "success", "run_id": runID, "kind": kind, "root": kind + "_source",
		"file_count": len(files), "total_bytes": total, "files": files,
		"archive_url":  "/scan-artifact/runs/" + runID + "/deliverables/" + kind + "_source.zip",
		"manifest_url": "/scan-artifact/runs/" + runID + "/deliverables/" + kind + "_source_manifest.json",
	})
}

func escapeSourcePath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func isDirectoryNoSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

// handleScanArtifactRunSourceFile serves one source file for online viewing or
// download. Only the generated source snapshot is reachable, never the HAP
// build directory or an arbitrary host path.
func (s *Server) handleScanArtifactRunSourceFile(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	kind := strings.TrimSpace(r.PathValue("kind"))
	if !scanArtifactRunIDOK(runID) || !scanArtifactSourceKindRe.MatchString(kind) {
		http.NotFound(w, r)
		return
	}
	rel, err := scanArtifactSourcePath(r.PathValue("path"))
	if err != nil {
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
	sourceRoot := scanArtifactSourceRoot(runDir, kind)
	path := filepath.Join(sourceRoot, rel)
	f, info, err := openRegularInRoot(root, path)
	if err != nil || !withinRoot(sourceRoot, path) {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if info.Size() > scanArtifactSourceMaxBytes {
		http.Error(w, "源码文件超过在线预览上限，请下载完整压缩包", http.StatusRequestEntityTooLarge)
		return
	}
	contentType := "text/plain; charset=utf-8"
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json", ".json5":
		contentType = "application/json; charset=utf-8"
	case ".md":
		contentType = "text/markdown; charset=utf-8"
	case ".xml":
		contentType = "application/xml; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	disposition := "inline"
	if r.URL.Query().Get("download") == "1" {
		disposition = "attachment"
	}
	fileName := strings.NewReplacer("\"", "'", "\r", "", "\n", "").Replace(filepath.Base(rel))
	w.Header().Set("Content-Disposition", disposition+`; filename="`+fileName+`"`)
	_, _ = io.Copy(w, io.LimitReader(f, scanArtifactSourceMaxBytes+1))
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
	case strings.HasSuffix(name, ".zip"):
		contentType = "application/zip"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = io.Copy(w, f)
}

// handleScanArtifactRunArtifacts lists the safe, user-facing snapshots of a
// dynamic-test run.  It intentionally returns definitions for snapshots that
// have not been written yet; the browser can then render “等待生成” and poll
// without guessing whether an empty result is a failure.
func (s *Server) handleScanArtifactRunArtifacts(w http.ResponseWriter, r *http.Request) {
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
	root, err := s.scanArtifactRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	artifactNames := make(map[string]bool, len(scanArtifactRunArtifactSpecs))
	for name := range scanArtifactRunArtifactSpecs {
		artifactNames[name] = true
	}
	if entries, readErr := os.ReadDir(runDir); readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() && scanArtifactManualReplayRe.MatchString(entry.Name()) {
				artifactNames[entry.Name()] = true
			}
		}
	}
	items := make([]map[string]any, 0, len(artifactNames))
	for name := range artifactNames {
		spec, ok := scanArtifactRunArtifactSpec(name)
		if !ok {
			continue
		}
		item := map[string]any{
			"name":        name,
			"label":       spec.label,
			"description": spec.description,
			"kind":        spec.kind,
			"available":   false,
			"url":         "/scan-artifact/runs/" + runID + "/artifacts/" + name,
		}
		path := filepath.Join(runDir, name)
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
			item["available"] = true
			item["bytes"] = info.Size()
			item["modified_at"] = info.ModTime().UTC().Format(time.RFC3339)
		} else if name == "result.json" {
			// Direct/legacy runs may not have the Web worker wrapper.  They still
			// expose a safe, derived result through the same endpoint.
			if derived, derivedErr := scanArtifactDerivedResult(root, runDir, runID); derivedErr == nil {
				if encoded, marshalErr := json.Marshal(derived); marshalErr == nil {
					item["available"] = true
					item["bytes"] = len(encoded)
					item["derived"] = true
				}
			}
		}
		items = append(items, item)
	}
	// Keep the browser stable across JSON map iteration and put the result last.
	sort.Slice(items, func(i, j int) bool {
		ai, _ := items[i]["name"].(string)
		aj, _ := items[j]["name"].(string)
		if ai == "result.json" {
			return false
		}
		if aj == "result.json" {
			return true
		}
		return ai < aj
	})
	scanArtifactJSON(w, http.StatusOK, map[string]any{
		"status":    "success",
		"run_id":    runID,
		"artifacts": items,
	})
}

// handleScanArtifactRunArtifact serves one allowlisted intermediate snapshot.
// JSONL is returned as text so the UI can stream/format it without changing
// the audit bytes.  The endpoint never exposes arbitrary files in the run
// directory (notably HAPs and build/signing directories).
func (s *Server) handleScanArtifactRunArtifact(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimSpace(r.PathValue("run_id"))
	name := strings.TrimSpace(r.PathValue("name"))
	spec, ok := scanArtifactRunArtifactSpec(name)
	if !scanArtifactRunIDOK(runID) || !ok || !scanArtifactDeliverableRe.MatchString(name) {
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
	if name == "result.json" {
		if _, statErr := os.Stat(filepath.Join(runDir, name)); os.IsNotExist(statErr) {
			if derived, derivedErr := scanArtifactDerivedResult(root, runDir, runID); derivedErr == nil {
				scanArtifactJSON(w, http.StatusOK, derived)
				return
			}
		}
	}
	f, info, err := openRegularInRoot(root, filepath.Join(runDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "产物尚未生成", http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if info.Size() > spec.maxBytes {
		http.Error(w, "产物超过读取上限", http.StatusRequestEntityTooLarge)
		return
	}
	if spec.kind == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

// scanArtifactJob tracks one background dynamic-test run observed by the page.
type scanArtifactJob struct {
	RunID     string             `json:"run_id"`
	Sample    string             `json:"sample,omitempty"`
	ScanID    string             `json:"scan_id,omitempty"`
	Serial    string             `json:"device_serial,omitempty"`
	CleanRoom bool               `json:"clean_room"`
	Status    string             `json:"status"`
	Error     string             `json:"error,omitempty"`
	StartedAt time.Time          `json:"started_at"`
	EndedAt   time.Time          `json:"ended_at,omitempty"`
	Cancel    context.CancelFunc `json:"-"`
}

// parseScanArtifactCleanRoom keeps the Web API strict and backwards
// compatible: an omitted checkbox means the historical assisted mode, while
// the browser sends the canonical string "true" when clean-room is selected.
func parseScanArtifactCleanRoom(raw string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("clean_room must be boolean")
	}
	return value, nil
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

func (s *Server) removeScanArtifactJob(runID string) {
	s.scanArtifactJobsMu.Lock()
	defer s.scanArtifactJobsMu.Unlock()
	delete(s.scanArtifactJobs, runID)
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
	// Direct/legacy runs: project verdict.json/run_record.json into the same
	// terminal status envelope used by Web-created jobs.
	if payload, derivedErr := scanArtifactDerivedResult(root, runDir, runID); derivedErr == nil {
		if nested, ok := payload["result"].(map[string]any); ok {
			status := strings.TrimSpace(fmt.Sprint(nested["status"]))
			if status == "" {
				status = "complete"
			}
			payload["status"] = status
		}
		payload["run_id"] = runID
		payload["terminal"] = true
		return payload, true, nil
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
		"clean_room": job.CleanRoom,
		"context_mode": map[bool]string{
			true:  "clean_room",
			false: "assisted",
		}[job.CleanRoom],
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

// scanArtifactReadOptionalJSON reads a JSON snapshot from a run directory.
// It deliberately treats a missing file as an ordinary miss: older/direct
// runs do not necessarily have every Web-worker wrapper file.
func scanArtifactReadOptionalJSON(root, path string) (map[string]any, error) {
	f, _, err := openRegularInRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(f, scanArtifactMaxResultBytes+1)).Decode(&payload); err != nil {
		return nil, err
	}
	if payload == nil {
		return nil, errors.New("empty JSON snapshot")
	}
	return payload, nil
}

// scanArtifactDerivedResult adapts direct/older dynamic-test directories to
// the same result envelope emitted by the Web worker.  A direct run normally
// persists verdict.json and run_record.json, but not the Go-owned result.json;
// hiding such a run made a valid CONFIRMED result appear to be absent in the
// browser.  This function only derives a read-only view from existing files;
// it never changes the verdict or invents device evidence.
func scanArtifactDerivedResult(root, runDir, runID string) (map[string]any, error) {
	verdictSnap, verdictErr := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "verdict.json"))
	recordSnap, recordErr := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "run_record.json"))
	contractSnap, contractErr := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "contract.json"))
	compileSnap, _ := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "compile_summary.json"))
	bridgeSnap, _ := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "bridge.json"))
	if verdictErr != nil && recordErr != nil {
		return nil, os.ErrNotExist
	}

	// verdict.json has the compact top-level fields plus a nested verdict;
	// run_record.json stores the same nested object for older direct runs.
	verdict := map[string]any{}
	if verdictErr == nil {
		if nested, ok := verdictSnap["verdict"].(map[string]any); ok {
			verdict = nested
		} else {
			verdict = verdictSnap
		}
	}
	if len(verdict) == 0 && recordErr == nil {
		if nested, ok := recordSnap["verdict"].(map[string]any); ok {
			verdict = nested
		}
	}
	status := strings.TrimSpace(fmt.Sprint(verdict["status"]))
	if status == "" && verdictErr == nil {
		status = strings.TrimSpace(fmt.Sprint(verdictSnap["status"]))
	}
	if status == "" {
		return nil, os.ErrNotExist
	}
	internalRunID := strings.TrimSpace(fmt.Sprint(verdict["run_id"]))
	if internalRunID == "" && recordErr == nil {
		internalRunID = strings.TrimSpace(fmt.Sprint(recordSnap["run_id"]))
	}
	if internalRunID == "" {
		internalRunID = runID
	}
	pattern := verdict["pattern"]
	if pattern == nil && verdictErr == nil {
		pattern = verdictSnap["pattern"]
	}
	if pattern == nil && recordErr == nil {
		pattern = recordSnap["pattern"]
	}
	evidenceGrade := verdict["evidence_grade"]
	if evidenceGrade == nil && verdictErr == nil {
		evidenceGrade = verdictSnap["evidence_grade"]
	}
	if evidenceGrade == nil && recordErr == nil {
		evidenceGrade = recordSnap["evidence_grade"]
	}

	result := map[string]any{
		"run_id":         internalRunID,
		"status":         status,
		"evidence_grade": evidenceGrade,
		"pattern":        pattern,
		"verdict":        verdict,
		"run_status":     "complete",
		"derived_from":   []string{"verdict.json", "run_record.json"},
	}
	if compileSnap != nil {
		result["compile"] = compileSnap
		if entryDiscovery, ok := compileSnap["entry_discovery"]; ok {
			result["entry_discovery"] = entryDiscovery
		}
		if protocolEvidence, ok := compileSnap["protocol_evidence"]; ok {
			result["protocol_evidence"] = protocolEvidence
		}
		if errorsValue, ok := compileSnap["errors"]; ok {
			result["compile_errors"] = errorsValue
		}
	}
	if contractErr == nil {
		result["contract"] = contractSnap
		if result["vuln_class"] == nil {
			result["vuln_class"] = contractSnap["vuln_class"]
		}
	}
	if recordErr == nil {
		result["record"] = recordSnap
	}
	if bridgeSnap != nil {
		result["bridge"] = bridgeSnap
	}
	return map[string]any{
		"status":     "success",
		"run_id":     runID,
		"run_status": "complete",
		"result":     result,
	}, nil
}

// scanArtifactRunMatches identifies a run without relying on a Web-memory
// job entry.  bridge.json is preferred because it ties the run to the exact
// scan result_file; contract/run_record are accepted for direct historical
// runs that predate the bridge snapshot.
func scanArtifactRunMatches(root, runDir, scanID, sample string) (bool, string) {
	if bridge, err := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "bridge.json")); err == nil {
		if entry, ok := bridge["entry"].(map[string]any); ok {
			if fmt.Sprint(entry["sample"]) == sample {
				resultFile := fmt.Sprint(entry["result_file"])
				if strings.Contains(resultFile, string(filepath.Separator)+scanID+string(filepath.Separator)) || resultFile == "" {
					return true, "bridge"
				}
			}
		}
	}
	if contract, err := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "contract.json")); err == nil {
		if ids, ok := contract["finding_ids"].([]any); ok {
			for _, id := range ids {
				if fmt.Sprint(id) == sample {
					return true, "contract"
				}
			}
		}
		if normalized := strings.TrimPrefix(fmt.Sprint(contract["contract_id"]), "GEN-"); normalized == sample {
			return true, "contract"
		}
	}
	if record, err := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "run_record.json")); err == nil {
		if normalized := strings.TrimPrefix(fmt.Sprint(record["contract_id"]), "GEN-"); normalized == sample {
			return true, "run_record"
		}
	}
	return false, ""
}

// scanArtifactRunHistory returns every historical and currently running run
// matching one scan/sample pair.  The old latest endpoint deliberately chose
// one directory, which made repeated experiments look as if they had
// overwritten each other in the UI.  History is built from the same
// evidence-backed bridge/contract matching rules, then enriched with the
// in-memory job table so a freshly started run is visible before bridge.json
// has been written.
func (s *Server) scanArtifactRunHistory(scanID, sample string) ([]map[string]any, error) {
	root, err := s.scanArtifactRoot()
	if err != nil {
		return nil, err
	}
	byID := make(map[string]map[string]any)
	add := func(item map[string]any) {
		id := strings.TrimSpace(fmt.Sprint(item["run_id"]))
		if id == "" || !scanArtifactRunIDOK(id) {
			return
		}
		if _, exists := byID[id]; !exists {
			byID[id] = item
			return
		}
		// In-memory metadata is fresher for active jobs, while disk metadata
		// contains the terminal verdict and match source.
		for key, value := range item {
			if value == nil || fmt.Sprint(value) == "" || fmt.Sprint(value) == "<nil>" {
				continue
			}
			byID[id][key] = value
		}
	}

	runsRoot := filepath.Join(root, "runs")
	entries, readErr := os.ReadDir(runsRoot)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, readErr
	}
	for _, entry := range entries {
		if !entry.IsDir() || !scanArtifactRunIDOK(entry.Name()) {
			continue
		}
		runDir := filepath.Join(runsRoot, entry.Name())
		matched, source := scanArtifactRunMatches(root, runDir, scanID, sample)
		if !matched {
			continue
		}
		modified := time.Time{}
		for _, name := range []string{"result.json", "verdict.json", "run_record.json", "bridge.json", "contract.json", "progress.jsonl", "ledger.jsonl"} {
			if info, statErr := os.Stat(filepath.Join(runDir, name)); statErr == nil && info.ModTime().After(modified) {
				modified = info.ModTime()
			}
		}
		if modified.IsZero() {
			if info, statErr := entry.Info(); statErr == nil {
				modified = info.ModTime()
			}
		}
		item := map[string]any{
			"run_id": entry.Name(), "scan_id": scanID, "sample": sample,
			"match_source": source, "run_status": "running", "status": "running",
			"dynamic_status": "", "terminal": false,
			"modified_at": modified.UTC().Format(time.RFC3339),
		}
		if payload, resultErr := scanArtifactReadResult(root, filepath.Join(runDir, "result.json")); resultErr == nil {
			item["run_status"] = nonEmptyString(fmt.Sprint(payload["run_status"]), "complete")
			item["status"] = item["run_status"]
			item["terminal"] = true
			item["dynamic_status"] = scanArtifactDynamicStatus(payload)
			if clean, ok := payload["clean_room"].(bool); ok {
				item["clean_room"] = clean
				item["context_mode"] = map[bool]string{true: "clean_room", false: "assisted"}[clean]
			}
		} else if derived, derivedErr := scanArtifactDerivedResult(root, runDir, entry.Name()); derivedErr == nil {
			item["run_status"] = "complete"
			item["status"] = "complete"
			item["terminal"] = true
			item["dynamic_status"] = scanArtifactDynamicStatus(derived)
		}
		if bridge, bridgeErr := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "bridge.json")); bridgeErr == nil {
			if clean, ok := bridge["clean_room"].(bool); ok {
				item["clean_room"] = clean
				item["context_mode"] = map[bool]string{true: "clean_room", false: "assisted"}[clean]
			}
		}
		add(item)
	}

	// Include in-memory jobs even before bridge.json has been written, and
	// overlay their authoritative mode/device/timestamp fields on disk items.
	s.scanArtifactJobsMu.RLock()
	jobs := make([]scanArtifactJob, 0, len(s.scanArtifactJobs))
	for _, job := range s.scanArtifactJobs {
		if job != nil && job.ScanID == scanID && job.Sample == sample {
			copy := *job
			copy.Cancel = nil
			jobs = append(jobs, copy)
		}
	}
	s.scanArtifactJobsMu.RUnlock()
	for _, job := range jobs {
		item, exists := byID[job.RunID]
		if !exists {
			item = map[string]any{
				"run_id": job.RunID, "scan_id": job.ScanID, "sample": job.Sample,
				"match_source": "web_job", "dynamic_status": "",
			}
		}
		item["run_status"] = job.Status
		item["status"] = job.Status
		item["device_serial"] = job.Serial
		item["clean_room"] = job.CleanRoom
		item["context_mode"] = map[bool]string{true: "clean_room", false: "assisted"}[job.CleanRoom]
		item["started_at"] = job.StartedAt.UTC().Format(time.RFC3339)
		if !job.EndedAt.IsZero() {
			item["ended_at"] = job.EndedAt.UTC().Format(time.RFC3339)
		}
		item["terminal"] = scanArtifactTerminal(job.Status)
		if job.Status == "running" {
			item["terminal"] = false
		}
		if strings.TrimSpace(fmt.Sprint(item["modified_at"])) == "" {
			item["modified_at"] = job.StartedAt.UTC().Format(time.RFC3339)
		}
		byID[job.RunID] = item
	}

	items := make([]map[string]any, 0, len(byID))
	for _, item := range byID {
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := historyItemTime(items[i])
		right := historyItemTime(items[j])
		if left.Equal(right) {
			return fmt.Sprint(items[i]["run_id"]) > fmt.Sprint(items[j]["run_id"])
		}
		return left.After(right)
	})
	if len(items) > scanArtifactMaxHistory {
		items = items[:scanArtifactMaxHistory]
	}
	return items, nil
}

func nonEmptyString(value, fallback string) string {
	if strings.TrimSpace(value) == "" || value == "<nil>" {
		return fallback
	}
	return value
}

func historyItemTime(item map[string]any) time.Time {
	for _, key := range []string{"modified_at", "ended_at", "started_at"} {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(fmt.Sprint(item[key]))); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

// scanArtifactDynamicStatus extracts the device verdict without confusing it
// with the Web worker execution status (complete/error/cancelled).
func scanArtifactDynamicStatus(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	for _, key := range []string{"dynamic_status", "verdict_status"} {
		if value := strings.TrimSpace(fmt.Sprint(payload[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	if nested, ok := payload["result"].(map[string]any); ok {
		if value := strings.TrimSpace(fmt.Sprint(nested["status"])); value != "" && value != "<nil>" {
			return value
		}
		if verdict, ok := nested["verdict"].(map[string]any); ok {
			if value := strings.TrimSpace(fmt.Sprint(verdict["status"])); value != "" && value != "<nil>" {
				return value
			}
		}
	}
	if verdict, ok := payload["verdict"].(map[string]any); ok {
		if value := strings.TrimSpace(fmt.Sprint(verdict["status"])); value != "" && value != "<nil>" {
			return value
		}
	}
	value := strings.TrimSpace(fmt.Sprint(payload["status"]))
	if strings.EqualFold(value, "confirmed") || strings.EqualFold(value, "not_reproduced") || strings.EqualFold(value, "inconclusive") || strings.EqualFold(value, "blocked") {
		return value
	}
	return ""
}

var scanArtifactEmbeddedScanIDRe = regexp.MustCompile(`(?:^|[/\\])([a-fA-F0-9]{8,64})(?:[/\\]|$)`)

func scanArtifactScanIDFromPath(pathValue string) string {
	match := scanArtifactEmbeddedScanIDRe.FindStringSubmatch(pathValue)
	if len(match) < 2 {
		return ""
	}
	return strings.ToLower(match[1])
}

// scanArtifactRunIdentity extracts the stable grouping identity from a run's
// own evidence. Web-created runs have bridge.entry.result_file; older direct
// runs may carry the same entry under result.json or only have a contract_id.
// The order is intentional: bridge.json is the narrow Web snapshot, then the
// result envelope, then the older contract/record snapshots. We never infer a
// scan ID from a run directory name; if no source contains one, the caller
// keeps the sample in the explicitly unassociated group.
func scanArtifactRunIdentity(root, runDir string) (scanID, sample, source string, metadata map[string]any) {
	metadata = make(map[string]any)
	readEntry := func(entry map[string]any, sourceName string) (string, string, string, bool) {
		candidateScan := strings.ToLower(strings.TrimSpace(fmt.Sprint(entry["scan_id"])))
		if len(candidateScan) < 8 || !scanArtifactScanIDOK(candidateScan) {
			candidateScan = ""
		}
		if candidateScan == "" {
			candidateScan = scanArtifactScanIDFromPath(fmt.Sprint(entry["result_file"]))
		}
		candidateSample := strings.TrimSpace(fmt.Sprint(entry["sample"]))
		for _, key := range []string{"function_analyzed", "location", "finding", "repository", "unit_id", "target_id"} {
			if value := strings.TrimSpace(fmt.Sprint(entry[key])); value != "" && value != "<nil>" {
				if _, exists := metadata[key]; !exists {
					metadata[key] = value
				}
			}
		}
		return candidateScan, candidateSample, sourceName, candidateScan != "" || candidateSample != ""
	}
	if bridge, err := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "bridge.json")); err == nil {
		if entry, ok := bridge["entry"].(map[string]any); ok {
			if candidateScan, candidateSample, candidateSource, usable := readEntry(entry, "bridge"); usable {
				return candidateScan, candidateSample, candidateSource, metadata
			}
		}
	}
	// Some historical Web runs persisted only result.json. Its normalized
	// result envelope still contains the original finding entry, so recover the
	// same identity instead of treating the run as anonymous.
	if result, err := scanArtifactReadResult(root, filepath.Join(runDir, "result.json")); err == nil {
		if nested, ok := result["result"].(map[string]any); ok {
			if entry, ok := nested["entry"].(map[string]any); ok {
				if candidateScan, candidateSample, candidateSource, usable := readEntry(entry, "result"); usable {
					return candidateScan, candidateSample, candidateSource, metadata
				}
			}
		}
	}
	if contract, err := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "contract.json")); err == nil {
		if ids, ok := contract["finding_ids"].([]any); ok && len(ids) > 0 {
			sample = strings.TrimSpace(fmt.Sprint(ids[0]))
		}
		if sample == "" {
			sample = strings.TrimPrefix(strings.TrimSpace(fmt.Sprint(contract["contract_id"])), "GEN-")
		}
		for _, key := range []string{"unit_id", "vuln_class", "description"} {
			if value := strings.TrimSpace(fmt.Sprint(contract[key])); value != "" && value != "<nil>" {
				metadata[key] = value
			}
		}
		return "", sample, "contract", metadata
	}
	if record, err := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "run_record.json")); err == nil {
		sample = strings.TrimPrefix(strings.TrimSpace(fmt.Sprint(record["contract_id"])), "GEN-")
		return "", sample, "run_record", metadata
	}
	return "", "", "", metadata
}

// handleScanArtifactHistory provides the cross-entry management view used by
// the standalone history page.  It is intentionally read-only and returns a
// compact hierarchy: scan -> sample -> runs.  The detail page continues to
// use /scan-artifact/runs for one scan/sample pair.
func (s *Server) handleScanArtifactHistory(w http.ResponseWriter, r *http.Request) {
	root, err := s.scanArtifactRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type historyGroup struct {
		ScanID  string
		Label   string
		Samples map[string]map[string]any
	}
	groups := make(map[string]*historyGroup)
	ensureGroup := func(scanID string) *historyGroup {
		key := scanID
		if key == "" {
			key = "__unlinked__"
		}
		group := groups[key]
		if group == nil {
			label := scanID
			if label == "" {
				label = "未关联扫描的历史产物"
			}
			group = &historyGroup{ScanID: scanID, Label: label, Samples: make(map[string]map[string]any)}
			groups[key] = group
		}
		return group
	}
	addRun := func(scanID, sample, source string, runID string, run map[string]any, metadata map[string]any) {
		if strings.TrimSpace(sample) == "" || !scanArtifactRunIDOK(runID) {
			return
		}
		group := ensureGroup(scanID)
		item := group.Samples[sample]
		if item == nil {
			item = map[string]any{"sample": sample, "run_count": 0, "runs": []map[string]any{}}
			for key, value := range metadata {
				item[key] = value
			}
			group.Samples[sample] = item
		}
		if source != "" && run["match_source"] == nil {
			run["match_source"] = source
		}
		runs, _ := item["runs"].([]map[string]any)
		for index, existing := range runs {
			if fmt.Sprint(existing["run_id"]) == runID {
				// A Web job can already have a disk snapshot. Merge the fresher
				// in-memory fields instead of showing the same run twice.
				for key, value := range run {
					if value != nil && fmt.Sprint(value) != "" && fmt.Sprint(value) != "<nil>" {
						existing[key] = value
					}
				}
				runs[index] = existing
				item["runs"] = runs
				return
			}
		}
		runs = append(runs, run)
		item["runs"] = runs
		item["run_count"] = len(runs)
	}

	runsRoot := filepath.Join(root, "runs")
	if entries, readErr := os.ReadDir(runsRoot); readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !scanArtifactRunIDOK(entry.Name()) {
				continue
			}
			runDir := filepath.Join(runsRoot, entry.Name())
			scanID, sample, source, metadata := scanArtifactRunIdentity(root, runDir)
			if sample == "" {
				// A failed/aborted run can be persisted before the worker has
				// written bridge, contract, or entry metadata. Keep it visible
				// rather than silently dropping an executed session. The label is
				// deliberately explicit so it cannot be mistaken for a real sample.
				sample = "未识别样本"
				metadata["identity_missing"] = true
			}
			modified := time.Time{}
			for _, name := range []string{"result.json", "verdict.json", "run_record.json", "bridge.json", "contract.json", "progress.jsonl", "ledger.jsonl"} {
				if info, statErr := os.Stat(filepath.Join(runDir, name)); statErr == nil && info.ModTime().After(modified) {
					modified = info.ModTime()
				}
			}
			run := map[string]any{
				"run_id": entry.Name(), "scan_id": scanID, "sample": sample,
				"run_status": "running", "status": "running", "dynamic_status": "",
				"terminal": false, "modified_at": modified.UTC().Format(time.RFC3339),
			}
			if payload, readResultErr := scanArtifactReadResult(root, filepath.Join(runDir, "result.json")); readResultErr == nil {
				run["run_status"] = nonEmptyString(fmt.Sprint(payload["run_status"]), "complete")
				run["status"] = run["run_status"]
				run["terminal"] = true
				run["dynamic_status"] = scanArtifactDynamicStatus(payload)
			} else if derived, derivedErr := scanArtifactDerivedResult(root, runDir, entry.Name()); derivedErr == nil {
				run["run_status"] = "complete"
				run["status"] = "complete"
				run["terminal"] = true
				run["dynamic_status"] = scanArtifactDynamicStatus(derived)
			}
			if bridge, bridgeErr := scanArtifactReadOptionalJSON(root, filepath.Join(runDir, "bridge.json")); bridgeErr == nil {
				if clean, ok := bridge["clean_room"].(bool); ok {
					run["clean_room"] = clean
					run["context_mode"] = map[bool]string{true: "clean_room", false: "assisted"}[clean]
				}
			}
			addRun(scanID, sample, source, entry.Name(), run, metadata)
		}
	}

	// A run started from the Web UI may not have any identifying snapshot yet;
	// include it from memory so the management page updates immediately.
	s.scanArtifactJobsMu.RLock()
	jobs := make([]scanArtifactJob, 0, len(s.scanArtifactJobs))
	for _, job := range s.scanArtifactJobs {
		if job != nil {
			copy := *job
			copy.Cancel = nil
			jobs = append(jobs, copy)
		}
	}
	s.scanArtifactJobsMu.RUnlock()
	for _, job := range jobs {
		run := map[string]any{
			"run_id": job.RunID, "scan_id": job.ScanID, "sample": job.Sample,
			"run_status": job.Status, "status": job.Status,
			"dynamic_status": "", "terminal": scanArtifactTerminal(job.Status),
			"device_serial": job.Serial, "clean_room": job.CleanRoom,
			"context_mode": map[bool]string{true: "clean_room", false: "assisted"}[job.CleanRoom],
			"started_at":   job.StartedAt.UTC().Format(time.RFC3339),
		}
		if !job.EndedAt.IsZero() {
			run["ended_at"] = job.EndedAt.UTC().Format(time.RFC3339)
		}
		addRun(job.ScanID, job.Sample, "web_job", job.RunID, run, nil)
	}

	result := make([]map[string]any, 0, len(groups))
	for _, group := range groups {
		samples := make([]map[string]any, 0, len(group.Samples))
		for _, sample := range group.Samples {
			runs, _ := sample["runs"].([]map[string]any)
			sort.SliceStable(runs, func(i, j int) bool {
				return historyItemTime(runs[i]).After(historyItemTime(runs[j]))
			})
			sample["runs"] = runs
			samples = append(samples, sample)
		}
		sort.Slice(samples, func(i, j int) bool { return fmt.Sprint(samples[i]["sample"]) < fmt.Sprint(samples[j]["sample"]) })
		result = append(result, map[string]any{
			"scan_id": group.ScanID, "label": group.Label,
			"sample_count": len(samples), "run_count": countHistoryRuns(samples), "samples": samples,
		})
	}
	sort.Slice(result, func(i, j int) bool { return fmt.Sprint(result[i]["label"]) < fmt.Sprint(result[j]["label"]) })
	scanArtifactJSON(w, http.StatusOK, map[string]any{
		"status": "success", "scan_count": len(result), "scans": result,
	})
}

// scanArtifactRunDynamicStatus returns the device-side verdict, deliberately
// separate from the Web worker status ("complete", "error", or "running").
// An empty value means that no verdict has been persisted; such a run is
// deletable unless an in-memory worker still owns it.
func scanArtifactRunDynamicStatus(root, runDir string) string {
	if payload, err := scanArtifactReadResult(root, filepath.Join(runDir, "result.json")); err == nil {
		if status := strings.TrimSpace(scanArtifactDynamicStatus(payload)); status != "" {
			return status
		}
	}
	if payload, err := scanArtifactDerivedResult(root, runDir, filepath.Base(runDir)); err == nil {
		return strings.TrimSpace(scanArtifactDynamicStatus(payload))
	}
	return ""
}

// handleScanArtifactRunDelete removes exactly one dynamic-test run directory.
// It is intentionally stricter than a generic artifact browser:
//   - same-origin + CSRF are required;
//   - a confirmed device verdict is immutable from this UI;
//   - a worker still running in this Web process is not deleted underneath;
//   - the run ID and directory are checked before RemoveAll.
//
// Historical runs whose worker process disappeared are safe to clean up even
// when their persisted execution status is still "running"; they have no
// in-memory owner and are explicitly displayed as stale history by the page.
func (s *Server) handleScanArtifactRunDelete(w http.ResponseWriter, r *http.Request) {
	if !s.scanArtifactMutationOK(w, r) {
		return
	}
	runID := strings.TrimSpace(r.PathValue("run_id"))
	runDir, err := s.scanArtifactRunDir(runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	info, err := os.Lstat(runDir)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "读取动态测试会话失败", http.StatusInternalServerError)
		return
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		http.NotFound(w, r)
		return
	}
	if job, ok := s.scanArtifactJob(runID); ok && strings.EqualFold(strings.TrimSpace(job.Status), "running") {
		scanArtifactJSON(w, http.StatusConflict, map[string]any{
			"status": "error", "run_id": runID,
			"error": "会话仍在运行，不能删除；请等待结束后再清理",
		})
		return
	}
	root, err := s.scanArtifactRoot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dynamicStatus := scanArtifactRunDynamicStatus(root, runDir)
	if strings.EqualFold(dynamicStatus, "CONFIRMED") {
		scanArtifactJSON(w, http.StatusConflict, map[string]any{
			"status": "error", "run_id": runID, "dynamic_status": dynamicStatus,
			"error": "CONFIRMED 会话受保护，不能删除",
		})
		return
	}
	if err := os.RemoveAll(runDir); err != nil {
		http.Error(w, "删除动态测试会话失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	s.removeScanArtifactJob(runID)
	scanArtifactJSON(w, http.StatusOK, map[string]any{
		"status": "deleted", "run_id": runID, "dynamic_status": dynamicStatus,
	})
}

func countHistoryRuns(samples []map[string]any) int {
	total := 0
	for _, sample := range samples {
		if n, ok := sample["run_count"].(int); ok {
			total += n
		}
	}
	return total
}

func (s *Server) latestScanArtifactRun(scanID, sample string) (map[string]any, error) {
	items, err := s.scanArtifactRunHistory(scanID, sample)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, os.ErrNotExist
	}
	best := items[0]
	return map[string]any{
		"status": "success", "found": true, "run_id": best["run_id"],
		"sample": sample, "scan_id": scanID, "match_source": best["match_source"],
		"dynamic_status": best["dynamic_status"], "modified_at": best["modified_at"],
	}, nil
}

// handleScanArtifactRunHistory lists all runs for a scan/sample pair.  It is
// read-only; selecting a history card only changes the browser view.
func (s *Server) handleScanArtifactRunHistory(w http.ResponseWriter, r *http.Request) {
	scanID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scan_id")))
	sample := strings.TrimSpace(r.URL.Query().Get("sample"))
	if len(scanID) > 64 || !scanArtifactScanIDOK(scanID) || sample == "" || len(sample) > 160 || !scanArtifactSampleOK(sample) {
		http.Error(w, "scan_id and sample are required", http.StatusBadRequest)
		return
	}
	items, err := s.scanArtifactRunHistory(scanID, sample)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scanArtifactJSON(w, http.StatusOK, map[string]any{
		"status": "success", "scan_id": scanID, "sample": sample,
		"count": len(items), "runs": items,
	})
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
	if payload, derivedErr := scanArtifactDerivedResult(root, runDir, runID); derivedErr == nil {
		scanArtifactJSON(w, http.StatusOK, payload)
		return
	}
	http.NotFound(w, r)
}

// handleScanArtifactLatestRun resolves the newest on-disk dynamic run for a
// scan/sample pair.  This is intentionally read-only and lets the browser
// recover a result produced by a CLI/clean-room run after a Web restart.
func (s *Server) handleScanArtifactLatestRun(w http.ResponseWriter, r *http.Request) {
	scanID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scan_id")))
	sample := strings.TrimSpace(r.URL.Query().Get("sample"))
	if len(scanID) > 64 || !scanArtifactScanIDOK(scanID) || sample == "" || len(sample) > 160 || !scanArtifactSampleOK(sample) {
		http.Error(w, "scan_id and sample are required", http.StatusBadRequest)
		return
	}
	payload, err := s.latestScanArtifactRun(scanID, sample)
	if err != nil {
		if os.IsNotExist(err) {
			scanArtifactJSON(w, http.StatusOK, map[string]any{"status": "success", "found": false, "scan_id": scanID, "sample": sample})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scanArtifactJSON(w, http.StatusOK, payload)
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
	cleanRoom, err := parseScanArtifactCleanRoom(r.FormValue("clean_room"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
	if cleanRoom {
		args = append(args, "--clean-room")
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
		RunID: runID, Sample: sample, ScanID: scanID, Serial: serial, CleanRoom: cleanRoom,
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
		"status":        "success",
		"run_id":        runID,
		"sample":        sample,
		"scan_id":       scanID,
		"device":        serial,
		"clean_room":    cleanRoom,
		"context_mode":  map[bool]string{true: "clean_room", false: "assisted"}[cleanRoom],
		"events_url":    "/scan-artifact/runs/" + runID + "/events",
		"status_url":    "/scan-artifact/runs/" + runID,
		"result_url":    "/scan-artifact/runs/" + runID + "/result",
		"artifacts_url": "/scan-artifact/runs/" + runID + "/artifacts",
		"message":       "动态测试已在后台启动；请通过 events 查看实时进度",
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
