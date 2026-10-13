package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vulnfounder/apps/vulnfounder-cli/internal/config"
)

var runtimeEnvNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

func opengrokHTTPSURL(fields sourceLocatorRequestFields) (string, error) {
	value, err := sourceLocatorString(fields, "base_url", 2048)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("OpenGrok 地址不能为空")
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("OpenGrok 地址必须是不带凭据、查询参数和片段的 HTTPS URL")
	}
	return strings.TrimRight(value, "/"), nil
}

func safeSettingText(fields sourceLocatorRequestFields, key string, max int, fallback string) (string, error) {
	value, err := sourceLocatorString(fields, key, max)
	if err != nil {
		return "", err
	}
	if value == "" {
		return fallback, nil
	}
	for _, r := range value {
		if r == '\x00' || r == '\r' || r == '\n' || r == '\t' {
			return "", fmt.Errorf("%s 不能包含控制字符", key)
		}
	}
	return value, nil
}

func sourceLocatorFloat(fields sourceLocatorRequestFields, key string, min, max float64, fallback float64) (float64, error) {
	value, err := sourceLocatorString(fields, key, 64)
	if err != nil {
		return 0, err
	}
	if value == "" {
		return fallback, nil
	}
	parsed, parseErr := strconv.ParseFloat(value, 64)
	if parseErr != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s 必须是 %.0f 到 %.0f 之间的数字", key, min, max)
	}
	return parsed, nil
}

func sourceLocatorAuthMode(fields sourceLocatorRequestFields, fallback string) (string, error) {
	value, err := safeSettingText(fields, "auth_mode", 32, fallback)
	if err != nil {
		return "", err
	}
	value = strings.ToLower(value)
	if value != "none" && value != "bearer_env" {
		return "", errors.New("OpenGrok 认证方式只能是 none 或 bearer_env")
	}
	return value, nil
}

func sourceLocatorTokenEnv(fields sourceLocatorRequestFields, mode string, fallback string) (string, error) {
	value, err := safeSettingText(fields, "token_env", 128, fallback)
	if err != nil {
		return "", err
	}
	if mode == "none" {
		return "", nil
	}
	if !runtimeEnvNameRe.MatchString(value) {
		return "", errors.New("token_env 必须是大写环境变量名，页面不会保存令牌值")
	}
	return value, nil
}

func settingsOpenGrokData(cfg *config.Config, loadErr error) map[string]any {
	settings := config.SourceLocatorSettings{}
	if cfg != nil {
		settings = cfg.GetSourceLocatorSettings()
	}
	data := map[string]any{
		"enabled":         settings.Enabled,
		"target_revision": settings.TargetRevision,
		"base_url":        settings.BaseURL,
		"project":         settings.Project,
		"api_prefix":      settings.APIPrefix,
		"timeout_seconds": settings.TimeoutSeconds,
		"max_retries":     settings.MaxRetries,
		"verify_tls":      settings.VerifyTLS,
		"auth_mode":       settings.AuthMode,
		"token_env":       settings.TokenEnv,
		"secret_policy":   "令牌只从指定环境变量读取，页面和配置文件不保存令牌值。",
	}
	if path, err := config.Path(); err == nil {
		data["config_path"] = path
	}
	if loadErr != nil {
		data["error"] = "读取配置失败：" + loadErr.Error()
	}
	return data
}

func (s *Server) handleSettingsOpenGrok(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load()
	status := http.StatusOK
	envelope := "success"
	errorsList := []string{}
	if err != nil {
		status = http.StatusInternalServerError
		envelope = "error"
		errorsList = []string{err.Error()}
	}
	sourceLocatorJSON(w, status, map[string]any{"status": envelope, "data": settingsOpenGrokData(cfg, err), "errors": errorsList})
}

func (s *Server) handleSettingsOpenGrokSave(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.settingsMutationAllowed(w, r, fields) {
		return
	}
	baseURL, err := opengrokHTTPSURL(fields)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	enabled, err := sourceLocatorBool(fields, "enabled", true)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	current := config.SourceLocatorSettings{}
	if cfg, loadErr := config.Load(); loadErr == nil {
		current = cfg.GetSourceLocatorSettings()
	}
	revision, err := safeSettingText(fields, "target_revision", 128, current.TargetRevision)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	project, err := safeSettingText(fields, "project", 128, current.Project)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	apiPrefix, err := safeSettingText(fields, "api_prefix", 256, current.APIPrefix)
	if err != nil || !strings.HasPrefix(apiPrefix, "/") || strings.Contains(apiPrefix, "..") || strings.ContainsAny(apiPrefix, "\\?#") {
		if err == nil {
			err = errors.New("api_prefix 必须是安全的相对路径")
		}
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	timeout, err := sourceLocatorFloat(fields, "timeout_seconds", 0.1, 300, current.TimeoutSeconds)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	retries, err := sourceLocatorInt(fields, "max_retries", 0, 3)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if _, exists := fields["max_retries"]; !exists {
		retries = current.MaxRetries
	}
	verifyTLS, err := sourceLocatorBool(fields, "verify_tls", current.VerifyTLS)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	authMode, err := sourceLocatorAuthMode(fields, current.AuthMode)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	tokenEnv, err := sourceLocatorTokenEnv(fields, authMode, current.TokenEnv)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := config.Load()
	if err == nil {
		cfg.WriteSourceLocatorSettings(config.SourceLocatorSettings{
			Enabled: enabled, TargetRevision: revision, BaseURL: baseURL, Project: project,
			APIPrefix: apiPrefix, TimeoutSeconds: timeout, MaxRetries: retries,
			VerifyTLS: verifyTLS, AuthMode: authMode, TokenEnv: tokenEnv,
		})
		err = config.Save(cfg)
	}
	if err != nil {
		sourceLocatorJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": settingsOpenGrokData(cfg, nil), "errors": []string{}})
}

type runtimeComponentStatus struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	Source string `json:"source,omitempty"`
	Found  bool   `json:"found"`
	Note   string `json:"note,omitempty"`
}

func projectToolchainCandidates(root string) []string {
	result := []string{}
	if explicit := strings.TrimSpace(os.Getenv("VULNFOUNDER_DYNAMIC_TOOLCHAIN")); explicit != "" {
		result = append(result, explicit)
	}
	if root != "" {
		result = append(result, filepath.Join(root, "runtime", "openharmony"), filepath.Join(root, "assets", "toolchains"))
	}
	return result
}

func expandToolchainRoot(candidate string) string {
	info, err := os.Stat(candidate)
	if err != nil || !info.IsDir() {
		return ""
	}
	if _, err := os.Stat(filepath.Join(candidate, "sdk", "default", "openharmony", "toolchains")); err == nil {
		return candidate
	}
	entries, _ := os.ReadDir(candidate)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		child := filepath.Join(candidate, entry.Name())
		if _, err := os.Stat(filepath.Join(child, "sdk", "default", "openharmony", "toolchains")); err == nil {
			return child
		}
	}
	return ""
}

func runtimeStatusData() map[string]any {
	root, _ := config.ProjectRoot()
	rootText := root
	candidates := projectToolchainCandidates(rootText)
	toolchain := ""
	for _, candidate := range candidates {
		if resolved := expandToolchainRoot(candidate); resolved != "" {
			toolchain = resolved
			break
		}
	}
	components := []runtimeComponentStatus{}
	add := func(name, path, source string, executable bool) {
		info, err := os.Stat(path)
		found := err == nil && !info.IsDir()
		note := ""
		if found && executable {
			if info.Mode()&0111 == 0 {
				found = false
				note = "文件存在但没有可执行权限"
			}
		}
		components = append(components, runtimeComponentStatus{Name: name, Path: path, Source: source, Found: found, Note: note})
	}
	if toolchain != "" {
		add("HDC", filepath.Join(toolchain, "sdk/default/openharmony/toolchains/hdc"), "项目内 OpenHarmony 工具链", true)
		add("Hvigor", filepath.Join(toolchain, "hvigor/bin/hvigorw"), "项目内 OpenHarmony 工具链", true)
		add("Node", filepath.Join(toolchain, "tool/node/bin/node"), "项目内 OpenHarmony 工具链", true)
		add("HAP 签名工具", filepath.Join(toolchain, "sdk/default/openharmony/toolchains/lib/hap-sign-tool.jar"), "项目内 OpenHarmony 工具链", false)
		add("HAP SDK 自动签名根材料", filepath.Join(toolchain, "sdk/default/openharmony/toolchains/lib/OpenHarmony.p12"), "项目内 OpenHarmony 工具链", false)
		for i := range components {
			if components[i].Name == "HAP SDK 自动签名根材料" && components[i].Found {
				components[i].Note = "动态测试可按当前 HDC serial 临时生成设备绑定 debug profile；不等同于生产证书"
			}
		}
	} else {
		if hdc, err := exec.LookPath("hdc"); err == nil {
			add("HDC", hdc, "系统 PATH", true)
		} else {
			components = append(components, runtimeComponentStatus{Name: "HDC", Found: false, Note: "项目内工具链和 PATH 均未找到"})
		}
	}
	certDir := strings.TrimSpace(os.Getenv("VULNFOUNDER_HAP_CERT_DIR"))
	if certDir == "" && rootText != "" {
		certDir = filepath.Join(rootText, "config", "hap_cert")
	}
	releaseNames := []string{"oh_release_chain.cer", "oh_profile8.p7b", "oh_release.p12"}
	releaseFound := true
	for _, name := range releaseNames {
		path := filepath.Join(certDir, name)
		if _, err := os.Stat(path); err != nil {
			releaseFound = false
		}
	}
	if releaseFound {
		for _, name := range releaseNames {
			add("HAP release 证书/"+name, filepath.Join(certDir, name), "项目内本地签名目录", false)
		}
	} else {
		// 交付包可带有研究用途 debug profile。它与 release 证书分开标识，
		// 便于用户知道设备是否接受该签名，而不会误认为是生产证书。
		for _, name := range []string{"app-cert.pem", "debug-profile.p7b", "debug.p12"} {
			itemName := "HAP debug 证书/" + name
			itemPath := filepath.Join(certDir, "debug", name)
			add(itemName, itemPath, "项目内本地研究签名目录", false)
			// 文件存在不等于它能被当前 hap-sign-tool 或目标设备接受。
			// 特别是 profile 具有版本、设备 ID 和有效期约束，不能仅靠
			// os.Stat 把它展示成“可安装”。
			if name == "debug-profile.p7b" {
				for i := range components {
					if components[i].Name == itemName && components[i].Found {
						components[i].Note = "仅研究用途；不会自动使用。需显式选择 debug，并验证 profile 与工具链及开发板匹配"
					}
				}
			}
		}
	}
	host := []runtimeComponentStatus{}
	for _, name := range []string{"python3", "go", "java"} {
		if path, err := exec.LookPath(name); err == nil {
			host = append(host, runtimeComponentStatus{Name: name, Path: path, Source: "系统 PATH", Found: true})
		} else {
			host = append(host, runtimeComponentStatus{Name: name, Found: false, Source: "系统 PATH"})
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
	return map[string]any{
		"project_root":         rootText,
		"toolchain_root":       toolchain,
		"toolchain_candidates": candidates,
		"components":           components,
		"host_dependencies":    host,
		"cert_policy":          "签名私钥只在本机受保护目录使用，页面和日志不显示内容；目录或文件缺失会在签名前阻止构建。",
	}
}

func (s *Server) handleSettingsRuntime(w http.ResponseWriter, r *http.Request) {
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": runtimeStatusData(), "errors": []string{}})
}
