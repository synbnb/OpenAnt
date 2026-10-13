package server

// Settings endpoints keep model/provider selection in one place.  Scan and
// device-discovery forms deliberately do not accept a per-request model
// selector anymore: changing the default here changes the next run of every
// stage in a predictable way.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"vulnfounder/apps/vulnfounder-cli/internal/config"
)

var settingsProviderTypes = map[string]struct{}{
	"openai":     {},
	"anthropic":  {},
	"openrouter": {},
	"google":     {},
	"bedrock":    {},
	"custom":     {},
}

var settingsPhases = []string{
	"analyze",
	"enhance",
	"verify",
	"report",
	"dynamic_test",
	"llm_reach",
	"app_context",
}

func (s *Server) handleSettingsIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.tmplSettings == nil {
		http.Error(w, "设置页面未初始化", http.StatusInternalServerError)
		return
	}
	if err := s.tmplSettings.Execute(w, struct{ CSRF string }{CSRF: s.csrfToken}); err != nil {
		http.Error(w, "设置页面渲染失败", http.StatusInternalServerError)
	}
}

// settingsLLMData intentionally contains no API-key value.  It is safe to
// render in HTML or return as JSON; credential_status only says where a
// credential was found.
func settingsLLMData(cfg *config.Config, loadErr error) map[string]any {
	status := buildLLMStatus(cfg)
	configs := make([]map[string]any, 0, len(status.Configs))
	for _, option := range status.Configs {
		phaseRows := make([]map[string]string, 0)
		providerNames := make(map[string]struct{})
		if cfg != nil {
			for _, phase := range cfg.LLMPhaseSummaries(option.Name) {
				phaseRows = append(phaseRows, map[string]string{
					"phase": phase.Phase, "provider": phase.Provider, "model": phase.Model,
				})
				providerNames[phase.Provider] = struct{}{}
			}
		}
		// The built-in config is supplied by the Python runtime, so it has no
		// JSON phase map.  Still show the credential source users need to fix.
		if len(providerNames) == 0 && config.IsBuiltinLLMConfigName(option.Name) {
			providerNames["anthropic"] = struct{}{}
		}
		providerRows := make([]map[string]any, 0, len(providerNames))
		for providerName := range providerNames {
			entry, found := config.ProviderEntry{}, false
			if cfg != nil {
				entry, found = cfg.GetProvider(providerName)
			}
			providerType := strings.TrimSpace(entry.Type)
			if providerType == "" && providerName == "anthropic" {
				providerType = "anthropic"
			}
			if providerType == "" {
				providerType = "custom"
			}
			providerRows = append(providerRows, map[string]any{
				"name":                  providerName,
				"type":                  providerType,
				"base_url":              entry.BaseURL,
				"credential_status":     llmCredentialStatus(entry, providerType),
				"credential_configured": llmCredentialStatus(entry, providerType) != "not detected",
				"auth_managed":          found && entry.APIKey == "" && llmCredentialStatus(entry, providerType) != "not detected",
			})
		}
		configs = append(configs, map[string]any{
			"name":      option.Name,
			"selected":  option.Selected,
			"builtin":   config.IsBuiltinLLMConfigName(option.Name),
			"phases":    phaseRows,
			"providers": providerRows,
		})
	}
	path, pathErr := config.Path()
	data := map[string]any{
		"available":       status.Available,
		"default_name":    status.ConfigName,
		"configs":         configs,
		"credential_hint": status.CredentialHint,
		"config_path":     path,
		"phase_names":     settingsPhases,
		"secret_policy":   "API Key 只保存在本地配置文件或环境变量中，页面不会回显密钥。",
	}
	if pathErr != nil {
		data["config_path_error"] = pathErr.Error()
	}
	if loadErr != nil {
		data["error"] = "读取模型配置失败：" + loadErr.Error()
	}
	return data
}

func (s *Server) handleSettingsLLM(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load()
	data := settingsLLMData(cfg, err)
	status := http.StatusOK
	envelopeStatus := "success"
	errorsList := []string{}
	if err != nil {
		status = http.StatusInternalServerError
		envelopeStatus = "error"
		errorsList = []string{err.Error()}
	}
	sourceLocatorJSON(w, status, map[string]any{
		"status": envelopeStatus,
		"data":   data,
		"errors": errorsList,
	})
}

func settingsRequiredName(fields sourceLocatorRequestFields, key string, max int) (string, error) {
	value, err := sourceLocatorString(fields, key, max)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("%s 不能为空", key)
	}
	if !sourceLocatorLLMConfigRe.MatchString(value) {
		return "", fmt.Errorf("%s 只能包含字母、数字、点、下划线和连字符", key)
	}
	return value, nil
}

func settingsRequiredText(fields sourceLocatorRequestFields, key string, max int) (string, error) {
	value, err := sourceLocatorString(fields, key, max)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("%s 不能为空", key)
	}
	for _, r := range value {
		if r == '\x00' || r == '\r' || r == '\n' || r == '\t' {
			return "", fmt.Errorf("%s 不能包含控制字符", key)
		}
	}
	return value, nil
}

func settingsProviderType(fields sourceLocatorRequestFields) (string, error) {
	value, err := sourceLocatorString(fields, "provider_type", 32)
	if err != nil {
		return "", err
	}
	value = strings.ToLower(value)
	if value == "" {
		return "", errors.New("provider_type 不能为空")
	}
	if _, ok := settingsProviderTypes[value]; !ok {
		return "", errors.New("provider_type 不受支持")
	}
	return value, nil
}

func settingsBaseURL(fields sourceLocatorRequestFields) (string, error) {
	value, err := sourceLocatorString(fields, "base_url", 2048)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", errors.New("base_url 必须是不包含凭据的 http/https URL")
	}
	return value, nil
}

// settingsMutationAllowed is kept separate in naming, while sharing the
// already-audited same-origin and constant-time CSRF implementation.
func (s *Server) settingsMutationAllowed(w http.ResponseWriter, r *http.Request, fields sourceLocatorRequestFields) bool {
	return s.sourceLocatorMutationAllowed(w, r, fields)
}

func (s *Server) handleSettingsLLMSave(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.settingsMutationAllowed(w, r, fields) {
		return
	}
	name, err := settingsRequiredName(fields, "name", 128)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if config.IsBuiltinLLMConfigName(name) {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"内置模型配置不可覆盖，请新建一个自定义名称"}})
		return
	}
	providerName, err := settingsRequiredName(fields, "provider_name", 128)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	providerType, err := settingsProviderType(fields)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	model, err := settingsRequiredText(fields, "model", 256)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	baseURL, err := settingsBaseURL(fields)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	apiKey, err := sourceLocatorString(fields, "api_key", 4096)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	makeDefault, err := sourceLocatorBool(fields, "make_default", false)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := config.Load()
	if err == nil && apiKey == "" {
		if existing, ok := cfg.GetProvider(providerName); ok {
			// Blank means “keep the existing secret” during an edit.  The
			// browser never needs to read the secret to update non-secret fields.
			apiKey = existing.APIKey
		}
	}
	if err == nil {
		phases := make(map[string]config.LLMPhaseRef, len(settingsPhases))
		for _, phase := range settingsPhases {
			phases[phase] = config.LLMPhaseRef{Provider: providerName, Model: model}
		}
		cfg.WriteLLMConfig(name, phases, map[string]config.ProviderEntry{
			providerName: {Type: providerType, APIKey: apiKey, BaseURL: baseURL},
		}, false)
		if makeDefault {
			err = cfg.SetDefaultLLM(name)
		}
	}
	if err == nil {
		err = config.Save(cfg)
	}
	if err != nil {
		sourceLocatorJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": settingsLLMData(cfg, nil), "errors": []string{}})
}

func (s *Server) handleSettingsLLMDefault(w http.ResponseWriter, r *http.Request) {
	fields, err := readSourceLocatorFields(r)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	if !s.settingsMutationAllowed(w, r, fields) {
		return
	}
	name, err := settingsRequiredName(fields, "name", 128)
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := config.Load()
	if err == nil {
		err = cfg.SetDefaultLLM(name)
	}
	if err == nil {
		err = config.Save(cfg)
	}
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": settingsLLMData(cfg, nil), "errors": []string{}})
}

func (s *Server) handleSettingsLLMDelete(w http.ResponseWriter, r *http.Request) {
	if !s.settingsMutationAllowed(w, r, nil) {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if !sourceLocatorLLMConfigRe.MatchString(name) {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{"模型配置名不安全"}})
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	cfg, err := config.Load()
	if err == nil {
		err = cfg.DeleteLLMConfig(name)
	}
	if err == nil {
		err = config.Save(cfg)
	}
	if err != nil {
		sourceLocatorJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "data": map[string]any{}, "errors": []string{err.Error()}})
		return
	}
	sourceLocatorJSON(w, http.StatusOK, map[string]any{"status": "success", "data": settingsLLMData(cfg, nil), "errors": []string{}})
}
