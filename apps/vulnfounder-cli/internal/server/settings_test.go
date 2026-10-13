package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vulnfounder/apps/vulnfounder-cli/internal/config"
)

func settingsRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("X-CSRF-Token", "token")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestSettingsLLMReadIsSecretFree(t *testing.T) {
	home := t.TempDir()
	writeTestLLMConfig(t, home, `{
  "$schema_version": 2,
  "default_llm": "custom-a",
  "llm_providers": {"private": {"type": "openai", "api_key": "super-secret", "base_url": "https://example.test/v1"}},
  "llm_configs": {"custom-a": {"analyze": {"provider": "private", "model": "qwen/qwen-3-coder"}}}
}`)
	s := &Server{csrfToken: "token"}
	rec := httptest.NewRecorder()
	s.handleSettingsLLM(rec, httptest.NewRequest(http.MethodGet, "/settings/llm", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET settings status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "super-secret") {
		t.Fatal("settings response leaked API key")
	}
	for _, want := range []string{"custom-a", "qwen/qwen-3-coder", "https://example.test/v1", "credential_status"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings response missing %q", want)
		}
	}
}

func TestSettingsLLMCreateSelectAndDelete(t *testing.T) {
	home := t.TempDir()
	writeTestLLMConfig(t, home, `{}`)
	s := &Server{csrfToken: "token"}
	create := settingsRequest(http.MethodPost, "/settings/llm/configs", `{"name":"team-model","provider_name":"proxy","provider_type":"openai","model":"deepseek-v4-flash","base_url":"https://proxy.example/v1","api_key":"secret-value","make_default":true}`)
	rec := httptest.NewRecorder()
	s.handleSettingsLLMSave(rec, create)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "team-model") {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-value") {
		t.Fatal("create response leaked API key")
	}
	cfg, err := config.Load()
	if err != nil || cfg.DefaultLLMName() != "team-model" || !cfg.LLMConfigExists("team-model") {
		t.Fatalf("created config was not persisted: err=%v default=%q exists=%v", err, cfg.DefaultLLMName(), cfg.LLMConfigExists("team-model"))
	}

	selectReq := settingsRequest(http.MethodPost, "/settings/llm/default", `{"name":"vulnfounder-default"}`)
	rec = httptest.NewRecorder()
	s.handleSettingsLLMDefault(rec, selectReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("select builtin status=%d body=%s", rec.Code, rec.Body.String())
	}
	cfg, _ = config.Load()
	if cfg.DefaultLLMName() != config.DefaultLLMConfigName {
		t.Fatalf("default selection not persisted: %q", cfg.DefaultLLMName())
	}

	deleteReq := settingsRequest(http.MethodDelete, "/settings/llm/configs/team-model", "")
	deleteReq.Header.Del("Content-Type")
	deleteReq.SetPathValue("name", "team-model")
	rec = httptest.NewRecorder()
	s.handleSettingsLLMDelete(rec, deleteReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	cfg, _ = config.Load()
	if cfg.LLMConfigExists("team-model") {
		t.Fatal("deleted config is still present")
	}

	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode delete envelope: %v", err)
	}
}

func TestSettingsLLMRejectsCrossOriginMutation(t *testing.T) {
	s := &Server{csrfToken: "token"}
	req := settingsRequest(http.MethodPost, "/settings/llm/default", `{"name":"vulnfounder-default"}`)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	s.handleSettingsLLMDefault(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin settings mutation status=%d, want 403", rec.Code)
	}
}

func TestSettingsOpenGrokReadAndSaveIsSecretFree(t *testing.T) {
	home := t.TempDir()
	writeTestLLMConfig(t, home, `{
  "source_locator": {
    "enabled": true,
    "target_revision": "OpenHarmony-6.1-LTS",
    "opengrok": {
      "base_url": "https://source.example/source",
      "project": "openharmony",
      "api_prefix": "/api/v1",
      "timeout_seconds": 20,
      "max_retries": 1,
      "verify_tls": true,
      "auth": {"mode": "bearer_env", "token_env": "OPENGROK_TOKEN"}
    }
  },
  "private_token": "must-not-render"
}`)
	s := &Server{csrfToken: "token"}
	rec := httptest.NewRecorder()
	s.handleSettingsOpenGrok(rec, httptest.NewRequest(http.MethodGet, "/settings/opengrok", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "must-not-render") || !strings.Contains(rec.Body.String(), "source.example") {
		t.Fatalf("OpenGrok GET status=%d body=%s", rec.Code, rec.Body.String())
	}

	req := settingsRequest(http.MethodPost, "/settings/opengrok", `{
  "enabled": true,
  "target_revision": "OpenHarmony-6.1-LTS",
  "base_url": "https://new.example/source",
  "project": "openharmony",
  "api_prefix": "/api/v1",
  "timeout_seconds": "25",
  "max_retries": "2",
  "verify_tls": true,
  "auth_mode": "bearer_env",
  "token_env": "OPENGROK_TOKEN"
}`)
	rec = httptest.NewRecorder()
	s.handleSettingsOpenGrokSave(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "new.example") {
		t.Fatalf("OpenGrok save status=%d body=%s", rec.Code, rec.Body.String())
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load after OpenGrok save: %v", err)
	}
	got := cfg.GetSourceLocatorSettings()
	if got.BaseURL != "https://new.example/source" || got.MaxRetries != 2 || got.TokenEnv != "OPENGROK_TOKEN" {
		t.Fatalf("saved OpenGrok settings mismatch: %+v", got)
	}
}

func TestSettingsOpenGrokRejectsCredentialsAndHTTP(t *testing.T) {
	s := &Server{csrfToken: "token"}
	for _, body := range []string{
		`{"base_url":"http://127.0.0.1:8080/source"}`,
		`{"base_url":"https://user:pass@example/source"}`,
		`{"base_url":"https://example/source?token=secret"}`,
	} {
		req := settingsRequest(http.MethodPost, "/settings/opengrok", body)
		rec := httptest.NewRecorder()
		s.handleSettingsOpenGrokSave(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unsafe OpenGrok URL status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}
