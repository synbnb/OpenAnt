package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestLLMConfig(t *testing.T, home, body string) {
	t.Helper()
	configDir := filepath.Join(home, "openant")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", home)
	// Keep the credential-status assertions deterministic without ever putting
	// a real secret into the rendered page.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
}

func renderIndexForTest(t *testing.T, outDir string) string {
	t.Helper()
	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.handleIndex(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func TestIndexShowsActiveOpenAIConfigWithoutAnthropicField(t *testing.T) {
	home := t.TempDir()
	writeTestLLMConfig(t, home, `{
  "$schema_version": 2,
  "default_llm": "openharmony-live-gpt",
  "llm_providers": {
    "autodl-openai": {
      "type": "openai",
      "api_key": "secret-openai-key",
      "base_url": "https://proxy.example/v1"
    }
  },
  "llm_configs": {
    "openharmony-live-gpt": {
      "analyze": {"provider": "autodl-openai", "model": "gpt-5.6-luna"},
      "verify": {"provider": "autodl-openai", "model": "gpt-5.6-luna"}
    }
  }
}`)

	body := renderIndexForTest(t, filepath.Join(home, "webui"))
	for _, want := range []string{"openharmony-live-gpt", "autodl-openai", "(openai)", "gpt-5.6-luna", "https://proxy.example/v1", "configured in config.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("index is missing %q", want)
		}
	}
	for _, forbidden := range []string{"Anthropic API Key", "LLM API Key (legacy Anthropic mode)", "secret-openai-key"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("index contains forbidden legacy/secret text %q", forbidden)
		}
	}
}

func TestIndexUsesBuiltinVulnFounderConfigWithoutV2Config(t *testing.T) {
	home := t.TempDir()
	writeTestLLMConfig(t, home, `{}`)
	body := renderIndexForTest(t, filepath.Join(home, "webui"))
	for _, want := range []string{"vulnfounder-default", "anthropic", "LLM API Key (legacy Anthropic mode)"} {
		if !strings.Contains(body, want) {
			t.Errorf("builtin index is missing %q", want)
		}
	}
	if strings.Contains(body, "Phase model bindings") {
		t.Error("built-in legacy config unexpectedly rendered custom phase bindings")
	}
}
