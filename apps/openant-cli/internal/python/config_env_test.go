package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithConfigEnvUsesExplicitResolvedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("OPENANT_CONFIG_FILE", path)

	env := withConfigEnv([]string{"KEEP=1", "OPENANT_CONFIG_FILE=old"})
	want := "OPENANT_CONFIG_FILE=" + path
	found := false
	for _, entry := range env {
		if entry == want {
			found = true
		}
		if strings.HasPrefix(entry, "OPENANT_CONFIG_FILE=") && entry != want {
			t.Fatalf("stale config path remained: %q", entry)
		}
	}
	if !found {
		t.Fatalf("config path not injected: %v", env)
	}
}

func TestWithConfigEnvPreservesExistingEnvironment(t *testing.T) {
	t.Setenv("OPENANT_CONFIG_FILE", filepath.Join(t.TempDir(), "config.json"))
	env := withConfigEnv([]string{"KEEP=1"})
	if len(env) < 2 {
		t.Fatalf("expected original and config environment entries, got %v", env)
	}
	if env[0] != "KEEP=1" {
		t.Fatalf("existing environment changed: %v", env)
	}
}

func TestWithConfigEnvDoesNotExposeSecrets(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "config-with-secret.json")
	if err := os.WriteFile(secretPath, []byte(`{"api_key":"must-not-be-copied"}`), 0o600); err != nil {
		t.Fatalf("write secret fixture: %v", err)
	}
	t.Setenv("OPENANT_CONFIG_FILE", secretPath)
	env := withConfigEnv(nil)
	for _, entry := range env {
		if strings.Contains(entry, "must-not-be-copied") {
			t.Fatalf("secret leaked into process environment: %q", entry)
		}
	}
}
