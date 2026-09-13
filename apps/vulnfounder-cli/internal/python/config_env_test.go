package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithConfigEnvUsesExplicitResolvedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("VULNFOUNDER_CONFIG_FILE", path)
	t.Setenv("OPENANT_CONFIG_FILE", "")

	env := withConfigEnv([]string{"KEEP=1", "VULNFOUNDER_CONFIG_FILE=old"})
	want := "VULNFOUNDER_CONFIG_FILE=" + path
	found := false
	for _, entry := range env {
		if entry == want {
			found = true
		}
		if strings.HasPrefix(entry, "VULNFOUNDER_CONFIG_FILE=") && entry != want {
			t.Fatalf("stale config path remained: %q", entry)
		}
	}
	if !found {
		t.Fatalf("config path not injected: %v", env)
	}
}

func TestWithConfigEnvPreservesExistingEnvironment(t *testing.T) {
	t.Setenv("VULNFOUNDER_CONFIG_FILE", filepath.Join(t.TempDir(), "config.json"))
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
	t.Setenv("VULNFOUNDER_CONFIG_FILE", secretPath)
	env := withConfigEnv(nil)
	for _, entry := range env {
		if strings.Contains(entry, "must-not-be-copied") {
			t.Fatalf("secret leaked into process environment: %q", entry)
		}
	}
}

func TestWithConfigEnvLeavesImplicitMissingPathUnset(t *testing.T) {
	// Keep the implicit legacy lookup isolated from the developer's real
	// configuration. A temporary Go test executable cannot be used to discover
	// the checkout root, so ResolvedPath returns this missing user path.
	t.Setenv("VULNFOUNDER_CONFIG_FILE", "")
	t.Setenv("OPENANT_CONFIG_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	env := withConfigEnv([]string{"KEEP=1"})
	for _, entry := range env {
		if strings.HasPrefix(entry, "VULNFOUNDER_CONFIG_FILE=") {
			t.Fatalf("implicit missing config path should not be passed: %q", entry)
		}
	}
}

func TestWithConfigEnvTranslatesLegacyOverrideToPrimaryName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-config.json")
	t.Setenv("VULNFOUNDER_CONFIG_FILE", "")
	t.Setenv("OPENANT_CONFIG_FILE", path)

	env := withConfigEnv([]string{"KEEP=1"})
	want := "VULNFOUNDER_CONFIG_FILE=" + path
	for _, entry := range env {
		if entry == want {
			return
		}
	}
	t.Fatalf("legacy override was not translated for Python: %v", env)
}
