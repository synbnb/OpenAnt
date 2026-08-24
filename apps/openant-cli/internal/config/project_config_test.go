package config

import (
	"os"
	"path/filepath"
	"testing"
)

func makeProjectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "libs", "openant-core"), 0o755); err != nil {
		t.Fatalf("mkdir core marker: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "config", "openant"), 0o700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	for _, marker := range []string{
		filepath.Join(root, "libs", "openant-core", "pyproject.toml"),
		filepath.Join(root, "config", "models.json"),
	} {
		if err := os.WriteFile(marker, []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("write marker %s: %v", marker, err)
		}
	}
	return root
}

func TestPathUsesExplicitConfigFile(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "portable.json")
	t.Setenv(ConfigFileEnv, explicit)
	t.Setenv(ProjectRootEnv, "")

	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != explicit {
		t.Fatalf("Path = %q, want %q", got, explicit)
	}
}

func TestProjectConfigWinsAndSaveTargetsProjectPath(t *testing.T) {
	root := makeProjectRoot(t)
	local := filepath.Join(root, filepath.FromSlash(ProjectConfigRelativePath))
	if err := os.WriteFile(local, []byte(`{"default_llm":"project"}`), 0o600); err != nil {
		t.Fatalf("write local config: %v", err)
	}
	legacyHome := t.TempDir()
	t.Setenv(ConfigFileEnv, "")
	t.Setenv(ProjectRootEnv, root)
	t.Setenv("XDG_CONFIG_HOME", legacyHome)
	legacyDir := filepath.Join(legacyHome, "openant")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("mkdir legacy config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{"default_model":"legacy"}`), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	path, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if path != local {
		t.Fatalf("Path = %q, want project path %q", path, local)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultLLMName() != "project" {
		t.Fatalf("Load selected %q, want project config", cfg.DefaultLLMName())
	}
	cfg.DefaultModel = "project-model"
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(local)
	if err != nil {
		t.Fatalf("stat saved project config: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("saved project config mode = %o, want 600", mode)
	}
}

func TestLoadFallsBackToLegacyWhenProjectFileMissing(t *testing.T) {
	root := makeProjectRoot(t)
	legacyHome := t.TempDir()
	t.Setenv(ConfigFileEnv, "")
	t.Setenv(ProjectRootEnv, root)
	t.Setenv("XDG_CONFIG_HOME", legacyHome)
	legacyDir := filepath.Join(legacyHome, "openant")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("mkdir legacy config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(`{"default_llm":"legacy"}`), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultLLMName() != "legacy" {
		t.Fatalf("Load selected %q, want legacy fallback", cfg.DefaultLLMName())
	}
	resolved, err := ResolvedPath()
	if err != nil {
		t.Fatalf("ResolvedPath: %v", err)
	}
	want := filepath.Join(legacyDir, "config.json")
	if resolved != want {
		t.Fatalf("ResolvedPath = %q, want %q", resolved, want)
	}
}
