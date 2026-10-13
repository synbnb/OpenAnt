package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func isolateBrandingEnvironment(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
		t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	} else {
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	}
	for _, key := range []string{
		"VULNFOUNDER_CONFIG_FILE",
		"OPENANT_CONFIG_FILE",
		"VULNFOUNDER_PROJECT_ROOT",
		"OPENANT_PROJECT_ROOT",
		"VULNFOUNDER_DATA_DIR",
	} {
		t.Setenv(key, "")
	}
	// Tests that exercise project data APIs use an explicit portable data root;
	// production code must never infer a home-directory runtime location.
	t.Setenv("VULNFOUNDER_DATA_DIR", filepath.Join(home, "result"))
	return home
}

func TestVulnFounderBrandConstantsArePrimary(t *testing.T) {
	if ConfigFileEnv != "VULNFOUNDER_CONFIG_FILE" {
		t.Fatalf("ConfigFileEnv = %q", ConfigFileEnv)
	}
	if LegacyConfigFileEnv != "OPENANT_CONFIG_FILE" {
		t.Fatalf("LegacyConfigFileEnv = %q", LegacyConfigFileEnv)
	}
	if ProjectRootEnv != "VULNFOUNDER_PROJECT_ROOT" {
		t.Fatalf("ProjectRootEnv = %q", ProjectRootEnv)
	}
	if LegacyProjectRootEnv != "OPENANT_PROJECT_ROOT" {
		t.Fatalf("LegacyProjectRootEnv = %q", LegacyProjectRootEnv)
	}
	if ProjectConfigRelativePath != "config/vulnfounder/config.json" {
		t.Fatalf("ProjectConfigRelativePath = %q", ProjectConfigRelativePath)
	}
}

func TestConfigPathPrefersNewEnvironmentVariable(t *testing.T) {
	isolateBrandingEnvironment(t)
	newPath := filepath.Join(t.TempDir(), "vulnfounder.json")
	oldPath := filepath.Join(t.TempDir(), "openant.json")
	t.Setenv("VULNFOUNDER_CONFIG_FILE", newPath)
	t.Setenv("OPENANT_CONFIG_FILE", oldPath)

	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != newPath {
		t.Fatalf("Path = %q, want new config %q", got, newPath)
	}
}

func TestConfigPathFallsBackToLegacyEnvironmentVariable(t *testing.T) {
	isolateBrandingEnvironment(t)
	legacyPath := filepath.Join(t.TempDir(), "openant.json")
	t.Setenv("OPENANT_CONFIG_FILE", legacyPath)

	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != legacyPath {
		t.Fatalf("Path = %q, want legacy config %q", got, legacyPath)
	}
}

func TestDataDirUsesVulnFounderForFreshInstall(t *testing.T) {
	home := isolateBrandingEnvironment(t)
	got, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	want := filepath.Join(home, "result")
	if got != want {
		t.Fatalf("DataDir = %q, want %q", got, want)
	}
}

func TestDataDirRejectsUnownedGlobalRuntime(t *testing.T) {
	isolateBrandingEnvironment(t)
	t.Setenv("VULNFOUNDER_DATA_DIR", "")
	if _, err := DataDir(); err == nil {
		t.Fatal("DataDir should require a project root or explicit data directory")
	}
}

func TestDataDirExplicitOverrideWinsOverLegacyHistory(t *testing.T) {
	home := isolateBrandingEnvironment(t)
	if err := os.MkdirAll(filepath.Join(home, "result"), 0o700); err != nil {
		t.Fatalf("mkdir legacy data: %v", err)
	}
	override := filepath.Join(t.TempDir(), "vulnfounder-data")
	t.Setenv("VULNFOUNDER_DATA_DIR", override)

	got, err := DataDir()
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	if got != override {
		t.Fatalf("DataDir = %q, want override %q", got, override)
	}
}
