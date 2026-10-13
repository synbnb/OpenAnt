package python

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPythonOverridePrefersVulnFounderEnvironment(t *testing.T) {
	t.Setenv("VULNFOUNDER_PYTHON", "/new/python")
	t.Setenv("OPENANT_PYTHON", "/legacy/python")
	value, source := pythonOverride()
	if value != "/new/python" || source != "VULNFOUNDER_PYTHON" {
		t.Fatalf("pythonOverride = (%q, %q)", value, source)
	}
}

func TestPythonOverrideFallsBackToLegacyEnvironment(t *testing.T) {
	t.Setenv("VULNFOUNDER_PYTHON", "")
	t.Setenv("OPENANT_PYTHON", "/legacy/python")
	value, source := pythonOverride()
	if value != "/legacy/python" || source != "OPENANT_PYTHON" {
		t.Fatalf("pythonOverride = (%q, %q)", value, source)
	}
}

func TestManagedVenvUsesFreshVulnFounderDataRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataRoot := filepath.Join(home, "result")
	t.Setenv("VULNFOUNDER_DATA_DIR", dataRoot)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	got := venvDir()
	want := filepath.Join(dataRoot, "venv")
	if got != want {
		t.Fatalf("venvDir = %q, want %q", got, want)
	}
}

func TestManagedVenvIgnoresLegacyRuntimeRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataRoot := filepath.Join(home, "result")
	t.Setenv("VULNFOUNDER_DATA_DIR", dataRoot)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	legacy := filepath.Join(home, ".vulnfounder")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatalf("mkdir legacy data: %v", err)
	}
	want := filepath.Join(dataRoot, "venv")
	if got := venvDir(); got != want {
		t.Fatalf("venvDir = %q, want canonical %q", got, want)
	}
}
