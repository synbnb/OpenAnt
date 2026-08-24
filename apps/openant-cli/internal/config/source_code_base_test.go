package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceCodeBaseDirUsesExplicitOverride(t *testing.T) {
	root := filepath.Join(t.TempDir(), "corpus")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}
	t.Setenv(SourceCodeBaseEnv, root)

	got, err := SourceCodeBaseDir()
	if err != nil {
		t.Fatalf("SourceCodeBaseDir: %v", err)
	}
	want, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if got != filepath.Clean(want) {
		t.Fatalf("SourceCodeBaseDir = %q, want %q", got, filepath.Clean(want))
	}
}

func TestSourceCodeBaseDirRejectsInvalidExplicitOverride(t *testing.T) {
	t.Setenv(SourceCodeBaseEnv, filepath.Join(t.TempDir(), "missing"))
	if got, err := SourceCodeBaseDir(); err == nil {
		t.Fatalf("SourceCodeBaseDir = %q, want an error for missing override", got)
	}
}

func TestSourceCodeBaseDirFindsWorkingDirectoryAncestor(t *testing.T) {
	projectRoot := t.TempDir()
	corpus := filepath.Join(projectRoot, "source_code_base")
	if err := os.MkdirAll(filepath.Join(corpus, "nested-repo"), 0o750); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}
	workingDir := filepath.Join(projectRoot, "apps", "openant-cli", "bin")
	if err := os.MkdirAll(workingDir, 0o750); err != nil {
		t.Fatalf("mkdir working directory: %v", err)
	}
	t.Chdir(workingDir)
	t.Setenv(SourceCodeBaseEnv, "")

	got, err := SourceCodeBaseDir()
	if err != nil {
		t.Fatalf("SourceCodeBaseDir: %v", err)
	}
	if got != corpus {
		t.Fatalf("SourceCodeBaseDir = %q, want %q", got, corpus)
	}
}
