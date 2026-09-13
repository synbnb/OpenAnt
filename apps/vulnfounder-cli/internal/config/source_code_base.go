package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SourceCodeBaseEnv is the canonical override for the project-local source
// corpus. It is intentionally an environment variable rather than a user
// specific absolute path so packaged VulnFounder copies can be relocated.
const SourceCodeBaseEnv = "VULNFOUNDER_SOURCE_CODE_BASE"

// LegacySourceCodeBaseEnv keeps existing launch scripts working during the
// rename window.
const LegacySourceCodeBaseEnv = "OPENANT_SOURCE_CODE_BASE"

// SourceCodeBaseDir resolves the project-local source corpus used by the Web
// repository catalog. An explicit override wins. Without one, the resolver
// searches ancestors of both the current working directory and the executable
// directory for a directory named source_code_base.
//
// An empty result with nil error means no project-local corpus is present. The
// Web UI can then continue to expose initialized projects, recent scans, and
// manual repository input without treating a normal installation as broken.
func SourceCodeBaseDir() (string, error) {
	raw := strings.TrimSpace(os.Getenv(SourceCodeBaseEnv))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(LegacySourceCodeBaseEnv))
	}
	if raw != "" {
		path, err := filepath.Abs(raw)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", SourceCodeBaseEnv, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("%s points to an unavailable directory %q: %w", SourceCodeBaseEnv, path, err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%s must point to a directory, got %q", SourceCodeBaseEnv, path)
		}
		return filepath.Clean(path), nil
	}

	seen := make(map[string]struct{})
	for _, base := range sourceCodeBaseSearchBases() {
		for _, candidateBase := range ancestorPaths(base) {
			candidate := filepath.Join(candidateBase, "source_code_base")
			candidate = filepath.Clean(candidate)
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", nil
}

func sourceCodeBaseSearchBases() []string {
	var bases []string
	if cwd, err := os.Getwd(); err == nil {
		bases = append(bases, cwd)
	}
	if executable, err := os.Executable(); err == nil {
		if abs, err := filepath.Abs(executable); err == nil {
			bases = append(bases, filepath.Dir(abs))
		}
	}
	return bases
}

func ancestorPaths(start string) []string {
	start = filepath.Clean(start)
	if start == "" || start == "." {
		return nil
	}
	var paths []string
	for {
		paths = append(paths, start)
		parent := filepath.Dir(start)
		if parent == start {
			break
		}
		start = parent
	}
	return paths
}
