// Package python handles Python runtime detection and validation.
package python

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config"
)

// MinPythonMajor is the minimum required Python major version.
const MinPythonMajor = 3

// MinPythonMinor is the minimum required Python minor version.
const MinPythonMinor = 11

// RuntimeInfo holds information about the detected Python runtime.
type RuntimeInfo struct {
	Path    string // Full path to the Python binary
	Version string // Version string (e.g., "3.11.5")
	Major   int
	Minor   int
}

// pythonCandidates returns a list of Python binary names to search for, in order of preference.
func pythonCandidates() []string {
	return []string{"python3", "python"}
}

const (
	pythonEnv       = "VULNFOUNDER_PYTHON"
	legacyPythonEnv = "OPENANT_PYTHON"
)

func firstEnvironment(primary, legacy string) (value string, source string) {
	if value := strings.TrimSpace(os.Getenv(primary)); value != "" {
		return value, primary
	}
	if value := strings.TrimSpace(os.Getenv(legacy)); value != "" {
		return value, legacy
	}
	return "", ""
}

func pythonOverride() (value string, source string) {
	return firstEnvironment(pythonEnv, legacyPythonEnv)
}

// venvDir returns the managed venv under the active VulnFounder data root.
func venvDir() string {
	dataDir, err := config.DataDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dataDir, "venv")
}

// venvPython returns the path to the Python binary inside the managed venv.
func venvPython() string {
	base := venvDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(base, "Scripts", "python.exe")
	}
	return filepath.Join(base, "bin", "python")
}

// DetectRuntime finds a suitable Python 3.11+ installation.
//
// Search order:
//  1. VULNFOUNDER_PYTHON (or legacy OPENANT_PYTHON) if set and valid.
//  2. Managed venv under the active VulnFounder data root.
//  3. python3 / python on PATH
//
// The managed-venv path (strategy 2) automatically detects the correct Python
// binary location based on the OS: "bin/python" on Unix-like systems, or
// "Scripts/python.exe" on Windows.
func DetectRuntime() (*RuntimeInfo, error) {
	// Strategy 0: honour the new override, then its legacy alias.
	// If the override is set but unusable, warn and fall through rather than
	// silently using a different interpreter behind the caller's back.
	if override, source := pythonOverride(); override != "" {
		info, err := checkPython(override)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: %s=%q is not a usable Python binary (%v); ignoring override\n",
				source, override, err)
		} else if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: %s=%q is Python %s, below the required %d.%d; ignoring override\n",
				source, override, info.Version, MinPythonMajor, MinPythonMinor)
		}
	}

	// Strategy 1: check managed venv
	vp := venvPython()
	if fileExists(vp) {
		if info, err := checkPython(vp); err == nil {
			if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
				return info, nil
			}
		}
	}

	// Strategy 2: check PATH
	for _, name := range pythonCandidates() {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}

		info, err := checkPython(path)
		if err != nil {
			continue
		}

		if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		}
	}

	return nil, fmt.Errorf(
		"Python %d.%d+ is required but not found on PATH.\n"+
			"Install Python from https://python.org or use your system package manager.",
		MinPythonMajor, MinPythonMinor,
	)
}

// checkPython runs the given binary and extracts version info.
func checkPython(path string) (*RuntimeInfo, error) {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run %s: %w", path, err)
	}

	// Output is "Python X.Y.Z\n"
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Python "))
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexpected version format: %s", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	return &RuntimeInfo{
		Path:    path,
		Version: version,
		Major:   major,
		Minor:   minor,
	}, nil
}

// CheckVulnFounderInstalled verifies that the `vulnfounder` package is importable.
// If the package is missing, it attempts to:
//  1. Locate libs/vulnfounder-core
//  2. Create a managed venv under the active data root
//  3. Install VulnFounder into the venv
//
// On success, it updates the RuntimeInfo to point to the venv Python.
func CheckVulnFounderInstalled(pythonPath string) error {
	if isVulnFounderImportable(pythonPath) {
		return nil
	}

	// Not installed — try to find the source and install it.
	corePath, err := findVulnFounderCore()
	if err != nil {
		return fmt.Errorf(
			"VulnFounder Python package is not installed and could not be located automatically.\n"+
				"Install it with: pip install -e <path-to-vulnfounder-core>\n"+
				"(%s)", err,
		)
	}

	// If we're not already using the managed venv, create one and use it.
	vp := venvPython()
	if pythonPath != vp {
		fmt.Fprintf(os.Stderr, "Creating managed Python environment at %s...\n", venvDir())
		if err := createVenv(pythonPath); err != nil {
			return fmt.Errorf(
				"failed to create venv at %s: %w\n"+
					"Try manually: %s -m venv %s && %s -m pip install -e %s",
				venvDir(), err, pythonPath, venvDir(), vp, corePath,
			)
		}
		pythonPath = vp
	}

	fmt.Fprintf(os.Stderr, "Installing VulnFounder from %s...\n", corePath)
	if err := installVulnFounder(pythonPath, corePath); err != nil {
		return fmt.Errorf(
			"failed to install VulnFounder from %s:\n  %w\n"+
				"Try manually: %s -m pip install -e %s",
			corePath, err, pythonPath, corePath,
		)
	}

	// Verify it actually worked.
	if !isVulnFounderImportable(pythonPath) {
		return fmt.Errorf(
			"pip install succeeded but `import vulnfounder` still fails.\n"+
				"Try manually: %s -m pip install -e %s",
			pythonPath, corePath,
		)
	}

	// Save dependency hash so CheckDepsStale knows this is the baseline.
	if h, err := depsHash(corePath); err == nil {
		if err := writeStoredHash(h); err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: could not save dependency hash at %s: %v (next run may reinstall)\n",
				depsHashPath(), err)
		}
	}

	fmt.Fprintln(os.Stderr, "VulnFounder installed successfully.")
	return nil
}

// CheckOpenantInstalled is retained for source compatibility with older
// integrations. New callers should use CheckVulnFounderInstalled.
func CheckOpenantInstalled(pythonPath string) error {
	return CheckVulnFounderInstalled(pythonPath)
}

// EnsureRuntime is a convenience that detects a runtime, ensures VulnFounder
// is installed (creating a venv if necessary), and returns the final
// RuntimeInfo pointing to the correct Python binary.
func EnsureRuntime() (*RuntimeInfo, error) {
	rt, err := DetectRuntime()
	if err != nil {
		return nil, err
	}

	if err := CheckVulnFounderInstalled(rt.Path); err != nil {
		return nil, err
	}

	// After CheckOpenantInstalled, the venv may have been created.
	// Re-detect to pick up the venv Python if it was just created.
	vp := venvPython()
	if rt.Path != vp && fileExists(vp) && isVulnFounderImportable(vp) {
		if info, err := checkPython(vp); err == nil {
			rt = info
		}
	}

	// Check if dependencies have changed since last install.
	if err := CheckDepsStale(rt.Path); err != nil {
		return nil, err
	}

	return rt, nil
}

// depsHashPath returns the path to the stored dependency hash inside the venv.
func depsHashPath() string {
	return filepath.Join(venvDir(), ".deps-hash")
}

// hashFile returns the hex-encoded SHA-256 of a file's contents.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// readHashAt reads a stored hash from the given path, or "" if absent.
func readHashAt(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// writeHashAt saves a hash to the given path, creating the parent directory
// if it does not already exist.
func writeHashAt(path, hash string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(hash+"\n"), 0644)
}

// readStoredHash reads the previously stored dependency hash, or "" if absent.
func readStoredHash() string { return readHashAt(depsHashPath()) }

// writeStoredHash saves the dependency hash to the venv marker file.
func writeStoredHash(hash string) error { return writeHashAt(depsHashPath(), hash) }

// depsHash keys the dependency stamp on BOTH pyproject.toml contents AND corePath (the
// editable-install source). The managed venv is a single global path shared across worktrees;
// without corePath in the key, two worktrees with identical pyproject.toml share one editable
// install and a binary built in one silently imports the other's source. Including corePath forces
// a reinstall (re-pointing the editable install) when the active source changes.
func depsHash(corePath string) (string, error) {
	pyproject, err := os.ReadFile(filepath.Join(corePath, "pyproject.toml"))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(corePath+"\x00"), pyproject...))
	return hex.EncodeToString(sum[:]), nil
}

// depsStalenessAt inspects pyproject.toml at corePath and the hash stored at
// hashPath, and reports whether a reinstall is needed. The boolean is true
// when deps are stale (i.e. the hash differs and a reinstall is warranted).
// The caller is expected to skip the check on any error.
func depsStalenessAt(corePath, hashPath string) (stale bool, currentHash string, err error) {
	currentHash, err = depsHash(corePath)
	if err != nil {
		return false, "", err
	}
	return currentHash != readHashAt(hashPath), currentHash, nil
}

// depsStaleness is the production wrapper around depsStalenessAt that uses
// the real venv hash path.
func depsStaleness(corePath string) (stale bool, currentHash string, err error) {
	return depsStalenessAt(corePath, depsHashPath())
}

// CheckDepsStale checks if pyproject.toml has changed since the last install.
// If stale, it re-runs pip install -e and updates the stored hash.
// Returns nil if deps are up-to-date or were successfully refreshed.
func CheckDepsStale(pythonPath string) error {
	return checkDepsStaleWith(pythonPath, findVulnFounderCore)
}

// checkDepsStaleWith is the testable core of CheckDepsStale; coreFinder is
// injected so tests can avoid os.Chdir to simulate a missing source tree.
func checkDepsStaleWith(pythonPath string, coreFinder func() (string, error)) error {
	corePath, err := coreFinder()
	if err != nil {
		// Can't find source — skip staleness check
		return nil
	}

	stale, currentHash, err := depsStaleness(corePath)
	if err != nil {
		// Can't read pyproject.toml — skip check
		return nil
	}
	if !stale {
		return nil // deps are up-to-date
	}

	fmt.Fprintln(os.Stderr, "Dependencies changed, updating VulnFounder installation...")
	// Known limitation: concurrent invocations that both detect stale deps
	// will race to pip-install into the same venv. pip does not support
	// concurrent writes; an OS-level lock would be needed to close this gap.
	if err := installVulnFounder(pythonPath, corePath); err != nil {
		return fmt.Errorf(
			"failed to update VulnFounder dependencies: %w\n"+
				"Try manually: %s -m pip install -e %s",
			err, pythonPath, corePath,
		)
	}

	// Store the new hash
	if err := writeStoredHash(currentHash); err != nil {
		// Non-fatal — install succeeded, just can't cache the hash
		fmt.Fprintf(os.Stderr, "Warning: could not save dependency hash: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "Dependencies updated successfully.")
	return nil
}

// createVenv creates a new managed venv using the given Python.
func createVenv(pythonPath string) error {
	dir := venvDir()
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return err
	}
	cmd := exec.Command(pythonPath, "-m", "venv", dir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// isVulnFounderImportable returns true when the primary Python package loads.
func isVulnFounderImportable(pythonPath string) bool {
	cmd := exec.Command(pythonPath, "-c", "from vulnfounder import __version__")
	return cmd.Run() == nil
}

// isOpenantImportable retains the old unexported helper for existing tests.
func isOpenantImportable(pythonPath string) bool {
	return isVulnFounderImportable(pythonPath)
}

// installVulnFounder runs `python -m pip install -e <corePath>`.
func installVulnFounder(pythonPath, corePath string) error {
	cmd := exec.Command(pythonPath, "-m", "pip", "install", "-e", corePath)
	cmd.Stdout = os.Stderr // pip output goes to stderr so it doesn't pollute JSON stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func installOpenant(pythonPath, corePath string) error {
	return installVulnFounder(pythonPath, corePath)
}

// PipUninstall removes the primary distribution and any legacy installation.
func PipUninstall(pythonPath string) *exec.Cmd {
	cmd := exec.Command(pythonPath, "-m", "pip", "uninstall", "vulnfounder", "openant", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd
}

// VulnFounderCoreEnv lets a developer point at a checkout explicitly. It is the ONLY
// way to name a core path that is not derived from the installed executable.
const VulnFounderCoreEnv = "VULNFOUNDER_CORE_PATH"

// OpenantCoreEnv remains as a source-compatible alias for the legacy name.
const OpenantCoreEnv = "OPENANT_CORE_PATH"

// findVulnFounderCore locates the primary core directory to install from.
//
// Resolution order, deliberately narrow:
//  1. $VULNFOUNDER_CORE_PATH or legacy $OPENANT_CORE_PATH.
//  2. Walking up from the running executable — the monorepo/dev layout.
//
// It does NOT search the current working directory, and that omission is the
// whole point of this function.
//
// The caller feeds the result to `pip install -e`, and an editable install
// EXECUTES the target's build backend. Searching upward from CWD therefore meant:
// run the scanner below a repository that happens to ship a matching-looking
// core directory, with the import probe failing, and the CLI
// installs and runs code from that repository.
//
// For a tool whose entire purpose is being pointed at untrusted third-party
// repositories, that turns the scan target into an installation source — remote
// code execution reachable by a repo layout alone. The trigger is conditional
// (the probe must fail first), which makes it latent rather than acceptable: a
// broken venv, a partial upgrade, or a Python version bump is enough.
//
// An operator who genuinely wants a checkout can say so with the env var. What
// they cannot do is have one chosen for them by whatever directory they happened
// to be standing in.
func findVulnFounderCore() (string, error) {
	primaryMarker := filepath.Join("libs", "vulnfounder-core", "pyproject.toml")
	legacyMarker := filepath.Join("libs", "openant-core", "pyproject.toml")

	// Strategy 1: explicit operator override.
	if explicit, source := firstEnvironment(VulnFounderCoreEnv, OpenantCoreEnv); explicit != "" {
		if fileExists(filepath.Join(explicit, "pyproject.toml")) {
			return explicit, nil
		}
		return "", fmt.Errorf(
			"%s=%q does not contain pyproject.toml; point it at libs/vulnfounder-core",
			source, explicit)
	}

	// Strategy 2: walk up from the executable. Trusted because the operator chose
	// which binary to run; the scan target has no say in where it lives.
	if exePath, err := os.Executable(); err == nil {
		exePath, _ = filepath.EvalSymlinks(exePath)
		dir := filepath.Dir(exePath)
		for range 6 { // at most 6 levels up
			if fileExists(filepath.Join(dir, primaryMarker)) {
				return filepath.Join(dir, "libs", "vulnfounder-core"), nil
			}
			if fileExists(filepath.Join(dir, legacyMarker)) {
				return filepath.Join(dir, "libs", "openant-core"), nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Fail closed, with the remediation the user needs. Previously this fell
	// through to a CWD search, which is how a scanned repository could answer the
	// question "where should I install the engine from?".
	return "", fmt.Errorf(
		"could not locate the VulnFounder engine relative to the executable.\n"+
			"The working directory is deliberately NOT searched: it may be an "+
			"untrusted repository, and installing from it would execute its build "+
			"code.\n"+
			"Fix by installing the engine (pip install vulnfounder) or, for a "+
			"development checkout, set %s=/path/to/libs/vulnfounder-core",
		VulnFounderCoreEnv)
}

func findOpenantCore() (string, error) {
	return findVulnFounderCore()
}

// fileExists is a small helper that returns true if path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
