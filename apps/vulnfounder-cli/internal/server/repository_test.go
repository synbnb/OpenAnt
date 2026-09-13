package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/config"
)

func writeCatalogProject(t *testing.T, home, name, repoPath, repoURL, source string) {
	t.Helper()
	projectDir := filepath.Join(home, ".openant", "projects", filepath.FromSlash(name))
	if err := os.MkdirAll(projectDir, 0700); err != nil {
		t.Fatalf("mkdir project dir: %v", err)
	}
	data, err := json.Marshal(map[string]string{
		"name":       name,
		"repo_path":  repoPath,
		"repo_url":   repoURL,
		"source":     source,
		"language":   "auto",
		"commit_sha": "nogit",
	})
	if err != nil {
		t.Fatalf("marshal project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "project.json"), data, 0600); err != nil {
		t.Fatalf("write project: %v", err)
	}
}

func newCatalogServer(t *testing.T, home string) *Server {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	// Keep catalog tests deterministic: the production resolver may otherwise
	// discover the repository's real source_code_base from the test process's
	// working directory.
	sourceRoot := filepath.Join(home, "source_code_base")
	if err := os.MkdirAll(sourceRoot, 0700); err != nil {
		t.Fatalf("mkdir source root: %v", err)
	}
	t.Setenv(config.SourceCodeBaseEnv, sourceRoot)
	outDir := filepath.Join(home, "webui")
	return &Server{outDir: outDir, mgr: newManager(outDir), csrfToken: "tok", sem: make(chan struct{}, 4), shutdownDone: make(chan struct{})}
}

func writeSourceCatalogRepo(t *testing.T, root, name string) string {
	t.Helper()
	repo := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0700); err != nil {
		t.Fatalf("mkdir source repo %q: %v", name, err)
	}
	return repo
}

func TestRepositoryCatalogEndpointUsesOpaqueIDs(t *testing.T) {
	home := t.TempDir()
	repoDir := filepath.Join(home, "src", "demo")
	if err := os.MkdirAll(repoDir, 0700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	writeCatalogProject(t, home, "demo/repo", repoDir, "", "local")
	// A credential-bearing URL must never enter the catalog.
	writeCatalogProject(t, home, "bad/remote", filepath.Join(home, "missing"), "https://user:secret@example.com/repo.git", "remote")

	s := newCatalogServer(t, home)
	s.mgr.add(&Job{ID: "abcdef0123456789", Repo: "https://github.com/acme/recent.git", StartedAt: time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC)})

	req := httptest.NewRequest(http.MethodGet, "/repositories", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog status = %d, want 200", rec.Code)
	}
	var payload repositoriesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(payload.Repositories) != 2 {
		t.Fatalf("catalog entries = %#v, want project + recent only", payload.Repositories)
	}
	if payload.Repositories[0].Source != "project" || payload.Repositories[1].Source != "recent" {
		t.Fatalf("catalog order/source = %#v, want project then recent", payload.Repositories)
	}
	for _, option := range payload.Repositories {
		if !strings.HasPrefix(option.ID, "repo-") || strings.ContainsAny(option.ID, "/:@") {
			t.Errorf("repository ID is not opaque: %q", option.ID)
		}
	}
	if strings.Contains(rec.Body.String(), "secret@example.com") {
		t.Error("credential-bearing project URL leaked into catalog response")
	}
}

func TestRepositoryIDResolutionAndUnknownSelection(t *testing.T) {
	home := t.TempDir()
	repoDir := filepath.Join(home, "src", "selected")
	if err := os.MkdirAll(repoDir, 0700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	writeCatalogProject(t, home, "selected", repoDir, "", "local")
	s := newCatalogServer(t, home)

	options := s.repositoryOptions()
	if len(options) != 1 {
		t.Fatalf("repository options = %#v, want one", options)
	}
	if got, ok := s.resolveRepositoryID(options[0].ID); !ok || got != repoDir {
		t.Fatalf("resolveRepositoryID = (%q, %v), want (%q, true)", got, ok, repoDir)
	}

	unknownReq := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader("csrf=tok&repo_id=repo-does-not-exist&repo=/tmp/attacker-controlled"))
	unknownReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unknownReq.Host = "127.0.0.1"
	unknownRec := httptest.NewRecorder()
	s.handleStartScan(unknownRec, unknownReq)
	if unknownRec.Code != http.StatusBadRequest {
		t.Fatalf("unknown repo_id status = %d, want 400", unknownRec.Code)
	}
	if got := len(s.mgr.all()); got != 0 {
		t.Fatalf("unknown repo_id created %d jobs", got)
	}

	validReq := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader("csrf=tok&repo_id="+options[0].ID+"&repo=/tmp/attacker-controlled"))
	validReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validReq.Host = "127.0.0.1"
	validRec := httptest.NewRecorder()
	s.pythonPath = "/bin/false"
	s.handleStartScan(validRec, validReq)
	if validRec.Code != http.StatusSeeOther {
		t.Fatalf("valid repo_id status = %d, want 303", validRec.Code)
	}
	jobs := s.mgr.all()
	if len(jobs) != 1 {
		t.Fatalf("valid repo_id created %d jobs, want 1", len(jobs))
	}
	job := jobs[0]
	job.mu.Lock()
	gotRepo := job.Repo
	cancel := job.Cancel
	done := job.done
	job.mu.Unlock()
	if gotRepo != repoDir {
		t.Errorf("selected job repo = %q, want %q", gotRepo, repoDir)
	}
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func TestRepositoryCatalogIncludesProjectLocalGitReposOnly(t *testing.T) {
	home := t.TempDir()
	s := newCatalogServer(t, home)
	root := filepath.Join(home, "source_code_base")
	wanted := writeSourceCatalogRepo(t, root, "communication_ipc")
	if err := os.Mkdir(filepath.Join(root, "not-a-repository"), 0700); err != nil {
		t.Fatalf("mkdir plain source directory: %v", err)
	}

	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(filepath.Join(outside, ".git"), 0700); err != nil {
		t.Fatalf("mkdir outside repo: %v", err)
	}
	linkedChild := filepath.Join(root, "linked-child")
	if err := os.Symlink(outside, linkedChild); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	linkedGit := filepath.Join(root, "linked-git")
	if err := os.Mkdir(linkedGit, 0700); err != nil {
		t.Fatalf("mkdir linked-git: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, ".git"), filepath.Join(linkedGit, ".git")); err != nil {
		t.Skipf("symlinked metadata unavailable: %v", err)
	}

	options := s.repositoryOptions()
	if len(options) != 1 {
		t.Fatalf("repository options = %#v, want one project-local Git repository", options)
	}
	option := options[0]
	if option.Source != "source_code_base" {
		t.Fatalf("source = %q, want source_code_base", option.Source)
	}
	if option.Label != "Project source — communication_ipc" {
		t.Fatalf("label = %q, want project-local repository name", option.Label)
	}
	if strings.Contains(option.Label, root) || strings.Contains(option.ID, root) {
		t.Fatalf("catalog entry leaked source root: %#v", option)
	}
	if got, ok := s.resolveRepositoryID(option.ID); !ok || got != wanted {
		t.Fatalf("resolveRepositoryID = (%q, %v), want (%q, true)", got, ok, wanted)
	}
}
