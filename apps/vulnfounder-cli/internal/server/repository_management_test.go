package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repositoryZip(t *testing.T, entries map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return &buf
}

func repositoryMultipart(t *testing.T, archive *bytes.Buffer, name string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("archive", "demo.zip")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := io.Copy(part, archive); err != nil {
		t.Fatalf("copy archive: %v", err)
	}
	if name != "" {
		if err := mw.WriteField("name", name); err != nil {
			t.Fatalf("write repository name: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &body, mw.FormDataContentType()
}

func repositoryRequest(t *testing.T, s *Server, method, target string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	req.Host = "127.0.0.1"
	req.Header.Set("X-CSRF-Token", s.csrfToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestRepositoryManagementListsDirectChildrenAndSkipsSymlinks(t *testing.T) {
	home := t.TempDir()
	s := newCatalogServer(t, home)
	root := filepath.Join(home, "source_code_base")
	if err := os.MkdirAll(filepath.Join(root, "repo-a", "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "repo-a", "src", "main.c"), []byte("int main(){}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "plain-directory"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	rec := repositoryRequest(t, s, http.MethodGet, "/api/repositories", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload repositoryInventoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 2 || len(payload.Repositories) != 2 {
		t.Fatalf("inventory = %#v, want two direct directories", payload)
	}
	if payload.Repositories[0].Name != "plain-directory" || payload.Repositories[1].Name != "repo-a" {
		t.Fatalf("inventory ordering/names = %#v", payload.Repositories)
	}
	if payload.Repositories[1].FileCount != 1 || len(payload.Repositories[1].PreviewFiles) != 1 {
		t.Fatalf("repository preview = %#v", payload.Repositories[1])
	}
}

func TestRepositoryManagementUploadAndDelete(t *testing.T) {
	home := t.TempDir()
	s := newCatalogServer(t, home)
	archive := repositoryZip(t, map[string]string{"repo-root/src/main.c": "int main() {}\n", "repo-root/README.md": "demo\n"})
	body, contentType := repositoryMultipart(t, archive, "uploaded-repo")
	rec := repositoryRequest(t, s, http.MethodPost, "/api/repositories", body, contentType)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var uploaded repositoryMutationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &uploaded); err != nil {
		t.Fatal(err)
	}
	if uploaded.Repository == nil || uploaded.Repository.Name != "uploaded-repo" || !uploaded.Repository.ScanAvailable {
		t.Fatalf("upload response = %#v", uploaded)
	}
	if _, err := os.Stat(filepath.Join(home, "source_code_base", "uploaded-repo", "src", "main.c")); err != nil {
		t.Fatalf("uploaded source missing: %v", err)
	}
	// The uploaded marker makes a ZIP without .git selectable in the scan form.
	options := s.repositoryOptions()
	found := false
	for _, option := range options {
		if option.Label == "Project source — uploaded-repo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("uploaded repository not present in scan catalog: %#v", options)
	}

	rec = repositoryRequest(t, s, http.MethodDelete, "/api/repositories/uploaded-repo", nil, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "uploaded-repo") {
		t.Fatalf("delete status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(home, "source_code_base", "uploaded-repo")); !os.IsNotExist(err) {
		t.Fatalf("uploaded repository still exists, stat err=%v", err)
	}
}

func TestRepositoryManagementRejectsTraversalAndMissingCSRF(t *testing.T) {
	home := t.TempDir()
	s := newCatalogServer(t, home)
	archive := repositoryZip(t, map[string]string{"../outside.txt": "blocked"})
	body, contentType := repositoryMultipart(t, archive, "")
	rec := repositoryRequest(t, s, http.MethodPost, "/api/repositories", body, contentType)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(home, "outside.txt")); !os.IsNotExist(err) {
		t.Fatalf("traversal escaped source root, stat err=%v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/repositories/anything", nil)
	req.Host = "127.0.0.1"
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, want 403", rec.Code)
	}
}
