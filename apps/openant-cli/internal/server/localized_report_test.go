package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverAndServeChineseReportArtifacts(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0123456789abcdef"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"report.html":             "<html>English report</html>",
		"report.zh-CN.html":       "<html>中文报告</html>",
		"SUMMARY_REPORT.md":       "# English summary",
		"SUMMARY_REPORT.zh-CN.md": "# 中文摘要",
	} {
		if err := os.WriteFile(filepath.Join(jobDir, name), []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}

	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	job, ok := s.mgr.get(jobID)
	if !ok {
		t.Fatal("recovered job not found")
	}
	job.mu.Lock()
	gotReportZH, gotSummaryZH := job.ReportPathZH, job.SummaryPathZH
	job.mu.Unlock()
	if gotReportZH == "" || gotSummaryZH == "" {
		t.Fatalf("localized paths not recovered: report=%q summary=%q", gotReportZH, gotSummaryZH)
	}

	for path, want := range map[string]string{
		"/report/" + jobID + "?lang=zh-CN":  "中文报告",
		"/summary/" + jobID + "?lang=zh-CN": "中文摘要",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, body = %q", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("GET %s body missing %q: %s", path, want, rec.Body.String())
		}
	}
}
