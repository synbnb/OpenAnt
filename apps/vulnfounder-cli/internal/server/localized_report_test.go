package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisclosureEndpointsPreferChineseArtifacts(t *testing.T) {
	outDir := t.TempDir()
	jobID := "fedcba9876543210"
	for dir, content := range map[string]string{
		"disclosures":       "# English disclosure\n\n## Summary\nEnglish summary\n",
		"disclosures.zh-CN": "# 中文漏洞披露\n\n## Summary\n中文摘要\n",
	} {
		path := filepath.Join(outDir, jobID, "report", dir)
		if err := os.MkdirAll(path, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "DISCLOSURE_01_SAMPLE.md"), []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}

	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	localized := get("/disclosures/" + jobID + "?lang=zh-CN")
	if localized.Code != http.StatusOK {
		t.Fatalf("localized list status = %d, body = %q", localized.Code, localized.Body.String())
	}
	var infos []disclosureInfo
	if err := json.Unmarshal(localized.Body.Bytes(), &infos); err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || !strings.Contains(infos[0].Summary, "中文摘要") {
		t.Fatalf("localized list = %#v", infos)
	}
	if !strings.Contains(infos[0].URL, "lang=zh-CN") {
		t.Fatalf("localized URL = %q", infos[0].URL)
	}

	detail := get("/disclosure/" + jobID + "/DISCLOSURE_01_SAMPLE.md?lang=zh-CN")
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "中文漏洞披露") {
		t.Fatalf("localized detail status/body = %d/%q", detail.Code, detail.Body.String())
	}

	english := get("/disclosure/" + jobID + "/DISCLOSURE_01_SAMPLE.md?lang=en")
	if english.Code != http.StatusOK || !strings.Contains(english.Body.String(), "English disclosure") {
		t.Fatalf("English detail status/body = %d/%q", english.Code, english.Body.String())
	}
}

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
