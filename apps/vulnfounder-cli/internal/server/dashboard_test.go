package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardIsRootAndScannerFormHasExplicitRoute(t *testing.T) {
	s, err := New("/bin/false", t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	root := httptest.NewRecorder()
	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootReq.Host = "127.0.0.1"
	s.Handler().ServeHTTP(root, rootReq)
	if root.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", root.Code)
	}
	if body := root.Body.String(); !strings.Contains(body, "<h1 id=\"dashboard-title\">首页</h1>") {
		t.Fatal("root response is missing the home title")
	}
	if strings.Contains(root.Body.String(), `id="new-scan-title"`) {
		t.Fatal("root response still renders the scanner form")
	}
	if strings.Contains(root.Body.String(), "快捷入口") {
		t.Fatal("root response still renders the quick-entry section")
	}
	for _, marker := range []string{"源码仓库数量", "最新设备暴露面", "漏洞报告总数"} {
		if !strings.Contains(root.Body.String(), marker) {
			t.Fatalf("dashboard is missing metric %q", marker)
		}
	}
	for _, marker := range []string{"设备暴露面发现", "暴露面识别与源码定位", "href=\"/device-socket-assets\"", "href=\"/exposure-locator\""} {
		if !strings.Contains(root.Body.String(), marker) {
			t.Fatalf("dashboard is missing stage label or link %q", marker)
		}
	}

	scan := httptest.NewRecorder()
	scanReq := httptest.NewRequest(http.MethodGet, "/scan", nil)
	scanReq.Host = "127.0.0.1"
	s.Handler().ServeHTTP(scan, scanReq)
	if scan.Code != http.StatusOK {
		t.Fatalf("scanner page status = %d, want 200", scan.Code)
	}
	if !strings.Contains(scan.Body.String(), `id="new-scan-title"`) {
		t.Fatal("/scan response is missing the scanner form")
	}
	if strings.Contains(scan.Body.String(), `id="repository-manager-title"`) {
		t.Fatal("/scan response still renders repository management")
	}

	repository := httptest.NewRecorder()
	repositoryReq := httptest.NewRequest(http.MethodGet, "/repository-manager", nil)
	repositoryReq.Host = "127.0.0.1"
	s.Handler().ServeHTTP(repository, repositoryReq)
	if repository.Code != http.StatusOK || !strings.Contains(repository.Body.String(), `id="repository-manager-title"`) {
		t.Fatalf("repository manager page status/body = %d/%q", repository.Code, repository.Body.String()[:minDashboardTest(120, len(repository.Body.String()))])
	}

	summary := httptest.NewRecorder()
	summaryReq := httptest.NewRequest(http.MethodGet, "/vulnerability-summary", nil)
	summaryReq.Host = "127.0.0.1"
	s.Handler().ServeHTTP(summary, summaryReq)
	if summary.Code != http.StatusOK || !strings.Contains(summary.Body.String(), `id="summary-repository"`) {
		t.Fatalf("vulnerability summary page status/body = %d", summary.Code)
	}

	api := httptest.NewRecorder()
	apiReq := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)
	apiReq.Host = "127.0.0.1"
	s.Handler().ServeHTTP(api, apiReq)
	if api.Code != http.StatusOK || !strings.Contains(api.Body.String(), `"status":"success"`) {
		t.Fatalf("vulnerability summary API status/body = %d/%s", api.Code, api.Body.String())
	}
}

func minDashboardTest(left, right int) int {
	if left < right {
		return left
	}
	return right
}
