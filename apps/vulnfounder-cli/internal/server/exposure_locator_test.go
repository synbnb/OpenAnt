package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposureLocatorRouteRendersUnifiedStages(t *testing.T) {
	s, err := New("/bin/false", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/exposure-locator", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("route status=%d cache-control=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	for _, marker := range []string{
		"暴露面识别与定位",
		"启动新的联合会话",
		"id=\"launch-panel\"",
		"id=\"runtime-panels\"",
		"id=\"history-page\"",
		"id=\"history-page-list\"",
		"id=\"history-delete-all\"",
		"deleteHistoryItem",
		"deleteAllHistory",
		"阶段 1 · 设备暴露面识别",
		"阶段 2 · OpenHarmony 源码定位",
		"/exposure-surface/sessions",
		"/source-locator/sessions",
		"locator-llm-rounds",
		"locator-repository-summary",
		"locatorRepositoryMappings",
	} {
		if !strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("unified page missing marker %q", marker)
		}
	}
}
