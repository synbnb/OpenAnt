package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exposureSurfaceRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1"
	return req
}

func TestExposureSurfaceCreateUsesDedicatedPythonNamespaceAndCSRF(t *testing.T) {
	envelope := `{"status":"success","data":{"session":{"session_id":"exp_test123456","state":"INTAKE"}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target":"/dev/unix/socket/demo"}`)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", rec.Code)
	}

	req = exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target":"/dev/unix/socket/demo","device_serial":"serial-1"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec = httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "exp_test123456") {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"exposure-surface", "create", "/dev/unix/socket/demo", "--device-serial", "serial-1", "--root"} {
		found := false
		for _, got := range argv {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("argv %q missing %q", argv, want)
		}
	}
}

func TestExposureSurfaceCreatePassesLLMAssistFlag(t *testing.T) {
	envelope := `{"status":"success","data":{"session":{"session_id":"exp_llm123456","state":"INTAKE"}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target":"/dev/unix/socket/demo","llm_assist":true}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(strings.Fields(string(args)), "--llm-assist") {
		t.Fatalf("create argv %q missing --llm-assist", strings.Fields(string(args)))
	}
}

func TestExposureSurfaceCreatePassesAgenticLoopOptions(t *testing.T) {
	envelope := `{"status":"success","data":{"session":{"session_id":"exp_agent123456","state":"INTAKE"}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target":"UDP 127.0.0.1:8283","mode":"agentic","allow_model_commands":true,"rag_mode":"off","max_rounds":12,"max_commands":50}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"--mode", "agentic", "--allow-model-commands", "--rag-mode", "off", "--max-rounds", "12", "--max-commands", "50"} {
		if !containsString(argv, want) {
			t.Fatalf("agentic argv %q missing %q", argv, want)
		}
	}
}

func TestExposureSurfaceCreatePassesBatchMetadata(t *testing.T) {
	envelope := `{"status":"success","data":{"session":{"session_id":"exp_batch123456","state":"INTAKE","batch_id":"batch_test123456","batch_index":2,"batch_total":3}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target":"/dev/unix/socket/demo","batch_id":"batch_test123456","batch_index":2,"batch_total":3}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"--batch-id", "batch_test123456", "--batch-index", "2", "--batch-total", "3"} {
		if !containsString(argv, want) {
			t.Fatalf("batch argv %q missing %q", argv, want)
		}
	}
}

func TestExposureSurfaceCreateRejectsInvalidBatchMetadata(t *testing.T) {
	s := &Server{outDir: t.TempDir(), csrfToken: "token"}
	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target":"/dev/unix/socket/demo","batch_id":"batch_test123456","batch_index":3,"batch_total":2}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "批次序号") {
		t.Fatalf("invalid batch status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExposureSurfaceCreateAcceptsStructuredNetworkTarget(t *testing.T) {
	envelope := `{"status":"success","data":{"session":{"session_id":"exp_network123456","state":"INTAKE"}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target_mode":"udp","network_process":"SP_daemon","network_address":"127.0.0.1","network_port":8283}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"exposure-surface", "create", "SP_daemon", "UDP", "127.0.0.1:8283"} {
		if !containsString(argv, want) {
			t.Fatalf("structured network argv %q missing %q", argv, want)
		}
	}
}

func TestExposureSurfaceCreateRejectsIncompleteStructuredNetworkTarget(t *testing.T) {
	s := &Server{outDir: t.TempDir(), csrfToken: "token"}
	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions", `{"target_mode":"tcp","network_address":"127.0.0.1"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceCreate(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "network_port") {
		t.Fatalf("incomplete network status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExposureSurfaceServiceDecisionRoutesAreCSRFProtectedAndBounded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "exposure-surface")
	id := "exp_startapi123"
	if err := os.MkdirAll(filepath.Join(root, id), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "session.json"), []byte(`{"schema_version":"openant.exposure-surface.session.v1","session_id":"exp_startapi123","state":"AWAIT_START_CONFIRMATION","artifacts":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, `{"status":"success","data":{"state":"DONE"},"errors":[]}`)
	s := &Server{outDir: filepath.Dir(root), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions/"+id+"/start-service", `{"option_id":"start-0000"}`)
	req.SetPathValue("id", id)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceStartService(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", rec.Code)
	}

	req = exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions/"+id+"/start-service", `{"option_id":"start-0000"}`)
	req.SetPathValue("id", id)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec = httptest.NewRecorder()
	s.handleExposureSurfaceStartService(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start-service status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"exposure-surface", "start-service", id, "--option-id", "start-0000", "--root"} {
		if !containsString(argv, want) {
			t.Fatalf("start-service argv %q missing %q", argv, want)
		}
	}

	req = exposureSurfaceRequest(t, http.MethodPost, "/exposure-surface/sessions/"+id+"/skip-start", `{"reason":"保持停止"}`)
	req.SetPathValue("id", id)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec = httptest.NewRecorder()
	s.handleExposureSurfaceSkipStart(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("skip-start status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestExposureSurfaceRouteRendersStandalonePage(t *testing.T) {
	s, err := New("/bin/false", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := exposureSurfaceRequest(t, http.MethodGet, "/exposure-surface", "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "暴露面识别") {
		t.Fatalf("route status=%d body prefix=%q", rec.Code, rec.Body.String()[:minInt(len(rec.Body.String()), 200)])
	}
	body := rec.Body.String()
	for _, marker := range []string{"target-mode", "network-process", "network-address", "network-port", "execution-mode", "allow-model-commands", "rag-mode", "TCP Socket", "UDP Socket", "buildExposureTarget", "history-select-all", "history-delete-selected", "deleteSelectedHistory"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("exposure page missing network endpoint marker %q", marker)
		}
	}
}

func TestExposureSurfaceTemplateFallsBackForUnknownLanguage(t *testing.T) {
	s, err := New("/bin/false", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := exposureSurfaceRequest(t, http.MethodGet, "/exposure-surface", "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("route status=%d", rec.Code)
	}
	body := rec.Body.String()
	for _, marker := range []string{"DEFAULT_LANGUAGE", "SUPPORTED_LANGUAGES", "function dictionary", "function i18n", "labels[DEFAULT_LANGUAGE]"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("template missing language fallback marker %q", marker)
		}
	}
	if strings.Contains(body, "labels[state.language][") {
		t.Fatal("template still indexes labels directly with unvalidated language")
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func TestExposureSurfaceArtifactIsAllowlistedAndContained(t *testing.T) {
	root := filepath.Join(t.TempDir(), "exposure-surface")
	id := "exp_artifact123"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	session := map[string]any{
		"schema_version": "openant.exposure-surface.session.v1",
		"session_id":     id,
		"state":          "DONE",
		"artifacts":      map[string]string{"exposure_surface.json": "exposure_surface.json"},
	}
	encoded, _ := json.Marshal(session)
	if err := os.WriteFile(filepath.Join(dir, "session.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exposure_surface.json"), []byte(`{"surfaces":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.json"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: filepath.Dir(root)}

	req := exposureSurfaceRequest(t, http.MethodGet, "/exposure-surface/sessions/"+id+"/artifact/exposure_surface.json", "")
	req.SetPathValue("id", id)
	req.SetPathValue("name", "exposure_surface.json")
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceArtifact(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "surfaces") {
		t.Fatalf("artifact status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = exposureSurfaceRequest(t, http.MethodGet, "/exposure-surface/sessions/"+id+"/artifact/outside.json", "")
	req.SetPathValue("id", id)
	req.SetPathValue("name", "../outside.json")
	rec = httptest.NewRecorder()
	s.handleExposureSurfaceArtifact(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal status=%d", rec.Code)
	}
}

func TestExposureSurfaceEventsValidateSchemaAndReplay(t *testing.T) {
	root := filepath.Join(t.TempDir(), "exposure-surface")
	id := "exp_events123"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	event := fmt.Sprintf(`{"schema_version":"openant.exposure-surface.event.v1","seq":1,"session_id":%q,"type":"session.created","state":"INTAKE","summary_zh":"已创建","evidence_ids":[],"details":{},"created_at":"2026-09-03T00:00:00Z"}`+"\n", id)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(event), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte(fmt.Sprintf(`{"state":"DONE","session_id":%q}`, id)), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: filepath.Dir(root)}
	req := exposureSurfaceRequest(t, http.MethodGet, "/exposure-surface/sessions/"+id+"/events/snapshot", "")
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.handleExposureSurfaceEventSnapshot(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "session.created") {
		t.Fatalf("snapshot status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = exposureSurfaceRequest(t, http.MethodGet, "/exposure-surface/sessions/"+id+"/events", "")
	req.SetPathValue("id", id)
	rec = httptest.NewRecorder()
	s.handleExposureSurfaceEvents(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "event: exposure") || !strings.Contains(rec.Body.String(), "event: done") {
		t.Fatalf("SSE status=%d body=%s", rec.Code, rec.Body.String())
	}
}
