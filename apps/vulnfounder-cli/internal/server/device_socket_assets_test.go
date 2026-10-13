package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeviceSocketAssetScanRequiresCSRFAndUsesExplicitNamespace(t *testing.T) {
	envelope := `{"status":"success","data":{"status":"complete","device_serial":"serial-1","assets":[]},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}

	req := exposureSurfaceRequest(t, http.MethodPost, "/device-socket-assets/scan", `{"device_serial":"serial-1"}`)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetScan(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = exposureSurfaceRequest(t, http.MethodPost, "/device-socket-assets/scan", `{"device_serial":"serial-1","consent":true,"task_goal":"检查SP_daemon","max_rounds":8,"max_commands":12,"max_wall_seconds":60}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec = httptest.NewRecorder()
	s.handleDeviceSocketAssetScan(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "serial-1") {
		t.Fatalf("scan status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"device-socket-inventory", "scan", "--device-serial", "serial-1", "--task-goal", "检查SP_daemon", "--max-rounds", "8", "--max-commands", "12", "--max-wall-seconds", "60", "--root"} {
		if !containsString(argv, want) {
			t.Fatalf("argv %q missing %q", argv, want)
		}
	}
}

func TestDeviceSocketAssetPageIsRegistered(t *testing.T) {
	s, err := New("/bin/false", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/device-socket-assets", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "设备 Socket 资产发现") || !strings.Contains(rec.Body.String(), "用户自定义设备扫描任务") {
		t.Fatalf("page status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeviceSocketAssetDeviceDiscoveryUsesHDCAndReturnsChoices(t *testing.T) {
	hdcDir := t.TempDir()
	hdc := filepath.Join(hdcDir, "hdc")
	if err := os.WriteFile(hdc, []byte("#!/bin/sh\necho board-a USB\necho board-b Connected\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULNFOUNDER_HDC", hdc)
	s := &Server{outDir: t.TempDir(), csrfToken: "token"}
	req := httptest.NewRequest(http.MethodGet, "/device-socket-assets/devices", nil)
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device discovery status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"available":true`, `"serial":"board-a"`, `"serial":"board-b"`, `hdc list targets`} {
		if !strings.Contains(body, want) {
			t.Errorf("device discovery response missing %q: %s", want, body)
		}
	}
}

func TestDeviceSocketAssetLLMConfigDiscoveryIsSecretFree(t *testing.T) {
	home := t.TempDir()
	writeTestLLMConfig(t, home, `{
  "$schema_version": 2,
  "default_llm": "asset-model",
  "llm_providers": {"provider-a": {"type": "openai", "api_key": "do-not-render"}},
  "llm_configs": {"asset-model": {"analyze": {"provider": "provider-a", "model": "model-a"}}}
}`)
	s := &Server{outDir: t.TempDir(), csrfToken: "token"}
	req := httptest.NewRequest(http.MethodGet, "/device-socket-assets/llm-configs", nil)
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetLLMConfigs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("LLM config discovery status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"selected":"asset-model"`, `"name":"asset-model"`, `"provider":"provider-a"`, `"model":"model-a"`} {
		if !strings.Contains(body, want) {
			t.Errorf("LLM config response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "do-not-render") {
		t.Error("LLM config response leaked provider credential")
	}
}

func TestDeviceSocketAssetAsyncReturnsRunImmediately(t *testing.T) {
	envelope := `{"status":"success","data":{"status":"complete","device_serial":"serial-1","assets":[]},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: t.TempDir(), pythonPath: pythonStub, csrfToken: "token"}
	req := exposureSurfaceRequest(t, http.MethodPost, "/device-socket-assets/scan?async=1", `{"device_serial":"serial-1","consent":true,"async":true,"max_rounds":2,"max_commands":2,"max_wall_seconds":60}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetScan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("async status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelopePayload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelopePayload); err != nil {
		t.Fatal(err)
	}
	data, ok := envelopePayload["data"].(map[string]any)
	if !ok || data["status"] != "running" {
		t.Fatalf("async response missing running state: %s", rec.Body.String())
	}
	runID, ok := data["run_id"].(string)
	if !ok || !deviceSocketAssetRunID(runID) {
		t.Fatalf("async response missing safe run_id: %s", rec.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if job, exists := s.deviceSocketAssetJob(runID); exists && job.Status != "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	if !containsString(argv, "--run-id") || !containsString(argv, runID) {
		t.Fatalf("worker argv %q missing run id %q", argv, runID)
	}
}

func TestDeviceSocketAssetRunStatusExposesIntermediateArtifacts(t *testing.T) {
	serial := "serial-status"
	runID := "20260912T010203000000Z-a1b2c3"
	root := filepath.Join(t.TempDir(), "device-socket-assets")
	keyBytes := sha256.Sum256([]byte(serial))
	deviceDir := filepath.Join(root, fmt.Sprintf("%x", keyBytes[:])[:32])
	runDir := filepath.Join(deviceDir, "runs", runID)
	if err := os.MkdirAll(runDir, 0700); err != nil {
		t.Fatal(err)
	}
	plan := `{"status":"running","device_serial":"serial-status","task_goal":"检查设备版本","task_scope":"custom_read_only","socket_inventory_required":false,"task_summary":"待提交","task_findings":[],"model":"test-model","rounds":2,"command_count":1,"evidence_count":1,"trace_count":2,"task_tree":{"nodes":[{"task_id":"x","title":"测试任务","status":"in_progress","children":[]}]},"rag":{"mode":"local"},"observed_endpoint_count":1,"observed_endpoints":[{"endpoint":"/dev/unix/socket/demo","state":"LISTENING"}],"socket_record_count":2,"socket_record_summary":{"total":2,"unix":2,"anonymous":1,"complete":true},"observed_socket_records":[{"record_id":"socket-record-000001","transport":"UNIX","state":"CONNECTED","endpoint":null},{"record_id":"socket-record-000002","transport":"UNIX","state":"LISTENING","endpoint":"/dev/unix/socket/demo"}],"last_event":{"event":"model.turn"}}`
	if err := os.WriteFile(filepath.Join(runDir, "socket_inventory_plan.json"), []byte(plan), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "socket_inventory_trace.jsonl"), []byte(`{"seq":1,"event":"agent.started","created_at":"2026-09-12T01:02:03Z","details":{}}
{"seq":2,"event":"model.turn","created_at":"2026-09-12T01:02:04Z","details":{"round":1}}
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "socket_inventory_evidence.json"), []byte(`{"evidence":[{"evidence_id":"DA-EV-0001","purpose":"测试","excerpt":"demo"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: filepath.Dir(root)}
	req := httptest.NewRequest(http.MethodGet, "/device-socket-assets/runs/"+runID, nil)
	req.SetPathValue("run_id", runID)
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetRun(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"model":"test-model"`) || !strings.Contains(rec.Body.String(), `"task_goal":"检查设备版本"`) || !strings.Contains(rec.Body.String(), "model.turn") || !strings.Contains(rec.Body.String(), `"socket_record_count":2`) || !strings.Contains(rec.Body.String(), "socket-record-000001") {
		t.Fatalf("run status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeviceSocketAssetOptionsReadHistoryAndBuildTargets(t *testing.T) {
	serial := "serial-options"
	root := filepath.Join(t.TempDir(), "device-socket-assets")
	keyBytes := sha256.Sum256([]byte(serial))
	deviceDir := filepath.Join(root, fmt.Sprintf("%x", keyBytes[:])[:32])
	if err := os.MkdirAll(filepath.Join(deviceDir, "snapshots"), 0700); err != nil {
		t.Fatal(err)
	}
	latest := `{"device_serial":"serial-options","run_id":"20260923T010203000000Z-a1b2c3","generated_at":"2026-09-23T01:02:03Z","assets":[{"socket_name":"/dev/unix/socket/paramservice","transport":"UNIX","address_family":"AF_UNIX","runtime_state":"LISTENING","process":"init"},{"socket_name":"127.0.0.1:8283","transport":"UDP","address_family":"AF_INET","address":"127.0.0.1","port":"8283","runtime_state":"LISTENING","process":"SP_daemon"}]}`
	if err := os.WriteFile(filepath.Join(deviceDir, "latest.json"), []byte(latest), 0600); err != nil {
		t.Fatal(err)
	}
	// The same endpoint in an older snapshot must be collapsed into one option.
	historical := `{"device_serial":"serial-options","run_id":"20260922T010203000000Z-a1b2c3","generated_at":"2026-09-22T01:02:03Z","assets":[{"socket_name":"/dev/unix/socket/paramservice","transport":"UNIX","address_family":"AF_UNIX","runtime_state":"LISTENING","process":"init"}]}`
	if err := os.WriteFile(filepath.Join(deviceDir, "snapshots", "socket_inventory_20260922T010203000000Z-a1b2c3.json"), []byte(historical), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: filepath.Dir(root)}
	req := httptest.NewRequest(http.MethodGet, "/device-socket-assets/asset-options", nil)
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetOptions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset options status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("asset options missing data: %s", rec.Body.String())
	}
	options, ok := data["options"].([]any)
	if !ok || len(options) != 2 {
		t.Fatalf("asset options count=%v body=%s", data["options"], rec.Body.String())
	}
	seen := map[string]bool{}
	for _, raw := range options {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		seen[fmt.Sprint(item["value"])] = true
	}
	if !seen["/dev/unix/socket/paramservice"] {
		t.Errorf("missing Unix socket option: %v", seen)
	}
	if !seen["SP_daemon UDP 127.0.0.1:8283"] {
		t.Errorf("missing network option: %v", seen)
	}
	// A selected run must scope the options to that historical snapshot rather
	// than silently falling back to the merged latest view.
	filteredReq := httptest.NewRequest(http.MethodGet, "/device-socket-assets/asset-options?run_id=20260922T010203000000Z-a1b2c3", nil)
	filteredRec := httptest.NewRecorder()
	s.handleDeviceSocketAssetOptions(filteredRec, filteredReq)
	if filteredRec.Code != http.StatusOK {
		t.Fatalf("filtered asset options status=%d body=%s", filteredRec.Code, filteredRec.Body.String())
	}
	var filteredEnvelope map[string]any
	if err := json.Unmarshal(filteredRec.Body.Bytes(), &filteredEnvelope); err != nil {
		t.Fatal(err)
	}
	filteredData, ok := filteredEnvelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("filtered asset options missing data: %s", filteredRec.Body.String())
	}
	filteredOptions, ok := filteredData["options"].([]any)
	if !ok || len(filteredOptions) != 1 {
		t.Fatalf("filtered asset options count=%v body=%s", filteredData["options"], filteredRec.Body.String())
	}
	if got := fmt.Sprint(filteredOptions[0].(map[string]any)["value"]); got != "/dev/unix/socket/paramservice" {
		t.Fatalf("filtered asset option=%q", got)
	}
}

func TestDeviceSocketAssetOptionsSelectedRunUsesCompleteRunPlan(t *testing.T) {
	serial := "serial-complete-history"
	runID := "20260923T022505000000Z-a973ba"
	root := filepath.Join(t.TempDir(), "device-socket-assets")
	keyBytes := sha256.Sum256([]byte(serial))
	deviceDir := filepath.Join(root, fmt.Sprintf("%x", keyBytes[:])[:32])
	runDir := filepath.Join(deviceDir, "runs", runID)
	if err := os.MkdirAll(runDir, 0700); err != nil {
		t.Fatal(err)
	}
	assets := make([]map[string]any, 0, 27)
	for i := 0; i < 27; i++ {
		assets = append(assets, map[string]any{
			"socket_name":    fmt.Sprintf("/dev/unix/socket/sample-%02d", i+1),
			"transport":      "UNIX",
			"address_family": "AF_UNIX",
			"runtime_state":  "LISTENING",
			"process":        "init",
		})
	}
	plan := map[string]any{
		"status":        "complete",
		"device_serial": serial,
		"run_id":        runID,
		"generated_at":  "2026-09-23T02:25:05Z",
		"task_goal":     "扫描所有 socket 暴露面",
		"assets":        assets,
		"asset_count":   27,
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "socket_inventory_plan.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{outDir: filepath.Dir(root)}
	req := httptest.NewRequest(http.MethodGet, "/device-socket-assets/asset-options?run_id="+runID, nil)
	rec := httptest.NewRecorder()
	s.handleDeviceSocketAssetOptions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("selected run options status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("selected run options missing data: %s", rec.Body.String())
	}
	options, ok := data["options"].([]any)
	if !ok || len(options) != 27 {
		t.Fatalf("selected historical run must expose all 27 assets, got %v body=%s", data["count"], rec.Body.String())
	}
	if got := fmt.Sprint(data["selected_run_id"]); got != runID {
		t.Fatalf("selected_run_id=%q, want %q", got, runID)
	}
}
