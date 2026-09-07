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

func sourceLocatorFakePython(t *testing.T, envelope string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "python-stub")
	// %q produces a shell-safe single argument while retaining the pretty
	// JSON envelope as one stdout document.
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q\n", envelope)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func sourceLocatorFakePythonRecordingArgs(t *testing.T, envelope string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "python-stub")
	argsPath := filepath.Join(dir, "args.txt")
	// The stub receives Python's complete argv.  Recording it lets the HTTP
	// boundary test assert that the opt-in LLM flags are passed as separate,
	// validated arguments rather than concatenated shell text.
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\nprintf '%%s\\n' %q\n", argsPath, envelope)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path, argsPath
}

func sourceLocatorRequest(t *testing.T, method, target string, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1"
	return req
}

func TestSourceLocatorCreateRequiresSameOriginAndCSRF(t *testing.T) {
	envelope := `{"status":"success","data":{"session":{"session_id":"loc_api123456","state":"INTAKE"}},"errors":[]}`
	s := &Server{outDir: t.TempDir(), pythonPath: sourceLocatorFakePython(t, envelope), csrfToken: "token"}

	req := sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions", `{"target":"paramservice"}`)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleSourceLocatorCreate(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", rec.Code)
	}

	req = sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions", `{"target":"paramservice"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	rec = httptest.NewRecorder()
	s.handleSourceLocatorCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || payload["status"] != "success" {
		t.Fatalf("unexpected create response: %s", rec.Body.String())
	}
}

func TestSourceLocatorDeleteRequiresCSRFAndInvokesDelete(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_delete123456"
	sessionDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_delete123456","raw_target":"paramservice","state":"INTAKE","artifacts":{},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(sessionDir, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}

	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, `{"status":"success","data":{"session_id":"loc_delete123456","deleted":true},"errors":[]}`)
	s := &Server{outDir: filepath.Dir(root), pythonPath: pythonStub, csrfToken: "token"}

	req := sourceLocatorRequest(t, http.MethodDelete, "/source-locator/sessions/loc_delete123456", `{}`)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorDelete(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", rec.Code)
	}

	req = sourceLocatorRequest(t, http.MethodDelete, "/source-locator/sessions/loc_delete123456", `{}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec = httptest.NewRecorder()
	s.handleSourceLocatorDelete(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"source-locator", "delete", sessionID, "--root", root} {
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

func TestSourceLocatorEventsReplayAndArtifactAllowlist(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	sessionDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatal(err)
	}
	event := `{"schema_version":"openant.source-locator.event.v1","seq":1,"session_id":"loc_api123456","type":"session.created","state":"INTAKE","summary_zh":"已创建","artifact":"evidence.json","evidence_ids":[],"details":{},"created_at":"2026-08-29T00:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(sessionDir, "events.jsonl"), []byte(event), 0600); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_api123456","raw_target":"paramservice","state":"DONE","artifacts":{"evidence.json":"证据图"},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(sessionDir, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "evidence.json"), []byte(`{"edges":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.json"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{outDir: filepath.Dir(root), csrfToken: "token"}
	req := sourceLocatorRequest(t, http.MethodGet, "/source-locator/sessions/"+sessionID+"/events", "")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorEvents(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "session.created") || !strings.Contains(rec.Body.String(), "event: done") {
		t.Fatalf("unexpected SSE response code=%d body=%s", rec.Code, rec.Body.String())
	}

	req = sourceLocatorRequest(t, http.MethodGet, "/source-locator/sessions/"+sessionID+"/artifact/evidence.json", "")
	req.SetPathValue("id", sessionID)
	req.SetPathValue("name", "evidence.json")
	rec = httptest.NewRecorder()
	s.handleSourceLocatorArtifact(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"edges"`) {
		t.Fatalf("artifact was not served: code=%d body=%s", rec.Code, rec.Body.String())
	}

	req = sourceLocatorRequest(t, http.MethodGet, "/source-locator/sessions/"+sessionID+"/artifact/outside.json", "")
	req.SetPathValue("id", sessionID)
	req.SetPathValue("name", "../outside.json")
	rec = httptest.NewRecorder()
	s.handleSourceLocatorArtifact(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("artifact traversal status=%d, want 404", rec.Code)
	}
}

func TestSourceLocatorEventSnapshotReturnsFiniteJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	sessionDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatal(err)
	}
	event := `{"schema_version":"openant.source-locator.event.v1","seq":1,"session_id":"loc_api123456","type":"session.created","state":"INTAKE","summary_zh":"已创建","evidence_ids":[],"details":{},"created_at":"2026-08-29T00:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(sessionDir, "events.jsonl"), []byte(event), 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{outDir: filepath.Dir(root), csrfToken: "token"}
	req := sourceLocatorRequest(t, http.MethodGet, "/source-locator/sessions/"+sessionID+"/events/snapshot", "")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorEventSnapshot(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("snapshot status/content type=%d/%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	var payload struct {
		Status string `json:"status"`
		Data   struct {
			Events  []sourceLocatorEvent `json:"events"`
			LastSeq int                  `json:"last_seq"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("snapshot is not JSON: %v; body=%s", err, rec.Body.String())
	}
	if payload.Status != "success" || len(payload.Data.Events) != 1 || payload.Data.LastSeq != 1 {
		t.Fatalf("unexpected snapshot payload: %+v", payload)
	}
}

func TestSourceLocatorEventReaderRejectsSequenceGap(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	sessionDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "events.jsonl"), []byte(`{"schema_version":"openant.source-locator.event.v1","seq":2,"session_id":"loc_api123456","type":"bad.event","state":"INTAKE","summary_zh":"bad","evidence_ids":[],"details":{},"created_at":"2026-08-29T00:00:00Z"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSourceLocatorEvents(root, sessionID, 0); err == nil {
		t.Fatal("sequence gap was accepted")
	}
}

func TestSourceLocatorAdvanceRequiresCSRFAndPassesBoundedSteps(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	if err := os.MkdirAll(filepath.Join(root, sessionID), 0750); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_api123456","raw_target":"paramservice","state":"INTAKE","artifacts":{},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, sessionID, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := `{"status":"success","data":{"session":{"session_id":"loc_api123456","state":"NORMALIZE_TARGET"}},"errors":[]}`
	s := &Server{outDir: filepath.Dir(root), pythonPath: sourceLocatorFakePython(t, envelope), csrfToken: "token"}

	req := sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_api123456/advance", `{"max_steps":"2"}`)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorAdvance(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", rec.Code)
	}

	req = sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_api123456/advance", `{"max_steps":"2"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec = httptest.NewRecorder()
	s.handleSourceLocatorAdvance(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "NORMALIZE_TARGET") {
		t.Fatalf("advance status=%d body=%s", rec.Code, rec.Body.String())
	}

	// API clients may use a JSON number instead of the browser's form-like
	// string; the boundary must accept only a bounded integer, not a float.
	req = sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_api123456/advance", `{"max_steps":2}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec = httptest.NewRecorder()
	s.handleSourceLocatorAdvance(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("numeric max_steps status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSourceLocatorAdvancePassesOptInLLMFlags(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	if err := os.MkdirAll(filepath.Join(root, sessionID), 0750); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_api123456","raw_target":"paramservice","state":"INTAKE","artifacts":{},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, sessionID, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := `{"status":"success","data":{"session":{"session_id":"loc_api123456","state":"SEARCH_INITIAL"}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: filepath.Dir(root), pythonPath: pythonStub, csrfToken: "token"}
	req := sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_api123456/advance", `{"max_steps":2,"llm_search":true,"llm_search_rounds":24,"llm_config":"openharmony-live-gpt"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorAdvance(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("advance status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"source-locator", "advance", sessionID, "--max-steps", "2", "--llm-search", "--llm-search-rounds", "24", "--llm-config", "openharmony-live-gpt"} {
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

func TestSourceLocatorAdvanceRejectsUnsafeLLMConfig(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	if err := os.MkdirAll(filepath.Join(root, sessionID), 0750); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_api123456","raw_target":"paramservice","state":"INTAKE","artifacts":{},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, sessionID, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := `{"status":"success","data":{"session":{"session_id":"loc_api123456","state":"SEARCH_INITIAL"}},"errors":[]}`
	s := &Server{outDir: filepath.Dir(root), pythonPath: sourceLocatorFakePython(t, envelope), csrfToken: "token"}
	// The browser control and the API boundary must reject values outside the
	// bounded planner budget before invoking the Python worker.
	req := sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_api123456/advance", `{"llm_search":true,"llm_search_rounds":41}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorAdvance(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "llm_search_rounds") {
		t.Fatalf("out-of-range rounds status=%d body=%s", rec.Code, rec.Body.String())
	}
	req = sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_api123456/advance", `{"llm_search":true,"llm_config":"../../secrets"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec = httptest.NewRecorder()
	s.handleSourceLocatorAdvance(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "llm_config") {
		t.Fatalf("unsafe config status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSourceLocatorSelectVersionRequiresCSRFAndPassesSafeRevision(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_version123456"
	sessionDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_version123456","raw_target":"paramservice","state":"VERSION_SELECTION_REQUIRED","version_selection":{"status":"ok","candidate_revisions":["OpenHarmony-6.1-LTS"]},"artifacts":{"repository_version_candidates.json":"候选版本"},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(sessionDir, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := `{"status":"success","data":{"session":{"session_id":"loc_version123456","state":"CLONE"}},"errors":[]}`
	pythonStub, argsPath := sourceLocatorFakePythonRecordingArgs(t, envelope)
	s := &Server{outDir: filepath.Dir(root), pythonPath: pythonStub, csrfToken: "token"}

	req := sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_version123456/select-version", `{"revision":"OpenHarmony-6.1-LTS"}`)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorSelectVersion(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", rec.Code)
	}

	req = sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_version123456/select-version", `{"revision":"OpenHarmony-6.1-LTS"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec = httptest.NewRecorder()
	s.handleSourceLocatorSelectVersion(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"CLONE"`) {
		t.Fatalf("select-version status=%d body=%s", rec.Code, rec.Body.String())
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Fields(string(args))
	for _, want := range []string{"source-locator", "select-version", sessionID, "--revision", "OpenHarmony-6.1-LTS", "--root", root} {
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

	req = sourceLocatorRequest(t, http.MethodPost, "/source-locator/sessions/loc_version123456/select-version", `{"revision":"../../etc/passwd"}`)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "token")
	req.SetPathValue("id", sessionID)
	rec = httptest.NewRecorder()
	s.handleSourceLocatorSelectVersion(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "revision") {
		t.Fatalf("unsafe revision status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSourceLocatorHandoffUsesReadOnlyPythonCommand(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source-locator")
	sessionID := "loc_api123456"
	if err := os.MkdirAll(filepath.Join(root, sessionID), 0750); err != nil {
		t.Fatal(err)
	}
	checkpoint := `{"schema_version":"openant.source-locator.session.v1","session_id":"loc_api123456","raw_target":"paramservice","state":"DONE","artifacts":{"source_handoff.json":"已验证交接"},"evidence_ids":[],"executed_queries":[],"executed_actions":[],"excluded_paths":[],"excluded_repos":[],"feedback_round":0,"budget":{},"metrics":{},"created_at":"2026-08-29T00:00:00Z","updated_at":"2026-08-29T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(root, sessionID, "session.json"), []byte(checkpoint), 0600); err != nil {
		t.Fatal(err)
	}
	envelope := `{"status":"success","data":{"primary_analysis_repo":"/tmp/source_code_base/startup_init","handoff":{"schema_version":"openant.source-locator.post-clone-verification.v1","status":"ready_for_analysis","project_name":"startup_init","repository_path":"/tmp/source_code_base/startup_init","repo_url":"https://gitcode.com/openharmony/startup_init.git","revision":"OpenHarmony-6.1-LTS","resolved_commit":"0123456789abcdef0123456789abcdef01234567","source_paths":["services/param/param_service.c"],"evidence_ids":["E-handoff"]}},"errors":[]}`
	s := &Server{outDir: filepath.Dir(root), pythonPath: sourceLocatorFakePython(t, envelope), csrfToken: "token"}
	req := sourceLocatorRequest(t, http.MethodGet, "/source-locator/sessions/loc_api123456/handoff", "")
	req.SetPathValue("id", sessionID)
	rec := httptest.NewRecorder()
	s.handleSourceLocatorHandoff(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "primary_analysis_repo") {
		t.Fatalf("handoff status=%d body=%s", rec.Code, rec.Body.String())
	}
}
