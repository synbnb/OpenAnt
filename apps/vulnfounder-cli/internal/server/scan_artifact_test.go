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

func TestParseScanArtifactCleanRoom(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "omitted keeps assisted default", input: "", want: false},
		{name: "false", input: "false", want: false},
		{name: "true", input: "true", want: true},
		{name: "html checkbox spelling", input: "1", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseScanArtifactCleanRoom(tt.input)
			if err != nil {
				t.Fatalf("parse(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parse(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
	if _, err := parseScanArtifactCleanRoom("sometimes"); err == nil {
		t.Fatal("invalid clean_room value should be rejected")
	}
}

func TestScanArtifactRunArtifactsExposeOnlySafeSnapshots(t *testing.T) {
	outDir := t.TempDir()
	runID := "abcdef12"
	runDir := filepath.Join(outDir, "scan-artifact", "runs", runID)
	if err := os.MkdirAll(runDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "bridge.json"), []byte(`{"source":"test"}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "secret.txt"), []byte("must not be served"), 0640); err != nil {
		t.Fatal(err)
	}
	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/"+runID+"/artifacts", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Artifacts []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Artifacts) != len(scanArtifactRunArtifactSpecs) {
		t.Fatalf("artifact count = %d, want %d", len(payload.Artifacts), len(scanArtifactRunArtifactSpecs))
	}
	seenBridge := false
	for _, item := range payload.Artifacts {
		if item.Name == "bridge.json" {
			seenBridge = item.Available
		}
		if item.Name == "secret.txt" {
			t.Fatal("unallowlisted artifact was exposed")
		}
	}
	if !seenBridge {
		t.Fatal("bridge snapshot should be marked available")
	}

	read := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/"+runID+"/artifacts/bridge.json", nil)
	read.Host = "127.0.0.1"
	readRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(readRec, read)
	if readRec.Code != http.StatusOK || !strings.Contains(readRec.Body.String(), `"source"`) {
		t.Fatalf("snapshot read status=%d body=%q", readRec.Code, readRec.Body.String())
	}
	if got := readRec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("snapshot content type = %q", got)
	}

	unknown := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/"+runID+"/artifacts/secret.txt", nil)
	unknown.Host = "127.0.0.1"
	unknownRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(unknownRec, unknown)
	if unknownRec.Code != http.StatusNotFound {
		t.Fatalf("unknown artifact status = %d, want 404", unknownRec.Code)
	}
}

func TestScanArtifactLatestAndDerivedResult(t *testing.T) {
	outDir := t.TempDir()
	runID := "latest123"
	scanID := "abcdef0123456789"
	sample := "SPUTILS-LOADCMD-CMD-INJECTION-001"
	runDir := filepath.Join(outDir, "scan-artifact", "runs", runID)
	if err := os.MkdirAll(runDir, 0750); err != nil {
		t.Fatal(err)
	}
	bridge := `{"entry":{"sample":"SPUTILS-LOADCMD-CMD-INJECTION-001","result_file":"/tmp/abcdef0123456789/results.json"}}`
	if err := os.WriteFile(filepath.Join(runDir, "bridge.json"), []byte(bridge), 0640); err != nil {
		t.Fatal(err)
	}
	verdict := `{"run_id":"vf-test","status":"CONFIRMED","evidence_grade":"A","pattern":"p","verdict":{"run_id":"vf-test","status":"CONFIRMED","evidence_grade":"A"}}`
	if err := os.WriteFile(filepath.Join(runDir, "verdict.json"), []byte(verdict), 0640); err != nil {
		t.Fatal(err)
	}
	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	latest := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/latest?scan_id="+scanID+"&sample="+sample, nil)
	latest.Host = "127.0.0.1"
	latestRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(latestRec, latest)
	if latestRec.Code != http.StatusOK || !strings.Contains(latestRec.Body.String(), `"run_id":"latest123"`) {
		t.Fatalf("latest status=%d body=%s", latestRec.Code, latestRec.Body.String())
	}
	result := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/"+runID+"/result", nil)
	result.Host = "127.0.0.1"
	resultRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(resultRec, result)
	if resultRec.Code != http.StatusOK || !strings.Contains(resultRec.Body.String(), `"CONFIRMED"`) {
		t.Fatalf("derived result status=%d body=%s", resultRec.Code, resultRec.Body.String())
	}
}

func TestScanArtifactRunHistoryListsAllMatchingRuns(t *testing.T) {
	outDir := t.TempDir()
	scanID := "abcdef0123456789"
	sample := "SPUTILS-LOADCMD-CMD-INJECTION-001"
	runsRoot := filepath.Join(outDir, "scan-artifact", "runs")
	for _, item := range []struct {
		id     string
		status string
		mode   string
	}{
		{id: "history01", status: "NOT_REPRODUCED", mode: "assisted"},
		{id: "history02", status: "CONFIRMED", mode: "clean_room"},
	} {
		runDir := filepath.Join(runsRoot, item.id)
		if err := os.MkdirAll(runDir, 0750); err != nil {
			t.Fatal(err)
		}
		bridge := `{"entry":{"sample":"SPUTILS-LOADCMD-CMD-INJECTION-001","result_file":"/tmp/abcdef0123456789/results.json"}}`
		if err := os.WriteFile(filepath.Join(runDir, "bridge.json"), []byte(bridge), 0640); err != nil {
			t.Fatal(err)
		}
		verdict := `{"run_id":"` + item.id + `","status":"` + item.status + `","verdict":{"status":"` + item.status + `"}}`
		if err := os.WriteFile(filepath.Join(runDir, "verdict.json"), []byte(verdict), 0640); err != nil {
			t.Fatal(err)
		}
		if item.mode == "clean_room" {
			result := `{"run_status":"complete","clean_room":true,"result":{"status":"` + item.status + `"}}`
			if err := os.WriteFile(filepath.Join(runDir, "result.json"), []byte(result), 0640); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs?scan_id="+scanID+"&sample="+sample, nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Count int `json:"count"`
		Runs  []struct {
			RunID         string `json:"run_id"`
			DynamicStatus string `json:"dynamic_status"`
			RunStatus     string `json:"run_status"`
			CleanRoom     *bool  `json:"clean_room"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 2 || len(payload.Runs) != 2 {
		t.Fatalf("history count=%d runs=%d body=%s", payload.Count, len(payload.Runs), rec.Body.String())
	}
	seen := map[string]bool{}
	for _, run := range payload.Runs {
		seen[run.RunID] = true
		if run.DynamicStatus == "" || run.RunStatus == "" {
			t.Fatalf("history item lacks status: %+v", run)
		}
	}
	if !seen["history01"] || !seen["history02"] {
		t.Fatalf("history omitted a matching run: %+v", seen)
	}
}

func TestScanArtifactHistoryGroupsScansAndSamples(t *testing.T) {
	outDir := t.TempDir()
	runsRoot := filepath.Join(outDir, "scan-artifact", "runs")
	fixtures := []struct {
		id, sample, scanID, status string
	}{
		{"global01", "SAMPLE-ONE", "abcdef0123456789", "CONFIRMED"},
		{"global02", "SAMPLE-ONE", "abcdef0123456789", "NOT_REPRODUCED"},
		{"global03", "SAMPLE-TWO", "fedcba9876543210", "INCONCLUSIVE"},
	}
	for _, fixture := range fixtures {
		runDir := filepath.Join(runsRoot, fixture.id)
		if err := os.MkdirAll(runDir, 0750); err != nil {
			t.Fatal(err)
		}
		bridge := `{"entry":{"sample":"` + fixture.sample + `","result_file":"/tmp/` + fixture.scanID + `/results.json","function_analyzed":"Fn::` + fixture.sample + `","location":"a.cpp:1-2"}}`
		if err := os.WriteFile(filepath.Join(runDir, "bridge.json"), []byte(bridge), 0640); err != nil {
			t.Fatal(err)
		}
		verdict := `{"run_id":"` + fixture.id + `","status":"` + fixture.status + `","verdict":{"status":"` + fixture.status + `"}}`
		if err := os.WriteFile(filepath.Join(runDir, "verdict.json"), []byte(verdict), 0640); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/scan-artifact/history", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		ScanCount int `json:"scan_count"`
		Scans     []struct {
			ScanID      string `json:"scan_id"`
			SampleCount int    `json:"sample_count"`
			RunCount    int    `json:"run_count"`
			Samples     []struct {
				Sample   string `json:"sample"`
				RunCount int    `json:"run_count"`
			} `json:"samples"`
		} `json:"scans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ScanCount != 2 || len(payload.Scans) != 2 {
		t.Fatalf("unexpected groups: %s", rec.Body.String())
	}
	seen := map[string]bool{}
	for _, group := range payload.Scans {
		seen[group.ScanID] = true
		if group.ScanID == "abcdef0123456789" && (group.SampleCount != 1 || group.RunCount != 2 || group.Samples[0].RunCount != 2) {
			t.Fatalf("first scan grouping incorrect: %+v", group)
		}
	}
	if !seen["abcdef0123456789"] || !seen["fedcba9876543210"] {
		t.Fatalf("missing scan group: %+v", seen)
	}
}

func TestScanArtifactHistoryRecoversResultOnlyAndAnonymousRuns(t *testing.T) {
	outDir := t.TempDir()
	runsRoot := filepath.Join(outDir, "scan-artifact", "runs")
	resultOnlyDir := filepath.Join(runsRoot, "resultonly1")
	anonymousDir := filepath.Join(runsRoot, "anonymous1")
	if err := os.MkdirAll(resultOnlyDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(anonymousDir, 0750); err != nil {
		t.Fatal(err)
	}
	resultOnly := `{"run_status":"complete","result":{"entry":{"sample":"RESULT-ONLY-001","result_file":"/tmp/abcdef0123456789/results.json","function_analyzed":"Fn"},"status":"CONFIRMED"}}`
	if err := os.WriteFile(filepath.Join(resultOnlyDir, "result.json"), []byte(resultOnly), 0640); err != nil {
		t.Fatal(err)
	}
	anonymous := `{"run_id":"anonymous1","run_status":"error","status":"error"}`
	if err := os.WriteFile(filepath.Join(anonymousDir, "result.json"), []byte(anonymous), 0640); err != nil {
		t.Fatal(err)
	}

	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/scan-artifact/history", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Scans []struct {
			ScanID  string `json:"scan_id"`
			Samples []struct {
				Sample string `json:"sample"`
				Runs   []struct {
					RunID string `json:"run_id"`
				} `json:"runs"`
			} `json:"samples"`
		} `json:"scans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	seenResultOnly := false
	seenAnonymous := false
	for _, group := range payload.Scans {
		for _, sample := range group.Samples {
			for _, run := range sample.Runs {
				if run.RunID == "resultonly1" {
					seenResultOnly = group.ScanID == "abcdef0123456789" && sample.Sample == "RESULT-ONLY-001"
				}
				if run.RunID == "anonymous1" {
					seenAnonymous = group.ScanID == "" && sample.Sample == "未识别样本"
				}
			}
		}
	}
	if !seenResultOnly {
		t.Fatalf("result-only historical run was not recovered: %s", rec.Body.String())
	}
	if !seenAnonymous {
		t.Fatalf("anonymous historical run was not retained: %s", rec.Body.String())
	}
}

func TestScanArtifactRunDeleteProtectsConfirmedAndRequiresCSRF(t *testing.T) {
	outDir := t.TempDir()
	runsRoot := filepath.Join(outDir, "scan-artifact", "runs")
	confirmedID := "confirmed1"
	removeID := "remove001"
	for _, fixture := range []struct {
		id     string
		status string
	}{
		{confirmedID, "CONFIRMED"},
		{removeID, "NOT_REPRODUCED"},
	} {
		runDir := filepath.Join(runsRoot, fixture.id)
		if err := os.MkdirAll(runDir, 0750); err != nil {
			t.Fatal(err)
		}
		result := `{"run_status":"complete","result":{"status":"` + fixture.status + `"}}`
		if err := os.WriteFile(filepath.Join(runDir, "result.json"), []byte(result), 0640); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{outDir: outDir, csrfToken: "token", scanArtifactJobs: make(map[string]*scanArtifactJob)}

	missingToken := httptest.NewRequest(http.MethodDelete, "/scan-artifact/runs/"+removeID, nil)
	missingToken.Host = "127.0.0.1"
	missingRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(missingRec, missingToken)
	if missingRec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", missingRec.Code)
	}

	confirmed := httptest.NewRequest(http.MethodDelete, "/scan-artifact/runs/"+confirmedID, nil)
	confirmed.Host = "127.0.0.1"
	confirmed.Header.Set("X-CSRF-Token", "token")
	confirmedRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(confirmedRec, confirmed)
	if confirmedRec.Code != http.StatusConflict {
		t.Fatalf("confirmed delete status=%d body=%s, want 409", confirmedRec.Code, confirmedRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(runsRoot, confirmedID)); err != nil {
		t.Fatalf("confirmed run was removed: %v", err)
	}

	remove := httptest.NewRequest(http.MethodDelete, "/scan-artifact/runs/"+removeID, nil)
	remove.Host = "127.0.0.1"
	remove.Header.Set("X-CSRF-Token", "token")
	removeRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(removeRec, remove)
	if removeRec.Code != http.StatusOK || !strings.Contains(removeRec.Body.String(), `"deleted"`) {
		t.Fatalf("non-confirmed delete status=%d body=%s", removeRec.Code, removeRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(runsRoot, removeID)); !os.IsNotExist(err) {
		t.Fatalf("non-confirmed run still exists, stat err=%v", err)
	}
}

func TestScanArtifactRunSourceListAndRead(t *testing.T) {
	outDir := t.TempDir()
	runID := "source123"
	sourceRoot := filepath.Join(outDir, "scan-artifact", "runs", runID, "deliverables", "poc_source", "Entry", "src")
	if err := os.MkdirAll(sourceRoot, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "Index.ets"), []byte("@Entry\nexport struct Index {}\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "scan-artifact", "runs", runID, "deliverables", "poc_source.zip"), []byte("zip"), 0640); err != nil {
		t.Fatal(err)
	}
	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}

	list := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/"+runID+"/deliverables/source/poc", nil)
	list.Host = "127.0.0.1"
	listRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(listRec, list)
	if listRec.Code != http.StatusOK {
		t.Fatalf("source list status = %d, body=%s", listRec.Code, listRec.Body.String())
	}
	var listing struct {
		Files []struct {
			Path        string `json:"path"`
			Previewable bool   `json:"previewable"`
		} `json:"files"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Files) != 1 || listing.Files[0].Path != "Entry/src/Index.ets" || !listing.Files[0].Previewable {
		t.Fatalf("unexpected source listing: %+v", listing.Files)
	}

	read := httptest.NewRequest(http.MethodGet, "/scan-artifact/runs/"+runID+"/deliverables/source/poc/Entry/src/Index.ets", nil)
	read.Host = "127.0.0.1"
	readRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(readRec, read)
	if readRec.Code != http.StatusOK || !strings.Contains(readRec.Body.String(), "export struct Index") {
		t.Fatalf("source read status=%d body=%q", readRec.Code, readRec.Body.String())
	}
	if got := readRec.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "inline") {
		t.Fatalf("source disposition = %q", got)
	}

	if _, err := scanArtifactSourcePath("../secret.txt"); err == nil {
		t.Fatal("source traversal path should be rejected")
	}
	if _, err := scanArtifactSourcePath("/etc/passwd"); err == nil {
		t.Fatal("absolute source path should be rejected")
	}
}
