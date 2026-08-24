package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactListAndReadRoutes(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0123456789abcdef"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "parse.report.json"), []byte(`{"step":"parse","status":"success"}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "pipeline_output.json"), []byte(`{"findings":[]}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "not-allowlisted.txt"), []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}

	mgr := newManager(outDir)
	mgr.add(&Job{ID: jobID, Status: StatusDone})
	s := &Server{outDir: outDir, mgr: mgr}

	listReq := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifacts", nil)
	listReq.Host = "127.0.0.1"
	listRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("artifact list status = %d, want 200", listRec.Code)
	}
	var artifacts []artifactView
	if err := json.Unmarshal(listRec.Body.Bytes(), &artifacts); err != nil {
		t.Fatalf("decode artifact list: %v", err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2: %#v", len(artifacts), artifacts)
	}
	byName := make(map[string]artifactView, len(artifacts))
	for _, artifact := range artifacts {
		byName[artifact.Name] = artifact
	}
	if got := byName["parse.report.json"]; got.Category != "stage-report" || got.Stage != "parse" || got.Description == "" || got.Size == 0 {
		t.Fatalf("parse artifact metadata = %#v", got)
	}
	if got := byName["pipeline_output.json"]; got.Stage != "build-output" || got.Description == "" {
		t.Fatalf("pipeline artifact metadata = %#v", got)
	}
	if _, ok := byName["not-allowlisted.txt"]; ok {
		t.Fatal("non-allowlisted file was exposed")
	}

	readReq := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifact/parse.report.json", nil)
	readReq.Host = "127.0.0.1"
	readRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusOK {
		t.Fatalf("artifact read status = %d, want 200", readRec.Code)
	}
	if got := readRec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("artifact content type = %q", got)
	}
	if !strings.Contains(readRec.Body.String(), `"step":"parse"`) {
		t.Fatalf("artifact body = %q", readRec.Body.String())
	}

	unknown := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifact/not-allowlisted.txt", nil)
	unknown.Host = "127.0.0.1"
	unknownRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(unknownRec, unknown)
	if unknownRec.Code != http.StatusNotFound {
		t.Fatalf("unknown artifact status = %d, want 404", unknownRec.Code)
	}

	missingJob := httptest.NewRequest(http.MethodGet, "/scan/abcdef12/artifacts", nil)
	missingJob.Host = "127.0.0.1"
	missingRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(missingRec, missingJob)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("unknown job artifact list status = %d, want 404", missingRec.Code)
	}
}

func TestStandaloneArtifactViewerRoute(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0123456789abcdef"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "report.html"), []byte("<html>report</html>"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "dataset.json"), []byte(`{"units":[]}`), 0640); err != nil {
		t.Fatal(err)
	}

	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifact-view/dataset.json?lang=zh-CN", nil)
	request.Host = "127.0.0.1"
	record := httptest.NewRecorder()
	s.Handler().ServeHTTP(record, request)
	if record.Code != http.StatusOK {
		t.Fatalf("artifact viewer status = %d, body = %q", record.Code, record.Body.String())
	}
	if got := record.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("artifact viewer content type = %q", got)
	}
	for _, want := range []string{"data-job-id=\"" + jobID + "\"", "data-artifact-name=\"dataset.json\"", "structured-view", "raw-view"} {
		if !strings.Contains(record.Body.String(), want) {
			t.Fatalf("artifact viewer body missing %q: %s", want, record.Body.String())
		}
	}

	unknown := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifact-view/not-allowlisted.json", nil)
	unknown.Host = "127.0.0.1"
	unknownRecord := httptest.NewRecorder()
	s.Handler().ServeHTTP(unknownRecord, unknown)
	if unknownRecord.Code != http.StatusNotFound {
		t.Fatalf("unknown artifact viewer status = %d, want 404", unknownRecord.Code)
	}
}

func TestArtifactReadRejectsSymlinkAndOversize(t *testing.T) {
	outDir := t.TempDir()
	jobID := "fedcba9876543210"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	mgr := newManager(outDir)
	mgr.add(&Job{ID: jobID, Status: StatusDone})
	s := &Server{outDir: outDir, mgr: mgr}

	secret := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(secret, []byte(`{"secret":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(jobDir, "pipeline_output.json")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	linkReq := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifact/pipeline_output.json", nil)
	linkReq.SetPathValue("id", jobID)
	linkReq.SetPathValue("name", "pipeline_output.json")
	linkRec := httptest.NewRecorder()
	s.handleArtifact(linkRec, linkReq)
	if linkRec.Code != http.StatusNotFound {
		t.Fatalf("symlink artifact status = %d, want 404", linkRec.Code)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte(strings.Repeat("x", maxArtifactBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	largeReq := httptest.NewRequest(http.MethodGet, "/scan/"+jobID+"/artifact/pipeline_output.json", nil)
	largeReq.SetPathValue("id", jobID)
	largeReq.SetPathValue("name", "pipeline_output.json")
	largeRec := httptest.NewRecorder()
	s.handleArtifact(largeRec, largeReq)
	if largeRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize artifact status = %d, want 413", largeRec.Code)
	}
}

func TestExploreDatasetSupportsSearchPaginationAndFullItem(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0123456789abcdef"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	dataset := map[string]any{
		"name":       "fixture",
		"repository": "fixture-repo",
		"units": []any{
			map[string]any{
				"id":             "src/service.cpp:Service::OnRemoteRequest",
				"language":       "cpp",
				"unit_type":      "method",
				"reachable":      true,
				"is_entry_point": true,
				"code": map[string]any{
					"primary_code": "return Dispatch(data);",
					"primary_origin": map[string]any{
						"file_path":  "src/service.cpp",
						"start_line": 10,
						"end_line":   14,
					},
				},
				"metadata": map[string]any{
					"direct_calls": []any{"src/service.cpp:Service::Dispatch"},
				},
			},
			map[string]any{
				"id":             "src/helper.cpp:Helper::Run",
				"language":       "cpp",
				"unit_type":      "method",
				"reachable":      false,
				"is_entry_point": false,
			},
		},
		"statistics": map[string]any{"total_units": 2},
	}
	writeJSONArtifact(t, filepath.Join(jobDir, "dataset.json"), dataset)

	mgr := newManager(outDir)
	mgr.add(&Job{ID: jobID, Status: StatusDone})
	s := &Server{outDir: outDir, mgr: mgr}

	listReq := httptest.NewRequest(http.MethodGet,
		"/scan/"+jobID+"/explore/dataset.json?q=OnRemoteRequest&entry_point=true&limit=1", nil)
	listReq.Host = "127.0.0.1"
	listRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("dataset explore status = %d, body = %q", listRec.Code, listRec.Body.String())
	}
	var list explorerView
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode dataset explore: %v", err)
	}
	if list.Kind != "collection" || list.CollectionKey != "units" || list.Total != 1 || len(list.Items) != 1 {
		t.Fatalf("dataset explore view = %#v", list)
	}
	if list.Items[0].File != "src/service.cpp" || list.Items[0].StartLine != 10 {
		t.Fatalf("dataset row location = %#v", list.Items[0])
	}

	itemID := url.QueryEscape("src/service.cpp:Service::OnRemoteRequest")
	detailReq := httptest.NewRequest(http.MethodGet,
		"/scan/"+jobID+"/explore/dataset.json?item="+itemID, nil)
	detailReq.Host = "127.0.0.1"
	detailRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("dataset detail status = %d, body = %q", detailRec.Code, detailRec.Body.String())
	}
	var detail explorerView
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode dataset detail: %v", err)
	}
	item, ok := detail.Item.(map[string]any)
	if !ok || item["id"] != "src/service.cpp:Service::OnRemoteRequest" {
		t.Fatalf("dataset detail item = %#v", detail.Item)
	}
	code, ok := item["code"].(map[string]any)
	if !ok || code["primary_code"] != "return Dispatch(data);" {
		t.Fatalf("dataset detail lost full code = %#v", item["code"])
	}
}

func TestExploreAnalyzerOutputSearchesFunctionMap(t *testing.T) {
	outDir := t.TempDir()
	jobID := "fedcba9876543210"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	analyzer := map[string]any{
		"repository": "fixture-repo",
		"functions": map[string]any{
			"src/service.cpp:Service::OnRemoteRequest": map[string]any{
				"name":      "Service::OnRemoteRequest",
				"language":  "cpp",
				"unitType":  "method",
				"filePath":  "src/service.cpp",
				"startLine": 20,
				"endLine":   30,
				"code":      "return (this->*handler)(data, reply);",
			},
			"src/helper.cpp:Helper::Run": map[string]any{
				"name":     "Helper::Run",
				"language": "cpp",
			},
		},
		"call_graph": map[string]any{
			"src/service.cpp:Service::OnRemoteRequest": []any{"src/service.cpp:Service::Dispatch"},
		},
		"reverse_call_graph": map[string]any{},
	}
	writeJSONArtifact(t, filepath.Join(jobDir, "analyzer_output.json"), analyzer)
	mgr := newManager(outDir)
	mgr.add(&Job{ID: jobID, Status: StatusDone})
	s := &Server{outDir: outDir, mgr: mgr}

	req := httptest.NewRequest(http.MethodGet,
		"/scan/"+jobID+"/explore/analyzer_output.json?q=OnRemoteRequest", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyzer explore status = %d, body = %q", rec.Code, rec.Body.String())
	}
	var view explorerView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode analyzer explore: %v", err)
	}
	if view.Kind != "collection" || view.CollectionKey != "functions" || view.Total != 1 || len(view.Items) != 1 {
		t.Fatalf("analyzer explore view = %#v", view)
	}
	if view.Items[0].ID != "src/service.cpp:Service::OnRemoteRequest" || view.Items[0].File != "src/service.cpp" {
		t.Fatalf("analyzer function row = %#v", view.Items[0])
	}
	if len(view.AvailableCollections) != 3 || view.AvailableCollections[0] != "functions" {
		t.Fatalf("analyzer collections = %#v", view.AvailableCollections)
	}

	graphReq := httptest.NewRequest(http.MethodGet,
		"/scan/"+jobID+"/explore/analyzer_output.json?collection=call_graph", nil)
	graphReq.Host = "127.0.0.1"
	graphRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(graphRec, graphReq)
	if graphRec.Code != http.StatusOK {
		t.Fatalf("call graph explore status = %d, body = %q", graphRec.Code, graphRec.Body.String())
	}
	var graphView explorerView
	if err := json.Unmarshal(graphRec.Body.Bytes(), &graphView); err != nil {
		t.Fatalf("decode call graph explore: %v", err)
	}
	if graphView.CollectionKey != "call_graph" || graphView.Total != 1 || len(graphView.Items) != 1 {
		t.Fatalf("call graph explore view = %#v", graphView)
	}
	if graphView.Items[0].ID != "src/service.cpp:Service::OnRemoteRequest" {
		t.Fatalf("call graph row = %#v", graphView.Items[0])
	}
}

func TestExploreRejectsNonJSONAndInvalidQuery(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0011223344556677"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "dynamic_test_results.md"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "dataset.json"), []byte(`{"units":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	mgr := newManager(outDir)
	mgr.add(&Job{ID: jobID, Status: StatusDone})
	s := &Server{outDir: outDir, mgr: mgr}

	for _, path := range []string{
		"/scan/" + jobID + "/explore/dynamic_test_results.md",
		"/scan/" + jobID + "/explore/dataset.json?limit=9999",
		"/scan/" + jobID + "/explore/dataset.json?entry_point=maybe",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if strings.Contains(path, "dynamic_test_results.md") {
			if rec.Code != http.StatusNotFound {
				t.Fatalf("non-json explore status = %d, want 404", rec.Code)
			}
		} else if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q status = %d, want 400", path, rec.Code)
		}
	}
}

func writeJSONArtifact(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestEveryArtifactHasValidStageAndDescription(t *testing.T) {
	validStages := make(map[string]bool, len(pipelineStepSpecs))
	for _, stage := range pipelineStepSpecs {
		validStages[stage.ID] = true
	}
	seen := make(map[string]bool, len(scanArtifactSpecs))
	for _, artifact := range scanArtifactSpecs {
		if seen[artifact.Name] {
			t.Errorf("duplicate artifact name %q", artifact.Name)
		}
		seen[artifact.Name] = true
		if !validStages[artifact.Stage] {
			t.Errorf("artifact %q has invalid stage %q", artifact.Name, artifact.Stage)
		}
		if strings.TrimSpace(artifact.Description) == "" {
			t.Errorf("artifact %q has no description", artifact.Name)
		}
	}
	for _, name := range []string{"call_graph.json", "report-data.report.json", "pipeline_results.json", "scan_results.json"} {
		if !seen[name] {
			t.Errorf("generated JSON artifact %q is not exposed by the allowlist", name)
		}
	}
}
