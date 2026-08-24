package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePipelineReport(t *testing.T, dir, name string, report pipelineReportFile) {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal %s report: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".report.json"), data, 0640); err != nil {
		t.Fatalf("write %s report: %v", name, err)
	}
}

func TestPipelineViewReadsStageReportsAndOptionalStages(t *testing.T) {
	outDir := t.TempDir()
	jobID := "abcdef0123456789"
	jobDir := filepath.Join(outDir, jobID)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}

	writePipelineReport(t, jobDir, "parse", pipelineReportFile{
		Step:            "parse",
		Status:          "success",
		Timestamp:       "2026-08-23T01:02:03Z",
		DurationSeconds: 1.25,
		CostUSD:         0.01,
		CostCNY:         0.0,
		CostAmount:      0.01,
		CostCurrency:    "USD",
		CostsByCurrency: map[string]float64{"USD": 0.01},
		TokenUsage:      map[string]int{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
		Summary:         map[string]any{"total_units": float64(42)},
	})
	writePipelineReport(t, jobDir, "app-context", pipelineReportFile{
		Step:            "app-context",
		Status:          "success",
		CostCNY:         5.684,
		CostAmount:      5.684,
		CostCurrency:    "CNY",
		CostsByCurrency: map[string]float64{"CNY": 5.684},
		TokenUsage:      map[string]int{"input_tokens": 20, "output_tokens": 8, "total_tokens": 28},
		Summary:         map[string]any{"application_type": "openharmony_component"},
	})

	job := &Job{
		ID:          jobID,
		Repo:        "/tmp/openharmony",
		StartedAt:   time.Date(2026, time.August, 23, 1, 0, 0, 0, time.UTC),
		Status:      StatusRunning,
		platform:    "openharmony",
		verify:      true,
		dynamicTest: false,
		LogBuf:      []string{"[app-context] generating application context"},
	}

	view := (&Server{outDir: outDir}).pipelineView(job)
	if view.CurrentStep != "app-context" {
		t.Fatalf("current step = %q, want app-context", view.CurrentStep)
	}
	if len(view.Steps) != len(pipelineStepSpecs) {
		t.Fatalf("got %d steps, want %d", len(view.Steps), len(pipelineStepSpecs))
	}

	byID := make(map[string]pipelineStepView, len(view.Steps))
	for _, step := range view.Steps {
		byID[step.ID] = step
	}
	if got := byID["parse"]; got.Status != "success" || got.DurationSeconds == nil || *got.DurationSeconds != 1.25 {
		t.Fatalf("parse projection = %#v", got)
	}
	if got := byID["parse"]; got.CostCurrency != "USD" || got.CostsByCurrency["USD"] != 0.01 {
		t.Fatalf("parse cost projection = %#v", got)
	}
	if got := byID["parse"]; got.Description == "" || len(got.Inputs) == 0 || len(got.Outputs) == 0 || got.Optional {
		t.Fatalf("parse explanation metadata = %#v", got)
	}
	if got := byID["app-context"]; got.Status != "success" || got.TokenUsage["total_tokens"] != 28 {
		t.Fatalf("app-context projection = %#v", got)
	}
	if got := byID["app-context"]; got.CostCurrency != "CNY" || got.CostsByCurrency["CNY"] != 5.684 {
		t.Fatalf("app-context CNY projection = %#v", got)
	}
	if got := byID["llm-reachability"]; got.Status != "not_requested" {
		t.Fatalf("llm reachability status = %q, want not_requested", got.Status)
	}
	if got := byID["llm-reachability"]; !got.Optional {
		t.Fatalf("llm reachability optional = %v, want true", got.Optional)
	}
	if got := byID["verify"]; got.Status != "pending" {
		t.Fatalf("verify status = %q, want pending before its report", got.Status)
	}
	if got := byID["dynamic-test"]; got.Status != "not_requested" {
		t.Fatalf("dynamic test status = %q, want not_requested", got.Status)
	}
}

func TestPipelineViewMarksLLMReachabilityAsRequested(t *testing.T) {
	outDir := t.TempDir()
	jobID := "fedcba9876543210"
	if err := os.MkdirAll(filepath.Join(outDir, jobID), 0750); err != nil {
		t.Fatal(err)
	}
	job := &Job{
		ID:              jobID,
		Repo:            "/tmp/openharmony",
		StartedAt:       time.Now().UTC(),
		Status:          StatusRunning,
		llmReachability: true,
	}
	view := (&Server{outDir: outDir}).pipelineView(job)
	for _, step := range view.Steps {
		if step.ID == "llm-reachability" {
			if step.Status == "not_requested" {
				t.Fatal("LLM reachability is marked not_requested despite being enabled")
			}
			return
		}
	}
	t.Fatal("llm-reachability step missing")
}

func TestPipelineViewInfersRunningFromLogs(t *testing.T) {
	outDir := t.TempDir()
	jobID := "1234567890abcdef"
	if err := os.MkdirAll(filepath.Join(outDir, jobID), 0750); err != nil {
		t.Fatal(err)
	}

	job := &Job{
		ID:     jobID,
		Status: StatusRunning,
		LogBuf: []string{"[analyze] running vulnerability detection"},
	}
	view := (&Server{outDir: outDir}).pipelineView(job)
	for _, step := range view.Steps {
		if step.ID == "analyze" {
			if step.Status != "running" {
				t.Fatalf("analyze status = %q, want running", step.Status)
			}
			return
		}
	}
	t.Fatal("analyze step missing")
}

func TestHandlePipelineReturnsJSONAnd404(t *testing.T) {
	outDir := t.TempDir()
	mgr := newManager(outDir)
	s := &Server{outDir: outDir, mgr: mgr}
	job := &Job{ID: "fedcba9876543210", Status: StatusDone, StartedAt: time.Now().UTC()}
	mgr.add(job)

	req := httptest.NewRequest(http.MethodGet, "/scan/"+job.ID+"/pipeline", nil)
	req.SetPathValue("id", job.ID)
	rec := httptest.NewRecorder()
	s.handlePipeline(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pipeline status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content type = %q, want application/json", got)
	}
	var payload pipelineView
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode pipeline JSON: %v", err)
	}
	if payload.ID != job.ID || len(payload.Steps) != len(pipelineStepSpecs) {
		t.Fatalf("payload = %#v", payload)
	}

	missing := httptest.NewRequest(http.MethodGet, "/scan/00000000/pipeline", nil)
	missing.SetPathValue("id", "00000000")
	missingRec := httptest.NewRecorder()
	s.handlePipeline(missingRec, missing)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("unknown job status = %d, want 404", missingRec.Code)
	}
}

func TestReadPipelineReportRejectsSymlinkAndOversize(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"status":"success"}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "parse.report.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, exists, err := readPipelineReport(root, pipelineStepSpec{ID: "parse"}); !exists || err == nil {
		t.Fatal("symlink stage report was accepted")
	}

	large := strings.Repeat("x", maxPipelineReportBytes+1)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte(large), 0600); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readPipelineReport(root, pipelineStepSpec{ID: "parse"}); !exists || err == nil {
		t.Fatal("oversize stage report was accepted")
	}
}

func TestPipelineStepFromLog(t *testing.T) {
	tests := map[string]string{
		"[parse] Parsed: 10 units":                        "parse",
		"Generating application context":                  "app-context",
		"[LLM Reachability] reviewing units":              "llm-reachability",
		"[enhance] Enhanced: 2":                           "enhance",
		"[detect] vulnerability analysis":                 "analyze",
		"[verify] Verification complete":                  "verify",
		"[build-output] Building pipeline_output.json...": "build-output",
		"[dynamic-test] Running dynamic test":             "dynamic-test",
		"[report] Generating reports...":                  "report",
	}
	for line, want := range tests {
		if got := pipelineStepFromLog(line); got != want {
			t.Errorf("pipelineStepFromLog(%q) = %q, want %q", line, got, want)
		}
	}
}
