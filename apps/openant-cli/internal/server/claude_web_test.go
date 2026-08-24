package server

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/knostic/open-ant-cli/internal/types"
)

func TestClaudeOutputIsTerminalSafeAndReplayable(t *testing.T) {
	session := newClaudeSession(t.TempDir())
	session.appendEvent("output", "\x1b[32mready\x1b[0m\rnext")
	session.appendEvent("input", "inspect results/")
	status, _, events := session.snapshot()
	if status != claudeStatusPrepared {
		t.Fatalf("unexpected initial status: %q", status)
	}
	if len(events) != 2 || events[0].Text != "ready\nnext" {
		t.Fatalf("unexpected cleaned events: %#v", events)
	}
	remaining := session.eventsAfter(events[0].ID)
	if len(remaining) != 1 || remaining[0].Kind != "input" {
		t.Fatalf("unexpected replay events: %#v", remaining)
	}
}

func TestClaudeSessionSubmitsMessagesWithCarriageReturn(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	session := newClaudeSession(t.TempDir())
	session.mu.Lock()
	session.status = claudeStatusRunning
	session.pty = writer
	session.mu.Unlock()

	if err := session.writeMessage("inspect candidates"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("inspect candidates\r"))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "inspect candidates\r" {
		t.Fatalf("message bytes = %q, want carriage-return submission", got)
	}
}

func TestUnmarshalLastEnvelopeAcceptsPrettyPrintedJSON(t *testing.T) {
	stdout := `{
  "status": "success",
  "data": {
    "mode": "claude-code",
    "findings_tested": 0
  },
  "errors": []
}
`
	var envelope types.Envelope
	if err := unmarshalLastEnvelope(stdout, &envelope); err != nil {
		t.Fatalf("pretty-printed envelope was rejected: %v", err)
	}
	if envelope.Status != "success" {
		t.Fatalf("status = %q, want success", envelope.Status)
	}
}

func TestUnmarshalLastEnvelopeKeepsCompactFallback(t *testing.T) {
	stdout := "diagnostic line\n{\"status\":\"error\",\"data\":null,\"errors\":[\"boom\"]}\n"
	var envelope types.Envelope
	if err := unmarshalLastEnvelope(stdout, &envelope); err != nil {
		t.Fatalf("compact envelope with diagnostic noise was rejected: %v", err)
	}
	if envelope.Status != "error" || len(envelope.Errors) != 1 || envelope.Errors[0] != "boom" {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
}

func TestPrepareClaudeCodeSkipsEmptyCandidateSession(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0123456789abcdef"
	jobRoot := filepath.Join(outDir, jobID)
	taskDir := filepath.Join(jobRoot, "run-empty", "task")
	if err := os.MkdirAll(taskDir, 0750); err != nil {
		t.Fatal(err)
	}

	response, err := json.Marshal(map[string]any{
		"status": "success",
		"data": map[string]any{
			"mode":                "claude-code",
			"task_workspace":      taskDir,
			"public_tool_library": filepath.Join(jobRoot, "run-empty", "tools"),
			"task_manifest_path":  filepath.Join(taskDir, "task_manifest.json"),
			"candidate_manifest":  filepath.Join(taskDir, "context", "candidate_manifest.json"),
			"launch_command":      "claude --dangerously-skip-permissions",
			"findings_tested":     0,
		},
		"errors": []string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	pythonStub := filepath.Join(t.TempDir(), "python-stub")
	script := "#!/bin/sh\ncat <<'OPENANT_RESPONSE'\n" + string(response) + "\nOPENANT_RESPONSE\n"
	if err := os.WriteFile(pythonStub, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	job := &Job{
		ID:              jobID,
		Repo:            "/tmp/repository",
		StartedAt:       time.Now().UTC(),
		Status:          StatusRunning,
		dynamicTest:     true,
		dynamicTestMode: "claude-code",
		ctx:             ctx,
	}
	s := &Server{outDir: outDir, pythonPath: pythonStub}
	if err := s.prepareAndRunClaudeCode(job, jobRoot, "/tmp/repository"); err != nil {
		t.Fatal(err)
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.claude != nil {
		t.Fatal("Claude session started despite zero dynamic candidates")
	}
	if job.claudeTask == nil || job.claudeTask.CandidateCount != 0 {
		t.Fatalf("empty task metadata was not retained: %#v", job.claudeTask)
	}
	if _, err := os.Stat(filepath.Join(jobRoot, "meta.json")); err != nil {
		t.Fatalf("empty task metadata was not persisted: %v", err)
	}
	if len(job.LogBuf) == 0 || job.LogBuf[len(job.LogBuf)-1] != "[dynamic-test] No dynamically testable candidates; skipping Claude Code session." {
		t.Fatalf("skip log missing: %#v", job.LogBuf)
	}
}

func TestClaudeWorkspacePathsRejectTraversalAndSymlinkReads(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := safeClaudeRelative(root, "../outside"); err == nil {
		t.Fatal("path traversal was accepted")
	}
	rel, safePath, err := safeClaudeRelative(root, "safe.txt")
	if err != nil || rel != "safe.txt" {
		t.Fatalf("safe path rejected: rel=%q err=%v", rel, err)
	}
	f, _, err := openRegularInRoot(root, safePath)
	if err != nil {
		t.Fatalf("safe file could not be opened: %v", err)
	}
	_ = f.Close()

	link := filepath.Join(root, "outside.txt")
	if err := os.Symlink("/etc/hosts", link); err != nil {
		t.Skipf("symlink test unavailable: %v", err)
	}
	_, linkPath, err := safeClaudeRelative(root, "outside.txt")
	if err != nil {
		return
	}
	if _, _, err := openRegularInRoot(root, linkPath); err == nil {
		t.Fatal("symlink file was opened")
	}
}

func TestClaudeSessionCanRelayARealPTYProcess(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake-claude")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'hello from claude\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("OPENANT_CLAUDE_BIN")
	if err := os.Setenv("OPENANT_CLAUDE_BIN", bin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Setenv("OPENANT_CLAUDE_BIN", old) })

	session := newClaudeSession(t.TempDir())
	if err := session.start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	session.wait()
	status, exitCode, events := session.snapshot()
	if status != claudeStatusDone || exitCode != 0 {
		t.Fatalf("PTY session status=%q exit=%d", status, exitCode)
	}
	found := false
	for _, event := range events {
		if event.Kind == "output" && event.Text != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("PTY output was not captured: %#v", events)
	}
}

func TestCollectClaudeResultsCreatesStableArtifactsAndPipelineEvidence(t *testing.T) {
	outDir := t.TempDir()
	jobID := "abcdef0123456789"
	jobDir := filepath.Join(outDir, jobID)
	taskDir := filepath.Join(jobDir, "run-1", "task")
	if err := os.MkdirAll(filepath.Join(taskDir, "results", "OH-001"), 0750); err != nil {
		t.Fatal(err)
	}
	verdict := map[string]any{
		"candidate_id": "OH-001",
		"status":       "BLOCKED",
		"limitations":  []any{"device unavailable"},
	}
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(filepath.Join(taskDir, "results", "OH-001", "verdict.json"), verdict)
	writeJSON(filepath.Join(taskDir, "results", "summary.json"), map[string]any{"status": "complete"})
	writeJSON(filepath.Join(outDir, "pipeline_output.json"), map[string]any{
		"findings": []any{map[string]any{"id": "OH-001", "stage2_verdict": "confirmed"}},
	})
	writeJSON(filepath.Join(outDir, "dynamic-test.report.json"), map[string]any{
		"step": "dynamic-test", "outputs": map[string]any{}, "summary": map[string]any{},
	})

	job := &Job{
		ID:              jobID,
		Status:          StatusRunning,
		StartedAt:       time.Now().UTC(),
		dynamicTest:     true,
		dynamicTestMode: "claude-code",
		claudeTask:      &claudeTaskInfo{Mode: "claude-code", TaskWorkspace: taskDir},
	}
	s := &Server{outDir: outDir}
	s.collectClaudeResults(job, outDir, job.claudeTask)

	resultsPath := filepath.Join(outDir, "dynamic_test_results.json")
	if _, err := os.Stat(resultsPath); err != nil {
		t.Fatal(err)
	}
	resultsBytes, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatal(err)
	}
	var results map[string]any
	if err := json.Unmarshal(resultsBytes, &results); err != nil {
		t.Fatal(err)
	}
	if got := results["results"].([]any)[0].(map[string]any)["finding_id"]; got != "OH-001" {
		t.Fatalf("report-compatible result missing: %#v", results)
	}
	pipelineBytes, err := os.ReadFile(filepath.Join(outDir, "pipeline_output.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pipeline map[string]any
	if err := json.Unmarshal(pipelineBytes, &pipeline); err != nil {
		t.Fatal(err)
	}
	finding := pipeline["findings"].([]any)[0].(map[string]any)
	if finding["dynamic_test_status"] != "BLOCKED" {
		t.Fatalf("dynamic status was not attached: %#v", finding)
	}
}
