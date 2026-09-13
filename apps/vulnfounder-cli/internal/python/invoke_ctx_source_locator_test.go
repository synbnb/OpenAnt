package python

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDecodeEnvelopeAcceptsPrettyPrintedSingleDocument(t *testing.T) {
	envelope, err := DecodeEnvelope("{\n  \"status\": \"success\",\n  \"data\": {\"state\": \"INTAKE\"},\n  \"errors\": []\n}\n")
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	if envelope.Status != "success" {
		t.Fatalf("status = %q, want success", envelope.Status)
	}
}

func TestDecodeEnvelopeRejectsEmptyAndTrailingOutput(t *testing.T) {
	for _, raw := range []string{"", "{} {}", "{\"status\":\"success\"} trailing"} {
		if _, err := DecodeEnvelope(raw); err == nil {
			t.Fatalf("DecodeEnvelope(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestDecodeEnvelopeRejectsUnknownStatus(t *testing.T) {
	if _, err := DecodeEnvelope(`{"status":"partial","data":{},"errors":[]}`); err == nil {
		t.Fatal("unknown status unexpectedly accepted")
	}
}

func writeSourceLocatorEmptyWorker(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("source-locator subprocess test uses a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "empty-worker.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write worker script: %v", err)
	}
	return path
}

func TestInvokeCtxCaptureEmptyStdoutIncludesExitAndStderrDiagnostics(t *testing.T) {
	script := writeSourceLocatorEmptyWorker(t, "printf 'opengrok transport failed\\n' >&2\nexit 17")
	stdout, exitCode, err := InvokeCtxCapture(
		context.Background(), script, []string{"source-locator", "advance"}, "", "", nil,
	)
	if err == nil {
		t.Fatal("empty worker output unexpectedly succeeded")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if exitCode != 17 {
		t.Fatalf("exitCode = %d, want 17", exitCode)
	}
	message := err.Error()
	if !strings.Contains(message, "no JSON envelope") ||
		!strings.Contains(message, "exit code 17") ||
		!strings.Contains(message, "opengrok transport failed") {
		t.Fatalf("diagnostic = %q, missing exit/stderr details", message)
	}
}

func TestInvokeSourceLocatorContextTimeoutDoesNotBecomeJSONEOF(t *testing.T) {
	script := writeSourceLocatorEmptyWorker(t, "sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := InvokeSourceLocator(ctx, script, []string{"advance", "loc_test12345678"}, "", nil)
	if err == nil {
		t.Fatal("timed-out worker unexpectedly succeeded")
	}
	message := err.Error()
	if strings.Contains(message, "decode Python JSON envelope: EOF") ||
		!strings.Contains(message, "context: context deadline exceeded") {
		t.Fatalf("timeout diagnostic = %q, want explicit context deadline", message)
	}
}
