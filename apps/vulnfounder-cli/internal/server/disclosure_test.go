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

func TestParseDisclosureMetadata(t *testing.T) {
	markdown := `# Security Disclosure: VULNERABLE

**Product:** sensors_medical_sensor
**Type:** CWE-862 (Missing Authorization)
**CVE:** cve-2026-55989
**Affected:** [NOT PROVIDED]

## Summary

OnRemoteRequest validates the interface token but does not authorize the caller identity.
An attacker can reach a state-changing callback.

## Vulnerable Code

` + "`services/samgr/native/source/stub.cpp`:" + `

` + "```cpp" + `
int32_t SomeStub::OnRemoteRequest(uint32_t code, MessageParcel& data)
{
    return Handle(code, data);
}
` + "```" + `
`
	got := parseDisclosureMetadata(markdown)

	if got.Label != "VULNERABLE" {
		t.Fatalf("Label = %q, want VULNERABLE", got.Label)
	}
	if got.VulnerabilityType != "CWE-862 (Missing Authorization)" {
		t.Fatalf("VulnerabilityType = %q", got.VulnerabilityType)
	}
	if got.CVE != "CVE-2026-55989" {
		t.Fatalf("CVE = %q, want CVE-2026-55989", got.CVE)
	}
	if got.FilePath != "services/samgr/native/source/stub.cpp" {
		t.Fatalf("FilePath = %q", got.FilePath)
	}
	if got.Function != "SomeStub::OnRemoteRequest" {
		t.Fatalf("Function = %q", got.Function)
	}
	if got.Summary != "OnRemoteRequest validates the interface token but does not authorize the caller identity. An attacker can reach a state-changing callback." {
		t.Fatalf("Summary = %q", got.Summary)
	}
}

func TestDisclosureMetadataFromFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.md")
	link := filepath.Join(dir, "link.md")
	if err := os.WriteFile(target, []byte("# Security Disclosure: SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if got := disclosureMetadataFromFile(link); got.Label != "" || strings.TrimSpace(got.Summary) != "" {
		t.Fatalf("symlink metadata = %#v, want empty metadata", got)
	}
}

func TestDisclosureCompactTextTruncatesByRune(t *testing.T) {
	got := disclosureCompactText("中文漏洞描述", 5)
	if got != "中文..." {
		t.Fatalf("compact text = %q, want 中文...", got)
	}
}

func TestDisclosureListIncludesEvidenceContext(t *testing.T) {
	outDir := t.TempDir()
	jobID := "0123456789abcdef"
	jobDir := filepath.Join(outDir, jobID)
	discDir := filepath.Join(jobDir, "report", "disclosures")
	if err := os.MkdirAll(discDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "report.html"), []byte("<html>ok</html>"), 0640); err != nil {
		t.Fatal(err)
	}
	markdown := `# Security Disclosure: Null Dereference

**Product:** fixture
**Type:** CWE-476 (NULL Pointer Dereference)
**CVE:** CVE-2026-55989
**Affected:** release-6.1

## Summary

The service dereferences an attacker-controlled element.

## Suggested Fix

` + "```cpp" + `
if (item == nullptr) return ERR_INVALID_VALUE;
` + "```" + `
修复状态：` + "`generated`" + `

## Evidence Context

### Target Source Location

- **Function:** ` + "`Service::Handle`" + `
- **File:** ` + "`services/service.cpp`" + ` (第 40-48 行)

- **Entry point:** BinderStub::OnRemoteRequest
- **Function route chain:** ["BinderStub::OnRemoteRequest", "Service::Handle"]
`
	if err := os.WriteFile(filepath.Join(discDir, "DISCLOSURE_01_NULL_DEREFERENCE.md"), []byte(markdown), 0640); err != nil {
		t.Fatal(err)
	}
	pipeline := map[string]any{
		"repository": map[string]any{"name": "fixture", "release_version": "OpenHarmony-6.1"},
		"findings": []any{map[string]any{
			"cwe_id": 476, "cwe_name": "NULL Pointer Dereference",
			"location":      map[string]any{"file": "services/service.cpp", "function": "Service::Handle", "start_line": 40, "end_line": 48},
			"suggested_fix": "if (item == nullptr) return ERR_INVALID_VALUE;",
			"report_context": map[string]any{
				"source_to_sink": map[string]any{"entry_point": "BinderStub::OnRemoteRequest", "function_route_chain": []any{"BinderStub::OnRemoteRequest", "Service::Handle"}},
				"call_chain": map[string]any{"node_count": 2, "omitted_node_count": 0, "nodes": []any{
					map[string]any{"function": "BinderStub::OnRemoteRequest", "file": "services/stub.cpp", "start_line": 10, "end_line": 20, "role": "entry"},
					map[string]any{"function": "Service::Handle", "file": "services/service.cpp", "start_line": 40, "end_line": 48, "role": "target"},
				}},
			},
		}},
	}
	pipelineBytes, err := json.Marshal(pipeline)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "pipeline_output.json"), pipelineBytes, 0640); err != nil {
		t.Fatal(err)
	}

	s, err := New("/bin/false", outDir)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/disclosures/"+jobID, nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disclosure list status = %d, body = %q", rec.Code, rec.Body.String())
	}
	var got []disclosureInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("disclosure list length = %d, want 1", len(got))
	}
	info := got[0]
	if info.CWEID != "476" || info.CWEName != "NULL Pointer Dereference" {
		t.Fatalf("CWE metadata = %#v", info)
	}
	if info.CVE != "CVE-2026-55989" {
		t.Fatalf("CVE metadata = %#v", info)
	}
	if info.FilePath != "services/service.cpp" || info.Function != "Service::Handle" || info.StartLine != 40 || info.EndLine != 48 {
		t.Fatalf("location metadata = %#v", info)
	}
	if info.AffectedVersion != "OpenHarmony-6.1" || info.RepairStatus != "generated" {
		t.Fatalf("revision/repair metadata = %#v", info)
	}
	if !info.ContextAvailable || info.SourceToSink == "" || info.CallChainCount != 2 || len(info.CallChain) != 2 {
		t.Fatalf("context metadata = %#v", info)
	}
}
