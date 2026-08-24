package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDisclosureMetadata(t *testing.T) {
	markdown := `# Security Disclosure: VULNERABLE

**Product:** sensors_medical_sensor
**Type:** CWE-862 (Missing Authorization)
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
