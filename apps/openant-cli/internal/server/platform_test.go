package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizePlatform(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{name: "empty preserves auto", input: "", want: "auto", valid: true},
		{name: "whitespace preserves auto", input: "  ", want: "auto", valid: true},
		{name: "openharmony", input: "openharmony", want: "openharmony", valid: true},
		{name: "generic", input: "generic", want: "generic", valid: true},
		{name: "unknown rejected", input: "android", want: "android", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, valid := normalizePlatform(tt.input)
			if got != tt.want || valid != tt.valid {
				t.Fatalf("normalizePlatform(%q) = (%q, %v), want (%q, %v)",
					tt.input, got, valid, tt.want, tt.valid)
			}
		})
	}
}

func TestPlatformArgs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "empty keeps historical argv", input: "", want: nil},
		{name: "auto keeps historical argv", input: "auto", want: nil},
		{name: "generic", input: "generic", want: []string{"--platform", "generic"}},
		{name: "openharmony", input: "openharmony", want: []string{"--platform", "openharmony"}},
		{name: "invalid is fail closed", input: "android", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := platformArgs(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("platformArgs(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("platformArgs(%q) = %v, want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestNormalizeLLMReachabilityMaxCodeBytes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
		valid bool
	}{
		{name: "empty default", input: "", want: defaultLLMReachabilityMaxCodeBytes, valid: true},
		{name: "default", input: "1500", want: 1500, valid: true},
		{name: "long handler", input: "8192", want: 8192, valid: true},
		{name: "too small", input: "255", valid: false},
		{name: "too large", input: "32769", valid: false},
		{name: "not a number", input: "many", valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, valid := normalizeLLMReachabilityMaxCodeBytes(tt.input)
			if got != tt.want || valid != tt.valid {
				t.Fatalf("normalizeLLMReachabilityMaxCodeBytes(%q) = (%d, %v), want (%d, %v)", tt.input, got, valid, tt.want, tt.valid)
			}
		})
	}
}

func TestNormalizeScanExecutionOptions(t *testing.T) {
	if got, ok := normalizeScanLevel(""); !ok || got != defaultScanLevel {
		t.Fatalf("default scan level = (%q, %v), want (%q, true)", got, ok, defaultScanLevel)
	}
	if _, ok := normalizeScanLevel("bogus"); ok {
		t.Fatal("unknown scan level was accepted")
	}
	if got, ok := normalizeEnhanceMode("single-shot"); !ok || got != "single-shot" {
		t.Fatalf("single-shot enhancement mode = (%q, %v)", got, ok)
	}
	if _, ok := normalizeEnhanceMode("multi-agent"); ok {
		t.Fatal("unknown enhancement mode was accepted")
	}
	for _, tt := range []struct {
		raw      string
		fallback int
		min      int
		max      int
		want     int
		valid    bool
	}{
		{"", 8, 1, 64, 8, true},
		{"16", 8, 1, 64, 16, true},
		{"0", 8, 0, 100, 0, true},
		{"65", 8, 1, 64, 0, false},
		{"oops", 8, 1, 64, 0, false},
	} {
		got, ok := normalizeBoundedInt(tt.raw, tt.fallback, tt.min, tt.max)
		if got != tt.want || ok != tt.valid {
			t.Errorf("normalizeBoundedInt(%q) = (%d, %v), want (%d, %v)", tt.raw, got, ok, tt.want, tt.valid)
		}
	}
	for _, tt := range []struct {
		raw   string
		want  float64
		valid bool
	}{
		{"", defaultMinLanguageShare, true}, {"0", 0, true}, {"0.5", 0.5, true}, {"1.01", 0, false}, {"x", 0, false},
	} {
		got, ok := normalizeMinLanguageShare(tt.raw)
		if got != tt.want || ok != tt.valid {
			t.Errorf("normalizeMinLanguageShare(%q) = (%v, %v), want (%v, %v)", tt.raw, got, ok, tt.want, tt.valid)
		}
	}
}

func TestBuildScanArgsForAllWebOptions(t *testing.T) {
	job := &Job{
		Repo:      "/tmp/repo",
		languages: []string{"c", "python"}, platform: "openharmony", level: "all",
		noContext: true, noEnhance: false, enhanceMode: "single-shot", noReport: true,
		noSkipTests: true, allLanguages: true, multiLanguage: false, minLanguageFiles: 9,
		minLanguageShare: 0, strictLanguages: true, limit: 42, llmConfig: "analysis",
		workers: 12, backoff: 0, verify: true, llmReachability: true,
		llmReachabilityMaxCodeBytes: 4096, llmCallGraphRecovery: true,
		llmCallGraphIterative: true, llmCallGraphCandidateReview: true,
		llmCallGraphProjection: true, dispatchCodeEvidence: true,
		dynamicTest: true, dynamicTestMode: "docker", libraryMode: true,
	}
	got := buildScanArgs(job, "/tmp/out", "/tmp/repo", false)
	for _, want := range []string{
		"--languages", "c,python", "--platform", "openharmony", "--level", "all",
		"--no-context", "--enhance-mode", "single-shot", "--no-report", "--no-skip-tests",
		"--all-languages", "--min-language-files", "9", "--min-language-share", "0",
		"--strict-languages", "--limit", "42", "--llm-config", "analysis", "--workers", "12",
		"--backoff", "0", "--verify", "--llm-reachability", "--llm-reachability-max-code-bytes", "4096",
		"--llm-call-graph-recovery", "--llm-call-graph-iterative-recovery",
		"--llm-call-graph-candidate-review", "--llm-call-graph-projection",
		"--openharmony-dispatch-code-evidence", "--dynamic-test", "--library-mode", "--", "/tmp/repo",
	} {
		found := false
		for _, arg := range got {
			if arg == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("buildScanArgs missing %q in %v", want, got)
		}
	}
	for _, arg := range got {
		if arg == "--dynamic-test-mode" {
			t.Error("default Docker mode should not add a redundant dynamic-test-mode flag")
		}
	}
}

func TestHandleStartScanRejectsUnsupportedPlatform(t *testing.T) {
	dir := t.TempDir()
	s := &Server{
		outDir:       dir,
		mgr:          newManager(dir),
		csrfToken:    "tok",
		sem:          make(chan struct{}, 4),
		shutdownDone: make(chan struct{}),
	}
	req := httptest.NewRequest(
		"POST",
		"/scan",
		strings.NewReader("csrf=tok&repo=/tmp/x&platform=android"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.handleStartScan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported platform status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := len(s.mgr.all()); got != 0 {
		t.Fatalf("unsupported platform created %d jobs", got)
	}
}
