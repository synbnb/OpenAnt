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
