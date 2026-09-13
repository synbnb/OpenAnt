package cmd

import "testing"

func TestParsePlatformFlagDefaultsToAuto(t *testing.T) {
	flag := parseCmd.Flag("platform")
	if flag == nil {
		t.Fatal("parse command is missing --platform")
	}
	if got, want := flag.DefValue, "auto"; got != want {
		t.Errorf("--platform default = %q, want %q", got, want)
	}
}

func TestBuildParsePyArgsForwardsExplicitPlatform(t *testing.T) {
	original := parsePlatform
	defer func() { parsePlatform = original }()

	parsePlatform = "auto"
	args := buildParsePyArgs("/repo", "/out", "", "auto", "reachable", "", false, false)
	if found, _ := findFlag(args, "--platform"); found {
		t.Errorf("default platform must be omitted, got %v", args)
	}

	parsePlatform = "openharmony"
	args = buildParsePyArgs("/repo", "/out", "", "auto", "reachable", "", false, false)
	found, value := findFlag(args, "--platform")
	if !found || value != "openharmony" {
		t.Errorf("explicit platform was not forwarded, got %v", args)
	}
}

func TestParsePlatformValidationUsesSharedContract(t *testing.T) {
	if err := validateScanPlatform("android"); err == nil {
		t.Error("unknown platform must be rejected")
	}
}
