package cmd

import "testing"

func TestValidateScanPlatform(t *testing.T) {
	for _, platform := range []string{"auto", "generic", "openharmony"} {
		if err := validateScanPlatform(platform); err != nil {
			t.Errorf("platform %q should be accepted: %v", platform, err)
		}
	}
	if err := validateScanPlatform("android"); err == nil {
		t.Error("unknown platform must be rejected")
	}
}

func TestScanPlatformFlagDefaultsToAuto(t *testing.T) {
	flag := scanCmd.Flag("platform")
	if flag == nil {
		t.Fatal("scan command is missing --platform")
	}
	if got, want := flag.DefValue, "auto"; got != want {
		t.Errorf("--platform default = %q, want %q", got, want)
	}
}

func TestBuildScanPyArgsForwardsOnlyExplicitPlatform(t *testing.T) {
	original := scanPlatform
	defer func() { scanPlatform = original }()

	scanPlatform = "auto"
	args := buildScanPyArgs("/repo")
	if found, _ := findFlag(args, "--platform"); found {
		t.Errorf("default platform must be omitted, got %v", args)
	}

	scanPlatform = "openharmony"
	args = buildScanPyArgs("/repo")
	found, value := findFlag(args, "--platform")
	if !found || value != "openharmony" {
		t.Errorf("explicit platform was not forwarded, got %v", args)
	}
}
