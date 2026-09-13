package cmd

import "testing"

func TestValidateDynamicTestMode(t *testing.T) {
	for _, mode := range []string{"docker", "claude-code"} {
		if err := validateDynamicTestMode(mode); err != nil {
			t.Errorf("mode %q should be accepted: %v", mode, err)
		}
	}
	if err := validateDynamicTestMode("unknown"); err == nil {
		t.Fatal("unknown dynamic-test mode must be rejected")
	}
}

func TestDynamicTestModeFlagDefaultsToDocker(t *testing.T) {
	flag := dynamicTestCmd.Flag("mode")
	if flag == nil {
		t.Fatal("dynamic-test command is missing --mode")
	}
	if got, want := flag.DefValue, "docker"; got != want {
		t.Errorf("--mode default = %q, want %q", got, want)
	}
}
