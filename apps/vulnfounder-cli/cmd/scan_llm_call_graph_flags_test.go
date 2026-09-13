package cmd

import "testing"

func TestScanLLMCallGraphFlagsDefaultOff(t *testing.T) {
	for _, name := range []string{
		"llm-call-graph-recovery",
		"llm-call-graph-iterative-recovery",
		"llm-call-graph-candidate-review",
		"llm-call-graph-projection",
	} {
		flag := scanCmd.Flag(name)
		if flag == nil {
			t.Fatalf("scan command is missing --%s", name)
		}
		if flag.DefValue != "false" {
			t.Errorf("--%s default = %q, want false", name, flag.DefValue)
		}
	}
}

func TestAppendScanLLMCallGraphPyArgsForwardsOnlyEnabledFlags(t *testing.T) {
	originalRecovery := scanLLMCallGraphRecovery
	originalIterative := scanLLMCallGraphIterative
	originalCandidate := scanLLMCallGraphCandidateReview
	originalProjection := scanLLMCallGraphProjection
	defer func() {
		scanLLMCallGraphRecovery = originalRecovery
		scanLLMCallGraphIterative = originalIterative
		scanLLMCallGraphCandidateReview = originalCandidate
		scanLLMCallGraphProjection = originalProjection
	}()

	scanLLMCallGraphRecovery = true
	scanLLMCallGraphIterative = true
	scanLLMCallGraphCandidateReview = false
	scanLLMCallGraphProjection = true
	args := appendScanLLMCallGraphPyArgs([]string{"scan", "/repo"})

	if found, _ := findFlag(args, "--llm-call-graph-recovery"); !found {
		t.Errorf("recovery flag was not forwarded: %v", args)
	}
	if found, _ := findFlag(args, "--llm-call-graph-iterative-recovery"); !found {
		t.Errorf("iterative recovery flag was not forwarded: %v", args)
	}
	if found, _ := findFlag(args, "--llm-call-graph-candidate-review"); found {
		t.Errorf("disabled candidate-review flag was forwarded: %v", args)
	}
	if found, _ := findFlag(args, "--llm-call-graph-projection"); !found {
		t.Errorf("projection flag was not forwarded: %v", args)
	}
}
