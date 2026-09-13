package cmd

import (
	"strings"
	"testing"
)

func TestRootCommandUsesVulnFounderBrand(t *testing.T) {
	if rootCmd.Use != "vulnfounder" {
		t.Fatalf("root command Use = %q, want vulnfounder", rootCmd.Use)
	}
	if !strings.Contains(rootCmd.Long, "VulnFounder") {
		t.Fatalf("root command description does not use VulnFounder brand: %q", rootCmd.Long)
	}
}
