// VulnFounder CLI - LLM-powered static analysis security testing.
//
// This binary wraps the Python `vulnfounder` package, providing a native CLI
// experience with colored output, progress streaming, and JSON mode.
package main

import "vulnfounder/apps/vulnfounder-cli/cmd"

func main() {
	cmd.Execute()
}
