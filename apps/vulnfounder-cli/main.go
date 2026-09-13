// VulnFounder CLI - LLM-powered static analysis security testing.
//
// This binary wraps the Python `vulnfounder` package, providing a native CLI
// experience with colored output, progress streaming, and JSON mode.
package main

import "github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd"

func main() {
	cmd.Execute()
}
