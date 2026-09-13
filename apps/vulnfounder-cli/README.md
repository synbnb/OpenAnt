# VulnFounder CLI

Go-based command-line wrapper for VulnFounder. Delegates parsing and analysis to
the Python core in `libs/vulnfounder-core/`.

See the [repo README](../../README.md) for setup, installation, and usage.

## Build

```bash
cd apps/vulnfounder-cli && make build
```

This compiles the Go source to `apps/vulnfounder-cli/bin/vulnfounder`.

`make build-legacy` additionally creates `bin/openant` for existing scripts.

## Environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key used for Stage 1/Stage 2 LLM calls. Overridden by the `--api-key` flag and the value stored via `vulnfounder set-api-key`. Required unless `VULNFOUNDER_LOCAL_CLAUDE=true`. |
| `VULNFOUNDER_PYTHON` | Pin a specific Python interpreter (for example `VULNFOUNDER_PYTHON=python3.11` or an absolute path). The legacy `OPENANT_PYTHON` spelling remains accepted. |
| `VULNFOUNDER_INVOKE_TIMEOUT` | Maximum time the CLI waits on a Python subprocess before killing it. The legacy `OPENANT_INVOKE_TIMEOUT` spelling remains accepted. |
| `VULNFOUNDER_LOCAL_CLAUDE` | Set to `true` to run analyses through a local Claude Code CLI session instead of the Anthropic API. The legacy `OPENANT_LOCAL_CLAUDE` spelling remains accepted. |
| `VULNFOUNDER_CLAUDE_BIN` | Optional path to the Claude Code executable. `OPENANT_CLAUDE_BIN` remains accepted as a legacy alias. |
| `CLAUDE_CONFIG_DIR` | Optional Claude Code configuration/session directory. |
