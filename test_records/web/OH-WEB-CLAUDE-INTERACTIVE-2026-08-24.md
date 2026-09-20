# OH-WEB-CLAUDE-INTERACTIVE-2026-08-24

## 本阶段目标

把 Claude Code 动态测试从“命令行手动打开任务目录”改成 Web 内交互：用户选择 Claude Code 模式后，扫描先完成动态测试前的静态阶段；页面在动态测试阶段显示 Claude 对话区，右侧实时显示任务工作目录和可读文件。

## 原项目逻辑与本次逻辑

原逻辑是 Web 直接启动一次 `python -m openant scan`。动态测试如果启用，会由 Python 侧完成 Docker 运行；Claude Code 模式此前只生成任务包，用户仍需自行在命令行执行启动命令。

本次逻辑为：

1. 首页的动态测试选项增加 `Docker 隔离执行` 和 `Claude Code 交互工作台`。
2. Web 选择 Claude Code 后，Python 静态扫描使用 `--no-report`，因此不会在用户交互前生成最终报告。
3. 静态扫描完成后，Web 自动执行 `dynamic-test --mode claude-code`，任务包写入当前扫描输出目录下的 `run-*/task/`，并把任务路径、候选数量、工具库和清单路径持久化到 `meta.json`。
4. Web 后端在任务目录启动 `claude --dangerously-skip-permissions` 的 PTY 会话。若需要指定二进制，可设置 `OPENANT_CLAUDE_BIN`。
5. 页面通过 SSE 接收 Claude 输出，通过 POST 接口发送消息或停止会话；右侧通过只读接口轮询任务目录和文件内容。
6. Claude 会话结束后，Web 读取任务目录 `results/` 中合法的 `verdict.json`，生成兼容报告阶段 `results[]` 结构的 `dynamic_test_results.json` 和 `dynamic_test_results.md`，并把合法状态回写到 `pipeline_output.json`，再继续生成中英文最终报告。

## 新增 Web 接口

| 接口 | 用途 | 写权限 |
| --- | --- | --- |
| `GET /scan/{id}/claude` | 会话状态、任务路径、候选数量和最近事件 | 只读 |
| `GET /scan/{id}/claude/events` | Claude PTY 输出的 SSE 流 | 只读 |
| `POST /scan/{id}/claude/message` | 向 PTY 写入一条用户消息 | 需要同源和 `X-CSRF-Token` |
| `POST /scan/{id}/claude/stop` | 停止当前会话 | 需要同源和 `X-CSRF-Token` |
| `GET /scan/{id}/claude/files` | 任务目录文件树 | 只读 |
| `GET /scan/{id}/claude/file?path=...` | 查看任务目录中的单个文本文件 | 只读、限制 4 MiB |

文件接口只接受扫描任务目录内的普通文件；拒绝 `..` 穿越、最终组件符号链接、特殊文件和超大文件。任务中的 `source_code` 链接会显示在树中，但不会被文件接口跟随到任务目录之外。

## 代码产物

- `apps/vulnfounder-cli/internal/server/claude_session.go`：PTY 会话、ANSI 清理、事件缓存、停止和状态机。
- `apps/vulnfounder-cli/internal/server/claude_web.go`：任务准备、Web API、文件树、结果归档和 pipeline 回写。
- `apps/vulnfounder-cli/ui/index.html`：动态测试模式选择器。
- `apps/vulnfounder-cli/ui/scan.html`：Claude 对话工作台、SSE transcript、任务文件树和文件预览。
- `libs/vulnfounder-core/core/schemas.py`、`core/dynamic_tester.py`、`openant/cli.py`：暴露候选清单路径，便于 Web 侧归档。
- `libs/vulnfounder-core/utilities/dynamic_tester/claude_code.py`：支持扫描输出目录本身作为任务包父目录，并避免复制已有 `run-*` 任务。

## 测试记录

### Python

```text
./.venv/bin/pytest -q libs/vulnfounder-core/tests/test_claude_code_task.py
4 passed

./.venv/bin/pytest -q \\
  libs/vulnfounder-core/tests/test_claude_code_task.py \\
  libs/vulnfounder-core/tests/test_cli_platform_flags.py \\
  libs/vulnfounder-core/tests/test_scanner.py
20 passed
```

另外执行了 `python3 -m py_compile`，覆盖本阶段修改的 Python 文件，成功。

### Go

```text
GOCACHE=/private/tmp/openant-go-cache \\
GOMODCACHE=/private/tmp/openant-go-modcache \\
../../.devtools/go1.25.7/go/bin/go test ./internal/...
```

结果：全部通过。

新增/覆盖的 Web 测试包括：

- Claude 输出 ANSI 清理和 SSE 事件重放；
- 真实 PTY 子进程启动、输出捕获和正常结束；
- 任务目录穿越、符号链接和普通文件读取边界；
- Claude `results/` 归档到稳定动态测试产物，并把 verdict 回写 pipeline；
- 页面模板解析、Claude 模式选择器、对话/文件树接口标记和响应式页面检查。

另外执行了：

```text
go test -race ./internal/server
ok
node --check /private/tmp/openant_scan.js
node --check /private/tmp/openant_index.js
```

并成功构建 CLI Web 二进制：

```text
go build -o /private/tmp/openant-web-test .
```

## 使用前提

- Web 进程所在机器必须能找到 Claude Code；默认查找 PATH 中的 `claude`，也可以用 `OPENANT_CLAUDE_BIN=/绝对路径/claude` 指定。
- Claude Code 的认证由 Claude Code 自己读取；VulnFounder 不复制 Claude 凭据到任务目录。
- 静态扫描阶段仍然需要当前 VulnFounder 配置的大模型凭据；Claude Code 动态阶段本身不调用 VulnFounder 的 LLM API。
- 页面当前使用轮询刷新文件树（约 1.4 秒）和 SSE 刷新会话输出，不是文件系统原生推送。
- 本阶段完成了 Web 编排和结果归档，但没有替用户选择具体 exploit payload，也不会因单条日志自动把结果标为 `CONFIRMED`；Claude 必须按 Skill 写入带设备因果证据的 verdict。
