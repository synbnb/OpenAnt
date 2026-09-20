# WEB-01：Web 全流程可观测性测试记录

## 1. 阶段目标

让 Web 扫描页能够查看一次扫描的完整阶段进度和阶段报告，不改变扫描器的漏洞分析逻辑，也不启用动态测试。

## 2. 修改前后逻辑

### 修改前

- `Job` 只保存运行状态、日志和最终报告路径。
- 页面主要根据 SSE 日志猜测 Parse、Enhance、Analyze、Verify、Report 五个阶段。
- `*.report.json` 阶段报告只能直接到磁盘查看。

### 修改后

- 新增只读接口 `GET /scan/{id}/pipeline`。
- 服务端读取扫描输出目录中的 `*.report.json`，并结合 Job 日志/状态投影九个阶段：
  `Parse → App Context → LLM Reachability → Enhance → Analyze → Verify → Build Output → Dynamic Test → Report`。
- 每个阶段返回状态、时间戳、耗时、token 用量、费用、摘要和错误。
- 未请求的 LLM Reachability、Dynamic Test 显示为 `not_requested`，不会伪装成成功。
- 阶段报告通过现有安全文件打开逻辑读取，拒绝符号链接和超过 2 MiB 的报告。
- 扫描页轮询上述接口，显示阶段状态和可展开的 JSON 摘要；原有 SSE 日志仍保留。
- Web 动态测试复选框仍为关闭状态；只有勾选时才追加 Python CLI 的 `--dynamic-test`。

## 3. 修改文件

- `apps/vulnfounder-cli/internal/server/server.go`
  - 注册 `/scan/{id}/pipeline`；
  - 增加阶段报告读取、状态投影和安全校验；
  - 保存/恢复平台字段；
  - 保持动态测试显式 opt-in。
- `apps/vulnfounder-cli/ui/scan.html`
  - 扩展九阶段时间线；
  - 增加状态轮询和阶段报告详情面板。
- `apps/vulnfounder-cli/internal/server/pipeline_test.go`
  - 增加阶段报告读取、可选阶段、运行中状态、接口 JSON、404、符号链接/超大文件拒绝和日志阶段识别测试。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Go | 项目内 `.devtools/go1.25.7` |
| 模块 | `apps/vulnfounder-cli` |
| Node.js | `/opt/homebrew/bin/node` |

## 5. 测试命令与结果

### 5.1 Web 服务专项测试

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./internal/server -count=1 -v
```

结果：通过。新增用例全部通过，服务端包结果为：

```text
ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/internal/server 1.888s
```

### 5.2 Go 全量回归

受限沙箱首次运行时，已有 `cmd.TestProbeOpenAI_AcceptsValid` 因禁止 `httptest` 绑定回环端口失败；在允许本机回环监听后用同一工具链重跑：

```bash
GOTOOLCHAIN=local GOTELEMETRY=off \
GOPATH="$PWD/../../.devtools/gopath" \
GOMODCACHE="$PWD/../../.devtools/gopath/pkg/mod" \
GOCACHE="$PWD/../../.devtools/gocache" \
../../.devtools/go1.25.7/go/bin/go test ./... -count=1
```

结果：全部通过，包括 `cmd`、`internal/server`、`internal/python`、`internal/report` 等包。

### 5.3 前端 JavaScript 语法检查

```bash
python3 -c 'from pathlib import Path; import re; s=Path("apps/vulnfounder-cli/ui/scan.html").read_text(); print(re.search(r"<script>(.*?)</script>", s, re.S).group(1))' | node --check
```

结果：通过，无语法错误。

### 5.4 页面阶段和接口静态检查

检查页面包含九个阶段、`pipeline-details` 容器和 `/scan/{id}/pipeline` 请求。

结果：

```text
WEB_01_UI_STATIC_OK stages=9
```

### 5.5 变更格式检查

```bash
git diff --check
```

结果：通过，无空白错误。

## 6. 未覆盖内容

- 尚未在浏览器中手工点击运行真实 Web 扫描；
- 尚未增加 Web 的分阶段启动/断点续跑控制；
- 尚未改造动态测试本身；
- 尚未把 OpenAI-compatible 模型配置暴露到 Web 表单（属于后续 Web-03）。

## 7. 结论

WEB-01 已完成。Web 页现在可以实时查看完整阶段状态和已生成的阶段报告；动态测试保持关闭，不会因本阶段改动被意外执行。
