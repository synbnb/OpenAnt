# OH 动态测试空候选与 JSON 响应修复测试记录

日期：2026-08-24  
范围：OpenAnt Web 动态测试准备阶段  
目标：修复动态准备命令成功但 Web 误报失败的问题，并确保 0 个动态候选时能够正常结束。

## 原始故障

在任务 `e66b949543d7ef8e` 中，静态扫描和验证均已完成：

- 分析单元：91
- Stage 1：183 次 API 调用
- Stage 2：186 次 API 调用
- 验证结果：0 个确认漏洞
- `pipeline_output.json`：0 个 findings
- 动态候选数：0

Web 最终报错：

```text
[dynamic-test] Task preparation failed: parse dynamic-test task response: no JSON envelope in command output
```

## 根因复现

使用同一份产物直接执行：

```text
/Users/shiyu/.openant/venv/bin/python -P -m openant dynamic-test \
  /Users/shiyu/.openant/webui/e66b949543d7ef8e/pipeline_output.json \
  --output <temporary-directory> \
  --mode claude-code \
  --repo-path /Users/shiyu/学习/hyl/new/OpenAnt/source_code_base/systemabilitymgr_samgr
```

实际结果：

- 退出码：`0`
- 顶层状态：`success`
- `findings_tested`：`0`
- 成功生成 Claude Code 任务目录
- 大模型调用数：`0`

Python 输出的是格式化多行 JSON，而旧 Web 解析器只按单行 JSON 尝试解析，因此把成功响应误判成没有 JSON envelope。

## 修复内容

修改文件：

- `apps/openant-cli/internal/server/claude_web.go`
- `apps/openant-cli/internal/server/claude_web_test.go`

具体行为：

1. 先对完整 stdout 做 JSON 解码，兼容 Python 的格式化多行响应；保留带诊断行的紧凑 JSON 兼容分支。
2. `findings_tested <= 0` 时记录“无动态候选，跳过 Claude Code 会话”，保留任务元数据但不启动空 PTY，也不等待用户交互。
3. 动态阶段正常返回，后续报告生成继续执行，不再把该情况标记为整个扫描失败。

## 自动化测试

### Go Web 单元测试

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test ./internal/server
```

结果：通过。

覆盖内容：

- 格式化多行 JSON envelope 可解析
- 带诊断行的紧凑 JSON 仍可解析
- 0 个候选时不启动 Claude 会话、保留元数据并记录跳过日志

### Go race 测试

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go test -race ./internal/server
```

结果：通过，无数据竞争报告。

### Python 动态任务回归测试

```text
.venv/bin/pytest -q \
  libs/openant-core/tests/test_claude_code_task.py \
  libs/openant-core/tests/test_scanner.py
```

结果：`16 passed`。

### 构建与 Web 冒烟测试

```text
GOCACHE=/private/tmp/openant-go-cache \
GOMODCACHE=/private/tmp/openant-go-modcache \
../../.devtools/go1.25.7/go/bin/go build -o bin/openant .
```

随后用最新构建重启 Web，并请求 `http://127.0.0.1:18080/`：

- HTTP 状态：`200 OK`
- 首页仍读取项目内 `autodl-openai / gpt-5.6-luna` 配置
- 动态测试选项正常加载

## 结论

0 个候选漏洞不是故障原因；它是一次合法的“无动态测试对象”结果。故障来自 Web 对 Python 多行 JSON 响应的解析不兼容，已修复并通过单元、race、Python 回归和 Web 冒烟测试。

注意：由于本次仓库扫描没有动态候选，即使修复后也不会启动实际 Claude Code 交互。要观察真实动态验证过程，需要扫描产生至少一个 `confirmed`、`agreed` 或未经过 Stage 2 的 `vulnerable` 候选。
