# OH-SL-09：Source Locator CLI/Go JSON 桥接测试记录

日期：2026-08-29

## 本阶段目标

为 Web/worker 提供一个受约束的 Python `source-locator` 命令族，并在 Go
侧只接受一个严格的 JSON envelope。每次调用只执行一个状态操作；源码路径、
状态转换和反馈约束仍由 Python 状态机校验。

## 已完成

- `openant source-locator create/status/events`：创建、恢复和增量读取 session
  事件。
- `transition`：仅允许状态机定义的下一状态，更新字段必须是白名单字段。
- `confirm/reject/apply-feedback/cancel`：确认、拒绝反馈、重试和取消均复用
  状态机，不直接操作 Git 或 shell。
- Go `DecodeEnvelope`：拒绝空输出、非法 JSON、多文档/尾随文本和未知状态；
  stderr 仍作为实时日志通道。
- Go `InvokeSourceLocator`：固定添加 `source-locator` 子命令，不暴露任意命令执行。

## 自动化测试

在 `libs/openant-core` 执行：

```text
../../.venv/bin/python -m pytest -q tests/source_locator
219 passed
../../.venv/bin/ruff check openant/cli.py tests/source_locator/test_cli_bridge.py core/source_locator
All checks passed
```

新增 CLI 测试 3 组，覆盖：

1. create/status/events 的单 envelope 输出与事件读取；
2. 合法状态转换、非法 confirm、cancel；
3. 非对象 updates JSON、错误状态下 reject 的安全失败。

另外通过实际命令验证：

```text
PYTHONPATH=libs/openant-core .venv/bin/python -m openant source-locator create \
  /dev/unix/socket/paramservice --root /tmp/openant-sl-cli-test \
  --session-id loc_cli12345678
```

命令返回 `status=success`，生成 `session.json` 和 `events.jsonl`，初始状态为
`INTAKE`，事件序号从 1 开始。Go 编译测试当前无法在本机执行：环境中没有
`go/gofmt` 可执行文件；Go 代码已按现有 `internal/python` 包接口编写，待安装
Go 工具链后需补跑 `go test ./internal/python`。

## 安全/回归结论

- Python stdout 只有一个 JSON 文档；诊断日志不混入 stdout。
- 不接受用户传入的 shell 字符串，Go 只拼接固定子命令和 argv token。
- 状态机终态、反馈轮次、查询预算和路径约束仍然有效。
- 本阶段没有触碰 Git clone、OpenGrok 网络请求或真实仓库内容。

