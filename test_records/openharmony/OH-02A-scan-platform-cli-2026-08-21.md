# OH-02A Scan Platform CLI 参数测试记录

## 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-02A：Go/Python `scan --platform` 参数契约与转发 |
| 日期 | 2026-08-21 |
| OpenAnt 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| Python | 3.11.15，项目 `.venv` |
| Go | 项目 `.devtools/go1.25.7/go` |

## 原逻辑与实现范围

原项目的 Go `openant scan` 与 Python `openant scan` 没有平台参数，Go 不能向 Python 转发平台选择，scanner/result 也不能记录该选择。

本阶段新增：

```text
--platform auto|generic|openharmony
```

默认 `auto` 保持旧命令和旧 JSON 输出形状。显式 `generic` 或 `openharmony` 会由 Go 转发到 Python，并记录为 `ScanResult.platform_selection`。本阶段不运行 profile builder、不识别真实仓、不改变语言发现、tree-sitter、GN/IDL、IPC、LLM 或漏洞结论；`parse` 子命令留给 OH-02B。

## 变更文件

```text
apps/openant-cli/cmd/scan.go
apps/openant-cli/cmd/scan_platform_test.go
libs/openant-core/openant/cli.py
libs/openant-core/core/scanner.py
libs/openant-core/core/schemas.py
libs/openant-core/tests/test_cli_platform_flags.py
```

关键兼容性措施：Python `cmd_scan` 使用 `getattr(args, "platform", "auto")`，因此既有直接构造 `argparse.Namespace` 的内部调用不因新字段而失败。

## TDD RED

Python 命令：

```bash
../../.venv/bin/python -m pytest tests/test_cli_platform_flags.py -v
```

结果：退出码 `1`，`3 failed, 1 passed`。

- `Namespace` 没有 `platform`。
- `ScanResult` 不接受 `platform_selection`。
- `--platform openharmony` 被 argparse 拒绝。

“未知 platform 被拒绝”在旧版本因所有 `--platform` 都未知而偶然通过，未将其作为单独 RED 证据。

Go 命令：

```bash
GOCACHE=/private/tmp/openant-go-build-cache \
GOPATH=/private/tmp/openant-go \
../../.devtools/go1.25.7/go/bin/go test ./cmd \
  -run 'TestScanPlatform|TestBuildScanPyArgsForwardsOnlyExplicitPlatform' -v
```

结果：退出码 `1`，编译报 `undefined: scanPlatform` 与 `undefined: buildScanPyArgs`。

## GREEN 与回归

Python 定向测试：

```text
4 passed in 0.04s
```

Go 定向测试覆盖默认省略、显式转发和非法值拒绝：

```text
3 passed
```

Python 相关回归命令：

```bash
../../.venv/bin/python -m pytest \
  tests/test_cli_platform_flags.py \
  tests/test_cli_multilang_flags.py \
  tests/test_llm_reachability.py \
  tests/test_schemas_multilang.py -v
```

结果：`67 passed in 0.09s`。

Go 全量 `cmd` 回归：

```bash
GOCACHE=/private/tmp/openant-go-build-cache \
GOPATH=/private/tmp/openant-go \
../../.devtools/go1.25.7/go/bin/go test ./cmd -v
```

结果：`ok github.com/knostic/open-ant-cli/cmd 0.547s`。

Go 的已有 `httptest` 需要本地回环监听；沙箱默认禁止该操作，因此最终 Go 回归在用户批准的受控环境执行，未访问外部服务。初次模块下载仅使用 `go.mod` 声明依赖，缓存位于 `/private/tmp`。

## 静态检查

以下检查均退出码 `0`：

- `ruff check openant/cli.py core/scanner.py core/schemas.py tests/test_cli_platform_flags.py`
- `python -m py_compile`（上述 Python 文件）
- `gofmt -d cmd/scan.go cmd/scan_platform_test.go`
- `git diff --check`

## 结论

OH-02A 已完成。Go 与 Python `scan` 现在均支持一致、受限的平台选择；默认行为兼容，显式选择可观察且已完成 Go/Python 两端回归。

下一小阶段为 OH-02B：将同一参数契约扩展至 Go/Python `parse`，并在 ParseResult 中记录显式选择；仍不启动 adapter 或改变解析行为。
