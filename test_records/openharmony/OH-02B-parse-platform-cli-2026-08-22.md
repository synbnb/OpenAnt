# OH-02B Parse Platform CLI 参数测试记录

## 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-02B：Go/Python `parse --platform` 参数契约与 ParseResult 记录 |
| 日期 | 2026-08-22 |
| VulnFounder 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| Python | 3.11.15，项目 `.venv` |
| Go | 项目 `.devtools/go1.25.7/go` |

## 原逻辑与实现范围

OH-02A 已让 `scan` 支持平台选择，但 `parse` 仍没有该参数。Python parse 同时存在单语言和多语言两条分支，平台选择若在分支内部处理容易产生不一致。

本阶段在两条分支汇合后的 `ParseResult` 位置记录显式选择：

```text
--platform auto|generic|openharmony
```

默认 `auto` 不增加旧 JSON 键；显式值写入 `platform_selection`。Go 默认不转发，显式值转发到 Python。没有接入 OpenHarmony adapter，也没有改变语言选择、tree-sitter、dataset unit、调用图或 LLM 行为。

## TDD RED

Python：

```bash
../../.venv/bin/python -m pytest tests/test_parse_platform_flags.py -v
```

结果：退出码 `1`，`2 failed, 1 passed`。旧 parser 没有 `platform`，旧 `ParseResult` 不接受 `platform_selection`。

Go：

```bash
GOCACHE=/private/tmp/openant-go-build-cache \
GOPATH=/private/tmp/openant-go \
../../.devtools/go1.25.7/go/bin/go test ./cmd \
  -run 'Test(ParsePlatform|BuildParsePyArgsForwardsExplicitPlatform)' -v
```

结果：退出码 `1`，编译报 `undefined: parsePlatform`。

## GREEN 与定向测试

Python 实现后执行同一测试文件：

```text
4 passed in 0.04s
```

其中包括：默认/合法/非法值、显式 ParseResult 序列化，以及用 fake parser 验证 `cmd_parse` 在 parser 返回后记录 `openharmony`。

Go 定向测试：

```text
3 passed
```

覆盖 parse flag 默认值、默认省略、显式 `--platform openharmony` 转发和共享非法值校验。

## 相关 Python 回归

命令：

```bash
../../.venv/bin/python -m pytest \
  tests/test_parse_platform_flags.py \
  tests/test_cli_multilang_flags.py \
  tests/test_multilang_critical_regressions.py \
  tests/test_schemas_multilang.py \
  tests/test_parser_adapter.py -v
```

结果：退出码 `0`，`57 passed in 0.12s`。

确认 parse 的语言选择、multi-language 分支、旧 ParseResult 序列化和 Python parser adapter 没有回归。

## Go 全量 cmd 回归

命令：

```bash
GOCACHE=/private/tmp/openant-go-build-cache \
GOPATH=/private/tmp/openant-go \
../../.devtools/go1.25.7/go/bin/go test ./cmd -v
```

结果：退出码 `0`，`ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd 0.533s`。

Go 既有 httptest 用例需要本地回环监听；最终回归在受控环境中运行，未连接外部服务。缓存位于 `/private/tmp`。

## 静态检查

以下检查均退出码 `0`：

- `ruff check openant/cli.py core/schemas.py tests/test_parse_platform_flags.py`
- `python -m py_compile`（上述 Python 文件）
- `gofmt -d cmd/parse.go cmd/parse_platform_test.go`
- `git diff --check`

## 阶段结论

OH-02B 已完成。Go/Python `parse` 与 OH-02A 的 `scan` 现在拥有一致的平台参数契约；显式平台选择可进入 ParseResult，默认 generic/auto 结果保持兼容。实际 OpenHarmony 解析行为仍待后续 adapter 接入阶段实现。

下一阶段建议为 OH-03A：只读盘点并锁定 C/C++ 文件范围、测试/fuzz 角色和 coverage 统计契约；用户批准前不修改代码。
