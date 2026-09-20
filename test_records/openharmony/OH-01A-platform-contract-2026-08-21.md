# OH-01A 平台协议基础契约测试记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-01A：平台无关协议、schema 版本与结果挂载位 |
| 日期 | 2026-08-21 |
| VulnFounder 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 开发分支 | `feature/openharmony-adaptation` |
| Python | 3.11.15，项目 `.venv` |
| pytest | 9.1.1 |

## 2. 原逻辑与本阶段目标

原项目的 `ParseResult` 和 `ScanResult` 只能携带通用语言解析与扫描结果。语言、构建、IPC、入口、权限等平台信息没有统一的数据契约；后续模块若直接各自定义字典，会导致字段漂移，且可能破坏 Go CLI 与既有 JSON 消费者。

OH-01A 建立最小的平台无关协议层：

- `RepositoryProfile`：平台识别、组件、语言、边界、覆盖和来源。
- `CoverageReport`：发现、可处理、已解析、未支持、失败和文件角色统计。
- `SemanticNode` / `SemanticEdge`：可表达语言外的语义节点、关系、证据、置信度与 resolver 版本。
- `PlatformProfileBuilder`：供未来平台 adapter 实现的类型接口。
- `ParseResult` / `ScanResult` 的可选平台挂载位。

本阶段不实现 OpenHarmony 识别、`bundle.json` 解析、GN、IDL、IPC、tree-sitter 扩展、入口检测或 CLI 参数；因此现有 generic 扫描的默认行为和 JSON 形状不改变。

## 3. 修改内容

新增：

```text
core/platforms/__init__.py
core/platforms/base.py
tests/platforms/test_base.py
```

修改：

```text
core/schemas.py
```

设计约束：

1. 每个新协议对象均以 `schema_version` 为必填字段；缺失、布尔值、0 或负数会被拒绝。
2. 所有对象只包含 JSON 友好的普通数据，可通过 `to_dict()` / `from_dict()` 无损往返。
3. 非语法确定的语义边可以记录 `evidence`、`confidence`、`resolver_version`，避免未来把猜测边冒充为语言 AST 直接调用。
4. `platform_profile` 和 `platform_coverage` 仅在调用方显式赋值时才写入结果 JSON；旧调用不出现新增键。

## 4. TDD RED

先新增平台契约测试，不创建 `core.platforms` 包，执行：

```bash
../../.venv/bin/python -m pytest tests/platforms/test_base.py -v
```

结果：退出码 `2`，收集阶段失败：

```text
ModuleNotFoundError: No module named 'core.platforms'
```

结论：RED 有效。测试在协议层不存在时无法导入，没有误通过。

## 5. GREEN 实现与独立测试

创建平台基础包、契约对象和可选结果字段后，以相同命令复测。

结果：退出码 `0`。

```text
7 passed in 0.03s
```

通过的契约：

1. RepositoryProfile 与 CoverageReport 可经 JSON 无损往返。
2. SemanticNode 与携带证据/置信度的 SemanticEdge 可经 JSON 无损往返。
3. 四种新协议对象缺失 `schema_version` 时都会 fail-safe 拒绝。
4. 旧 ParseResult/ScanResult 不输出平台字段；显式提供 Profile/Coverage 后才输出且仍 JSON 可序列化。

## 6. 既有 schema 兼容回归

命令：

```bash
../../.venv/bin/python -m pytest \
  tests/test_schemas_multilang.py \
  tests/test_parse_repository_analyzer_schema.py \
  tests/test_json_corrector_verify_schema.py \
  tests/test_llm_config_schema.py -v
```

结果：退出码 `0`。

```text
30 passed in 0.05s
```

确认已有的多语言字段、主语言标量兼容性、parse/scan 序列化、analyzer call graph、验证结果 JSON 和 LLM 配置 schema 没有回归。

## 7. 静态与差异检查

命令：

```bash
../../.venv/bin/ruff check \
  core/platforms/base.py core/schemas.py tests/platforms/test_base.py
../../.venv/bin/python -m py_compile \
  core/platforms/base.py core/schemas.py tests/platforms/test_base.py
git diff --check
```

结果：三项退出码均为 `0`；Ruff 输出 `All checks passed!`，Python 语法检查和 Git 空白错误检查通过。

## 8. 测试范围说明

本切片修改了通用结果 schema，但没有修改解析、扫描、CLI、依赖或任何平台 adapter。直接风险范围已由 7 项新契约测试和 30 项既有 schema/兼容测试覆盖；没有重复运行完整 Python 套件。OH-00 环境阶段的完整套件基线仍为 `2969 passed, 34 skipped`。

## 9. 阶段结论

OH-01A 已完成。VulnFounder 现在拥有可版本化、可序列化、默认不改变旧输出的平台数据协议；这为后续 OpenHarmony Profile Builder、GN/IDL/IP C 语义图和覆盖报告提供了公共输入/输出边界。

下一小阶段建议为 OH-01B：只实现 OpenHarmony Profile Builder 的最小工厂与静态样例 profile，不接入 scanner，也不扫描真实仓。用户批准前不修改代码。
