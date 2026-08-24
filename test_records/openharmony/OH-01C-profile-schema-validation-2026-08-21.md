# OH-01C Profile Schema 校验测试记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-01C：Profile/Coverage 严格 schema 与一致性校验 |
| 日期 | 2026-08-21 |
| OpenAnt 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 开发分支 | `feature/openharmony-adaptation` |
| Python | 3.11.15，项目 `.venv` |
| pytest | 9.1.1 |

## 2. 原逻辑与本阶段目标

OH-01A/B 已提供版本化平台协议及 OpenHarmony 静态 Profile Builder，但 `RepositoryProfile.from_dict()` 和 `CoverageReport.from_dict()` 除 `schema_version` 外主要只做字段还原。非法置信度、反常覆盖计数或错误字段类型可能被接受，直到更后续的扫描/报告流程才失败。

OH-01C 在协议边界增加 fail-safe 校验，不改变 builder 识别阈值、平台信号、scanner、CLI 或真实仓扫描行为。

## 3. 修改内容

修改：

```text
core/platforms/base.py
tests/platforms/test_base.py
```

新增校验：

1. `schema_version` 必须是非布尔的正整数。
2. `CoverageReport` 的 `discovered_files`、`eligible_files`、`parsed_files` 必须为非负整数，并满足：

```text
parsed_files <= eligible_files <= discovered_files
```

3. `unsupported_files` / `parse_failures` 必须是对象列表；`roles` 必须是字符串键与非负整数值的对象。
4. `RepositoryProfile` 的 platform、repository root、detection、components、languages、boundaries、coverage 和 provenance 必须具有规定形状。
5. detection confidence 必须位于 `[0, 1]`；evidence 必须为非空字符串列表。
6. Profile 与 Coverage 的 schema version 必须一致。

以上校验通过 dataclass `__post_init__` 统一执行，因此直接构造和 `from_dict()` 反序列化均适用。

## 4. TDD RED

先在既有有效 profile 上分别注入非法 confidence、`parsed_files > eligible_files`、错误 languages 类型、空 platform，以及负/非单调 coverage 计数，执行：

```bash
../../.venv/bin/python -m pytest tests/platforms/test_base.py -v
```

结果：退出码 `1`。

```text
5 failed, 7 passed in 0.05s
```

5 个失败均为 `Failed: DID NOT RAISE ValueError`，证明旧逻辑确实接受了这些畸形输入，而不是测试误设预期。

## 5. GREEN 实现与独立测试

实现校验后，执行：

```bash
../../.venv/bin/python -m pytest \
  tests/platforms/test_base.py \
  tests/platforms/test_openharmony_profile.py -v
```

结果：退出码 `0`。

```text
15 passed in 0.03s
```

有效 Profile/JSON 往返、OpenHarmony 静态信号 builder、证据不足 fail-safe 与未知信号忽略均继续通过。

## 6. 联合回归

命令：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest \
  tests/platforms \
  tests/openharmony \
  tests/test_schemas_multilang.py \
  tests/test_parse_repository_analyzer_schema.py \
  tests/test_json_corrector_verify_schema.py \
  tests/test_llm_config_schema.py -v
```

结果：退出码 `0`。

```text
54 passed in 0.30s
```

覆盖 OH-01A/B/C、OH-00 外部五仓清单/IPC fixture/当前行为基线，以及既有 schema、多语言序列化、验证 JSON 和 LLM 配置兼容性。

## 7. 静态与差异检查

命令：

```bash
../../.venv/bin/ruff check core/platforms tests/platforms
../../.venv/bin/python -m py_compile \
  core/platforms/base.py \
  core/platforms/openharmony/profile.py \
  tests/platforms/test_base.py \
  tests/platforms/test_openharmony_profile.py
git diff --check
```

结果：三项退出码均为 `0`；Ruff 输出 `All checks passed!`，Python 语法检查和 Git 空白错误检查通过。

## 8. 测试范围说明

本阶段只改变新平台协议对象的校验行为。未修改 generic ParseResult/ScanResult 的既有字段语义、语言发现、tree-sitter、入口识别、扫描器、CLI、GN/IDL/IP C 处理或任何外部 OpenHarmony 源码。

因此未重复运行完整 Python 套件；直接影响范围由 54 项联合回归及静态检查覆盖。环境阶段的完整套件基线仍为 `2969 passed, 34 skipped`。

## 9. 阶段结论

OH-01C 已完成，OH-01「平台协议和 schema」至此完成。后续 adapter 只能在结构、版本、覆盖统计与置信度均有效时输出 profile，避免畸形数据静默流入安全分析。

下一阶段为 OH-02：Go/Python CLI 平台参数打通。用户批准前不修改代码。
