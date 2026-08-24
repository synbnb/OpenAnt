# OH-15A-1：Unit 真实语言元数据与兼容读取

日期：2026-08-22  
阶段：OH-15A-1  
范围：为 C/C++ Unit 和 analyzer output 增加稳定的 `c/cpp` 语言信息，并让分析 Prompt 优先使用该信息；不接入 component/target/guard、语义图或新的规则。

## 1. 原逻辑与修改逻辑

原逻辑中，C/C++ `UnitGenerator` 生成的 unit 没有明确的 `language` 字段；多语言合并时才可能由合并层补写语言，单语言 C/C++ dataset 本身没有该信息。`core.analysis_core.analyze_unit()` 又把所有 unit 的 Prompt 代码块语言固定为 `code`，因此 C 和 C++ 源码无法在分析上下文中区分。

本阶段修改为：

1. 根据源文件扩展名推断语言：`.c/.h` → `c`，`.cc/.cpp/.cxx/.hh/.hpp/.hxx` → `cpp`；若函数记录已经提供语言，则优先使用并归一化 `c++/cc/cxx` 为 `cpp`；未知扩展名保守回退为 `code`；
2. 新生成的 unit 在顶层写入 `language`，同时在 `metadata.language` 保留同一值；
3. `generate_analyzer_output()` 为函数记录增加同样的 `language` 字段；
4. `analysis_core` 优先读取 unit 的语言，其次读取 `metadata.language`；旧 dataset 没有语言字段时继续使用 `code`，不在迁移时重新解释旧数据；
5. 所有新增字段均为 additive，不改变原有 C/C++ unit 的代码、依赖、ground truth 和其它 metadata 字段。

## 2. 修改文件

- `libs/openant-core/parsers/c/unit_generator.py`
  - 增加 C/C++ 扩展名和语言归一化逻辑；
  - 在 unit、metadata 和 analyzer output 中写入语言。
- `libs/openant-core/core/analysis_core.py`
  - 增加兼容读取 helper；
  - Prompt 代码块从固定 `code` 改为 unit 语言，旧数据仍回退 `code`。
- `libs/openant-core/tests/test_unit_language_metadata.py`
  - 覆盖 C/C++/头文件推断、analyzer output、真实 Prompt 代码围栏和旧 unit 回退。

## 3. TDD 与专项测试

### RED

先加入测试，再运行：

```text
../../.venv/bin/python -m pytest tests/test_unit_language_metadata.py -q
```

结果：`3 failed, 1 passed`。失败分别对应 unit 缺少 `language`、analyzer output 缺少 `language`、Prompt 仍固定为 `code`；旧 unit 回退测试先通过，说明兼容契约没有依赖新实现。

### GREEN

实现后运行：

```text
../../.venv/bin/python -m py_compile \
  parsers/c/unit_generator.py core/analysis_core.py \
  tests/test_unit_language_metadata.py
../../.venv/bin/python -m pytest tests/test_unit_language_metadata.py -q
```

结果：`4 passed in 0.02s`。

C Unit、schema 和 Prompt 安全回归：

```text
../../.venv/bin/python -m pytest \
  tests/parsers/c/test_unit_generator_u3.py \
  tests/parsers/c/test_c_schema_completeness.py \
  tests/test_analysis_prompt_injection.py -q
31 passed in 0.05s
```

OpenHarmony/C parser 影响范围回归：

```text
../../.venv/bin/python -m pytest \
  tests/test_unit_language_metadata.py \
  tests/platforms tests/openharmony tests/parsers/c -q
186 passed, 6 skipped in 0.51s
```

多语言合并、analyzer output 和 scanner re-filter 兼容回归：

```text
../../.venv/bin/python -m pytest \
  tests/test_parse_repository_analyzer_schema.py \
  tests/test_scanner_multilang.py \
  tests/test_scanner_refilter_multilang.py \
  tests/test_metadata_plumbing.py -q
24 passed in 0.63s
```

质量检查：

```text
../../.venv/bin/ruff check \
  parsers/c/unit_generator.py core/analysis_core.py \
  tests/test_unit_language_metadata.py
```

结果：`All checks passed!`；`git diff --check` 通过。

## 4. 真实 OpenHarmony 仓库验证

验证仓库：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_wifi
```

流程：

```text
RepositoryScanner(platform="openharmony", skip_tests=True)
→ FunctionExtractor
→ CallGraphBuilder(platform="openharmony")
→ UnitGenerator
```

结果：

| 项目 | 数量 |
|---|---:|
| production C/C++ 文件 | 683 |
| native 函数 | 9,263 |
| 生成 Unit | 9,204 |
| `cpp` Unit | 7,638 |
| `c` Unit | 1,566 |

真实仓库中 `.cpp/.hpp` unit 的语言均为 `cpp`，`.c/.h` unit 的语言均为 `c`，没有依赖文件名之外的名称猜测，也没有改变函数代码和调用图内容。

## 5. 兼容性与边界

- 旧 dataset 没有 `language` 时，`analysis_core` 仍使用 `code` 代码围栏；
- 未知扩展名的新 C Unit 保守写入 `code`，不会伪称为 C 或 C++；
- 多语言合并层原有的 unit `language` 字段继续保留；
- 本阶段没有修改 scanner、入口检测、reachability 或语义图；
- component、target、boundary、guard 等平台上下文留给后续 OH-15A-2。

OH-15A-1 已完成：单语言 OpenHarmony C/C++ dataset 现在携带真实语言信息，分析 Prompt 能够区分 `c` 和 `cpp`，而历史 dataset 仍可被安全读取。
