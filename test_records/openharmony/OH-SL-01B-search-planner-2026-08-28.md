# OH-SL-01B：OpenGrok 初始查询计划执行测试记录

日期：2026-08-28
阶段：源码定位器 SL-01B（固定查询计划接入 OpenGrok 客户端）
目标：将 SL-01A 生成的 `LocatorQuery` 按稳定顺序交给现有只读 `OpenGrokClient`，限制请求规模，并保留每条查询的成功、失败或重复跳过结果。

## 1. 原项目逻辑与修改后逻辑

原项目只有独立的 `OpenGrokClient.search()`。调用方如果需要执行多策略检索，必须自行判断 `def`、`symbol`、`path`、`full` 并拼接参数，查询顺序、上限和错误记录没有统一契约。

本阶段新增 `core/source_locator/search_planner.py`，执行逻辑为：

```text
已验证的 LocatorQuery 序列
  → 校验查询对象和数量上限
  → 按原顺序映射为 OpenGrokClient.search 参数
  → 每条查询使用统一 max_results/max_hits_per_file
  → 成功保存 SearchResponse
  → typed OpenGrok 错误保存错误类型、状态码和清洗后的消息
  → 重复查询记录 skipped_duplicate，不重复发送 HTTP 请求
  → 汇总唯一结果文件和执行统计
```

新增的 `execute_initial(target)` 会直接调用 SL-01A 的固定查询计划；`execute(queries)` 则用于后续 LLM 建议查询的白名单执行。它不接受任意字典作为查询，不调用 shell，不调用 LLM，也不执行文件写入。

## 2. 关键行为

- `definition` 映射到客户端 `definition` 参数，最终由客户端发送 OpenGrok `def`；
- `symbol`、`path`、`full` 分别映射到对应查询字段；
- `file_type`、`max_results`、`max_hits_per_file` 统一传入客户端；
- C++ 查询继续使用 `cxx`，不会生成 `cpp`；
- 单个 OpenGrok HTTP/传输/协议错误被记录后继续执行后续查询，任意编程错误不会被静默吞掉；
- 结果对象可序列化为 `openant.source-locator.search-plan.v1`，包含目标、执行明细和唯一结果文件数。

## 3. 文件变更

- `libs/openant-core/core/source_locator/search_planner.py`
- `libs/openant-core/core/source_locator/__init__.py`
- `libs/openant-core/tests/source_locator/test_search_planner.py`

## 4. 独立测试

执行：

```text
cd libs/openant-core
../../.venv/bin/python -m pytest -q \
  tests/source_locator/test_search_planner.py \
  tests/source_locator/test_target_normalizer.py \
  tests/source_locator/test_config.py \
  tests/source_locator/test_opengrok_live_fixture_contract.py \
  tests/test_opengrok_client.py \
  tests/test_opengrok_protocol_models.py \
  tests/test_llm_config_schema.py
```

结果：`77 passed in 0.08s`。

覆盖内容包括：

- 查询类型到 OpenGrok 客户端参数的精确映射；
- 从标准化目标执行完整固定查询序列；
- 重复查询记录和去重发送；
- HTTP 401 typed error 记录后继续后续查询；
- 空计划、超过预算、非 `SearchResponse` 返回值拒绝；
- 使用 SL-00A 真实 `InitParamService` 搜索响应回放两个实际源码文件；
- 搜索结果唯一文件统计和 JSON 序列化。

静态检查：

```text
.venv/bin/ruff check \
  libs/openant-core/core/source_locator/search_planner.py \
  libs/openant-core/core/source_locator/__init__.py \
  libs/openant-core/tests/source_locator/test_search_planner.py
```

结果：`All checks passed!`；Python `compileall` 和 `git diff --check` 均通过。

## 5. 结论与边界

SL-01B 已证明标准化查询可以由统一执行器安全、可重复地接入真实响应形态。当前执行器只负责“按计划搜索并记录结果”，还没有做路径分类、候选排序、源码读取、宏/常量关系追踪或 Manifest 映射；因此搜索命中仍不是服务归属结论。

下一阶段建议执行 SL-02A：对真实搜索结果进行路径分类和可解释排序，验证生产代码、测试代码、生成代码、SELinux 和内核噪声不会被静默删除。
