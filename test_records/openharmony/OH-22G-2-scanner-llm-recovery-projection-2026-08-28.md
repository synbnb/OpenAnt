# OH-22G-2：扫描器调用图恢复叠加阶段测试记录

日期：2026-08-28  
阶段：OH-22G-2（第 2A 小阶段）  
目标：在不修改原生调用图、数据集和 reachable 结果的前提下，将已经完成校验的 OpenHarmony LLM 调用边恢复结果接入扫描器，生成独立的语义叠加图产物。

## 本阶段逻辑

原有流程中，`llm_call_graph_recovery.json` 和
`llm_call_graph_candidate_review.json` 只是审核记录；即使其中存在
`validation.accepted`，后续扫描阶段也不会消费这些边。

本阶段新增显式开关 `--llm-call-graph-projection`。开启后，扫描器：

1. 读取扫描输出目录中的恢复审核和候选审核产物；
2. 按语言和函数索引匹配审核报告，避免把多语言报告投影到错误的函数表；
3. 只接受已位于 `validation.accepted`、置信度达到 `high`、候选/检索集合一致且同时具备调用点证据与目标/注册证据的决定；
4. 将通过校验的边写入 `llm_call_graph_overlay.json`，边类型为
   `llm_confirmed_indirect_call`；
5. 将拒绝原因、来源文件、语言和摘要保留在同一产物中，便于审计；
6. 不写回 `call_graph.json`，不改 `dataset.json`，不执行 reachable BFS。

因此，本阶段只是“审核结果 → 独立 semantic graph overlay”的边界；下一阶段才讨论是否在显式策略下把 overlay 并入 reachable。

## 自动化测试

运行命令：

```text
.venv/bin/pytest -q libs/vulnfounder-core/tests/test_scanner_llm_recovery_integration.py
```

结果：`12 passed`。

覆盖内容：

- Python CLI 开关默认关闭并能转发到扫描器；
- OpenHarmony 恢复产物可被扫描器生成；
- 投影阶段可生成独立叠加图；
- 原生 `call_graph.json` 内容保持不变；
- `ScanResult` 和 `scan.report.json` 暴露叠加图路径；
- generic 平台不会调用 OpenHarmony 投影逻辑，而是安全跳过。

运行命令：

```text
.venv/bin/pytest -q libs/vulnfounder-core/tests/openharmony/test_llm_call_graph_projection.py
```

结果：`4 passed`（与投影纯函数边界相关的单元测试）。

运行命令：

```text
.venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/test_scanner.py \
  libs/vulnfounder-core/tests/test_scanner_llm_recovery_integration.py \
  libs/vulnfounder-core/tests/test_schemas_multilang.py
```

结果：`185 passed, 2 skipped`。

另外，以下静态检查通过：

- `py_compile`：`scanner.py`、`schemas.py`、`openant/cli.py`；
- `ruff check`：本阶段修改的实现和测试文件。

## 真实产物回放

为了避免产生新的模型费用，使用之前对
`sensors_medical_sensor` 真实运行得到的文件进行离线回放：

- 恢复审核产物：`OH-22F-2-real-sensors-20260827/llm_call_graph_recovery.json`；
- 候选审核产物：`OH-22F-3B-real-sensors-20260827/llm_call_graph_candidate_review.json`；
- 函数索引：`OH-22F-2-real-sensors-20260827/call_graph.json`。

回放结果：

```text
status: complete
source_artifacts: 2
reports_consumed: 2
accepted_input: 8
projected_edges: 8
rejected: 0
duplicate_edges: 0
unmatched_reports: 0
errors: 0
edge kind: llm_confirmed_indirect_call
```

这说明真实候选审核中的 8 条已接受决定均能在真实函数索引中找到调用方、目标函数和源证据，并成功写入叠加图；恢复审核本身没有已接受边，因此没有额外增加边。回放未触发模型调用。

## 全量测试说明

曾启动 `libs/vulnfounder-core/tests` 全量测试，但该集合包含已有的本地
LLM/HTTP 集成测试；运行早期即建立多条 localhost 连接并长时间无输出，无法在本阶段作为稳定的离线回归依据，已停止该进程。它不影响上面的定向结果；本阶段没有把中途的集成测试状态宣称为通过。

## 结论

OH-22G-2 已完成。扫描器现在可以在显式开关下生成可审计的 LLM 调用图叠加产物，同时保持原有调用图、数据集和 reachable 结果不变。当前叠加图尚未参与 BFS/reachable 裁剪，这是有意保留的安全边界。
