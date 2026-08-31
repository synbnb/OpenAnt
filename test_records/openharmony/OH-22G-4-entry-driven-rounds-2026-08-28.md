# OH-22G-4 第一小切片：入口驱动逐轮调用图恢复

## 测试日期

2026-08-28

## 本切片的原逻辑

此前的 OpenHarmony LLM 调用边恢复是“一次性审核”：扫描器读取某个语言的
`call_graph_residuals.json`，把这一语言的残余调用点一次性组成一个 worklist，
调用模型审核一次，然后单独生成投影图。投影图接入 reachable 后，只能使用这次
已经生成的边，不能在新到达的函数上继续审核残余调用点。

## 本切片的修改逻辑

新增 `core/platforms/openharmony/llm_call_graph_rounds.py`，提供有界的
`run_iterative_recovery_review`：

1. 结构化入口（函数自身的 `is_entry_point` 和调用方传入的入口 ID）作为 BFS 初始种子；
2. 原生 `call_graph` 和已有确定性 `semantic_graph` 只用于发现下一层函数，不会被模型改写；
3. 只选择当前前沿函数拥有的、尚未处理的残余调用点；一个调用点最多调度一次；
4. 每轮调用现有严格 JSON 审核器，再调用现有证据投影器；只有投影成功的
   `llm_confirmed_indirect_call` 边才能把目标函数加入下一轮前沿；
5. 每轮上限、总调用点上限、总新增边上限、LLM 调用次数、重试次数和总时长均可限制；
6. 每轮保留审核报告和投影报告，模型失败时只保留残余，不会凭空扩展调用图；
7. 同时统一了候选为空时的投影边界：无解析候选的残余只能从本地有界
   `retrieval_candidates` 中选择目标，仍必须通过函数 ID、调用点和目标源码证据校验。

本阶段的第一小切片先独立验证调度器；随后已将它以显式
`--llm-call-graph-iterative-recovery` 选项接入 `scanner.py`，默认扫描仍走旧路径。

## 自动化测试

执行环境：仓库 `.venv`（Python 3.13，含 tree-sitter 依赖）。

### 新增/相关单元测试

```text
.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_llm_call_graph_rounds.py \
  libs/openant-core/tests/openharmony/test_llm_call_graph_projection.py \
  libs/openant-core/tests/openharmony/test_llm_recovery_execution.py
```

结果：`12 passed`。

覆盖内容：

- 两跳恢复：入口 → 第一层残余目标 → 第二层残余目标；
- 只有已投影边才能扩展下一轮；
- 原生直接边可以把残余函数带入下一轮；
- 单轮上限导致的残余调用点会重新排队，不会因 caller 已扩展而丢失；
- 没有入口时不调用模型；
- 无候选残余从有界本地检索短名单投影；
- 原有重试、证据校验和投影拒绝行为保持通过。

### OpenHarmony 回归套件

```text
.venv/bin/python -m pytest -q libs/openant-core/tests/openharmony
```

结果：`156 passed, 2 skipped`。

### 扫描器相关回归

```text
.venv/bin/python -m pytest -q \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py
```

结果：`17 passed`。

新增的扫描器回归覆盖 CLI 转发、轮次产物落盘、投影阶段重新校验每一轮以及非
OpenHarmony 平台安全跳过。

### 静态检查

```text
.venv/bin/python -m py_compile \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_rounds.py \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_recovery.py \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_projection.py
.venv/bin/ruff check \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_rounds.py \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_recovery.py \
  libs/openant-core/core/platforms/openharmony/llm_call_graph_projection.py \
  libs/openant-core/tests/openharmony/test_llm_call_graph_rounds.py \
  libs/openant-core/tests/openharmony/test_llm_call_graph_projection.py
git diff --check
```

结果：编译、ruff 和 diff 检查均通过。

## 真实 sensors_medical_sensor 产物回放

输入产物：`debug_outputs/OH-22F-2-real-sensors-20260827/`，包括真实解析得到的
`call_graph.json`、`call_graph_residuals.json`、`semantic_graph.json` 和
`dataset.json`。该目录包含 340 个函数、7 个结构化入口和 3 个残余调用点。
回放使用离线 completion，仅返回 `keep_unresolved`，不产生 API 费用；目的只是验证
入口筛选、原生/语义前沿遍历、轮次记录和安全降级。

### 默认残余模式（`include_candidate_sites=false`）

```text
worklist_sites: 2
rounds: 2
sites_scheduled: 0
sites_reviewed: 0
unreviewed_sites: 2
llm_calls: 0
projected_edges: 0
termination_reason: frontier_exhausted
```

两个无候选残余分别是 `CompatibleConnection::SensorDataCallback` 和
`SensorEventCallback::OnDataEvent`。它们没有从当前 7 个入口经原生/确定性语义边
到达，因此本轮不会为了“覆盖所有残余”而盲目调用模型。这是入口驱动策略的预期行为，
但也提示后续需要在扫描器中明确展示“未达入口的残余”数量，不能把它们误报成已验证。

### 包含候选模式（`include_candidate_sites=true`）

```text
worklist_sites: 3
rounds: 2
sites_scheduled: 1
sites_reviewed: 1
unreviewed_sites: 2
llm_calls: 1
accepted_decisions: 0
projected_edges: 0
termination_reason: frontier_exhausted
```

入口 `MedicalSensorServiceStub::OnRemoteRequest` 的候选分发点被调度；两个 callback
残余仍因不可达而未调度。离线 completion 明确返回保留未解析，所以没有伪造新增边。

## 结论

本切片验证了逐轮调度和 BFS 扩展的核心不变量：模型不能直接扩展前沿，未确认边不能
触发下一轮，原生图与确定性语义图保持只读，预算耗尽/模型失败可以安全结束。真实
传感器仓库回放没有发出网络模型请求，也没有修改原始调用图。

本阶段合计相关测试为 `173 passed, 2 skipped`。下一阶段需在真实 OpenHarmony 仓库上用受控预算运行该显式迭代选项，比较一次性审核
与逐轮审核的边召回、残余数量和成本；现有“一次性审核”继续作为默认兼容路径。
