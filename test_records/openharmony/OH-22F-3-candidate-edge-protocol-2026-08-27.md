# OH-22F-3：候选边多目标审核协议测试记录

**日期**：2026-08-27  
**阶段**：OH-22F-3 第一小阶段  
**范围**：扩展 OpenHarmony LLM 调用边审核协议，使其能够审核同一 IPC 分发点的多个候选 handler  
**阶段边界**：只修改 worklist、prompt 和本地校验协议；不接入 scanner 候选模式，不调用真实模型，不修改调用图。

## 1. 问题背景

OpenHarmony 的 `OnRemoteRequest()` 通常先接收外部 Binder 事务 `code`，再从分发表中
取出成员函数指针。一个 residual 调用点可能对应多个运行时目标，而不是一个唯一目标。

以 `sensors_medical_sensor` 为例：

```cpp
baseFuncs_[ENABLE_SENSOR] = &MedicalSensorServiceStub::AfeEnableInner;
baseFuncs_[DISABLE_SENSOR] = &MedicalSensorServiceStub::AfeDisableInner;
...
baseFuncs_[SET_OPTION] = &MedicalSensorServiceStub::AfeSetOptionInner;

auto memberFunc = itFunc->second;
return (this->*memberFunc)(data, reply);
```

因此静态调用图应表达同一入口到多个 handler 的并集，并在边证据中保留类似
`code == 0`、`code == 7` 的运行时条件。

此前协议存在三个限制：

1. `max_shortlist` 可能截断 parser 已发现的候选目标；
2. prompt 只要求每个 site 输出一条 decision；
3. 本地校验只检查目标是否存在于函数索引，没有检查它是否属于该 residual 的候选集合。

## 2. 本阶段修改

### 候选目标完整进入检索上下文

`_shortlist_functions()` 新增必选目标集合参数。候选审核模式开启时：

- 所有已知的 `candidate_target_ids` 都优先进入 `retrieval_candidates`；
- 即使候选数量大于普通 `max_shortlist`，也不会把已知候选静默截断；
- 剩余空间才用于补充普通的同文件/同类名检索候选；
- 函数源码仍受 `max_code_bytes` 限制。

worklist 新增：

```text
review_scope: candidate_edges | unknown_indirect
```

### 同一 site 支持多条边

prompt 改为要求：

```text
对每个 site 输出一个或多个 decision
```

候选分发点可以返回多条：

```json
{
  "site_id": "native:68:...",
  "decision": "add_edge",
  "target_id": "...AfeEnableInner",
  "evidence": [{"kind": "registration", "text": "code == 0"}]
}
```

同一 `site_id` 下的不同 `target_id` 不会被去重为一条。

### 候选集合约束

对 `add_edge`，本地校验现在要求：

1. `target_id` 必须存在于函数索引；
2. 对候选边 residual，`target_id` 必须存在于 `candidate_target_ids`；
3. `target_id` 必须存在于 `retrieval_candidates`；
4. 仍然需要高置信度、调用点证据以及目标/注册/类型证据。

因此模型不能仅凭函数名相似度把同类中的其他函数连入调用图。

## 3. TDD 测试过程

测试文件：

```text
libs/vulnfounder-core/tests/openharmony/test_llm_candidate_edge_review.py
```

### RED

生产代码修改前运行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_llm_candidate_edge_review.py
```

结果：

```text
3 failed
```

失败分别证明：

- 8 个候选被 `max_shortlist=2` 截断；
- prompt 没有声明一对多决策和候选集合约束；
- 已知但未注册的目标能够错误进入 accepted 集合。

### GREEN

实现协议修改并修正测试夹具后运行：

```text
3 passed in 0.02s
```

覆盖内容：

1. 8 个候选 handler 全部保留在检索上下文；
2. prompt 明确支持一个 site 返回多个 decision；
3. 一个 site 的多条 `add_edge` 可以同时通过；
4. 函数索引中存在但不在候选注册表中的目标被拒绝。

## 4. 回归测试

候选协议、既有协议和执行器测试：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_llm_candidate_edge_review.py \
  libs/vulnfounder-core/tests/openharmony/test_llm_call_graph_recovery.py \
  libs/vulnfounder-core/tests/openharmony/test_llm_recovery_execution.py
```

结果：

```text
12 passed in 0.02s
```

OpenHarmony 全量回归：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony
```

结果：

```text
135 passed, 2 skipped in 0.63s
```

静态检查：

```bash
.venv/bin/ruff check \
  libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_recovery.py \
  libs/vulnfounder-core/tests/openharmony/test_llm_candidate_edge_review.py
git diff --check
```

结果：

```text
All checks passed!
```

## 5. 尚未完成的工作

- `scanner` 目前仍使用默认的 `include_candidate_sites=False`；
- 尚未增加候选边审核的 CLI 开关或第二审核 pass；
- 尚未把 `code` 数字与注册语句自动提炼成结构化证据；
- 尚未再次调用真实 `sensors_medical_sensor` 模型扫描；
- 尚未投影任何审核结果到 `call_graph.json` 或 reachable。

下一小阶段需要单独决定：候选审核是作为现有开关的第二 pass 自动运行，还是增加独立的
CLI/Web 选项。两者的 API 费用和默认行为不同，不能直接假定。
