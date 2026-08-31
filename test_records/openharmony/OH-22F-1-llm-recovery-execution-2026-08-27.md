# OH-22F-1：LLM 间接调用审核执行器测试记录

**日期**：2026-08-27  
**范围**：OpenHarmony 间接调用残余的受控 LLM 执行层  
**阶段边界**：只生成审核结果对象，不接入 scanner，不修改调用图或 reachable，不调用真实模型。

## 1. 本阶段实现内容

现有协议层已经能够生成 bounded worklist、严格 prompt、解析模型 JSON 并校验函数 ID
和源码证据，但此前没有统一的执行入口。本阶段新增：

```text
core.platforms.openharmony.llm_call_graph_recovery.run_recovery_review()
```

执行器逻辑：

1. 调用已有 `build_recovery_worklist()`，先在本地去重、分类和生成候选；
2. worklist 为空时直接返回 `status=no_sites`，不调用模型；
3. 支持生产环境的 `PhaseBinding`，也支持测试注入 `completion(prompt)`；
4. 真实绑定复用现有 `utilities.llm.simple_text()` 和 token tracker；
5. 传输异常、非文本响应或严格 JSON 校验错误最多重试 2 次；
6. 对成功响应调用已有 parser/validator，拒绝未知函数 ID、无证据或低置信度边；
7. 返回 `complete`、`no_sites` 或 `failed`，并记录 attempts、重试次数、解析决策数、
   accepted/kept/rejected/unreviewed 数量以及错误列表；
8. 输入 diagnostics 只读，结果是 advisory artifact，不会写入 `call_graph.json`、
   `semantic_graph.json` 或 `dataset.json`。

## 2. TDD 过程

新增测试：

```text
libs/openant-core/tests/openharmony/test_llm_recovery_execution.py
```

RED 阶段：

```text
ImportError: cannot import name 'run_recovery_review'
```

该失败发生在生产函数尚不存在时，确认测试不是对既有行为的重复验证。

GREEN 阶段：

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/openharmony/test_llm_recovery_execution.py
```

结果：

```text
3 passed in 0.02s
```

覆盖的行为：

- 空 worklist：0 次模型调用、0 次尝试；
- 第一次非法 JSON、第二次合法响应：重试 1 次，已知目标边通过校验；
- 连续 `TimeoutError`：达到 2 次重试后 `failed`，共 3 次调用；
- diagnostics 在执行前后完全一致。

## 3. 相关回归测试

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/openharmony
```

结果：

```text
132 passed, 2 skipped in 0.64s
```

`ruff check` 和 `git diff --check` 均通过。

## 4. 真实 OpenHarmony 产物上的离线执行验证

为了验证 worklist 和执行器接口确实能消费真实产物，使用此前生成的两个仓库结果，
注入一个本地假 completion。假 completion 对每个 worklist 返回合法的
`keep_unresolved`，不产生 API 费用，也不模拟任何漏洞判断。

### communication_netmanager_base

输入：

```text
debug_outputs/OH-22E-4-netmanager-20260827/call_graph.json
debug_outputs/OH-22E-4-netmanager-20260827/call_graph_residuals.json
```

结果：

```text
diagnostics summary residuals: 17
LLM worklist sites: 2
model calls: 1
status: complete
kept_unresolved: 2
accepted: 0
diagnostics_unchanged: true
```

其余 15 个残余没有进入这一阶段的首轮审核队列，原因是已有候选、确定性分发或
外部边界分类；它们不会被本阶段的模型调用重复覆盖。

### sensors_medical_sensor

输入：

```text
debug_outputs/OH-22E-4-sensors-20260827/call_graph.json
debug_outputs/OH-22E-4-sensors-20260827/call_graph_residuals.json
```

结果：

```text
diagnostics summary residuals: 3
LLM worklist sites: 2
model calls: 1
status: complete
kept_unresolved: 2
accepted: 0
diagnostics_unchanged: true
```

## 5. 当前未做的事情

- 尚未在 scanner/CLI/Web 中增加开关；
- 尚未调用真实 GPT/Claude API；
- 尚未把审核通过的边投影到 SemanticGraph 或 reachable；
- 尚未验证真实模型对 OpenHarmony `baseFuncs_`、Lambda、回调和 IPC 残余的召回率。

下一阶段应单独实现 pipeline 可选接入，并保留该执行器的 advisory、可审计和安全降级边界。
