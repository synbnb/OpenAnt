# OH-22G-6：逐轮恢复提前终止与预算语义修复

日期：2026-08-28  
范围：`libs/openant-core/core/platforms/openharmony/llm_call_graph_rounds.py` 及其回归测试

## 修改前逻辑

每轮处理完当前前沿后，只要某个原生/确定性语义后继还有出边，调度器就会把它加入下一轮。即使所有未处理残余都已经不可达，仍可能继续遍历普通调用链，直到命中 `max_rounds`，从而把“恢复目标已完成”显示为 `partial/max_rounds`。

## 修改后逻辑

下一轮候选函数必须满足以下条件之一：

1. 函数自身拥有尚未处理的残余调用点；或
2. 沿原生调用边/确定性语义边可以到达拥有尚未处理残余的函数。

同一调用者因 `max_sites_per_round` 被延后的 site 仍通过 `deferred_callers` 显式重排，不会被提前终止逻辑丢弃。模型失败、调用预算、边预算和 site 总预算的原有状态处理保持不变。

## TDD 验证

### RED：先复现旧问题

新增测试 `test_stops_after_reachable_residuals_are_processed`，构造入口残余已处理、但目标函数仍有普通原生后继的调用链。修改前测试失败：实际 `rounds=2`，预期 `rounds=1`。

### GREEN：最小修复后

同一测试通过，结果为：

- `status=complete`
- `rounds=1`
- `llm_calls=1`
- `unreviewed_sites=0`
- `termination_reason=frontier_exhausted`

## 回归测试

执行：

```text
.venv/bin/python -m pytest -q libs/openant-core/tests/openharmony libs/openant-core/tests/test_scanner_llm_recovery_integration.py
.venv/bin/python -m ruff check libs/openant-core/core/platforms/openharmony/llm_call_graph_rounds.py libs/openant-core/tests/openharmony/test_llm_call_graph_rounds.py
git diff --check
```

结果：`174 passed, 2 skipped`；Ruff 全部通过；无空白错误。

## 真实 OpenHarmony 回放

使用真实 `sensors_medical_sensor` 的 OH-22F-2 解析产物和 OH-22F-3B 历史模型响应，未发起新 API 请求：

| 场景 | 修改前（OH-22G-5） | 修改后 |
| --- | --- | --- |
| 默认残余模式（2 个无候选 callback） | 2 轮，`complete`，模型调用 0 | 1 轮，`complete`，模型调用 0 |
| 候选分派模式（8 个 handler） | 4 轮，`partial/max_rounds` | 1 轮，`complete/frontier_exhausted` |
| 候选分派新增边 | 8 | 8 |
| 未复核无候选残余 | 2 | 2 |

一次性投影与逐轮投影的 8 条边集合仍完全相等；4 个输入 JSON 的 SHA-256 前后保持不变。

## 结论

本阶段修复了“已完成恢复却因继续遍历普通调用链而显示 partial”的可观测性问题。优化只改变前沿筛选和停止时机，不放宽 LLM 输出验证，不修改原生 `call_graph.json`，也不把不可达残余强行加入调用图。
