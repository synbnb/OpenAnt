# OH-22G-9D：模型证据行号确定性校正

日期：2026-08-28  
类型：离线回放，不调用大模型

## 1. 原逻辑与修改逻辑

原逻辑直接使用模型返回的 `start_line`/`end_line`。OH-22G-9C 已证明模型能正确引用注册文本，
但在没有逐行编号的上下文中，注册项行号会系统性偏移到表头或前一行。

本阶段增加两层保护：

1. `registration_context` 为每个片段增加 `line_numbered_text`，保留原始 `text` 不变，供模型
   同时看到真实行号和可复制的源码文本；
2. 模型响应落盘前，`evidence_line_resolver` 在声明的源码仓库内对证据文本进行唯一匹配。
   唯一匹配才校正行号；多匹配、找不到或源码不可用时保留模型原始行号，并写入
   `line_resolution` 状态。`target` 证据在文本格式不一致时可回退到已知函数索引的行范围。

该阶段不改变候选集合、模型决定、边置信度、原始调用图或 reachable 输入。

## 2. 回放输入

- 输入报告：`debug_outputs/OH-22G-9C-real-faultloggerd-20260828/llm_call_graph_recovery.json`
- 输入 overlay：`debug_outputs/OH-22G-9C-real-faultloggerd-20260828/llm_call_graph_overlay.json`
- 源码：`openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd`
- 模型调用：0 次
- 原始决定：31 条 `add_edge`

## 3. 结果

| 指标 | 结果 |
|---|---:|
| 归一化决定数 | 31 |
| 注册证据唯一校正 | 31/31 |
| 调用点证据 `exact` | 31 |
| 目标证据 `exact` | 22 |
| 目标证据函数索引回退 | 9 |
| 未定位/歧义证据 | 0 |
| 归一化后 accepted | 31 |
| 归一化后 rejected | 0 |
| 归一化后 overlay 边 | 31 |

注册证据的校正示例：

- 模型报告 `minidump_factory.cpp:51`，源码唯一匹配后改为第 52 行；
- 后续 8 条 `RegisterCreator` 依次校正到第 53～60 行；
- `decodeTable` 的 18 条和 `parseTable_` 的 4 条注册证据也全部唯一匹配。

归一化前后的 `(caller_id, target_id)` 边集合完全相同，增强图仍包含 34 个已索引节点，
无重复边、自环、幽灵节点或投影拒绝。

## 4. 测试

- `test_evidence_line_resolver.py`、注册上下文、恢复器、逐轮调度、执行器、投影器及相关
  OpenHarmony 回归测试：`51 passed`；
- Ruff：`All checks passed`；
- 9C 真实报告离线归一化及 overlay 回归：`PASS`；
- 归一化结果：
  - `debug_outputs/OH-22G-9D-evidence-line-normalization-20260828/llm_call_graph_recovery_normalized.json`
  - `debug_outputs/OH-22G-9D-evidence-line-normalization-20260828/llm_call_graph_overlay_normalized.json`
  - `debug_outputs/OH-22G-9D-evidence-line-normalization-20260828/normalization_summary.json`

## 5. 限制

- 这是对已有真实响应的离线回放，没有证明模型在看到逐行编号后一定会正确输出行号；需要下一轮
  小规模真实模型实验确认；
- 归一化只在源码路径属于声明仓库且匹配足够明确时生效，不能解决条件编译导致的多份注册、宏
  展开后行号或生成代码与源码不一致的问题；
- 行号校正只改善证据可审计性，不代表调用图已覆盖所有未解析边。

## 6. 结论

OH-22G-9D 在已知真实样本上消除了 OH-22G-9C 暴露的注册行号偏移，同时保持边集合和投影结果
不变。后续可带着逐行编号 prompt 在 2～3 个其他 OpenHarmony 仓库做小批量真实复测，再评估
是否扩大默认上下文和证据校正范围。
