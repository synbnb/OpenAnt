# OH-22G-7C：参考仓库逐轮恢复离线评估

日期：2026-08-28  
输入批次：`debug_outputs/OH-22G-7B-reference-corpus-20260828`

## 测试边界

对 9 个新解析仓库分别运行一次性 `run_recovery_review` 和 OH-22G-6 逐轮 `run_iterative_recovery_review`，配置为 `max_rounds=4`、`max_sites_per_round=50`、`max_edges=1000`、`max_llm_calls=32`、无重试。所有 completion 都是本地 `keep_unresolved` 回退，不发起网络请求，因此本阶段只评估调度范围、终止状态和安全降级，不评价模型准确率。

## 汇总结果

| 仓库 | 残余 site | 候选模式 worklist | 逐轮调度 site | 逐轮接受边 | 未复核 site | 终止原因 | 输入未改变 |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `communication_netmanager_base` | 17 | 19 | 17 | 0 | 2 | `frontier_exhausted` | 是 |
| `developtools_hdc` | 0 | 0 | 0 | 0 | 0 | `no_sites` | 是 |
| `hiviewdfx_faultloggerd` | 3 | 3 | 0 | 0 | 3 | `frontier_exhausted` | 是 |
| `hiviewdfx_hilog` | 0/1（主残余/ Lambda） | 1 | 0 | 0 | 1 | `frontier_exhausted` | 是 |
| `hiviewdfx_hiview` | 1 + Lambda 残余 | 15 | 0 | 0 | 15 | `frontier_exhausted` | 是 |
| `multimedia_audio_framework` | 55 | 61 | 0 | 0 | 61 | `frontier_exhausted` | 是 |
| `startup_appspawn` | 1 | 1 | 0 | 0 | 1 | `frontier_exhausted` | 是 |
| `startup_init` | 0 | 0 | 0 | 0 | 0 | `no_sites` | 是 |
| `telephony_core_service` | 4 + Lambda 残余 | 20 | 5 | 0 | 15 | `frontier_exhausted` | 是 |

一次性与逐轮投影边集合在 9 个仓库、两种 worklist 模式下均相等（本批次回退不接受任何新边，因此均为空）。

## 重点观察

1. `communication_netmanager_base` 有 72 个入口，逐轮调度了 17 个入口可达的候选 site，2 个无候选 callback 被保留为未复核。
2. `hiviewdfx_faultloggerd` 的 3 个候选 site 当前不在入口可达前沿，因此逐轮不调用 completion；这不是源码缺失，而是当前调用图范围的结果。
3. `multimedia_audio_framework` 虽有 61 个残余 worklist 项，但当前 28 个入口和原生/确定性语义边没有将它们连接到入口前沿，逐轮安全停止并保留 61 个未复核项。
4. `telephony_core_service` 逐轮调度了 5 个当前可达 site；由于 fallback 全部 `keep_unresolved`，没有投影边，剩余 15 个 site 保留。
5. 缺少 `semantic_graph.json` 的 `developtools_hdc`、`startup_appspawn` 仍可使用原生调用图运行调度；本批次没有残余或没有可接受候选，未产生错误。

## 费用与可信度说明

本阶段没有真实模型请求。报告中的 runner 调用计数仅表示本地 completion 被调用，不产生 API 费用。未接受边数不能作为模型拒绝率，未复核 site 数也不能作为漏洞数量。

测试结果：通过（9 个仓库调度均安全结束，所有输入 JSON 哈希保持不变；模型效果仍需后续受控 API 实验）。
