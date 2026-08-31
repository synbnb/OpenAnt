# OH-22G-7A：OpenHarmony 参考仓库批量离线评估

日期：2026-08-28  
范围：`source_code_base` 下的 OpenHarmony 仓库；验证 OH-22G-6 提前终止逻辑在不同仓库上的调度表现

## 评估原则

- 不重新解析源码，不运行漏洞检测，不调用网络模型，不覆盖已有 debug 产物。
- 只接收同时具备 `call_graph.json`、`call_graph_residuals.json`、`semantic_graph.json`、`dataset.json` 的产物目录。
- 入口从 `dataset.json` 的 `is_entry_point=true` 单元读取。
- `sensors_medical_sensor` 使用此前真实模型响应作为离线回放；另外两个仓库没有对应的标准 LLM 恢复响应，因此使用显式 `keep_unresolved` completion，只验证调度范围和安全降级，不把它当作模型准确率。
- 每个仓库运行一次性复核和逐轮复核，逐轮预算为 `max_rounds=4`、`max_sites_per_round=50`、`max_edges=1000`、`max_llm_calls=32`、无重试。

## 覆盖范围

`source_code_base` 共发现 22 个仓库。本次具有完整可评估产物的仓库为 3 个：

1. `communication_netmanager_base`
2. `multimedia_audio_framework`
3. `sensors_medical_sensor`

以下 19 个仓库目前没有完整四类产物，因此标记为“未评估”，不是“通过”或“无残余”：

`ability_ability_runtime`、`ark_js_runtime`、`arkui_ace_engine`、`arkui_napi`、`arkweb_arkweb_cangjie_wrapper`、`communication_ipc`、`communication_wifi`、`distributeddatamgr_datamgr_service`、`drivers_hdf_core`、`drivers_interface`、`drivers_peripheral`、`filemanagement_dfs_service`、`filemanagement_storage_service`、`multimedia_camera_framework`、`multimedia_video_processing_engine`、`security_certificate_manager`、`security_device_auth`、`systemabilitymgr_samgr`、`window_window_manager`。

## 输入一致性检查

3 个仓库的所有残余调用点都能在对应 `source_code_base/<repo>` 中找到源码文件；残余 caller ID 和候选 target ID 均能在 `call_graph.json` 的函数索引中找到。四个输入 JSON 在运行前后 SHA-256 均保持一致。

| 仓库 | 函数数 | 数据集单元 | 入口数 | 残余调用点 | 源码文件缺失 | 输入是否未改变 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `communication_netmanager_base` | 6,967 | 718 | 72 | 17 | 0 | 是 |
| `multimedia_audio_framework` | 23,178 | 287 | 30 | 55 | 0 | 是 |
| `sensors_medical_sensor` | 340 | 25 | 7 | 3 | 0 | 是 |

## 调度结果

### communication_netmanager_base

产物：`debug_outputs/OH-22E-4-netmanager-20260827`。确定性诊断包含 307 个分派赋值和 306 条候选边；另有 2 个 Lambda callback site 没有候选。

| 模式 | worklist | 有候选 site | 一次性：解析/接受 | 逐轮：调度/接受 | 逐轮状态 |
| --- | ---: | ---: | ---: | ---: | --- |
| 仅无候选残余 | 2 | 0 | 2 / 0 | 0 / 0 | `complete/frontier_exhausted` |
| 包含候选分派 | 19 | 17 | 7 / 0（其余 12 个受离线 prompt 回放限制） | 17 / 0 | `complete/frontier_exhausted` |

一次性与逐轮投影边集合均为空且一致；逐轮没有把 2 个无候选 callback 强行加入模型复核。

### multimedia_audio_framework

产物：`debug_outputs/OH-22E-3-reference-20260827/multimedia_audio_framework`。确定性诊断包含 34 个分派赋值、66 条候选边；Lambda 诊断还报告 8 个 callback site、60 条候选边和 4 个无候选 site。

| 模式 | worklist | 有候选 site | 一次性：解析/接受 | 逐轮：调度/接受 | 逐轮状态 |
| --- | ---: | ---: | ---: | ---: | --- |
| 仅无候选残余 | 53 | 0 | 7 / 0（46 个未由离线 prompt 回放覆盖） | 0 / 0 | `complete/frontier_exhausted` |
| 包含候选分派 | 61 | 10 | 7 / 0（54 个未由离线 prompt 回放覆盖） | 0 / 0 | `complete/frontier_exhausted` |

当前入口和原生/确定性语义边没有把这些残余带入逐轮前沿，因此没有离线模型调用；这反映的是“当前图上不可达”，不是“源码中不存在这些 callback”。

### sensors_medical_sensor

产物：`debug_outputs/OH-22F-2-real-sensors-20260827`。使用 `OH-22F-3B-real-sensors-20260827/llm_call_graph_candidate_review.json` 的历史真实模型响应回放。

| 模式 | worklist | 有候选 site | 一次性：接受/投影边 | 逐轮：调度/接受/投影边 | 逐轮状态 |
| --- | ---: | ---: | ---: | ---: | --- |
| 仅无候选残余 | 2 | 0 | 0 / 0 | 0 / 0 / 0 | `complete/frontier_exhausted` |
| 包含候选分派 | 3 | 1 | 8 / 8 | 1 / 8 / 8 | `complete/frontier_exhausted` |

一次性投影和逐轮投影的 8 条边逐项相等：`MedicalSensorServiceStub::OnRemoteRequest` 到 8 个 `*Inner` handler。两个无候选 callback 仍为未复核残余。

## 费用与回放说明

本批次没有真实网络请求。报告中的 `llm_calls=1` 仅表示 runner 调用了一次本地 replay/fallback completion，不是新的 API 请求，也没有产生模型费用。netmanager 和 multimedia 的“解析数较少”是有意的离线 prompt 范围限制，不能解释为模型已审查全部 site。

## 结论

1. OH-22G-6 的提前终止逻辑在 3 个真实 OpenHarmony 仓库上均能正常结束，没有因普通调用链造成额外轮次或虚假 `max_rounds`。
2. 逐轮模式只调度从入口和现有原生/确定性语义边可达的残余；不可达或无候选残余被保留并计入 `unreviewed_sites`。
3. 传感器仓库复现了 8 条恢复边，且一次性与逐轮边集合完全一致；另外两个仓库本轮只验证了调度和安全降级，尚不能评价 LLM 边召回。
4. 当前批量评估覆盖率为 3/22。要完成 22 个仓库的效果评估，需要先为其生成完整的四类解析产物，再对选定仓库进行受控真实模型调用。

测试结果：通过（已评估仓库输入完整性、调度终止和原始产物不变性通过；全量 22 仓库的模型效果评估尚未完成）。
