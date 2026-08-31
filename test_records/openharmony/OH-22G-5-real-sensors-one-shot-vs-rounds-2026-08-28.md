# OH-22G-5：真实 sensors_medical_sensor 一次性与逐轮恢复离线比较

日期：2026-08-28  
仓库：`source_code_base/sensors_medical_sensor`  
目的：在不产生新的大模型费用的前提下，验证 OH-22G-4-2 接入扫描器后的调度行为，并比较一次性恢复与入口驱动逐轮恢复是否得到一致的调用边。

## 测试边界

- 输入解析产物：
  - `debug_outputs/OH-22F-2-real-sensors-20260827/call_graph.json`
  - `debug_outputs/OH-22F-2-real-sensors-20260827/call_graph_residuals.json`
  - `debug_outputs/OH-22F-2-real-sensors-20260827/semantic_graph.json`
  - `debug_outputs/OH-22F-2-real-sensors-20260827/dataset.json`
- 历史模型响应回放：`debug_outputs/OH-22F-3B-real-sensors-20260827/llm_call_graph_candidate_review.json`。
- 回放 completion 只从历史响应中选取当前 prompt 内的 `site_id`，没有网络请求，也没有重新运行漏洞检测、解析或动态测试。
- 入口集合从 `dataset.json` 的 `is_entry_point=true` 单元读取，共 7 个。
- 输入文件前后 SHA-256 完全一致，说明本测试没有修改原始解析产物。

## 源码一致性检查

3 个残余调用点均能在真实源码中找到对应行，且行文本包含成员函数指针调用：

| 调用点 | 源码行 | 检查结果 |
| --- | ---: | --- |
| `CompatibleConnection::SensorDataCallback` | `hdi_connection/adapter/src/compatible_connection.cpp:147` | 存在，匹配 `reportDataCache_->*cacheData_` |
| `SensorEventCallback::OnDataEvent` | `hdi_connection/adapter/src/sensor_event_callback.cpp:55` | 存在，匹配 `reportDataCallback_->*reportDataCb_` |
| `MedicalSensorServiceStub::OnRemoteRequest` | `src/medical_service_stub.cpp:68` | 存在，匹配 `this->*memberFunc` |

## 结果

### 1. 仅复核无候选残余（默认 `include_candidate_sites=false`）

- 一次性：2 个 site，1 次历史响应回放，2 个均 `keep_unresolved`，新增边 0。
- 逐轮（最大 4 轮）：入口可达的残余 site 数为 0，模型调用 0，新增边 0，2 个 site 保留为未复核。
- 逐轮（最大 8 轮）：结果相同，并以 `frontier_exhausted` 结束。

这表明入口驱动策略不会把两个没有候选目标、且当前不在入口可达原生图中的回调强行加入调用图。

### 2. 包含候选分派 site（`include_candidate_sites=true`）

历史响应对 `OnRemoteRequest` 的 8 个候选 handler 全部给出高置信 `add_edge`，对两个无候选回调给出 `keep_unresolved`。

| 模式 | site 数 | 模型调用（回放） | 接受决策 | 投影边 | 状态/结束原因 |
| --- | ---: | ---: | ---: | ---: | --- |
| 一次性 | 3 | 1 | 8 | 8（随后使用同一严格投影器） | `complete` |
| 逐轮，最大 4 轮 | 3 | 1 | 8 | 8 | `partial / max_rounds` |
| 逐轮，最大 8 轮 | 3 | 1 | 8 | 8 | `complete / frontier_exhausted` |

一次性结果经过 `project_recovery_overlay` 后，与最大 8 轮逐轮结果的边集合逐项相等（8/8 相同）。两种逐轮配置也得到完全相同的 8 条边，均为：

`MedicalSensorServiceStub::OnRemoteRequest → AfeEnableInner/AfeDisableInner/GetAfeStateInner/RunCommandInner/GetAllSensorsInner/CreateDataChannelInner/DestroyDataChannelInner/AfeSetOptionInner`

逐轮模式第 0 轮只调度入口可达的 `native:68:fdb812c5a482`；另外两个无候选回调仍显示为 `unreviewed_sites=2`，没有被错误地当成可确认边。最大 4 轮时，恢复边已经完成，但原生图前沿仍有待扩展函数，因此命中轮数上限并报告 `partial`；将预算提高到 8 轮后才自然结束。这个现象是预算语义，不是解析失败。

## 结论

1. 在该真实仓库上，入口驱动逐轮调度与一次性复核在相同历史响应下得到一致的 8 条分派边，说明 OH-22G-4-2 的 scanner 接线和严格投影路径工作正常。
2. 逐轮模式确实能区分“入口可达且有候选”的 dispatcher 与“无候选/当前不可达”的回调，不会为了追求边数而扩大范围。
3. 当前默认 `max_rounds=4` 对本仓库会出现“边已恢复但状态为 partial”的可解释情况；后续可考虑按“残余 site 已处理且前沿无残余”提前结束，或调整默认轮数，但本测试阶段不修改实现。
4. 该记录是历史模型响应的离线回放和调度验证，不是新模型调用，也不是独立的准确率/召回率证明；要评估模型在新输入上的判断，仍需另行进行受控 API 实验。

## 测试命令

使用 `.venv/bin/python` 直接调用 `run_recovery_review` 与 `run_iterative_recovery_review`，分别运行 `include_candidate_sites=false/true`、`max_rounds=4/8`，并在运行前后计算四个输入 JSON 的 SHA-256。

测试结果：通过（输入完整性通过；两种恢复策略的边集合在候选分派场景下一致）。
