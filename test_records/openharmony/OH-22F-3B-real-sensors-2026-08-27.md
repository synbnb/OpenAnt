# OH-22F-3B：`sensors_medical_sensor` 真实候选边审核记录

**日期**：2026-08-27  
**仓库**：`source_code_base/sensors_medical_sensor`  
**阶段**：OH-22F-3B 真实模型验证  
**模型配置**：项目内 `config/openant/config.json` 的 `openharmony-live-gpt`，
`autodl-openai / gpt-5.6-luna`  
**结果性质**：仅生成独立 advisory 产物，不修改正式调用图或 reachable。

## 1. 验证目的

验证新增候选边审核流程是否能够：

1. 把一个 IPC 分发点的全部候选 handler 放入 worklist；
2. 允许模型对同一 site 返回多条 `add_edge`；
3. 不把候选集合之外的函数误连入调用图；
4. 对无法确定具体目标的函数指针保持保守的 unresolved 状态。

## 2. 输入产物

为节省 API，本次没有重新执行解析、漏洞检测和 Stage 2 验证，而是复用此前真实扫描
生成的：

```text
debug_outputs/OH-22F-2-real-sensors-20260827/call_graph.json
debug_outputs/OH-22F-2-real-sensors-20260827/call_graph_residuals.json
```

原始 residual 共 3 个：

| 调用点 | 候选数 | 类型 |
|---|---:|---|
| `medical_service_stub.cpp:68` `OnRemoteRequest` | 8 | `baseFuncs_` 成员函数指针分发 |
| `compatible_connection.cpp:147` `SensorDataCallback` | 0 | 参数传入的回调指针 |
| `sensor_event_callback.cpp:55` `OnDataEvent` | 0 | accessor 返回的成员函数指针 |

## 3. 执行方式

本次直接调用已有 `run_recovery_review()`，设置：

```text
include_candidate_sites=True
max_sites=-1
max_shortlist=32
max_code_bytes=8000
max_retries=0
```

单次请求超时上限为 180 秒，SDK 自动重试关闭。结果写入：

```text
debug_outputs/OH-22F-3B-real-sensors-20260827/llm_call_graph_candidate_review.json
```

## 4. 请求过程

第一次尝试使用 45 秒超时，模型请求在本机代理处超时；由于尚未收到模型响应，
没有产生 token 统计，也没有进行自动重试。随后确认服务端地址可达，将单次上限提高到
180 秒并重新执行，第二次请求成功。

## 5. 真实模型结果

```text
status: complete
worklist_sites: 3
parsed_decisions: 10
accepted: 8
kept_unresolved: 2
rejected: 0
unreviewed_sites: 0
llm_calls: 1
```

### 5.1 `OnRemoteRequest` 候选边

候选数量为 8，接受数量也为 8，集合差异为空：

| `baseFuncs_` 注册常量 | 接受目标 |
|---|---|
| `ENABLE_SENSOR` | `AfeEnableInner` |
| `DISABLE_SENSOR` | `AfeDisableInner` |
| `GET_SENSOR_STATE` | `GetAfeStateInner` |
| `RUN_COMMAND` | `RunCommandInner` |
| `GET_SENSOR_LIST` | `GetAllSensorsInner` |
| `TRANSFER_DATA_CHANNEL` | `CreateDataChannelInner` |
| `DESTROY_SENSOR_CHANNEL` | `DestroyDataChannelInner` |
| `SET_OPTION` | `AfeSetOptionInner` |

模型对每条边都给出 `high` 置信度，并引用三类证据：

- 调用点：`return (this->*memberFunc)(data, reply);`（第 68 行）；
- 注册点：`baseFuncs_[...] = &MedicalSensorServiceStub::...`（第 38–44 行）；
- 目标函数定义：对应 handler 的函数签名和实现位置。

### 5.2 与真实源码对照

人工查看了：

```text
source_code_base/sensors_medical_sensor/services/medical_sensor/src/medical_service_stub.cpp
```

源码中的构造函数确实逐一注册以上 8 个成员函数，`OnRemoteRequest()` 通过 `code` 查表，
再调用成员函数指针。因此本次 8 条 accepted 边与真实源码完全一致，没有发现误加或遗漏。

注意：当前模型证据使用 `ENABLE_SENSOR` 等符号常量，而不是进一步解析其数值定义。
这不影响本次边目标判断，但后续若要生成可执行的运行时载荷，仍需单独提炼常量到数字的映射。

### 5.3 两个 unresolved 回调

模型保守保留了两个未确定目标：

1. `CompatibleConnection::SensorDataCallback` 的 `cacheData_` 来自
   `RegisteDataReport(DataCacheFunc cacheData, ...)` 参数；
2. `SensorEventCallback::OnDataEvent` 的 `reportDataCb_` 来自
   `HdiConnection_->getReportDataCb()`。

人工查看源码可见，`MedicalSensorService::InitDataCache()` 确实将
`&ReportDataCache::CacheData` 传入注册流程；但这两个回调经过接口/成员状态传递，当前
worklist 没有确定候选集合，模型没有在证据不足时强行补边。该行为符合当前“宁可保留
unresolved，也不猜测目标”的安全策略，并不表示模型证明了这些回调不存在。

## 6. 费用与产物完整性

```text
input_tokens:  13,743
output_tokens: 2,284
total_tokens:  16,027
llm_calls:     1
cost:          ¥0.022287
```

产物包含完整的 worklist、原始决策、验证分组、证据和错误列表；正式的
`call_graph.json` 未被覆盖。

## 7. 结论与限制

本次真实验证证明 OH-22F-3B 的候选审核接入能够在一个真实 OpenHarmony 仓库中完整
恢复 `OnRemoteRequest` 的 8 条候选边，且没有误加非候选目标。它还证明了模型会对没有
足够证据的函数指针保持 unresolved。

但本次只验证了一个仓库和一个候选分发点，不能据此推断所有 OpenHarmony 仓库都无遗漏。
当前 accepted 结果仍未投影到正式调用图；数字 `code` 映射和两个回调的跨函数数据流仍需
后续阶段单独处理。
