# OH-22A：sensors_medical_sensor 的 LLM 可达性复核实测记录

- 日期：2026-08-26
- 项目：OpenAnt
- 平台：OpenHarmony
- 仓库：`source_code_base/sensors_medical_sensor`
- 目的：验证 `--llm-reachability` 能否发现结构化入口检测遗漏的 OpenHarmony IPC、N-API、HDI 和异步回调入口
- 状态：完成（复用已有真实成功运行，未新增模型费用）

## 1. 原逻辑与本次验证逻辑

### 原逻辑

结构化解析器先抽取 C/C++ 函数和普通直接调用边，再由 OpenHarmony 入口检测器识别 Binder `OnRemoteRequest`、System Ability 生命周期等入口。没有被识别为入口、且没有从已有入口通过调用图到达的函数，会在 `reachable` 过滤时被裁剪。

当前原生调用图仍然主要记录 AST 中能直接解析的调用。函数指针、Binder 分发表、HDI 回调和 EventRunner 回调可能没有 caller → callee 边。

### LLM 可达性复核逻辑

开启 `--llm-reachability` 后，扫描器：

1. 先保留全部解析单元，而不是先裁剪到 `reachable`；
2. 按批次将单元的有限代码片段和 OpenHarmony 平台上下文发送给模型；
3. 要求模型输出 `entry_point`、`external_input`、`cross_process` 三类严格 JSON 信号；
4. 只将高置信度 `entry_point` 信号提升为额外入口；
5. 用这些额外入口重新执行现有的 BFS reachable 过滤；
6. 不修改原始 `call_graph.json`，也不自动补 caller → callee 边。

因此，本阶段验证的是“入口种子召回能力”，不是调用图边恢复能力。

## 2. 实际运行来源

项目中已经存在一次真实成功运行，避免为了重复验证再次产生 API 费用：

- 运行目录：`/Users/shiyu/.openant/webui/ecad4bdd3d5f9ae8`
- 仓库：`/Users/shiyu/学习/hyl/new/OpenAnt/source_code_base/sensors_medical_sensor`
- Provider：`autodl-openai`
- Model：`gpt-5.6-luna`
- LLM 可达性代码上限：1536 字节/单元
- 结果文件：`llm_reachability.json`
- 阶段报告：`llm-reachability.report.json`

本轮另外尝试了同仓库的低推理强度重试，但请求在本地 HTTP 代理处长时间无响应，已停止。该重试不计入成功统计，也没有修改源码。

## 3. 真实运行统计

来自 `llm-reachability.report.json`：

| 指标 | 结果 |
|---|---:|
| 全部解析单元 | 408 |
| 模型复核单元 | 408 |
| LLM 信号总数 | 157 |
| `entry_point` 信号 | 41 |
| `external_input` 信号 | 46 |
| `cross_process` 信号 | 70 |
| 高置信度入口提升 | 40 |
| 产生信号的单元 | 111 |
| 重新过滤后的单元 | 93 |
| 输入 token | 252,126 |
| 输出 token | 20,506 |
| 总 token | 272,632 |
| 阶段耗时 | 330.22 秒 |
| 阶段费用 | ¥0.304632 |
| 阶段错误 | 0 |

当前结构化 BFS 的离线基线（使用同仓库 408 个单元、当前 OpenHarmony 检测器和相同调用图）为：

- 检测到结构化入口：7 个；
- reachable 单元：11 个；
- 过滤掉：397 个。

历史 LLM 运行最终保留 93 个单元，说明 LLM 入口种子确实显著扩大了后续分析范围。但历史运行与当前离线基线不是同一时刻生成的完全配对运行，不能把 `93 - 11` 当作严格的增量实验值；严格增量应在后续固定版本后重新做一次不带 LLM/带 LLM 的配对扫描。

## 4. 源码核验

对模型输出中具有代表性的 IPC、N-API、HDI、异步回调和生命周期信号进行了源码核对，均能在真实源码中找到对应模式：

| 模型信号 | 源码证据 | 判断 |
|---|---|---|
| `MedicalSensorClientStub::OnRemoteRequest` | `frameworks/native/medical_sensor/src/medical_client_stub.cpp:32` 读取 `MessageParcel` 接口令牌 | 有效 Binder 入口 |
| `MedicalSensorServiceStub::OnRemoteRequest` | `services/medical_sensor/src/medical_service_stub.cpp:54` 根据 transaction code 查找 `baseFuncs_` 并调用成员函数 | 有效 Binder 分发入口 |
| `MyFileDescriptorListener::OnReadable` | `frameworks/native/medical_sensor/src/my_file_descriptor_listener.cpp:39` 由框架回调并执行 `recv` | 有效异步数据入口 |
| `CompatibleConnection::SensorDataCallback` | `compatible_connection.cpp:119` 定义回调，`RegisteDataReport` 在 158 行注册 | 有效 HDI 回调入口 |
| `SensorEventCallback::OnDataEvent` | `sensor_event_callback.cpp:31` 覆盖 HDF/HDI 事件回调并复制事件数据 | 有效设备事件入口 |
| `HdiServiceImpl::DataReportThread` | `hdi_service_impl.cpp:54` 为线程函数，88 行由 `std::thread` 启动 | 有效异步线程入口 |
| N-API `On`/`Off`/`SetOpt`/`Init` | `interfaces/plugin/src/medical_js.cpp` 中读取 N-API 参数并注册模块 | 有效应用调用入口 |
| `MedicalSensorService::OnStart`/`OnStop`/`OnDump` | `services/medical_sensor/src/medical_service.cpp` 实现 System Ability 生命周期和 dump 回调 | 有效系统框架入口 |

## 5. 发现的语义问题

### 5.1 头文件声明被提升为入口

以下信号对应的是头文件中的类/声明单元，而不是独立的可执行函数：

- `OHOS.Sensors.MyEventHandler`
- `OHOS.Sensors.MyFileDescriptorListener`
- `OHOS.Sensors.SensorEventCallback`
- `OHOS.Sensors.MedicalSensorServiceStub`
- `OHOS.Sensors.OnRemoteDied`

这些声明能证明类实现了某种框架接口，但不应直接等同于可执行入口。它们作为上下文提示有价值，作为入口根则属于粒度偏粗。

### 5.2 分发目标被标成“外部入口”

例如：

- `MedicalSensorService::EnableSensor`
- `MedicalSensorService::DisableSensor`
- `MedicalSensorService::SetOption`
- `MedicalSensorService::GetSensorState`
- `MedicalSensorService::RunCommand`
- `MedicalSensorService::DestroySensorChannel`
- `MedicalSensorServiceStub::AfeEnableInner` 等 8 个 transaction handler

这些函数确实可以被外部 IPC 请求最终触达，但更准确的关系应当是：

```text
外部 IPC
  → MedicalSensorServiceStub::OnRemoteRequest
  → baseFuncs_ 分发表
  → AfeEnableInner 等 handler
  → MedicalSensorService::EnableSensor 等业务函数
```

当前调用图没有完整表达这条分发边，所以 LLM 把部分下游目标直接提升为入口。这有助于避免 reachable 裁剪，但会损失调用路径的因果语义。

### 5.3 `external_input` 不会自动成为入口

例如 `MedicalSensor::ReadFromParcel`、`MedicalSensorBasicDataChannel::ReceiveData` 被标记为 `external_input`，但当前实现只对高置信度 `entry_point` 做 BFS 种子提升。因此这些信号会被记录，却不会单独触发可达性扩展。

### 5.4 不会修复调用图

尽管模型发现了 `baseFuncs_` 分发、HDI callback、线程和 EventRunner 等模式，本次运行的 `call_graph.json` 没有新增边。LLM 复核只能扩大入口集合，不能替代后续的确定性 dispatch map 或调用边恢复阶段。

## 6. 结论

1. 对 `sensors_medical_sensor`，LLM 可达性复核确实发现了规则入口检测不容易表达的 OpenHarmony 框架入口，包括 Binder 分发、N-API 导出、HDI 回调、文件描述符回调、线程入口和 System Ability 生命周期。
2. 157 条信号和 40 个高置信度入口提升说明它具有明显的召回价值；¥0.30 的成本在该规模仓库上可以接受，但耗时约 5.5 分钟。
3. 它不是完整入口真值生成器：头文件声明会被粗粒度提升，业务分发目标会被当作入口，`external_input` 信号也不会自动参与 BFS。
4. 它不会补全 `OnRemoteRequest → handler`、回调注册 → 回调实现等调用边，因此不能解决调用图拓扑遗漏。
5. 当前最合理的定位是：结构化入口检测之后的“补充召回和风险提示”，而不是替代规则或调用图恢复。

## 7. 下一步

按照 `ADR-001-OPENHARMONY-LLM-CALL-GRAPH-RECOVERY.zh-CN.md`，下一阶段是 OH-22B：先用源码证据恢复确定性的 OpenHarmony 分发边，并单独验证 SemanticGraph、reachable 和 Unit 上下文是否单调增加；之后再把 LLM 用于确定性 resolver 无法消歧的残余候选。

本记录没有修改检测器、LLM 可达性实现或原始调用图。
