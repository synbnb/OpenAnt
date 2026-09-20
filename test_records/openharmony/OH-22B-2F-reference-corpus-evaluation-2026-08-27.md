# OH-22B-2F：OpenHarmony 全部参考仓库离线评估记录

- 日期：2026-08-27
- 评估对象：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`
- 仓库数量：9
- 评估类型：真实源码静态评估；不调用大模型；不修改源码
- 目的：验证 OH-22B-2E Lambda 语义投影及既有原生分派恢复在全部参考仓库中的覆盖、证据完整性和 reachable 行为。

## 1. 评估范围和原逻辑

本次评估使用当前工作树中的 VulnFounder 解析器，对参考目录下的 9 个仓库分别执行
`all` 和 `reachable` 两种解析。每个仓库都单独保存 `dataset.json`、
`call_graph.json`、`call_graph_residuals.json`、`semantic_graph.json`（如果非空）、
`parse.report.json` 和控制台日志。

本次没有重新运行 Stage 1/Stage 2 LLM 漏洞分析，因此表中的结果只描述静态解析、
调用图诊断、语义图和可达性，不代表漏洞数量或漏洞检测准确率。

当前逻辑分为两层：

1. 原生调用图：tree-sitter 提取直接调用边，并由 OpenHarmony 分派诊断器恢复成员
   函数表、transaction map 等确定性分派边。
2. SemanticGraph 覆盖层：保存原生分派、服务实现、IDL/Proxy/Stub 等带证据的语义边；
   其中 `lambda_dispatch` 只有在注册点、读取点、selector、字段身份和已知目标函数
   能够闭合时才投影为 `native_dispatch_to_handler` 边。

## 2. 可复现命令

### All 模式

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output debug_outputs/OH-22B-2F-all-20260827/<repo> \
  --platform openharmony --language c --level all --fresh
```

### Reachable 模式

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output debug_outputs/OH-22B-2F-reachable-20260827/<repo> \
  --platform openharmony --language c --level reachable --fresh
```

9 个仓库的两种模式均返回成功，全部 `parse.report.json` 的 `errors` 数量为 0。

## 3. 全部仓库原始指标

下表来自各仓库的真实产物，而不是估算值。`语义边`包含当前 SemanticGraph 中的所有
边；`Lambda 边`只统计 `attributes.callable_kind=lambda`。

| 仓库 | 发现文件 | 生产解析文件 | Unit | Native 边 | 语义边 | Lambda 边 | 语义 orphan | 语义上下文 Unit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 1356 | 730 | 7563 | 6394 | 642 | 0 | 45 | 603 |
| developtools_hdc | 423 | 196 | 2052 | 2831 | 0 | 0 | 0 | 0 |
| hiviewdfx_faultloggerd | 683 | 359 | 2994 | 3415 | 0 | 0 | 0 | 0 |
| hiviewdfx_hilog | 183 | 117 | 857 | 851 | 0 | 0 | 0 | 0 |
| hiviewdfx_hiview | 1970 | 1054 | 7008 | 5687 | 30 | 0 | 60 | 0 |
| multimedia_audio_framework | 3520 | 1514 | 23178 | 33816 | 715 | 12 | 1402 | 13 |
| startup_appspawn | 633 | 120 | 1204 | 2267 | 0 | 0 | 0 | 0 |
| startup_init | 1560 | 343 | 2708 | 4929 | 9 | 0 | 18 | 0 |
| telephony_core_service | 1056 | 540 | 6842 | 7196 | 341 | 320 | 42 | 336 |
| **合计** | **11384** | **4973** | **54406** | **67386** | **1737** | **332** | **1567** | **952** |

所有 SemanticGraph 边都满足以下结构检查：

- 源节点和目标节点都存在于对应的 SemanticGraph 节点集合；
- 2667 条带文件证据的边，其证据文件全部存在；
- 332 条 Lambda 边的 650 条注册/调用证据全部能在真实源码中找到对应文本；
- 本次没有发现幽灵节点或不存在的证据文件。

## 4. 分派和 Lambda 诊断指标

| 仓库 | 直接分派注册 | 直接候选边 | 顶层残余调用点 | Lambda 注册 | Lambda 调用点 | Lambda 候选边 | Lambda 无候选 | Lambda orphan |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 307 | 306 | 17 | 0 | 2 | 0 | 2 | 0 |
| developtools_hdc | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| hiviewdfx_faultloggerd | 0 | 0 | 1 | 0 | 2 | 0 | 2 | 0 |
| hiviewdfx_hilog | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |
| hiviewdfx_hiview | 0 | 0 | 0 | 42 | 22 | 0 | 22 | 42 |
| multimedia_audio_framework | 33 | 66 | 55 | 72 | 7 | 12 | 6 | 26 |
| startup_appspawn | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| startup_init | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| telephony_core_service | 0 | 0 | 11 | 347 | 16 | 320 | 0 | 17 |
| **合计** | **340** | **372** | **85** | **461** | **50** | **332** | **33** | **85** |

### 4.1 已闭合且经源码核对的 Lambda 边

#### telephony_core_service

320 条边全部满足：

- 目标函数 ID 存在；
- 注册表和调用点的 table/field identity 可匹配；
- selector 与注册点一致；
- 注册源码和调用源码证据都存在。

典型来源包括：

- `INetworkSearchCallbackStub::memberFuncMap_`；
- `CoreServiceCommonEventHub::actionHandlersMap_`；
- `CellInfo::memberFuncMap_`；
- `NetworkSearchHandler::memberFuncMap_`；
- `SimStateHandle::memberFuncMap_`。

#### multimedia_audio_framework

12 条边全部来自真实的 `AudioSuiteCapabilities::loadCapabilityFuncs_`：

```text
AudioSuiteCapabilities::GetNodeParameter
  -> AudioSuiteCapabilities::LoadAinrCapability
  -> AudioSuiteCapabilities::LoadAissCapability
  -> ...
```

对应源码为：

```text
services/audio_suite/client/config/src/audio_suite_capabilities.cpp:36
services/audio_suite/client/config/src/audio_suite_capabilities.cpp:365
```

这些边的注册形式是函数体内 `initializer_list`，目标方法在函数索引中唯一存在，
不是依据函数名猜测。

#### communication_netmanager_base

306 条直接分派边来自网络回调 Stub 的成员函数表，另外 280 条
`native_dispatch_to_service` 边由已证明的继承关系和 handler 内直接调用得到。
全部语义边的源码文件证据均存在，节点端点也全部有效。

## 5. Reachable 结果

| 仓库 | 原始 Unit | 入口数 | 仅 Native 可达 | 语义新增可达 | 最终保留 | 过滤数 | 缩减比例 | 单调性违规 |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| communication_netmanager_base | 7563 | 79 | 300 | 1017 | 1317 | 6246 | 82.6% | 否 |
| developtools_hdc | 2052 | 19 | 164 | 0 | 164 | 1888 | 92.0% | 否 |
| hiviewdfx_faultloggerd | 2994 | 21 | 79 | 0 | 79 | 2915 | 97.4% | 否 |
| hiviewdfx_hilog | 857 | 22 | 79 | 0 | 79 | 778 | 90.8% | 否 |
| hiviewdfx_hiview | 7008 | 68 | 202 | 0 | 202 | 6806 | 97.1% | 否 |
| multimedia_audio_framework | 23178 | 30 | 287 | 0 | 287 | 22891 | 98.8% | 否 |
| startup_appspawn | 1204 | 18 | 81 | 0 | 81 | 1123 | 93.3% | 否 |
| startup_init | 2708 | 48 | 628 | 0 | 628 | 2080 | 76.8% | 否 |
| telephony_core_service | 6842 | 50 | 113 | 318 | 431 | 6411 | 93.7% | 否 |
| **合计** | **54406** | — | **1933** | **1335** | **3268** | **51138** | — | **全部通过** |

说明：`语义新增可达`表示相对于原生调用图可达集合，SemanticGraph overlay 额外带来的
单元数。通信网络和 telephony 的新增较明显；audio 的 12 条 Lambda 边虽然已经正确
生成，但两端都不在当前入口的原生可达集合中，因此本次 reachable 结果没有扩大，不能
据此判定这 12 条边无效。

## 6. 各仓库源码抽查结论

### 6.1 communication_netmanager_base：直接分派覆盖良好，回调参数仍是残余

未闭合的两个 Lambda 调用点位于：

```text
services/netstatsmanager/src/net_stats_listener.cpp:73
services/netstatsmanager/src/net_stats_listener.cpp:89
```

实际源码中 `callbackMap_`/`callbackMapData_` 的值来自：

- 构造函数中登记的匿名命名空间 Lambda `onUidRemove`；
- `RegisterStatsCallback` 和 `RegisterStatsCallbackData` 的运行时 callback 参数。

当前诊断器没有把“命名 Lambda 变量/函数对象别名”和“函数参数注册”跨函数传播，
所以保留为 residual 是安全的；不能把所有 `callback->second` 直接连接到任意函数。

### 6.2 hiviewdfx_faultloggerd：存在非 Lambda 函数指针和参数工厂

两个残余调用点为：

```text
services/snapshot/kernel_snapshot_parser.cpp:218
tools/process_dump/minidump_parser/minidump_factory.cpp:39
```

源码核对：

- `KernelSnapshotParser::parseTable_` 在 `InitializeParseTable()` 中以初始化列表注册
  `KernelSnapshotParser::ParseTransStart` 等成员函数指针，但写法没有 `&`，当前直接
  分派识别器未收集这种形式；
- `MinidumpStreamFactory::creators_` 通过 `RegisterCreator(streamType, creator)` 接受
  函数对象参数，默认注册发生在另一个函数中，调用点位于 `CreateStream()`。

这不是 tree-sitter 不能解析 C++ 语法，而是当前语义层尚未做无 `&` 成员指针、参数
回调和跨函数注册传播。

### 6.3 hiviewdfx_hilog：局部静态初始化列表未进入 Lambda 注册诊断

`FormatHandler` 在：

```text
services/hilogtool/main.cpp:855-901
```

声明局部静态 `handlers` map，并用 Lambda 调用 `TimeHandler`、`TimeAccuHandler`。
当前诊断器记录了 `handler->second(...)` 调用点，但没有收集函数体内
`init_declarator = initializer_list` 形式的局部 map 注册。因此这里是一个明确的
确定性解析缺口，不应交给模型直接猜测。

### 6.4 hiviewdfx_hiview：22 个调用点主要是局部 map 初始化缺口

调用点分布在：

- `base/event_raw/decoded/decoded_event.cpp`；
- `base/event_raw/encoded/raw_data_builder.cpp`；
- `base/event_raw/encoded/raw_data_builder_json_parser.cpp`；
- `base/event_raw/include/encoded/raw_data_builder.h`；
- `framework/native/unified_collection/collector/impl/memory/memory_collector_impl.cpp`；
- `plugins/event_store/event_export/task/export/event_write_strategy_factory.cpp`；
- `plugins/faultlogger/service/bdfr_base/fault_file/faultlog_formatter.cpp`。

这些源码中的 map 通常是函数体内声明：

```cpp
std::unordered_map<..., std::function<...>> allFuncs = {
    {TYPE, [this](...) { this->AppendValue(...); }}
};
```

当前 42 条已观测到的 `initializer_list` 注册来自另一个 fold usage helper，Lambda
本身只修改结构体字段，没有命名函数调用目标；因此它们没有被错误提升为边是合理的。
真正的 22 个 map 调用点尚未获得注册表候选，属于应优先修复的“局部变量初始化列表
收集”问题。

### 6.5 multimedia_audio_framework：部分闭合，剩余形式有明确分类

已闭合的 12 条边来自 `AudioSuiteCapabilities`，证据完整。

未闭合部分包括：

- `HpaeManager::RegisterHandler` 和 `AudioSuiteEngine::RegisterHandler`：Lambda 捕获
  模板参数 `func`，实际调用通过 `std::apply` 和成员函数指针展开；目标要从构造函数
  中的 `RegisterHandler(CODE, &Class::Handler)` 传播到模板实例，当前没有跨函数模板
  参数流；
- `AudioSuitePipeline::effectNodeFactory_`：文件级 Lambda 通过
  `std::make_shared<ConcreteNode>()` 构造对象，当前 Lambda 目标提取器不把模板构造
  调用归一化为构造函数 Unit；
- `FormatConverter` 中有些 Lambda 只是设置标志或返回常量，没有实际命名函数目标，
  不应生成调用边。

这些残余不能用“同类函数名”批量补边，否则会把不同 command code 或工厂类型错误
连接起来。

### 6.6 developtools_hdc、startup_appspawn、startup_init

这三个仓库在本次诊断中没有 Lambda 候选边。`startup_init` 有 9 条 IDL
`interface_to_transaction` 语义边，但当前没有函数级分派边；`developtools_hdc` 和
`startup_appspawn` 没有非空 SemanticGraph。所有原生调用图和 reachable 解析均成功，
没有解析错误。

## 7. 原生调用图不变性

对每个仓库分别比较 all 和 reachable 产物中按 `(source_id, target_id)` 排序后的
Native 调用图边集，9 个仓库的函数数、边数和 SHA-256 均完全一致：

| 仓库 | 函数数 | 边数 | all/reachable 哈希是否一致 |
|---|---:|---:|---|
| communication_netmanager_base | 7563 | 6394 | 是 |
| developtools_hdc | 2052 | 2831 | 是 |
| hiviewdfx_faultloggerd | 2994 | 3415 | 是 |
| hiviewdfx_hilog | 857 | 851 | 是 |
| hiviewdfx_hiview | 7008 | 5687 | 是 |
| multimedia_audio_framework | 23178 | 33816 | 是 |
| startup_appspawn | 1204 | 2267 | 是 |
| startup_init | 2708 | 4929 | 是 |
| telephony_core_service | 6842 | 7196 | 是 |

这证明 reachable 过滤消费的是附加语义 overlay，而不是重新写入或裁剪原生调用图。

## 8. 评估结论

### 已验证

1. 9 个参考仓库、总计 4973 个生产 C/C++ 文件均成功解析，没有 parse error。
2. 当前 SemanticGraph 的 1737 条边端点和源码证据完整，没有发现幽灵节点或不存在的
   证据文件。
3. OH-22B-2E 的 Lambda 投影对 telephony（320 条）和 audio（12 条）均产生了真实、
   可回溯的边；不是只对单个 telephony 例子有效。
4. communication_netmanager_base 的直接函数表和服务实现恢复在真实仓库中有效，
   形成 306 + 280 条语义边。
5. 9 个仓库的 reachable 单调性全部通过；没有出现新增 overlay 导致原有可达单元
   被裁剪的情况。

### 发现的真正泛化缺口

优先级从高到低建议为：

1. **局部变量声明初始化列表**：覆盖 hiview/hilog 的
   `std::map = {{key, lambda}, ...}`，这是当前最明确、最可确定性修复的缺口；
2. **非 Lambda 函数指针初始化**：覆盖 faultloggerd 的无 `&` 成员函数指针表；
3. **命名函数对象和 callback 参数传播**：覆盖 netmanager 的 callback map；
4. **模板注册参数传播**：覆盖 audio `RegisterHandler` 的 `func`；
5. **工厂 Lambda 的构造函数目标**：覆盖 `std::make_shared` 等模板调用，但需要严格
   的类型/构造函数证据。

### 不建议现在做的事情

- 不应把所有 `it->second(...)` 通过函数名相似性连接到任意方法；
- 不应把所有 Lambda 赋值都视为安全的调用边，必须区分“Lambda 内有命名调用”和
  “Lambda 只修改字段/返回常量”；
- 不应在没有跨函数证据时把 callback 参数或模板函数指针直接加入 SemanticGraph；
- 不应因为 semantic graph 中有 IDL 边就把 IDL 声明边当作函数级 reachable 边。

## 9. 产物目录

### All 结果和日志

- [All 结果目录](../../debug_outputs/OH-22B-2F-all-20260827)
- [All 控制台日志](../../debug_outputs/OH-22B-2F-all-20260827-logs)

### Reachable 结果和日志

- [Reachable 结果目录](../../debug_outputs/OH-22B-2F-reachable-20260827)
- [Reachable 控制台日志](../../debug_outputs/OH-22B-2F-reachable-20260827-logs)

每个仓库目录下包含：`dataset.json`、`call_graph.json`、
`call_graph_residuals.json`、`semantic_graph.json`（存在时）、`parse.report.json`、
`pipeline_results.json` 和 `scan_results.json`。
