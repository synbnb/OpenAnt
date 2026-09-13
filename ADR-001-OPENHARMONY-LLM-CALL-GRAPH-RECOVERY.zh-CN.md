# ADR-001：OpenHarmony 间接调用边的 LLM 辅助增量恢复

## 状态

In Progress（OH-22A/22D 诊断与确定性恢复、OH-22F LLM 审核、OH-22G 叠加图与入口驱动逐轮恢复已接入；仍需扩大真实仓库和真实模型评估）

## 日期

2026-08-23

最近更新：2026-08-28

## 背景

VulnFounder 当前的 C/C++ 调用图主要由 tree-sitter AST 和静态名称解析构建。它能够处理直接调用、部分带静态类型的成员调用以及同文件/头文件中的函数解析，但不能完整处理：

- 函数指针和成员函数指针调用；
- 容器或映射表中的 callback/handler 注册；
- OpenHarmony OnRemoteRequest 根据 transaction code 进行的间接分发；
- Binder/IPC、HDF、FFI、异步队列和插件注册等运行时边界；
- 虚函数、接口实现和跨文件注册关系。

在 sensors_medical_sensor 中，构造函数建立了如下映射：

~~~cpp
baseFuncs_[ENABLE_SENSOR] = &MedicalSensorServiceStub::AfeEnableInner;
baseFuncs_[DISABLE_SENSOR] = &MedicalSensorServiceStub::AfeDisableInner;
// ... 共 8 个 handler
~~~

OnRemoteRequest 随后执行：

~~~cpp
auto itFunc = baseFuncs_.find(code);
auto memberFunc = itFunc->second;
return (this->*memberFunc)(data, reply);
~~~

tree-sitter 能解析出 call_expression，但调用目标是 memberFunc 指向的间接成员函数，而不是可直接查找的函数名。当前 C/C++ CallGraphBuilder 没有进行函数指针映射和数据流追踪，因此扫描产物中表现为：

~~~text
MedicalSensorServiceStub::OnRemoteRequest → []
~~~

而 8 个 handler 函数本身已经成功提取为函数节点。这说明缺口位于调用边语义恢复，而不是源码语法解析。

## 决策

采用“确定性证据提取 + 函数索引候选搜索 + LLM 边审核 + 证据验证 + 增量 BFS”的混合架构。

LLM 不直接自由生成整张调用图，也不直接覆盖原始 call_graph.json。规则和 tree-sitter 负责发现调用点、注册关系及候选目标；LLM 负责在有限候选集和完整证据上判断复杂语义；验证器负责决定候选边是否可以进入增强图。

## 目标架构

### 1. 保留原生图和语义覆盖图

~~~text
call_graph.json
  原始语言级静态调用图，保持可复现，不被 LLM 改写

semantic_graph.json
  OpenHarmony IPC/函数表/注册表等语义边，带证据和置信度

llm_call_graph_overlay.json
  已验证 LLM 间接边的独立语义图产物，带来源、拒绝原因和摘要

内存中的 semantic reachability overlay
  semantic_graph.json + llm_call_graph_overlay.json 的原始图并集，用于本次
  reachable BFS；不把推断边写回 call_graph.json
~~~

当前 OpenHarmony 语义覆盖图已经采取“原生图不变、语义边作为 reachability overlay”的设计；本方案继续沿用该原则，而不是把推断边伪装成普通直接调用。

### 2. 边类型和证据等级

| 边类型 | 来源 | 默认是否参与 reachable | 说明 |
|---|---|---:|---|
| direct_call | tree-sitter 直接调用 | 是 | 目标函数可静态解析 |
| typed_member_call | 静态 receiver 类型解析 | 是 | 已知对象类型的成员调用 |
| native_dispatch_map | 函数表/注册表确定性证据 | 是 | 例如 baseFuncs_[X] = &Handler |
| transaction_to_handler | IDL/IPC 语义图 | 是 | 已有 OpenHarmony 语义边类型 |
| llm_confirmed_indirect_call | LLM 审核且证据验证通过 | 按阈值 | 规则难以覆盖的间接关系 |
| llm_candidate | LLM 提议但证据不足 | 否 | 只进入残余和人工审阅文件 |

所有新增边必须包含：

~~~yaml
source_id: caller function id
target_id: callee function id
kind: edge kind
confidence: 0.0-1.0
evidence:
  - file: relative path
    start_line: integer
    end_line: integer
    text: source excerpt
resolver_version: integer
attributes:
  dispatch_map: optional map name
  transaction_code: optional enum/constant
  possible: true/false
~~~

未知函数 ID、缺少源码证据或无法通过端点校验的关系不得直接写入增强图；应写入 orphans/残余记录。

## 目标流程

### 阶段 A：未解析调用点和证据诊断

不调用 LLM、不改变 reachable 结果，只对每个函数生成未解析关系清单：

~~~json
{
  "caller": "services/medical_sensor/src/medical_service_stub.cpp:MedicalSensorServiceStub::OnRemoteRequest",
  "site": {
    "line": 68,
    "expression": "(this->*memberFunc)(data, reply)",
    "ast_kind": "indirect_member_call"
  },
  "static_resolution": "unresolved",
  "nearby_evidence": [
    {
      "line": 39,
      "expression": "baseFuncs_[ENABLE_SENSOR] = &MedicalSensorServiceStub::AfeEnableInner"
    }
  ]
}
~~~

同时抽取：

- 函数指针/成员函数指针赋值；
- map/array/registry 的键到函数地址关系；
- callback 注册和取消注册；
- virtual/interface/继承关系；
- 已有直接调用边和未解析原因。

该阶段的产物用于确认候选抽取是否完整，不能因为诊断结果就扩展调用图。

### 阶段 B：候选目标搜索

基于函数索引和语义证据生成有限候选集。当前 RepositoryIndex 的函数定义、函数名和正则使用搜索可以复用，但需要增加更适合 C/C++ 的查询能力：

- search_symbol_references：搜索函数名、限定名和地址引用；
- search_function_pointer_assignments：搜索 &Class::Method 等赋值；
- search_dispatch_registrations：搜索 map/registry/callback 注册；
- search_class_methods：按类名、继承关系列出候选成员；
- read_source_evidence：按文件和行范围读取证据。

以 OnRemoteRequest 为例，候选集应优先来自 baseFuncs_ 的 8 个赋值目标，而不是让模型从整个仓库自由猜测。

### 阶段 C：LLM 候选边审核

LLM 每次只审核一个函数或一组高度相关的未解析调用点。输入必须包括：

1. caller 的函数 ID、文件、行号和完整代码；
2. tree-sitter 识别出的 AST 类型；
3. 当前已经确认的直接调用边；
4. 未解析表达式及上下文；
5. 函数索引返回的候选目标及代码；
6. 函数指针赋值、transaction、注册表和继承证据；
7. OpenHarmony 平台上下文。

建议要求模型只返回严格 JSON：

~~~json
{
  "decisions": [
    {
      "caller": "...:OnRemoteRequest",
      "callee": "...:AfeEnableInner",
      "relation": "indirect_dispatch",
      "decision": "accept",
      "confidence": 0.96,
      "reason": "memberFunc comes from baseFuncs_ and the constructor maps ENABLE_SENSOR to this handler",
      "evidence": [
        {"file": "medical_service_stub.cpp", "line": 39},
        {"file": "medical_service_stub.cpp", "line": 68}
      ]
    }
  ],
  "unresolved": []
}
~~~

模型可以通过函数索引请求更多定义或引用，但不能把不存在于函数索引中的函数直接作为目标。无法确认的关系必须返回 uncertain，不能用自然语言替代结构化证据。

### 阶段 D：证据验证和语义覆盖图

验证器执行以下检查：

- caller/target 是否都是已提取的函数 ID；
- 引用的文件和行是否仍然存在；
- 证据中是否真的出现函数地址、注册或分发表关系；
- 类、命名空间、继承和 receiver 是否一致；
- transaction/枚举值是否可追踪；
- 是否为重复边或自调用；
- 是否违反当前平台/组件范围。

只有验证通过的 native_dispatch_map、transaction_to_handler 或
llm_confirmed_indirect_call 才能进入本次扫描的内存 semantic reachability
overlay。LLM 边保存在独立的 llm_call_graph_overlay.json，不写入现有
semantic_graph.json。

验证失败的边必须保留在残余文件中，不能静默丢弃。

### 阶段 E：入口驱动的增量 BFS

使用结构化入口和经过确认的 LLM 入口作为初始种子：

~~~text
seed = structural_entry_points ∪ llm_confirmed_entry_points
queue = seed
visited_functions = {}
visited_call_sites = {}

while queue 非空：
    caller = queue.pop()
    如果 caller 已处理：继续

    读取原始直接边
    读取 caller 的未解析调用点
    生成候选并审核/验证
    把通过验证的边加入增强图

    对新增 callee 加入 queue
~~~

现有 ReachabilityAnalyzer.get_all_reachable() 会从 reverse graph 重建 forward graph，再从入口进行 BFS；本方案只扩展它使用的增强 reverse graph，不改变已有直接边的含义。

以医疗传感器 Stub 为例：

~~~text
OnRemoteRequest
  ↓ 识别 baseFuncs_ + memberFunc 间接分发
8 个 Inner handler
  ↓ 逐个分析 handler 的直接边和未解析边
权限检查、服务实现、数据通道等下游函数
  ↓
直到没有新增已验证边，或达到资源预算
~~~

必须设置以下停止条件：

- 最大 BFS 深度；
- 最大新增边数量；
- 每个调用点最大候选数；
- 最大 LLM 请求次数和 token 数；
- 单次扫描总耗时；
- 已处理函数和调用点去重。

## 与 --llm-reachability 的关系

现有 --llm-reachability 负责发现额外的入口、外部输入和跨进程信号。它只会把高置信度 entry_point 信号加入 BFS 种子，不会生成 caller/callee 边，也不会改变原始 call_graph.json。

本方案不应把调用边恢复逻辑悄悄塞进现有阶段。建议后续使用独立的可选阶段或明确的子选项，例如：

~~~text
--llm-call-edge-recovery
~~~

两者可以按以下顺序协作：

~~~text
结构化入口检测
  → 可选 LLM reachability（补入口）
  → 间接调用候选提取
  → LLM 边审核
  → 语义覆盖图合并
  → reachable BFS
~~~

这样可以分别统计入口发现成本和调用边恢复成本，也避免用户误以为开启 --llm-reachability 就会修复调用图。

## 可靠性和安全边界

### 1. 单调扩展

增强图只能新增边，不能删除原始静态边。增强后的 reachable 集合必须是原生 reachable 集合的超集；如果发生缩小，应记录错误并保留原生结果。

### 2. 区分确定路径和可能路径

reachable 过滤可以使用经过证据约束的可能分发边，以降低漏报风险；但漏洞报告和可视化必须显示边类型和置信度，不能把 possible_dispatch 描述为确定的运行时执行路径。

### 3. 模型失败时安全降级

LLM 超时、认证失败、响应格式错误或候选验证失败时：

- 原始静态调用图仍然可用；
- 不删除已有入口和单元；
- 未解析调用点进入 call_graph_residuals.json；
- 报告明确显示调用边恢复阶段失败或部分完成。

### 4. 代码外发和成本控制

该阶段可能向配置的模型发送源代码片段，必须保持显式 opt-in，并沿用现有 LLM 配置、模型绑定和日志脱敏策略。候选生成和函数索引搜索应在本地完成，LLM 只接收当前调用点和有限候选代码。

建议采用：

- 候选集大小上限；
- 单调用点只审核一次，必要时才二次复核；
- 先使用轻量模型提出候选，再对高风险边使用强模型验证；
- 缓存以源码哈希、提示版本和模型配置为键的审核结果。

## 不采用的方案

### 方案 A：纯规则覆盖所有 OpenHarmony 模式

不采用。OpenHarmony 仓库、生成代码、构建条件和跨进程边界很多，规则很难一次覆盖全部变体。但规则非常适合做 AST 证据提取、候选生成和结果验证，因此不是完全放弃规则。

### 方案 B：LLM 直接扫描整个仓库并自由输出调用图

不采用。该方案容易出现幻觉目标、同名函数误配、循环扩展和结果不可复现，且无法对每条边提供可审计证据。

### 方案 C：只依赖现有 --llm-reachability

不采用。该阶段输出的是入口/输入/跨进程信号，不是调用边；它不能理解 baseFuncs_ 的键值到成员函数映射，也不会修改 native call graph。

## 分阶段实施计划

### 阶段 1：诊断产物，不改变行为（OH-22A 第一切片已完成）

- 输出未解析调用点、函数指针赋值和候选目标；
- 对 sensors_medical_sensor 验证是否得到 8 个 handler 候选；
- 新增离线测试，确保原有 call_graph.json 和 reachable 结果不变；
- 生成 call_graph_residuals.json。

2026-08-26 的 OH-22A 已实现：

- 识别 `parenthesized_expression` 形式的函数指针/成员函数指针调用；
- 识别 `table[selector] = &Class::Handler` 形式的确定性分发表赋值；
- 跟踪 `table.find(...) → iterator->second → memberFunc` 的函数内取值链；
- 只把能够精确映射到现有函数 ID 的目标加入候选；
- 将未知目标写入 orphan，将证据不足的调用点保留为无候选残余；
- OpenHarmony C/C++ 流水线生成 `call_graph_residuals.json`，失败时安全降级；
- 不修改原生调用图、语义图和 reachable 结果。

该切片尚未覆盖 callback 参数跨函数传递、虚调用和所有注册表变体。真实仓库中发现的 `CompatibleConnection::SensorDataCallback` 已被正确保留为无候选残余，后续阶段不得靠猜测直接补边。

### 阶段 2：确定性 OpenHarmony 分发边

- 识别 baseFuncs_、transaction map、callback registry 等常见模式；
- 生成带证据的 native_dispatch_map 语义边；
- 扩展 OpenHarmony semantic reachability overlay；
- 对医疗传感器 Stub 添加 golden fixture 和回归测试。

2026-08-27 的 OH-22D 确定性恢复切片已补充以下通用写法：

- 追踪 `find/begin` 迭代器以及后续 `iterator = table.find(...)` 赋值；
- 识别 `emplace/try_emplace/insert({key, lambda})` 的 Lambda 注册；
- 结构化识别把 callable 参数写入 `table[key]` 的注册辅助函数，并沿调用参数传播
  `&Class::Method`；
- 识别初始化列表中的已索引自由函数引用；
- 新证据继续通过现有 SemanticGraph resolver 生成 overlay 候选，原生
  `call_graph.json` 保持不变。

该切片已在真实 `hpae_manager.cpp`、`raw_data_builder.cpp`、
`raw_data_builder_json_parser.cpp` 和 `faultlog_formatter.cpp` 上验证。未索引的模板、
文件级变量别名和外部 callback 仍保留为残余，尚未进入 LLM 或增量 BFS。

### 阶段 3：LLM 候选审核

- 增强 C/C++ 函数索引；
- 建立严格 JSON prompt 和候选边工具；
- 增加证据验证器、置信度和拒绝/不确定记录；
- 生成 llm_call_edge_review.json，但默认不覆盖 native graph。

### 阶段 4：增量 BFS 和成本治理

OH-22G-3 已完成第一步接入：

- `apply_reachability_filter` 接受独立的 LLM 语义叠加图，并与确定性
  `semantic_graph.json` 分别解析后合并到内存 reverse graph；
- 扫描器在显式 `--llm-call-graph-projection` 下先保存全量数据集，再以
  原生入口和已有 LLM reachability 入口为种子执行 promote-only BFS；
- 原生可达集合被单调保留，叠加图只能增加可达函数，不能裁剪原有函数；
- 多语言输出按语言函数索引匹配 overlay，无法安全匹配时记录错误并保留
  原有数据；
- `reachability_filter` 元数据记录 native_reachable_units、
  semantic_reachable_added、边类型和来源。

当前阶段仍不是“边发现后递归调用模型”的完整 agentic loop；它只消费已经
通过审核与证据验证的边。调用点逐层重新分析、预算控制和循环终止属于后续
阶段。

2026-08-28 的 OH-22G-4 第一小切片已在独立调度器中实现入口驱动的逐轮审核：

- 结构化入口作为 BFS 种子，原生调用边和确定性语义边只用于发现后续前沿；
- 每轮只审核当前前沿函数的未处理残余，投影成功的边才允许加入下一轮；
- 调度器对轮数、调用点、边数、模型请求数、重试和耗时设置上限，并保留每轮报告；
- 没有入口、模型失败或预算耗尽时安全结束，不修改原始调用图；
- 无解析候选的残余可以从有界本地检索短名单中选择目标，但仍须通过源码证据投影。

该切片目前尚未接入 scanner 主流程，正式接入时将保留现有一次性审核作为默认
兼容路径，并单独落盘逐轮产物。

2026-08-28 的 OH-22G-4-2 已接入 scanner/CLI：

- 新增显式 `--llm-call-graph-iterative-recovery`，它不会改变默认扫描成本；
- 迭代结果写入 `llm_call_graph_recovery_rounds.json`，旧模式仍写入
  `llm_call_graph_recovery.json`；
- 投影阶段会重新读取每轮审核结果并执行证据投影，而不是直接信任轮次文件中的
  已合并图；
- 轮次 overlay 与候选审核 overlay 一起进入现有 promote-only reachable 过滤；
- `ScanResult`、`scan.report.json` 和 CLI 转发均记录新的轮次产物路径；
- OpenHarmony 以外的平台会安全跳过该阶段，缺少语义图或残余文件时不影响原有扫描。

2026-08-28 的 OH-22G-6 优化了逐轮调度的终止判定：

- 下一轮前沿不再因为存在普通原生后继就无条件继续扩展；只有能够到达尚未处理残余
  调用点的函数才会进入后续前沿；
- 调度器仍会保留同一调用者被每轮 site 限额延后的残余，并继续处理显式 deferred
  caller；
- 真实 `sensors_medical_sensor` 回放中，候选分派场景从默认 4 轮降为 1 轮并以
  `frontier_exhausted` 正常结束，8 条恢复边和 2 个无候选未复核残余保持不变；
- 该优化只改变停止时机，不改变候选、证据校验、投影边类型或原生调用图。

### 阶段 5：多仓库评估

- 在已准备的 OpenHarmony 仓库中运行离线/真实模型两组测试；
- 对已知函数表、IPC、HDI/HDF、注册回调样例分别统计召回和误加边；
- 比较 native graph、semantic graph 和派生 overlay；
- 只有在真实源码证据和回归测试通过后，才考虑默认开启或接入 Web UI。

2026-08-28 的 OH-22G-7A 完成了第一轮批量离线评估：

- `source_code_base` 中共盘点 22 个仓库，其中 3 个仓库具有完整的四类解析产物和
  入口标记，已实际运行一次性/逐轮比较；
- 3 个仓库的残余源码文件、caller/target 索引和输入哈希均通过一致性检查；
- `sensors_medical_sensor` 使用历史真实模型响应回放，8 条分派边在一次性与逐轮投影中
  完全一致；`communication_netmanager_base` 与 `multimedia_audio_framework` 本轮
  使用无网络的 keep-unresolved fallback，只验证调度范围和安全降级；
- 其余 19 个仓库因缺少完整产物被明确列为未评估，不把缺失当作通过；
- 本轮没有新增模型请求，也没有修改既有 `call_graph.json`、残余或语义图产物。

2026-08-28 的 OH-22G-7B/7C 针对参考目录
`openharmony_reference/openharmony_source_code` 完成了新的静态解析与离线逐轮评估：

- 9 个仓库全部完成 OpenHarmony C/C++ 静态解析，共生成 4,973 个源码文件索引、
  50,304 个函数索引、57,180 条原生调用边和 312 个入口；
- 7 个仓库生成语义图，`developtools_hdc` 与 `startup_appspawn` 没有确定性语义边，
  因此明确记录为空文件缺口，不把它们误报为解析失败；
- 81 个残余调用点的源码文件和函数索引均通过一致性检查；
- 在不调用模型的 `keep_unresolved` 回退下，9 个仓库的一次性与逐轮投影边集合均相等，
  所有输入 JSON 保持不变；
- `communication_netmanager_base` 调度了 17 个入口可达残余，
  `telephony_core_service` 调度了 5 个入口可达残余，其余不可达残余被安全保留；
- 该批次只证明静态产物和逐轮调度的安全边界，不代表 LLM 召回率，真实模型效果需另行
  进行受控 API 实验。

2026-08-28 的 OH-22G-8 在 `hiviewdfx_faultloggerd` 上完成了第一次真实模型受控实验：

- 3 个残余调用点、31 个候选目标使用项目内 `autodl-openai / gpt-5.6-luna` 进行一次性审核；
  首次响应格式错误后自动重试 1 次，最终 2 次调用消耗 28,958 输入 token、3,191 输出 token，
  费用约 ¥0.039060；
- 模型接受并投影 4 条边，均来自 `KernelSnapshotParser::ProcessSnapshotSection` 的
  `parseTable_` 初始化，逐条源码证据核验通过；另外两个残余点被模型保守地保留未解析；
- 对照源码注册表，31 条可验证候选边中恢复 4 条（12.9%），接受边源码核验精确率为 100%；
- 同一输入执行入口驱动逐轮调度时，3 个残余均不在 18 个入口的可达子图中，因此 1 轮后
  `frontier_exhausted`、0 次模型调用、0 费用；该结果验证了调度器的早停和成本边界；
- 本次实验显示下一步不应继续为单个语法增加规则，而应增强残余点上下文检索，把跨函数的
  注册定义、初始化表和调用参数传播一并提供给模型。完整过程记录于
  `test_records/openharmony/OH-22G-8-real-faultloggerd-llm-recovery-2026-08-28.md`。

2026-08-28 的 OH-22G-9A 完成了跨函数注册上下文收集器的第一切片：

- 新增只读的 `registration_context` 收集层，按分发表变量、候选限定名和调用者所属类名
  检索仓库内源码片段，并返回相对路径、行号、匹配原因和截断状态；
- 调用者文件与候选文件优先，生产源码优先于测试/示例目录；仓库路径越界、文件大小、
  文件数和上下文字节均有上限，找不到上下文时安全返回 `not_found`，不生成调用边；
- 在 `hiviewdfx_faultloggerd` 离线验证中，成功找回 `RegisterDefaultCreator`、局部
  `decodeTable` 和 `InitializeParseTable` 三类关键片段；
- 新增单元测试 3 个，并与恢复器、投影器、逐轮调度器和 scanner 集成回归测试合计
  `36 passed`；本切片尚未接入模型 prompt，因此不改变现有真实扫描行为；
- 详细记录见 `test_records/openharmony/OH-22G-9A-registration-context-2026-08-28.md`。

2026-08-28 的 OH-22G-9B 将注册上下文以受控方式接入恢复 worklist 和 prompt：

- `run_recovery_review()` 与入口驱动逐轮恢复默认携带 `registration_context`；直接构造
  worklist 仍可通过开关保持旧行为；
- prompt 明确要求模型使用带路径/行号的注册片段判断边，文件名和函数名本身不算证据，
  缺少上下文时必须保留未解析；
- 在 `hiviewdfx_faultloggerd` 的离线 prompt 检查中，3 个残余点的初始化/注册片段均进入
  90,071 字符的受控请求上下文，未发起 API 调用；
- 新增/修改后的恢复相关测试为 `42 passed`，本切片尚未宣称真实模型召回率提升；下一步
  需要用相同模型和预算重跑 OH-22G-8，比较边召回、证据质量和费用；
- 详细记录见 `test_records/openharmony/OH-22G-9B-registration-context-prompt-integration-2026-08-28.md`。

2026-08-28 的 OH-22G-9C 使用相同的 `hiviewdfx_faultloggerd` 输入和真实模型完成了注册上下文增强复测：

- 3 个残余间接调用点共 31 个候选目标；新增上下文包含 `creators_`、`decodeTable` 和
  `parseTable_` 的跨函数注册/初始化片段，每个残余点限制为 6,000 字符；
- 真实模型 1 次调用、无重试，消耗 25,943 输入 token、9,028 输出 token，成本约 ¥0.065050；
- 31/31 条模型接受边均属于输入候选集合，并逐条在源码注册表中核验，源码真值召回率从
  OH-22G-8 的 12.9% 提升到本轮 100%，接受边精确率保持 100%；
- 增强 overlay 的 34 个节点全部存在于原函数索引，无重复、自环或幽灵节点，原始调用图和
  残余产物保持不变；
- 模型返回的注册文本正确，但注册证据行号普遍把表头/前一行作为注册行，说明当前上下文
  片段缺少逐行标号。后续应增加行号标注和确定性证据归一化，不能把本轮召回结果当成行号
  定位已经完全可靠；
- 完整数据、prompt 摘要、用量和源码核验记录见
  `test_records/openharmony/OH-22G-9C-real-faultloggerd-context-aware-recovery-2026-08-28.md`。

2026-08-28 的 OH-22G-9D 对 9C 的真实响应进行了离线证据行号校正：

- 注册上下文片段新增 `line_numbered_text`；模型返回的原始 `text` 保持不变，便于同时满足
  行号阅读和源码匹配；
- `evidence_line_resolver` 只在声明源码仓库内对证据文本做唯一匹配，唯一匹配才更正
  `start_line`/`end_line`，并保留 `reported_*` 原始行号和 `line_resolution` 状态；目标证据
  在文本格式不同且带已知目标 ID 时可回退到函数索引；
- 对 OH-22G-9C 的 31 条真实决定离线回放，31 条注册证据全部唯一校正，84 条证据文本直接
  匹配，9 条目标证据使用函数索引回退，无未定位或歧义证据；校正前后仍为 31 条 accepted
  和 31 条 overlay 边；
- 新增行号解析测试后相关测试为 `25 passed`，Ruff 通过；该阶段没有模型调用，也没有修改
  原始调用图；
- 详细记录和归一化产物见
  `test_records/openharmony/OH-22G-9D-evidence-line-normalization-2026-08-28.md`。

2026-08-28 的 OH-22G-10A/10B 修复了真实模型响应的 JSON 协议与重试可诊断性：

- OH-22G-10 在 `hiviewdfx_hiview` 和 `communication_netmanager_base` 各选择一个真实残余入口进行
  批量实验时，两次请求均因 `evidence.text` 内含未经转义的真实换行而无法通过严格 JSON 解析；这不是
  输出截断或 Markdown 围栏问题。诊断记录只保存响应长度、哈希和括号位置，不保存敏感响应正文。
- OH-22G-10B 的提示明确要求 `evidence.text` 单行化，解析器拒绝含真实换行的证据；解析失败重试时
  增加有限的格式纠正指令，而不是重复原提示；每次响应在 `response_diagnostics` 中记录
  `valid`/`invalid`/`transport_error` 状态和非敏感元数据，仍不做启发式 JSON 修复。
- 在真实 `hiviewdfx_hiview` 的 `GetLogParseSections` 入口复测中，9 个候选目标 1 次调用即返回合法
  JSON，9/9 条边通过高置信度、候选集合和源码证据校验并投影；注册行、目标行、调用行共 27 条证据
  全部精确对齐，费用约 ¥0.023094。
- 在真实 `communication_netmanager_base` 的 `NetConnCallbackStub::OnRemoteRequest` 入口复测中，
  6 个候选目标 1 次调用即返回合法 JSON，6/6 条边通过源码证据校验并投影；注册和目标证据 12 条
  精确对齐，调用点证据 6 条通过唯一邻近匹配校正，费用约 ¥0.017815。
- 相关恢复/注册/证据测试为 `21 passed`，完整 OpenHarmony 测试集为 `169 passed, 2 skipped`，
  Ruff 检查通过。详细记录见
  `test_records/openharmony/OH-22G-10B-json-retry-fix-2026-08-28.md`。

## 验收标准

实现阶段至少满足：

1. sensors_medical_sensor 中 OnRemoteRequest 能产生 8 个有证据的间接分发候选；
2. 原始 call_graph.json 保持不变，增强图明确标识新增边来源；
3. 经过验证的边全部指向已知函数 ID，不产生幽灵节点；
4. reachable 结果只增不减，且新增单元可通过增强边追溯到入口；
5. LLM 不可用时扫描仍能完成静态阶段，并明确记录降级；
6. 每个未接受候选都有拒绝原因或 uncertain 记录；
7. BFS 在循环、重复注册和高连接度函数下能够终止；
8. 真实模型结果可通过源码行证据复核，不能只依赖模型自然语言解释；
9. Web 可视化能够区分直接边、语义边、可能边和未解析边；
10. 16 个已准备仓库的运行结果包含新增边数、残余数、模型调用次数和成本统计。

## 后续待确认事项

- 是否把 llm-call-edge-recovery 作为独立 CLI 选项，还是作为 OpenHarmony 平台下的可选子阶段；
- llm_confirmed_indirect_call 参与 reachable 的最低置信度和证据门槛；
- 是否对高风险边使用第二个模型或人工复核；
- 增强图是否只用于 reachable/上下文，还是也用于漏洞路径报告；
- 真实模型调用结果是否需要持久化完整 prompt，还是只保存 prompt 哈希和源码证据。

## 当前结论

OH-22A 已完成阶段 1 的第一个可运行切片：诊断器可以在真实 `sensors_medical_sensor` 中找到 2 个间接成员调用残余，其中 `OnRemoteRequest` 得到 8/8 个有源码证据且指向已知函数 ID 的候选；另一处证据不足的 callback 调用没有被猜测补边。原生调用图和 reachable 行为保持不变。

OH-22D 已完成阶段 2 的第一批通用确定性恢复：注册表和 helper 参数的源码证据能够形成
候选并投影到 SemanticGraph overlay；原生调用图仍未被直接改写。

OH-22F/22G 已完成真实 LLM 审核、独立投影和 promote-only BFS 接入；OH-22G-4
已完成入口驱动逐轮调度器的独立验证：

- `llm_call_graph_recovery.json` 与 `llm_call_graph_candidate_review.json` 仍是审核原始记录；
- `llm_call_graph_overlay.json` 只收录高置信度、候选集合一致且具有调用点与目标证据的决定；
- `--llm-call-graph-projection` 开启后，reachable/codeql/exploitable 级别会从保存的全量数据集重新过滤；
- 原生 `call_graph.json` 保持不变，BFS 只使用内存合并图；
- 在真实 `sensors_medical_sensor` 回放中，8 条 LLM 边全部通过投影，并与已有确定性语义边重合，未新增额外可达单元。

- 在真实 `sensors_medical_sensor` 的离线产物回放中，默认残余模式识别 2 个无候选
  callback 残余但因未从入口可达而不盲目调用模型；候选模式只调度入口上的候选分发点。
- 新调度器的两跳 fixture、原生边跨层调度、延迟调用点重排和无入口降级测试均通过。

`registration_context` 已以受控字段接入 worklist/prompt，OH-22G-10B 又补充了单行 JSON 证据协议、
针对性重试和 `response_diagnostics`。下一步应在更多真实 OpenHarmony 仓库上按相同预算运行，统计
格式成功率、边召回率、证据定位状态、残余数量和成本；仍须保持证据不足时不补边。任何阶段都必须
先说明原逻辑、计划修改逻辑和独立测试记录。
