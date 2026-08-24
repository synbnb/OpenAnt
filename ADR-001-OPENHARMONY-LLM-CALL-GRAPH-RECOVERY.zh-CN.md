# ADR-001：OpenHarmony 间接调用边的 LLM 辅助增量恢复

## 状态

Proposed（方案已记录，尚未实现）

## 日期

2026-08-23

## 背景

OpenAnt 当前的 C/C++ 调用图主要由 tree-sitter AST 和静态名称解析构建。它能够处理直接调用、部分带静态类型的成员调用以及同文件/头文件中的函数解析，但不能完整处理：

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

### 1. 保留三类图

~~~text
call_graph.json
  原始语言级静态调用图，保持可复现，不被 LLM 改写

semantic_call_graph.json
  OpenHarmony IPC/函数表/注册表等语义边，带证据和置信度

augmented_call_graph.json
  原始图 + 已验证的语义边，用于可达性、上下文和可视化
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

只有验证通过的 native_dispatch_map、transaction_to_handler 或 llm_confirmed_indirect_call 才能写入 semantic_call_graph.json，并在需要时合并为 augmented_call_graph.json。

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

### 阶段 1：诊断产物，不改变行为

- 输出未解析调用点、函数指针赋值和候选目标；
- 对 sensors_medical_sensor 验证是否得到 8 个 handler 候选；
- 新增离线测试，确保原有 call_graph.json 和 reachable 结果不变；
- 生成 call_graph_residuals.json。

### 阶段 2：确定性 OpenHarmony 分发边

- 识别 baseFuncs_、transaction map、callback registry 等常见模式；
- 生成带证据的 native_dispatch_map 语义边；
- 扩展 OpenHarmony semantic reachability overlay；
- 对医疗传感器 Stub 添加 golden fixture 和回归测试。

### 阶段 3：LLM 候选审核

- 增强 C/C++ 函数索引；
- 建立严格 JSON prompt 和候选边工具；
- 增加证据验证器、置信度和拒绝/不确定记录；
- 生成 llm_call_edge_review.json，但默认不覆盖 native graph。

### 阶段 4：增量 BFS 和成本治理

- 将已验证语义边接入 augmented graph；
- 从入口开始使用工作队列递归扩展；
- 增加深度、边数、调用次数、token 和耗时预算；
- 输出每轮新增函数、边和残余调用点统计。

### 阶段 5：多仓库评估

- 在已准备的 OpenHarmony 仓库中运行离线/真实模型两组测试；
- 对已知函数表、IPC、HDI/HDF、注册回调样例分别统计召回和误加边；
- 比较 native、semantic 和 augmented 三张图；
- 只有在真实源码证据和回归测试通过后，才考虑默认开启或接入 Web UI。

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

本方案暂不修改调用图构建器、LLM 阶段或 reachable 主流程。后续优化应先执行阶段 1 的诊断产物，确认候选提取质量，再按阶段 2→5 逐步接入。任何阶段都必须先说明原逻辑、计划修改逻辑和独立测试记录。
