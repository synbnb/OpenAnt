# ADR-004：以对比 PoC 评估 Joern 是否值得进入 OpenHarmony 语义边恢复流程

## 状态

Proposed（批准只读对比实验，不批准接入主扫描流程）

## 日期

2026-08-26

## 与现有文档的关系

本文是对以下两份文档的批判性补充：

- `ADR-001-OPENHARMONY-LLM-CALL-GRAPH-RECOVERY.zh-CN.md`
- `/Users/shiyu/学习/hyl/new/OpenHarmony_TreeSitter_to_Joern_技术方案.md`

本文不取代 ADR-001。ADR-001 仍然定义“间接调用边必须有证据、原生图保持不变、增强只能单调增加、LLM 失败时安全降级”等基本原则。本文主要回答另一个问题：

> Joern 应当成为 OpenAnt 的正式 C/C++ 语义后端，还是只作为实验工具，甚至根本没有必要用于当前调用边缺失问题？

当前决定不是“引入 Joern”，而是“先做能够否决 Joern 的小规模对比实验”。

## 结论先行

我的结论是：

1. `sensors_medical_sensor` 的 8 条缺失边已经被证明是语义解析缺口，不是 tree-sitter 语法解析失败。
2. 对这个具体案例，Joern 不是恢复 8 条边的必要条件。tree-sitter 已经能看到分发表赋值、成员函数地址、`find(code)`、`itFunc->second` 和间接成员调用；缺少的是把这些事实串起来的 resolver。
3. Joern 的潜在价值主要在跨函数 def-use、控制流、数据流、别名和类型事实，而不是“换一个 parser 就自动得到完整调用图”。
4. Joern 原生调用图也不能被假定为能解析 `STL 容器 + iterator + 成员函数指针`。技术方案本身实际上也承认仍然需要 OpenHarmony 专用 resolver。
5. 因此，第一轮实验必须同时比较：
   - 当前 tree-sitter；
   - tree-sitter 事实 + 同一个确定性 resolver；
   - Joern 原生结果；
   - Joern 事实 + 同一个确定性 resolver。
6. 如果 Joern 不能比 `tree-sitter + resolver` 恢复更多正确边，或者不能明显改善后续 CFG/data-flow 证据，就不应为了“技术更高级”把 JVM、CPG 缓存、Scala 查询脚本和额外故障面引入正式管线。
7. LLM 仍只处理确定性分析后的残余歧义。模型自报的置信度不能代替源码证据，也不应直接成为普通调用边。

一句话概括：

> 先把 Joern 当成候选事实提供者来测，而不是把它当成已经选定的新调用图引擎。

## 一、当前问题的准确边界

### 1. 已经确认的真实缺口

当前历史扫描结果中：

- `sensors_medical_sensor` 提取了 408 个函数、227 条原生调用边；
- `MedicalSensorServiceStub::OnRemoteRequest` 的原生下游为空；
- 8 个 handler 都已经被提取为合法函数节点；
- 源码中存在 8 条明确的 `baseFuncs_[KEY] = &Class::Handler` 赋值；
- 调用点通过 `itFunc->second` 得到成员函数指针，再执行 `(this->*memberFunc)(data, reply)`。

所以缺口可以准确描述为：

```text
语法节点存在
  + 函数节点存在
  + 映射关系存在
  + 间接调用点存在
  - 缺少跨这些节点的语义关系恢复
```

这与“tree-sitter 不支持 OpenHarmony C++”不是一回事。

本次还直接用项目虚拟环境中的 `tree-sitter-cpp` 对真实文件做了节点核对：

```text
第 39～46 行  8 个 assignment_expression
第 64 行      baseFuncs_.find(code)，call function 为 field_expression
第 68 行      (this->*memberFunc)(data, reply)，call function 为 parenthesized_expression
```

因此，在这个案例上，tree-sitter 已经产出了恢复关系所需的主要语法节点；当前缺失发生在“把分发表赋值、查表取值和间接调用连接成目标函数边”的语义解析阶段。

### 2. 当前 CallGraphBuilder 的行为

当前 `CallGraphBuilder` 会：

- 对每个函数体重新运行 tree-sitter；
- 提取普通 `call_expression`；
- 解析直接调用和部分静态 receiver 类型明确的成员调用；
- 把作为普通函数参数传入的回调名加入候选；
- 对同文件、头文件、唯一全仓名称和原型做有限符号解析；
- 对 `parenthesized_expression` 形式的函数指针调用明确返回未解析。

最后一点正是 `(this->*memberFunc)(...)` 不产生目标边的直接原因。

### 3. 当前项目已经具备的增强图骨架

OpenAnt 已经存在：

- `SemanticGraph`：带节点、边、证据、置信度、resolver 版本和 orphan；
- `semantic_graph.json`：当前主要保存 OpenHarmony IDL/IPC 语义关系；
- `build_semantic_reachability_overlay()`：把合法语义路径投影为原生函数边；
- `merge_reachability_graph()`：在内存中把语义边追加到原生图；
- 单调性保护：增强 reachable 结果不得丢失原生 reachable 单元；
- Unit 上下文中的 `context_functions`：可携带语义相关函数及证据路径。

因此不需要再发明一套互不兼容的图模型。新的间接调用恢复应扩展现有语义图，而不是另起一个主数据源。

## 二、对 Joern 技术方案中合理部分的判断

以下内容值得吸收。

### 1. 保留 tree-sitter，Joern 只做可选的 C/C++ 深层语义后端

这是正确方向。OpenAnt 是多语言系统，且现有函数 ID、Unit、函数索引、入口检测和源码切片都建立在当前解析结果之上。Joern 即使通过实验，也只能补充 C/C++ 事实，不应接管全部解析。

### 2. Joern 输出必须经过稳定 JSON Contract

正确。OpenAnt 不应让 Python 主流程依赖 Joern 内部节点对象或 Scala 类型。适配层只应输出有限事实，例如：

```json
{
  "schema_version": 1,
  "provider": "joern",
  "repository_commit": "...",
  "methods": [],
  "call_sites": [],
  "method_refs": [],
  "assignments": [],
  "dataflow_paths": [],
  "quality": {}
}
```

### 3. 按仓库和提交缓存 CPG

正确。Joern 的冷启动建图成本远高于 tree-sitter。缓存键至少应包含：

```text
repository commit
Joern 版本
c2cpg 参数哈希
源码范围哈希
查询脚本版本
OpenAnt 事实协议版本
```

只用 `repo + commit` 不够，因为排除规则、前端参数或查询逻辑变化后，旧结果可能已经不兼容。

### 4. OpenHarmony 专用 resolver 必不可少

正确。IPC、HDF、函数表和 callback 是框架关系，不应该期待通用静态分析器自动理解所有工程约定。Joern 可以提供 METHOD_REF、CALL、局部 def-use 和 CFG 等事实，但最终映射仍需要 OpenHarmony resolver。

### 5. LLM 只消费压缩后的证据

正确。LLM 应看到规范化的 caller、callsite、候选目标、赋值链、控制条件和源码行，而不是整个 CPG 或数百行无关源码。

### 6. 先建立小型 ground truth 再扩大范围

正确。没有人工确认的边集，就无法区分“新增了很多边”和“恢复了很多正确边”。

## 三、不能直接吸收或需要修改的部分

### 1. 不接受“跨函数 caller/callee 默认 Joern first”

当前方案把跨函数 caller/callee 简化为 `Joern first`，这不适合 OpenAnt。

原因是：

- 现有原生调用图已经覆盖大多数直接调用；
- 当前函数 ID 是 `相对路径:函数名`，Joern 的 `METHOD_FULL_NAME` 可能包含签名、命名空间、匿名作用域或不完整类型；
- 两套符号系统如果没有严格映射，会让上下游函数重复、错连或成为幽灵节点；
- Joern 不可用时不能导致同一仓库输出完全不同的基本函数集合。

调整为：

```text
Tree-sitter 原生函数与直接边 = 稳定基线
Joern = 可选补充事实
只有成功映射到现有函数 ID 的 Joern 事实才可进入语义图
```

### 2. 不接受“用 Joern 替代部分 RepositoryIndex”作为第一阶段目标

RepositoryIndex 不只是 C++ 符号表，它还是 Stage 2/LLM 工具的统一多语言搜索接口。第一阶段替换它会扩大改动范围，而且不能直接证明缺边问题得到改善。

Joern 方法索引可以作为附加索引，但不能先替换现有索引。

### 3. 不接受“Joern 有 CFG/DDG，所以数据流天然可靠”

Joern 官方文档说明：对于未建模的外部方法，数据流引擎可能保守地在多个参数和返回值之间传播，从而引入额外路径。OpenHarmony 大量调用来自系统 SDK、IPC、HDI/HDF 和外部组件，如果没有自定义语义，`reachableByFlows` 可能召回很多并不精确的路径。

所以：

- source/sink 名称表不等于可靠 taint model；
- 需要为 `MessageParcel::Read*`、常见序列化/转换函数和关键系统 API 建立语义；
- 数据流评估必须与调用边恢复分开验收；
- 第一轮 PoC 不应把 Joern data-flow 直接送入漏洞判定。

### 4. 不接受“模式命中即 confidence = 1.0”的单字段表达

这里混淆了两件事：

- 映射关系是否确实存在；
- 某次运行时是否一定选择该目标。

例如 `ENABLE_SENSOR -> AfeEnableInner` 的表项可以是确定事实，但 `OnRemoteRequest` 每次并不都会执行 `AfeEnableInner`。

建议把一个 `confidence` 拆成：

```json
{
  "resolution_certainty": "exact",
  "runtime_relation": "possible_dispatch",
  "evidence_grade": "assignment_lookup_call_chain"
}
```

数值置信度可以保留用于排序，但不能替代离散证据等级。

### 5. 不接受第一阶段就建立新的权威 augmented_call_graph.json

现有代码已经在内存中完成 native graph 与 semantic overlay 的合并。再持久化一份新的权威增强图会产生三个同步问题：

- 原生图与增强图版本可能不一致；
- downstream 不清楚应该读取哪一份；
- 重新运行 resolver 后容易遗留旧边。

第一阶段只需要：

```text
call_graph.json                 原生基线，保持不变
semantic_facts.*.json           各事实提供者的只读结果
semantic_graph.json             通过验证的统一语义边
call_graph_residuals.json       未解析调用点和拒绝原因
```

Web 需要展示增强图时，可以按需生成派生视图，但不把它当第二个事实源。

### 6. 不接受从 Joern 标准输出中直接抓 JSON

Joern、JVM 和查询脚本都可能在标准输出中混入日志、进度或警告。OpenAnt 已经在其他外部工具调用中遇到过“预期 JSON envelope，但 stdout 混入交互文本”的问题。

建议查询脚本把结果原子写入指定文件，Python 只读取该文件，并验证：

- schema version；
- 完成标记；
- repo commit；
- query script hash；
- 文件大小上限；
- 节点和证据路径类型。

stdout/stderr 只作为运行日志保存。

### 7. 不接受把整个仓库无差别交给 Joern 后直接使用全部结果

OpenAnt 当前会区分 production、test、fuzz、vendor 等源码范围，而 Joern 示例命令直接解析仓库根目录。这样容易把测试 Stub、mock handler 和 fuzz 入口混入候选。

初始 PoC 可以完整建 CPG以保留头文件和类型上下文，但输出适配层必须使用当前 `eligible function IDs` 作为端点白名单。正式实现后再评估：

- 使用 `--exclude/--exclude-regex` 排除测试和生成目录；
- 或保留全量 CPG，但查询和边验证只允许 production 端点；
- 不应把源码扁平化，因为文件路径、include 和类作用域仍然重要。

### 8. 不接受 LLM 自报置信度直接驱动 reachable

LLM 可能稳定地给出高置信度错误答案。进入默认 reachable 的条件应由验证器决定，而不是由模型的 `0.96` 决定。

建议区分两套可达性：

```text
definite_reachable
  原生直接边 + 确定性 resolver 边

possible_reachable
  definite_reachable + 证据受限但仍有歧义的候选边
```

默认漏洞分析优先 definite 集。possible 集可以在显式选项或剩余预算允许时进入分析，且报告必须标记其路径性质。

## 四、建议的新架构

### 1. 总体流程

```text
RepositoryScanner / scope classifier
                |
                v
Tree-sitter native parser
  functions + direct call graph
                |
                +-------------------------------+
                |                               |
                v                               v
Tree-sitter fact provider              optional Joern fact provider
  AST-local facts                       CPG/CFG/def-use facts
                |                               |
                +---------------+---------------+
                                v
                    normalized semantic facts
                                |
                                v
                OpenHarmony deterministic resolvers
          dispatch map / callback / IPC / HDF ops / virtual
                                |
                                v
               endpoint + evidence + scope validator
                                |
                  +-------------+-------------+
                  |                           |
                  v                           v
          accepted semantic edge          residual candidate
                  |                           |
                  v                           v
          semantic_graph.json          optional LLM review
                  |                           |
                  +-------------+-------------+
                                v
                    semantic reachability overlay
                                |
                                v
                  Unit context / analysis / Web
```

### 2. 事实提供者接口

建议先定义稳定、只读的 provider contract，而不是让 resolver 直接依赖 Joern：

```python
class SemanticFactProvider:
    def collect_methods(...): ...
    def collect_call_sites(...): ...
    def collect_method_references(...): ...
    def collect_assignments(...): ...
    def collect_local_flows(...): ...
    def quality_report(...): ...
```

第一版可以有两个实现：

```text
TreeSitterSemanticFactProvider
JoernSemanticFactProvider
```

resolver 只消费统一事实，不知道事实来自哪种工具。这样才能真正进行 A/B 对比，也避免以后被 Joern 的版本和 DSL 锁死。

### 3. Joern 方法到 OpenAnt 函数 ID 的映射

Joern 不能自行创建最终函数端点。建议按以下顺序映射：

1. 规范化仓库相对路径；
2. 使用方法起始行/代码范围与 tree-sitter 函数范围求唯一重叠；
3. 校验限定名或末级方法名；
4. 对重载使用参数数量和签名作附加校验；
5. 只有唯一匹配才返回现有 OpenAnt function ID；
6. 多匹配、零匹配或路径越界全部进入 orphan。

所有被接受的语义边必须满足：

```text
caller in current functions
callee in current functions
caller != callee
caller/callee 位于允许源码范围
证据文件位于仓库内
证据行仍包含相应结构
```

### 4. 语义边类型

第一阶段只建议增加两类确定性边：

```text
native_dispatch_map
hdf_registered_callback
```

后续再考虑：

```text
callback_registration
virtual_dispatch_candidate
factory_implementation
llm_supported_indirect_call
```

当前 `build_semantic_reachability_overlay()` 和 UnitGenerator 的 edge-kind allowlist 只接受 IPC 相关边。正式接入时必须同步扩展两个 allowlist，并为每一类边单独测试，不能只让 Web 看见边而 reachable 不使用，或 reachable 使用了边但 Unit 上下文看不见。

### 5. LLM 的位置

ADR-001 中“LLM 辅助增量 BFS”的思想可以保留，但顺序应调整为：

```text
确定性 resolver 先运行
  -> 对 accepted 边直接扩展 BFS
  -> 对 residual callsite 生成有限候选
  -> LLM 只审核 residual
  -> 验证器再次核对端点和证据
  -> 高证据候选进入 possible overlay
```

LLM 不应重复审核已经由 assignment/lookup/call 链完整证明的 8 条边，否则只会增加成本和不确定性。

## 五、第一轮小规模实验设计

### 1. 实验问题

第一轮只回答以下问题：

1. Joern 能否在当前 macOS ARM 环境稳定为目标源码生成 CPG？
2. Joern 原生能否解析 ADR-001 中缺失的 8 条边？
3. 如果不能，Joern 是否能输出比 tree-sitter 更容易使用的 assignment、method reference 和 local def-use 事实？
4. 使用同一个 resolver 时，Joern facts 相比 tree-sitter facts 是否提高正确边召回？
5. Joern 的额外时间、内存、磁盘和维护成本是否与收益匹配？

第一轮不测试漏洞检测准确率，也不把 Joern data-flow 接进 LLM prompt。调用边价值没有被证明前，不扩大问题范围。

### 2. 实验环境注意事项

当前本机没有发现 Joern 安装，Java 是 OpenJDK 25.0.2。Joern 官方安装文档当前列出的前置条件是 JDK 19，并说明更新 JDK 可能可用但未被充分测试。

因此 PoC 应固定：

- 一个明确的 Joern release 版本；
- 项目内或明确记录路径的 JDK 19；
- macOS ARM 架构和命令；
- Joern、JDK、查询脚本的版本清单；
- 冷启动和缓存命中两种性能数据。

不能因为 JDK 25 恰好能启动，就把它当作可交付环境基线。

### 3. 样本 A：sensors_medical_sensor

仓库提交：

```text
6f87daec8f0a91057336b0b243eee702bd8731e7
```

用途：正向验证 `std::map/unordered_map + 成员函数指针 + iterator`。

人工 ground truth：

```text
MedicalSensorServiceStub::OnRemoteRequest
  -> AfeEnableInner
  -> AfeDisableInner
  -> GetAfeStateInner
  -> RunCommandInner
  -> GetAllSensorsInner
  -> CreateDataChannelInner
  -> DestroyDataChannelInner
  -> AfeSetOptionInner
```

验收要求：8/8，零幽灵端点，每条边都能回指表项赋值和间接调用点。

### 4. 样本 B：systemabilitymgr_samgr

仓库提交：

```text
ab33181bdb13d9e2bd0ee4961dc8315f6ba618bc
```

用途：负向/对照样本。`SystemAbilityLoadCallbackStub::OnRemoteRequest` 使用直接 `switch(code)` 调用 handler，当前 tree-sitter 已经恢复 5 条相关直接边。

实验目标：

- Joern 不应重复创造不同 ID 的同一批函数；
- resolver 不应把直接 switch 调用再次伪装成 indirect 边；
- 合并后边数量应幂等；
- Joern 不可用时原有结果完全保留。

这个仓库用于防止实验只看“多了多少边”，却不检查重复边和错误边。

### 5. 样本 C：drivers_hdf_core 的小模块

仓库提交：

```text
aea1dfcf1fb6fc711abcb4985556e571b4719cf6
```

第一轮不直接分析全部约 1483 个 C/C++ 文件，只选：

```text
framework/sample/platform/uart/src/uart_sample.c
```

用途：验证 C designated initializer、`HdfDriverEntry`、`HDF_INIT` 和 `.Dispatch` 注册关系。

人工确认的关系至少包括：

```text
g_sampleUartDriverEntry.Bind    -> SampleUartDriverBind
g_sampleUartDriverEntry.Init    -> SampleUartDriverInit
g_sampleUartDriverEntry.Release -> SampleUartDriverRelease
uartHost->service.Dispatch      -> SampleDispatch
```

这组样本与 C++ 成员函数表不同，可以判断 provider/resolver 协议是否真的通用，而不只是为一个案例写死。

### 6. 四组对比

| 组别 | 事实来源 | resolver | 目的 |
|---|---|---|---|
| T0 | 当前 tree-sitter | 无新增 | 原生基线 |
| T1 | tree-sitter semantic facts | 同一 resolver | 判断 Joern 是否必要 |
| J0 | Joern 原生 CPG/call graph | 无新增 | 测量 Joern 自身能力 |
| J1 | Joern semantic facts | 同一 resolver | 测量 Joern facts 的增量价值 |

LLM 不进入第一轮。否则无法区分改进来自 Joern、resolver 还是模型猜测。

## 六、实验产物

每个样本、每个 provider 单独保存：

```text
experiment_root/
  manifest.json
  tree_sitter/
    semantic_facts.json
    proposed_edges.json
    residuals.json
    quality.json
  joern/
    cpg_meta.json
    semantic_facts.json
    native_edges.json
    proposed_edges.json
    residuals.json
    quality.json
    stdout.log
    stderr.log
  evaluation.json
  EVALUATION.zh-CN.md
```

`manifest.json` 至少记录：

- 仓库路径和 commit；
- source scope；
- OpenAnt commit；
- Joern/JDK 版本；
- provider/resolver/schema 版本；
- 命令行参数；
- 开始/结束时间；
- 是否命中缓存。

## 七、评价指标

### 1. 函数身份映射

```text
Joern METHOD 映射成功率
唯一映射率
歧义映射数
越界/测试目录端点数
```

最终接受边的端点映射必须 100% 成功，不能用模糊匹配强行补齐。

### 2. 调用边质量

```text
precision = 正确新增边 / 所有新增边
recall    = 正确新增边 / ground-truth 缺失边
duplicate native edges
phantom endpoints
self edges
```

### 3. 证据质量

每条边检查：

- 是否有表项/注册赋值证据；
- 是否有 lookup/value extraction 证据；
- 是否有间接调用点证据；
- 文件和行是否能重新读取；
- selector、table、receiver/class 是否一致。

### 4. 对现有管线的影响

```text
native reachable units
semantic reachable added
错误新增 reachable units
Unit context 新增函数数
context 代码体积变化
```

### 5. 工程成本

```text
冷建 CPG 时间
峰值内存
CPG 磁盘体积
缓存查询时间
查询脚本失败率
超时和降级是否可靠
```

## 八、决策门槛

### Gate 1：环境可用

三个样本均能在固定 Joern/JDK 版本下重复构建；失败时有结构化错误，不影响当前 parser。

### Gate 2：具体案例正确

`sensors_medical_sensor` 必须恢复 8/8；samgr 不得产生重复或错误边；HDF 小样本必须恢复已确认注册目标。

### Gate 3：Joern 有独立增量价值

至少满足一项：

- J1 比 T1 多恢复了人工确认的正确关系；
- Joern 提供了 tree-sitter 当前难以稳定获得的跨函数 def-use/alias 证据；
- Joern CFG/data-flow 在后续独立实验中显著改善 guard/path 判断。

如果 T1 与 J1 在调用边上等价，则当前调用边恢复优先采用更轻的 tree-sitter provider；Joern 只保留为后续 data-flow 实验候选。

### Gate 4：可安全接入

- 原生 `call_graph.json` 不变；
- 所有 accepted target 都是现有 function ID；
- semantic overlay 只增不减；
- Joern 缺失、超时或损坏时静态扫描仍成功；
- 不把 tests/fuzz/vendor 端点混入 production reachable。

未同时通过 Gate 1、2、3、4，不进入正式实现。

## 九、建议实施顺序

### P0：环境和原生能力手工验证

- 安装固定 Joern + JDK 19；
- 对三个小样本建 CPG；
- 手工查询 METHOD、CALL、METHOD_REF、assignment 和 local flow；
- 记录 Joern 原生是否恢复目标，而不是先写 OpenAnt 集成代码。

### P1：只读事实导出

- 编写最小 Joern 查询脚本；
- 输出稳定 JSON 文件；
- 不修改 `call_graph.json`、dataset 或 reachable；
- 同时输出等价的 tree-sitter semantic facts。

### P2：离线统一 resolver 和 evaluator

- 同一个 resolver 分别消费 T1/J1；
- 生成 proposed edges 和 residuals；
- 与人工 ground truth 对比；
- 得出是否值得集成的结论。

### P3：通过门槛后才接入 SemanticGraph

- 增加新 edge kind；
- 扩展 reachability 和 Unit context allowlist；
- 加入端点/证据/scope 验证；
- 仍保持 opt-in 和安全降级。

### P4：最后才评估 LLM 残余恢复

- LLM 只处理 deterministic resolver 无法决定的调用点；
- 使用有限候选和工具查询；
- possible edge 与 definite edge 分层；
- 单独统计模型成本、稳定性和误边。

## 十、主要风险与对策

| 风险 | 后果 | 对策 |
|---|---|---|
| Joern fullName 与现有函数 ID 不一致 | 重复或幽灵函数 | 以现有 ID 为唯一端点，唯一映射失败即 orphan |
| 缺少 include/宏/build flags | 类型和调用解析质量下降 | 保存质量指标，以 ground truth 而非“CPG 构建成功”验收 |
| 外部 API 缺少 data-flow semantics | 污染 source-to-sink | 数据流单独评测，增加 OpenHarmony 自定义语义 |
| CPG 冷启动成本高 | Web 扫描等待过长 | 按 repo@commit 缓存，Joern 阶段可选、可超时 |
| stdout 混入日志 | JSON 解析失败 | JSON 原子写文件，日志独立保存 |
| 全仓 tests/fuzz 混入 | reachable 和候选膨胀 | 端点白名单 + source scope 验证 |
| LLM 扩边失控 | 成本和误报增加 | 只处理 residual，有限候选，possible 图分层 |
| Joern 版本变化 | 查询脚本失效 | 固定版本并把脚本哈希放入缓存键 |
| 工具链交付体积增加 | 项目难以打包 | PoC 后再决定项目内工具链、下载器或外部依赖形式 |

## 十一、最终建议

针对 ADR-001 的近期工作，我建议优先级是：

```text
第一优先：建立 unresolved callsite / semantic fact 诊断产物
第二优先：用现有 tree-sitter facts 恢复简单确定性分发表
并行实验：用 Joern 对相同样本导出 facts，验证是否有独立增益
通过门槛后：Joern 作为可选 provider 接入现有 SemanticGraph
最后：LLM 审核确定性工具仍无法解决的 residual
```

这比“先引入 Joern，再围绕 Joern 重构”更符合 OpenAnt 当前状态，因为：

- 缺边问题已有精确案例；
- 现有语义图和单调 overlay 已经可复用；
- tree-sitter 对该案例的语法事实并不缺失；
- Joern 的真实增益需要数据证明；
- 后续仍可把 Joern 的 CFG/data-flow 能力用于 Unit 上下文和漏洞路径判断，但那应是独立决策。

## 十二、官方资料核对

截至本文日期，Joern 官方资料支持以下有限结论：

- Joern 官方将 C/C++ 前端列为较高成熟度，并说明其 CPG 可组合 AST、控制流和数据流；
- `c2cpg` 对应 `--language C`；
- `reachableBy`/`reachableByFlows` 可用于数据流来源和路径查询；
- 外部方法缺少自定义语义时，数据流分析可能产生额外、不精确的传播；
- 官方安装文档列出 JDK 19，并提示大型代码库需要显式配置 JVM 内存。

参考：

1. https://docs.joern.io/
2. https://docs.joern.io/frontends/
3. https://docs.joern.io/installation/
4. https://docs.joern.io/cpgql/data-flow-steps/
5. https://docs.joern.io/dataflow-semantics/
6. https://docs.joern.io/cpgql/control-flow-steps/

这些资料只能证明 Joern“具备相应机制”，不能证明它对当前 OpenHarmony 仓库和具体函数指针模式一定有效；后者必须由上述 PoC 证明。
