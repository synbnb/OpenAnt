# VulnFounder 面向 OpenHarmony 的完整目标态扫描流程指南

> 文档性质：本文描述 VulnFounder 面向 OpenHarmony 源码扫描和开发板验证的完整目标架构，用现在时连贯说明最终产品流程，适合方案汇报、架构讲解和后续实施对照。本文不是当前代码版本的功能验收证明；具体功能是否已经可运行，应以对应代码、阶段测试记录和真实设备测试结果为准。

本文把以下内容合并为一条完整链路：

- OpenHarmony 仓库选择和平台识别；
- C/C++、IDL、SA、NAPI、HDF/HDI 等源码解析；
- native 调用图和 OpenHarmony semantic graph；
- LLM 辅助的间接调用边恢复；
- 入口点、可达性和 Unit 上下文；
- 应用上下文、Stage 1 和 Stage 2；
- `pipeline_output.json`；
- Docker 通用动态测试；
- OpenHarmony 开发板动态验证；
- 中英文报告、Web 可视化和历史扫描管理。

相关设计依据：

- [`VULNFOUNDER_COMPLETE_PIPELINE_GUIDE_OH17A.zh-CN.md`](VULNFOUNDER_COMPLETE_PIPELINE_GUIDE_OH17A.zh-CN.md)
- [`VULNFOUNDER_COMPLETE_PIPELINE_GUIDE.zh-CN.md`](VULNFOUNDER_COMPLETE_PIPELINE_GUIDE.zh-CN.md)
- [`ADR-001-OPENHARMONY-LLM-CALL-GRAPH-RECOVERY.zh-CN.md`](ADR-001-OPENHARMONY-LLM-CALL-GRAPH-RECOVERY.zh-CN.md)
- [`ADR-002-OPENHARMONY-DEVICE-DYNAMIC-VERIFICATION.zh-CN.md`](ADR-002-OPENHARMONY-DEVICE-DYNAMIC-VERIFICATION.zh-CN.md)

## 1. 一句话总览

```text
OpenHarmony 仓库或本地源码目录
  → 项目初始化、配置和模型检查
  → 平台识别、语言检测和源码范围确定
  → C/C++、IDL、SA、NAPI、HDF/HDI 解析
  → native 函数索引和确定性调用图
  → OpenHarmony IPC semantic graph
  → LLM 辅助恢复间接调用边
  → OpenHarmony 原生入口识别
  → reachable 传播和 Unit 上下文构建
  → PlatformPromptContext 和应用威胁模型
  → Agent 上下文增强
  → Stage 1 漏洞检测
  → Stage 2 攻击路径验证
  → pipeline_output.json
  → Docker 通用动态测试 / OpenHarmony 开发板动态验证
  → 证据关联和漏洞结论分级
  → 中英文摘要、HTML 报告和 Web 可视化
  → scan.report.json 和完整历史产物
```

这条流水线解决三个不同问题：

1. **源码结构问题**：代码里有哪些函数、谁调用谁、哪里接收外部输入。
2. **安全判断问题**：外部输入能否到达危险操作，权限和校验是否足够。
3. **真实验证问题**：候选问题能否在对应 OpenHarmony 开发板和调用者身份下复现。

## 2. 给第一次接触 OpenHarmony 的读者讲人话

### 2.1 常用术语

| 术语 | 小白解释 | 在流程中的作用 |
|---|---|---|
| OpenHarmony 组件 | 操作系统源码中的一个功能模块，例如窗口、音频或传感器 | 扫描和报告的基本仓库单位 |
| HDC | OpenHarmony 设备连接工具，类似设备调试桥 | 与开发板交互、安装 HAP、传文件和采日志 |
| HAP | OpenHarmony 应用安装包 | 从普通应用身份发起真实调用 |
| SA | System Ability，系统级服务能力，通常有数字 ID | 定位系统服务和 IPC 目标 |
| IPC | 两个进程之间发送请求和响应 | OpenHarmony 系统服务最重要的外部输入边界之一 |
| Proxy | 客户端代理，把本地函数调用打包成远程请求 | 识别 transaction code 和 Parcel 写入顺序 |
| Stub | 服务端接收对象，读取请求并分发 | 常见入口是 `OnRemoteRequest` |
| handler | 真正处理某个业务请求的函数 | 漏洞分析和动态验证的目标函数 |
| MessageParcel | IPC 参数的“快递箱” | 保存跨进程传入的字符串、整数和对象 |
| IDL | 跨进程接口说明书 | 定义接口、方法、参数和 transaction |
| NAPI | ArkTS/JavaScript 调用 C/C++ 的桥梁 | 识别普通 HAP 可进入的 native API |
| HDF/HDI | OpenHarmony 驱动框架和硬件接口 | 识别来自设备、HAL 或驱动的输入 |
| `bundle.json` | 组件身份证 | 提供组件名、子系统、依赖和构建入口 |
| `BUILD.gn` | 编译目标清单 | 说明源码属于哪个库、进程或测试目标 |
| SA profile | SA 的注册信息 | 提供 SA ID、进程名和动态库等证据 |
| Tree-sitter | 源码语法解析器 | 抽取函数、参数、调用表达式和代码位置 |
| call graph | 函数“谁调用谁”的关系图 | 构建上下文和计算可达性 |
| semantic graph | IDL、transaction、Stub、Proxy、handler 等语义关系图 | 补足普通函数调用图无法表达的系统语义 |
| Unit | 交给大模型分析的一个函数包 | 包含主函数和有限的上下游上下文 |
| guard | 权限、接口 token、UID、参数校验等防护信号 | 帮助模型理解防护，但不自动证明安全 |
| sink | 文件、命令、内存、权限或敏感系统操作 | 判断外部输入最终造成什么影响 |

### 2.2 一次 IPC 请求如何流动

可以把 IPC 想成跨进程寄快递：

```text
应用或客户端
  → Proxy：把参数写入 MessageParcel
  → SendRequest：发送 transaction code
  → OpenHarmony IPC 驱动
  → Stub::OnRemoteRequest：验证 token 并读取 code
  → handler：读取参数、检查权限、执行业务
  → reply：把结果返回客户端
```

VulnFounder 需要同时回答：

- 请求从哪里进入；
- transaction code 对应哪个 handler；
- Parcel 中哪些字段由外部控制；
- 权限检查发生在数据流的什么位置；
- handler 后续调用了哪些敏感函数；
- 真实设备上的普通 HAP 是否能到达这条路径。

## 3. 输入、项目和配置

### 3.1 源码输入

核心输入是：

```text
repo_path
```

它可以来自：

- `source_code_base/<项目名>` 下的本地仓库；
- 用户指定的任意本地仓库路径；
- 远程 Git URL，由 Go CLI clone 后转换为本地路径；
- 用户上传并安全解压后的源码目录。

项目元数据保存在项目目录中，扫描产物保存在每次独立 scan 目录中。源码库、VulnFounder 代码和扫描结果物理上可随项目一起打包，但 API 密钥、签名私钥和设备隐私数据不进入仓库。

### 3.2 主要扫描参数

```text
--platform openharmony
--language auto|c|cpp|...
--level all|reachable|codeql|exploitable
--verify
--llm-reachability
--library-mode
--workers N
--limit N
--llm-config NAME
--skip-dynamic-test
```

OpenHarmony 开发板验证使用独立参数：

```text
--device <serial>
--candidate <candidate-id>
--identity normal_hap|debug_hap|native_privileged
--risk readonly|benign|boundary
```

指定 `--platform openharmony` 只改变平台解析和 Prompt 上下文，不自动操作开发板。

### 3.3 配置加载

Go CLI 和 Python 核心共享项目内模型配置：

```text
config/vulnfounder/config.json
config/models.json
config/languages.json
```

扫描启动时会：

1. 解析项目和输出目录；
2. 加载模型 provider、模型 ID 和价格；
3. 为各 LLM 阶段建立 `PhaseRegistry`；
4. 检查所需 API 凭据；
5. 初始化 token、费用和耗时追踪；
6. 为每个阶段准备 checkpoint 和 step report。

## 4. 平台识别和 OpenHarmony 源码范围

### 4.1 平台选择

平台可以显式指定，也可以通过仓库证据自动识别。OpenHarmony 证据包括：

- `bundle.json`；
- `BUILD.gn` 和 OpenHarmony GN 模板；
- SA profile；
- `MessageParcel`、`IRemoteBroker`、`IPCObjectStub`；
- NAPI module；
- HDF/HDI 文件；
- OpenHarmony 目录约定和组件元数据。

识别结果写入：

```text
platform_profile.json
```

### 4.2 `bundle.json` 的作用

`bundle.json` 用来识别：

- component；
- subsystem；
- 适配的系统类型；
- 组件依赖；
- build target；
- inner kit；
- service group；
- test/fuzz target。

它不会取代 C/C++ 文件解析，也不会单独决定入口。它只是告诉 VulnFounder “这份源码属于什么组件、会被编译成什么”。

### 4.3 `BUILD.gn` 的作用

`BUILD.gn` 提供：

- source 到 target 的映射；
- target 是 executable、shared library、static library 还是 fuzztest；
- external dependencies；
- include path；
- 输出镜像和 subsystem；
- 某段源码是否进入生产构建。

这一步可以避免把测试代码、示例代码或只存在于库中的 callback 误认为独立系统服务进程。

### 4.4 文件角色

每个文件被标记为：

```text
production
test
fuzz
example
generated
third_party
unknown
```

默认安全扫描保留 production；test 和 fuzz 作为入口、协议和动态 harness 证据使用，但不会与生产漏洞结论混写。

## 5. 多语言检测和源码解析

### 5.1 语言检测

VulnFounder 遍历受支持源码文件，按文件数量和占比选择语言。`auto` 模式可以并行解析多个达到阈值的语言，避免只扫描主语言而漏掉 NAPI、ArkTS 或辅助脚本。

### 5.2 C/C++ Tree-sitter 解析

Tree-sitter 抽取：

- 函数和方法名称；
- class/namespace；
- 参数和返回值；
- 起止行号；
- 完整函数体；
- include；
- prototype；
- macro 和 alias；
- call expression；
- exported/static/inline 等元数据。

函数使用稳定 ID：

```text
<repo-relative-file>:<qualified-function-name>
```

例如：

```text
services/medical_sensor/src/medical_service_stub.cpp:
MedicalSensorServiceStub::OnRemoteRequest
```

### 5.3 IDL 解析

IDL parser 抽取：

- interface；
- method；
- 参数；
- 返回类型；
- `[ipccode N]`；
- namespace；
- 继承关系。

生成节点：

```text
idl:interface:<qualified-interface>
idl:transaction:<qualified-interface>:<method>
```

### 5.4 SA profile 解析

SA profile 提取：

```text
SA ID
process
libpath
run-on-create
distributed
dump-level
```

SA profile 与 bundle、GN target 和 native class 联合使用，不能只凭相似名字强行绑定。

### 5.5 NAPI 解析

NAPI parser 识别：

- `DECLARE_NAPI_FUNCTION`；
- `napi_define_properties`；
- `napi_module`；
- module name；
- ArkTS/JS 参数读取；
- Native client 调用。

这些函数是普通 HAP 进入 Native 层的重要入口。

### 5.6 HDF/HDI 解析

HDF/HDI parser 识别：

- driver entry；
- HDI interface；
- generated proxy/stub；
- service registration；
- device node；
- callback；
- HCS 或相关配置证据。

HDF 文件级注册只表示驱动或服务加载点；只有存在明确外部数据入口时，才作为漏洞分析入口。

## 6. native 函数索引和确定性调用图

### 6.1 函数索引

解析完成后生成：

```text
analyzer_output.json
```

它相当于仓库函数数据库，保存函数源码、位置、签名和平台证据。

### 6.2 正向和反向调用图

```text
call_graph[caller] = [callee...]
reverse_call_graph[callee] = [caller...]
```

调用目标解析综合使用：

- 同文件候选；
- class owner；
- namespace；
- receiver type；
- prototype；
- include；
- 继承关系；
- overload 参数数量；
- 仓库唯一性。

结果写入：

```text
call_graph.json
```

### 6.3 为什么确定性图仍然可能漏边

常见漏边来源：

- 函数指针；
- virtual dispatch；
- callback 注册；
- lambda/FFRT task；
- 宏分发表；
- transaction table；
- generated wrapper；
- 跨仓库动态库调用；
- runtime service lookup。

确定性调用图继续作为高置信基础图，不会因为 LLM 推测而被覆盖或删边。

## 7. OpenHarmony semantic graph

普通调用图只描述“函数调用函数”。semantic graph 还描述：

```text
component → build target
SA profile → process/library
IDL interface → transaction
Proxy function → transaction
Stub::OnRemoteRequest → transaction
transaction → handler
NAPI API → native function
HDF service → HDI method
```

### 7.1 IPC resolver

resolver 联合读取：

- IDL；
- function index；
- native call graph；
- Stub/Proxy 源码；
- transaction code；
- class owner 和 method variant。

方法变体包括：

```text
Method
HandleMethod
MethodInner
HandleMethodInner
MethodImpl
HandleMethodImpl
```

### 7.2 `transaction → handler`

从 `OnRemoteRequest` 沿 native 调用图执行有界 BFS：

```text
depth 0: OnRemoteRequest
depth 1: OnRemoteRequestInner / direct handler
depth 2: wrapper / handler
depth 3: final handler
```

候选同时满足 transaction/method 名称、owner/variant 和调用路径证据后，写入：

```text
transaction_to_handler
```

无法确认时写入：

```text
unresolved_ipc_handler
ambiguous_ipc_handler
```

orphan 是待核对关系，不是漏洞。

### 7.3 数字 transaction code

数字 code 从以下来源解析：

- IDL `[ipccode N]`；
- enum；
- `static constexpr`；
- generated header；
- Proxy `SendRequest(code, ...)`；
- Stub `switch (code)` 或 dispatch table。

最终语义节点同时保存方法名和数字 code，使动态 IPC adapter 能按真实协议构造请求。

## 8. LLM 辅助的调用图恢复

确定性调用图完成后，VulnFounder 生成未解析调用点清单：

```text
caller
call expression
source location
receiver/type hints
argument count
附近代码
候选函数索引
```

### 8.1 候选搜索

程序先确定性搜索有限候选：

- 同文件；
- 同 class；
- 同 namespace；
- 签名兼容；
- 相同 receiver type；
- callback 注册记录；
- dispatch table；
- semantic graph 相邻节点。

LLM 不自由搜索整个仓库，只在受约束候选集中判断。

### 8.2 LLM 边审核

模型输出：

```json
{
  "caller_id": "...",
  "callsite": "...",
  "selected_callees": ["..."],
  "edge_kind": "virtual_dispatch|callback|function_pointer|semantic_dispatch",
  "confidence": 0.93,
  "reasoning": "...",
  "source_evidence": []
}
```

输出经过函数 ID、签名、源文件和候选集合校验。不在候选集合中的函数不会加入图。

### 8.3 单调扩展

VulnFounder 保存三类边：

```text
native_confirmed_edges
semantic_confirmed_edges
llm_suggested_edges
```

LLM 只补充新边，不删除原确定性边。所有 LLM 边带有证据、置信度和来源，分析结果可以区分确定路径和可能路径。

### 8.4 入口驱动的增量 BFS

补边从真实入口和高价值候选开始：

```text
入口集合
  → BFS 访问当前可达函数
  → 发现未解析调用点
  → 搜索候选并请求 LLM 审核
  → 加入通过校验的增量边
  → 继续 BFS
  → 达到深度、边数、token 或时间预算后停止
```

这样只修复会影响入口可达性和漏洞上下文的漏边，不让模型扫描所有无关函数。

## 9. OpenHarmony 原生入口识别

入口表示外部进程、应用、设备或系统事件可以进入代码的位置。

### 9.1 IPC 入口

- `OnRemoteRequest`；
- Stub dispatch table；
- IDL method；
- callback Stub；
- DBinder/分布式请求入口。

### 9.2 HAP 和 NAPI 入口

- Ability 生命周期；
- exported Ability；
- NAPI 导出函数；
- JS/ArkTS callback；
- Want、URI、Bundle 等参数入口。

### 9.3 SA 入口

- SA 注册；
- `OnStart`、`OnStop`；
- `OnAddSystemAbility`、`OnRemoveSystemAbility`；
- dump；
- SA 事件和监听器。

生命周期函数只有在接收外部事件或进一步调用输入处理函数时才扩展为安全入口。

### 9.4 HDF/HDI 入口

- HDI IPC method；
- driver dispatch；
- device data callback；
- hardware event；
- device node read/write/ioctl。

### 9.5 异步入口

- FFRT task；
- EventHandler；
- timer；
- listener；
- observer；
- lambda callback；
- common event subscriber。

异步入口通过 semantic edge 保留“由谁注册、由什么事件触发”的信息。

## 10. reachable 过滤和 library mode

### 10.1 默认 reachable

从入口种子沿以下边传播：

```text
native confirmed edge
semantic confirmed edge
经过阈值和预算校验的 LLM edge
```

传播结果写入：

```text
reachable
is_entry_point
entry_point_reason
entry_point_path
```

semantic graph 的加入采用单调扩展：它能增加已证实的 OpenHarmony 跨层关系，不会删除原 native 可达节点。

### 10.2 无入口保护

如果没有识别到可信入口，VulnFounder 不把 dataset 清空，而是：

- 保留全部单元；
- 写入入口识别警告；
- 在报告中说明 reachable 结果不可作为完整裁剪依据。

### 10.3 library mode

库型仓库没有独立服务进程或 main，外部调用从导出 API 进入。`--library-mode` 把公开导出 API 作为入口种子，但不会把“库函数可调用”自动等同于“普通 HAP 可调用”。

## 11. Unit 和完整上下文

### 11.1 Unit 组成

```text
主目标函数
  + native caller/callee
  + semantic context functions
  + entry path
  + platform context
  + guard signals
  + source/target evidence
```

依赖深度有明确上限，并使用 `visited` 防止循环。

### 11.2 `context_functions`

`context_functions` 包含：

- Stub 对应 handler；
- transaction 上下游；
- Proxy；
- 权限 helper；
- 关键 sink helper；
- 异步 callback；
- LLM 补边到达且通过校验的函数。

每个 context function 保存：

```text
function ID
edge kinds
distance
confidence
evidence source
```

它帮助模型理解数据流，不把上下文函数自动变成独立漏洞结论。

### 11.3 guard signals

guard signals 包括：

- interface token；
- permission check；
- UID/PID/token 校验；
- SELinux/DAC 边界；
- 参数类型和范围校验；
- 路径规范化；
- 状态机检查；
- rate limit；
- object ownership。

规则匹配只提供候选信号。Prompt 明确告诉模型：guard 列表可能不完整，必须继续阅读源码确认，不能因为列表为空就断言没有保护，也不能因为命中一个 guard 就断言安全。

## 12. PlatformPromptContext

每次 LLM 调用统一获得平台上下文：

```json
{
  "platform": "openharmony",
  "component": ["medical_sensor"],
  "subsystem": "sensors",
  "source_role": "production",
  "targets": ["libmedical_service"],
  "boundaries": ["binder_ipc", "napi"],
  "entry_point": {
    "is_entry_point": true,
    "reason": "platform:openharmony:binder_ipc"
  },
  "guards": [
    {"kind": "interface_token", "matched": "ReadInterfaceToken"}
  ],
  "semantic_context": [],
  "evidence": []
}
```

这个对象统一进入：

- app context；
- LLM reachability；
- Agent enhancer；
- Stage 1；
- Stage 2；
- 报告；
- 动态候选规划。

它解决“每个 Prompt 各自猜平台”的问题，同时保持字段可追踪。

## 13. 应用上下文和威胁模型

应用上下文回答：

```text
组件是什么
运行在什么身份和进程
攻击者是谁
公开边界是什么
需要保护的资产是什么
哪些操作属于预期功能
什么结果才算越权或漏洞
```

### 13.1 仓库提供威胁模型

优先读取：

```text
VULNFOUNDER.THREATMODEL.md（兼容读取 OPENANT.THREATMODEL.md）
```

解析后记录来源、SHA-256 和 schema 警告。

### 13.2 LLM 生成上下文

没有威胁模型时，LLM 读取：

- README、SECURITY、AGENTS、CLAUDE；
- bundle、GN、SA profile；
- 目录结构；
- 平台入口摘要；
- 组件依赖；
- public API/NAPI/IPC 证据。

输出经过结构校验，写入：

```text
application_context.json
```

## 14. LLM reachable 复核

`--llm-reachability` 按批次复核入口和外部输入位置。它的作用是发现规则漏掉的入口，不负责修复完整调用图。

它与调用图恢复的分工：

```text
LLM reachability：这个函数像不像入口或外部输入位置
LLM call graph recovery：这个调用点实际可能调用哪个函数
```

复核结果只能补充信号，不能删除确定性入口和确定性调用边。

## 15. Agent 上下文增强

增强 Agent 围绕一个 Unit 使用受限工具：

| 工具 | 作用 |
|---|---|
| `get_static_dependencies` | 查看 caller、callee 和 semantic edge |
| `search_definitions` | 搜索函数、类和常量定义 |
| `search_usages` | 搜索调用位置 |
| `read_function` | 读取函数源码 |
| `list_functions` | 列出文件函数 |
| `read_file_section` | 读取指定范围 |
| `get_platform_context` | 查看 OpenHarmony 平台证据 |
| `finish` | 返回结构化增强结果 |

Agent 的典型流程：

```text
读取主函数
  → 看入口路径和 transaction
  → 搜索 Proxy/Stub/handler
  → 补读权限和 sink
  → 检查异步 callback
  → 描述外部输入到危险操作的数据流
  → 输出 agent_context
```

结果写入：

```text
dataset_enhanced.json
enhance_checkpoints/
enhance.report.json
```

## 16. Stage 1：漏洞检测

Stage 1 对每个 Unit 判断：

- 外部输入来自哪里；
- 攻击者身份是什么；
- 数据如何跨 IPC/NAPI/HDF 边界；
- guard 是否正确、完整且位于正确位置；
- 数据是否到达 sink；
- 是否存在越权、内存安全、路径、命令、反序列化或逻辑问题；
- 漏洞归属哪个主函数；
- 需要什么动态验证条件。

Prompt 输入包括：

```text
主函数
native 和 semantic context_functions
入口路径
PlatformPromptContext
应用上下文
Agent 上下文
规则库安全知识
```

输出状态：

```text
vulnerable
bypassable
inconclusive
protected
safe
error
```

结果写入：

```text
results.json
analyze_checkpoints/
analyze.report.json
```

## 17. Stage 2：攻击路径验证

Stage 2 只处理 Stage 1 高价值候选。Verifier 站在攻击者角度重新检查：

```text
真实入口是否存在
普通应用或指定身份是否可到达
输入控制程度
完整调用路径
权限检查能否绕过
sink 是否真的执行
路径在哪一步断裂
源码和上下文是否足以形成结论
```

输出包含：

```text
agree
entry_point
exploit_path
data_flow
sink_reached
attacker_control_at_sink
path_broken_at
verification_explanation
dynamic_requirements
```

状态规则：

```text
明确同意且路径完整     → confirmed
同意但路径证据仍有限   → agreed
验证未完成或工具错误   → unverified / needs_review
明确证明不可达或被保护 → rejected
```

不完整验证不会自动当作安全。

## 18. 构建统一的 `pipeline_output.json`

这是确定性转换步骤，不调用 LLM。

主要输入：

```text
results_verified.json（优先）
results.json（回退）
application_context.json
各 step report
仓库和平台元数据
```

每个 finding 保存：

```json
{
  "id": "VULN-001",
  "unit_id": "path/file.cpp:Class::Function",
  "location": {
    "file": "path/file.cpp",
    "function": "Class::Function",
    "start_line": 32
  },
  "entry_path": [],
  "platform_context": {},
  "cwe_id": 862,
  "stage1_verdict": "vulnerable",
  "stage2_verdict": "confirmed",
  "description": "...",
  "vulnerable_code": "...",
  "impact": "...",
  "steps_to_reproduce": "...",
  "dynamic_requirements": {}
}
```

它是静态分析、动态测试、报告和 Web 之间的统一桥梁。

## 19. 动态测试双后端

VulnFounder 将动态测试拆成两个后端：

```text
Dynamic Backend A：Docker 通用复现
Dynamic Backend B：OpenHarmony 开发板验证
```

两个后端共享 finding、成本统计、checkpoint 和报告接口，但执行环境、身份模型和证据等级独立。

### 19.1 Docker 通用复现

适用于 Python、JavaScript、Go 等可以在容器中构建最小环境的漏洞。

```text
finding
  → LLM 生成 Dockerfile/test script
  → schema 校验
  → 隔离 build/run
  → 结构化 stdout
  → 动态结果
```

容器采用：

- 无外部网络或内部测试网络；
- 只读根文件系统；
- `cap-drop ALL`；
- `no-new-privileges`；
- CPU、内存、PID 和超时限制；
- Docker Compose allowlist；
- 无主机 bind mount。

### 19.2 OpenHarmony 开发板验证

适用于 C/C++、NAPI、SA、IPC、HDF/HDI 和真实系统权限边界。

```text
finding/unit
  → DynamicCandidate
  → candidate_plan.json
  → HDC 设备预检
  → baseline
  → HAP/Native/IPC/HDF adapter
  → 单次触发
  → 响应、PID、HiLog、faultlog、SELinux 前后关联
  → 证据分级
  → cleanup
```

开发板验证不会由普通 scan 自动启动，必须显式选择设备、candidate、调用身份和风险等级。

## 20. OpenHarmony DynamicCandidate

候选编译器联合读取：

```text
pipeline_output.json
dataset_enhanced.json
call_graph.json
semantic_graph.json
platform_profile.json
bundle.json / BUILD.gn / IDL / SA profile
```

生成：

```json
{
  "candidate_id": "OH-CAND-001",
  "finding_ids": ["VULN-001"],
  "unit_id": "path/file.cpp:Class::Function",
  "entry": {
    "kind": "binder_ipc_stub",
    "file": "path/file.cpp",
    "function": "Class::Function"
  },
  "target": {
    "component": "samgr",
    "build_target": "samgr_proxy",
    "process": null,
    "sa_id": null
  },
  "adapter": "ipc_proxy",
  "allowed_identities": ["normal_hap", "debug_hap", "native_privileged"],
  "input_contract": {},
  "risk_tier": "benign",
  "limitations": []
}
```

候选状态包括：

```text
ELIGIBLE
REQUIRES_HAP
REQUIRES_NATIVE_ARTIFACT
REQUIRES_PROTOCOL_REVIEW
PERMISSION_EXPECTED
SOURCE_FIRMWARE_MISMATCH
UNSUPPORTED
NEEDS_HUMAN_APPROVAL
```

## 21. HDC 设备会话

HDC 在 macOS 主机运行，所有命令强制使用：

```text
hdc -t <device-serial> ...
```

统一 HDC client 提供：

- 明确设备选择；
- 单设备独占锁；
- 参数数组和命令 allowlist；
- Python 层超时；
- 进程组回收；
- stdout、stderr、exit code 和耗时记录；
- 设备断开检测；
- 敏感输出脱敏；
- `commands.jsonl` 审计日志。

### 21.1 设备预检

采集：

```text
HDC 版本和 server 状态
设备序列号 hash
API 和 build fingerprint
产品型号
CPU 架构
内核
shell UID/GID/domain
SELinux
磁盘
目标进程和 socket
hilog/hidumper/ss/dmesg/bm/aa 能力
```

### 21.2 安全边界

默认不执行：

- `smode`；
- 关闭 SELinux；
- 挂载 system/vendor 可写；
- 修改系统分区；
- 重启开发板；
- kill 关键系统服务；
- 删除整个 `/data/local/tmp`。

## 22. 开发板触发适配器

### 22.1 HAP NAPI Adapter

```text
NAPI 导出函数
  → 最小 HAP harness
  → 构建和签名
  → 安装和启动
  → normal/debug 身份记录
  → 合法 API 调用
  → 边界参数
  → force-stop 和卸载
```

### 22.2 IPC/SA Adapter

优先使用：

1. 源码已有 Proxy；
2. IDL 生成 client；
3. 仓库已有测试 client；
4. Stub/Proxy 共同验证的 MessageParcel schema。

请求记录：

```text
SA ID
interface token
transaction code
Parcel 字段顺序
调用者身份
返回码
reply 内容
目标进程
```

### 22.3 Native UNIX Socket Adapter

只有 socket、服务端、协议 framing、目标进程和合法 baseline 均确认时才执行。默认不运行随机或无限 fuzz。

### 22.4 HDF/HDI Adapter

使用生成的 HDI client、已有测试工具或明确的 device protocol；文件级注册和设备节点权限只作为候选证据。

### 22.5 SA 生命周期和 Dump Adapter

用于确认 SA 是否注册、服务是否加载、dump 是否可达。生命周期函数不会因为名字是 `OnStart` 或 `OnDump` 就自动判定为攻击面。

## 23. Payload 和 artifact

### 23.1 Payload 顺序

```text
合法最小请求
  → 合法重复
  → 可选字段缺失
  → 类型边界
  → 小规模长度边界
  → 获得批准后的协议感知变异
```

每个 payload 保存语义、长度、SHA-256、seed、生成规则和预期结果。

### 23.2 Native artifact

记录：

- OpenHarmony SDK；
- compiler；
- target triple；
- sysroot；
- 架构和 ELF interpreter；
- 动态依赖；
- SHA-256；
- 构建日志。

### 23.3 HAP artifact

记录：

- bundle/ability；
- API/compatible version；
- 权限；
- debug/release；
- 证书公开摘要；
- HAP SHA-256；
- 签名验证结果。

签名私钥和密码不进入项目仓库、报告或 Docker 镜像。

## 24. 观察、关联和证据判定

### 24.1 前后快照

每次 attempt 采集：

```text
before：PID、进程启动时间、socket、faultlog index、SELinux、资源
trigger：request、response、exit code、timeout、errno
after：PID、服务健康、HiLog、dmesg、新 faultlog、资源
```

### 24.2 Run Marker

每次运行生成唯一 `run_id`。HAP 和 Native harness 在自己的日志中写入 marker。无法写 marker 的系统日志使用设备时间校准和前后增量关联。

### 24.3 结论状态

```text
REPRODUCED_NORMAL_APP
REPRODUCED_DEBUG_HAP
REPRODUCED_NATIVE_PRIVILEGED
SERVICE_FAULT_CORRELATED
PERMISSION_BLOCKED
NOT_REPRODUCED
INCONCLUSIVE
INFRA_ERROR
SOURCE_FIRMWARE_MISMATCH
UNSUPPORTED_TRANSPORT
```

高权限 Native 能复现只证明高权限条件下存在行为，不自动证明普通 HAP 可利用。

### 24.4 证据等级

| 等级 | 含义 |
|---|---|
| A | 普通/release-like HAP 可达，安全影响明确且重复成功 |
| B | debug HAP 可达，安全影响明确且重复成功 |
| C | Native 高权限身份可达，但不代表普通应用 |
| D | 服务异常或权限日志存在，因果证据不足 |
| E | 只有静态推断或未关联日志 |

强结论要求目标 PID、时间窗口、新增 faultlog、请求响应、调用身份和重复实验共同支持。

## 25. 真实源码示例

### 25.1 `sensors_medical_sensor`

SA profile：

```text
process: sensors
SA ID: 3605
library: libmedical_service.z.so
```

NAPI 导出：

```text
on
setOpt
off
```

完整验证路径：

```text
normal HAP
  → medical_sensor NAPI on
  → native SubscribeSensor
  → medical sensor client/proxy
  → SA 3605
  → MedicalSensorServiceStub::OnRemoteRequest
  → transaction handler
  → sensors process
  → callback
  → HAP off 清理
```

这条路径先用于验证 HAP、NAPI、IPC、身份和观察基础设施，再用于具体候选的边界测试。

### 25.2 `systemabilitymgr_samgr`

静态路径示例：

```text
SystemAbilityLoadCallbackStub::OnRemoteRequest
  → EnforceInterceToken
  → OnLoadSystemAbilitySuccessInner
  → OnLoadSystemAbilityFailInner
  → OnLoadSACompleteForRemoteInner
  → OnLoadSystemAbilityFailWithCodeInner
```

其中 `OnLoadSACompleteForRemoteInner` 读取：

```text
string deviceId
int32 systemAbilityId
bool result
IRemoteObject
```

因为该 Stub 位于 `samgr_proxy` library target，动态候选编译器先查明 callback object 的创建方和真实执行进程，再决定 IPC adapter，不能仅凭仓库名把目标进程写成 samgr。

## 26. 报告流水线

### 26.1 动态结果合并

动态结果按 `finding_id + unit_id + run_id` 合并到报告数据中，不直接覆盖原静态结论。

报告同时显示：

```text
Stage 1 verdict
Stage 2 verdict
Docker 动态结果
OpenHarmony 开发板结果
调用身份
证据等级
复现次数
限制
```

### 26.2 中英文摘要

输出：

```text
report/SUMMARY_REPORT.zh-CN.md
report/SUMMARY_REPORT.en.md
```

摘要包含：

- 仓库和平台；
- 扫描范围；
- 入口和可达性统计；
- 漏洞列表；
- 静态和动态证据；
- 风险优先级；
- 修复建议；
- 已知限制；
- 成本和耗时。

### 26.3 HTML 报告

HTML 报告提供：

- 漏洞概览；
- 按 CWE、文件、入口、组件筛选；
- 单漏洞数据流；
- 调用图和 semantic edge；
- 动态证据时间线；
- 中英文切换；
- 原始证据下载。

### 26.4 单漏洞披露

每个符合披露条件的 finding 生成独立文档，源码片段由程序确定性插入，LLM 负责摘要、影响、复现说明和修复建议。

## 27. Web 完整交互

### 27.1 首页

用户可以：

- 选择界面语言；
- 选择 `source_code_base` 中的仓库；
- 输入本地路径或 Git URL；
- 选择 OpenHarmony 平台；
- 选择 LLM 配置；
- 查看模型凭据和费用；
- 启动静态扫描；
- 查看所有历史扫描。

### 27.2 阶段菜单

```text
项目初始化
源码解析
平台识别
调用图
入口和 reachable
应用上下文
上下文增强
Stage 1
Stage 2
统一输出
动态验证
报告
```

每个阶段显示：

- 目的；
- 输入；
- 输出文件；
- 状态和耗时；
- token 和费用；
- 友好视图；
- 原始 JSON；
- 错误和跳过原因。

### 27.3 调用图可视化

调用图页面支持：

- 入口列表；
- 文件和函数搜索；
- 选择入口；
- 深度 1/2/3/5/全部可控；
- 节点展开和折叠；
- caller/callee 方向；
- native、semantic、LLM edge 类型筛选；
- 点击节点查看源码和 Unit；
- 从入口向下查看完整路径；
- 高亮 unresolved/ambiguous 调用点。

### 27.4 友好产物查看

`dataset.json`、`analyzer_output.json`、`call_graph.json`、`pipeline_output.json` 和动态结果分别使用针对性的表单和列表渲染，不把所有文件都显示成通用 JSON 树。

大型 JSON 使用服务端分页、索引、搜索和按需加载，避免一次性传输所有源码和图节点。

### 27.5 开发板动态验证页面

显示：

- HDC server 和设备状态；
- 设备指纹；
- candidate 列表；
- 调用身份和风险等级；
- artifact 和 hash；
- baseline；
- 逐步执行时间线；
- 请求、响应、PID、HiLog、faultlog 和 SELinux；
- 证据等级；
- cleanup 状态；
- 历史动态运行。

Web 不接受任意 HDC shell 文本，高风险测试需要二次确认。

## 28. 输出目录结构

```text
scan_dir/
├── meta.json
├── platform_profile.json
├── analyzer_output.json
├── call_graph.json
├── semantic_graph.json
├── unresolved_calls.json
├── llm_call_graph_edges.json
├── dataset.json
├── dataset_enhanced.json
├── application_context.json
├── results.json
├── results_verified.json
├── pipeline_output.json
├── dynamic_test_results.json
├── DYNAMIC_TEST_RESULTS.md
├── openharmony_dynamic/
│   └── <run_id>/
│       ├── run.json
│       ├── candidate_plan.json
│       ├── device_preflight.json
│       ├── commands.jsonl
│       ├── baseline/
│       ├── artifacts/manifest.json
│       ├── attempts/
│       ├── dynamic_test_results.json
│       ├── DYNAMIC_TEST_RESULTS.zh-CN.md
│       └── DYNAMIC_TEST_RESULTS.en.md
├── parse.report.json
├── app-context.report.json
├── llm-reachability.report.json
├── enhance.report.json
├── analyze.report.json
├── verify.report.json
├── build-output.report.json
├── dynamic-test.report.json
├── openharmony-dynamic.report.json
├── report.report.json
├── scan.report.json
├── enhance_checkpoints/
├── analyze_checkpoints/
├── verify_checkpoints/
├── dynamic_test_checkpoints/
└── report/
    ├── SUMMARY_REPORT.zh-CN.md
    ├── SUMMARY_REPORT.en.md
    ├── disclosures/
    └── report.html
```

## 29. 哪些阶段使用大模型

| 阶段 | 是否调用 LLM | 主要作用 |
|---|---|---|
| 平台识别和解析 | 否 | 确定性读取源码和元数据 |
| native 调用图 | 否 | Tree-sitter 和索引解析 |
| semantic graph | 否 | 确定性 IPC/SA/NAPI/HDF 关系 |
| 间接调用边恢复 | 可选 | 在有限候选中审核漏边 |
| LLM reachability | 可选 | 补充入口和外部输入信号 |
| 应用上下文 | 可选 | 没有威胁模型文件时生成上下文 |
| Agent 增强 | 是 | 搜索和补读关键上下游函数 |
| Stage 1 | 是 | 漏洞检测 |
| Stage 2 | 可选 | 攻击路径验证 |
| pipeline output | 否 | 确定性组装 |
| Docker 动态测试生成 | 是 | 生成受限容器 PoC |
| 开发板候选规划 | 可选 | 协议和安全测试建议 |
| HDC 执行和证据采集 | 否 | 确定性执行和记录 |
| 动态结论 | 规则为主 | LLM 只辅助解释，证据规则决定等级 |
| 报告 | 是 | 中英文摘要和披露文本 |

所有 LLM 输出经过 schema 校验。模型不能直接删除确定性调用边、执行任意设备命令或把未关联日志升级为强动态证据。

## 30. 费用和可恢复性

每个 LLM 阶段记录：

```text
provider
model
input tokens
output tokens
计费币种
输入单价
输出单价
阶段成本
累计成本
```

checkpoint 支持中断恢复：

```text
enhance_checkpoints
analyze_checkpoints
verify_checkpoints
dynamic_test_checkpoints
```

开发板验证按 `run_id/attempt_id` 保存，每个阶段完成后立即落盘。HDC 断开或用户取消时，已有证据不会丢失，并进入安全 cleanup。

## 31. 可靠性和安全原则

### 31.1 确定性证据优先

```text
源码 AST / call graph / IDL / SA profile / runtime PID
    优先于
名称相似 / LLM 推断 / 单条日志
```

### 31.2 模型失败安全降级

LLM 阶段失败时：

- 不删除已确认入口；
- 不删除确定性调用边；
- 不把 candidate 自动标记安全；
- 保留 checkpoint 和错误；
- 报告中显示降级原因。

### 31.3 动态验证身份隔离

```text
native privileged 结果
debug HAP 结果
normal HAP 结果
system identity 结果
```

分别保存、分别判定。

### 31.4 不把 guard 规则当完整真相

guard signals 只是索引提示。模型和验证器继续检查真实代码顺序、失败分支、返回值和调用身份。

### 31.5 源码和固件匹配

设备动态结论记录：

- 源码 commit；
- OpenHarmony build fingerprint；
- API 版本；
- 目标 library hash；
- artifact SDK 和架构。

无法匹配时结论为 `SOURCE_FIRMWARE_MISMATCH` 或降低证据等级。

## 32. 完整运行示例

### 32.1 静态扫描

```bash
./apps/vulnfounder-cli/bin/vulnfounder scan \
  ./source_code_base/sensors_medical_sensor \
  --platform openharmony \
  --verify \
  --skip-dynamic-test
```

### 32.2 单独生成开发板候选

```bash
./apps/vulnfounder-cli/bin/vulnfounder ohos-dynamic plan \
  <scan-dir>/pipeline_output.json \
  --repo ./source_code_base/sensors_medical_sensor \
  --output <scan-dir>/openharmony_dynamic/<run-id>
```

### 32.3 设备预检

```bash
./apps/vulnfounder-cli/bin/vulnfounder ohos-dynamic preflight \
  --device <serial> \
  --output <scan-dir>/openharmony_dynamic/<run-id>
```

### 32.4 执行一个候选

```bash
./apps/vulnfounder-cli/bin/vulnfounder ohos-dynamic run \
  --device <serial> \
  --run <scan-dir>/openharmony_dynamic/<run-id> \
  --candidate OH-CAND-001 \
  --identity normal_hap \
  --risk benign
```

### 32.5 分析和报告

```bash
./apps/vulnfounder-cli/bin/vulnfounder ohos-dynamic analyze \
  --run <scan-dir>/openharmony_dynamic/<run-id>

./apps/vulnfounder-cli/bin/vulnfounder report \
  <scan-dir>/pipeline_output.json \
  --format html \
  --output <scan-dir>/report/report.html
```

## 33. 一页汇报版

```text
1. VulnFounder 接收 OpenHarmony 组件仓库和平台配置。
2. 扫描器读取 bundle、GN、IDL、SA、NAPI 和 HDF/HDI 元数据。
3. Tree-sitter 建立函数索引、native 调用图和反向调用图。
4. IPC resolver 建立 interface、transaction、Stub、Proxy 和 handler 语义图。
5. 受约束的 LLM 只对未解析间接调用点进行候选审核，单调补充调用边。
6. OpenHarmony 入口检测识别 IPC、NAPI、SA、Ability、HDF 和异步事件入口。
7. reachable 从入口沿 native、semantic 和可信增量边传播。
8. Unit 汇总主函数、上下游、入口路径、guard 和 PlatformPromptContext。
9. Agent 补读定义和使用位置，形成完整数据流上下文。
10. Stage 1 检测漏洞，Stage 2 以攻击者视角验证可达路径和控制程度。
11. 程序确定性生成 pipeline_output.json，统一静态候选和动态需求。
12. 通用漏洞在 Docker 隔离环境验证，OpenHarmony C/C++ 候选在开发板验证。
13. 开发板后端区分 normal HAP、debug HAP 和 Native 高权限身份。
14. HDC 预检、合法 baseline、有限触发、PID/日志/faultlog 关联和 cleanup 形成证据闭环。
15. 动态结论按身份和证据等级回流到中英文摘要、HTML 报告和 Web 历史扫描。
```

## 34. 最终交付结果

一轮完整分析最终交付：

- 可追溯的源码函数索引；
- native、semantic 和 LLM 增量调用图；
- OpenHarmony 入口与 reachable 路径；
- 带平台上下文的 Unit 数据集；
- Stage 1/Stage 2 漏洞判断；
- 统一的 `pipeline_output.json`；
- Docker 或开发板动态证据；
- 调用身份和证据等级；
- 中英文摘要；
- HTML 和 Web 可视化；
- 每阶段耗时、费用、错误和产物；
- 可重复的测试记录与清理记录。

这套流程的核心不是让大模型代替解析器或证据，而是让确定性源码关系、受约束的大模型推理和真实设备验证互相校验，最终把“可能存在问题的函数”转化为“入口、调用路径、权限边界和运行证据都能够解释的安全结论”。
