# VulnFounder 完整扫描主流程学习笔记（截至 OH-17A）

本文按照 [`VULNFOUNDER_COMPLETE_PIPELINE_GUIDE.zh-CN.md`](VULNFOUNDER_COMPLETE_PIPELINE_GUIDE.zh-CN.md) 的结构，记录当前 OpenHarmony 改造已经实际实现到的阶段。

本文的截止点是 **OH-17A：使用 native 调用图补全 OpenHarmony IPC 的 `transaction → handler` 关系**。因此本文只解释从仓库路径进入 C/C++ 解析，到语义 IPC 图接入分析单元的流程；不展开后续 Stage 1 漏洞分析、Stage 2 验证、LLM Agent、动态测试和报告生成，也不把尚未实现的 OH-17B IDL 修复写成已完成能力。

## 0. 先给完全不了解 OpenHarmony 的读者讲人话

如果你第一次接触 OpenHarmony，可以先把本文想象成下面这个问题：

> 一个应用或系统组件从别的进程收到一条请求后，数据经过哪些 C/C++ 函数，最后执行了什么操作？VulnFounder 怎样把这条路径找出来并交给后续安全分析？

OpenHarmony 是一个操作系统。它的源码不是一个单独的程序，而是很多组件组成的大型代码库，例如窗口管理、音频、文件管理、设备驱动和 Ability 运行时。本文只讨论 VulnFounder 如何读取其中一个组件的源码并建立 IPC 语义关系。

### 0.1 最重要的几个词

| 术语 | 小白解释 | 在本文中的作用 |
|---|---|---|
| OpenHarmony 组件 | 操作系统源码中的一个功能模块，例如窗口、音频或文件服务 | 本阶段按组件仓库进行扫描 |
| 进程 | 正在运行的一个程序实例。两个进程通常不能直接读写对方内存 | OpenHarmony 服务经常运行在独立进程中 |
| IPC | Inter-Process Communication，进程间通信，也就是“一个进程给另一个进程发请求” | 本阶段重点追踪的边界 |
| native | 直接运行在系统本地的 C/C++ 代码，不是 JavaScript/ArkTS 层代码 | 本文的 native 函数和 native 调用图来自 C/C++ |
| 客户端（client） | 发起请求的一方 | 调用 proxy 并发送 transaction |
| 服务端（server） | 接收请求并执行实际功能的一方 | 通过 stub 接收请求 |
| proxy | 客户端一侧的“代理对象”，看起来像本地函数，实际把请求发到另一个进程 | 常见证据是 `SendRequest(...)` |
| stub | 服务端一侧的“接收对象”，负责从请求包中读出参数并分发 | 常见入口是 `OnRemoteRequest(...)` |
| handler | 真正处理某一种业务请求的函数 | 例如 `HandleGetCutoutInfo` |
| Parcel / `MessageParcel` | 一种“快递箱”，把整数、字符串、对象等参数打包后跨进程传递 | handler 从中读取外部输入 |
| IDL | Interface Definition Language，接口说明书，先约定有哪些远程方法和参数 | 生成 interface 和 transaction 节点 |
| interface | IDL 中的一组远程方法，相当于服务提供的功能清单 | 例如 `IDisplayManagerLite` |
| method | interface 中的一项远程功能 | 例如 `GetCutoutInfo()` |
| transaction | 一次远程请求的编号/逻辑身份，用来区分“这次请求要执行哪个 method” | 连接 IDL method 与 native 函数 |
| `OnRemoteRequest` | 服务端收到 IPC 请求后的总入口函数，通常先读 token，再根据 code 分发 | OH-17A 的调用图起点 |
| `SendRequest` | 客户端向服务端发送 IPC 请求的函数 | 识别 proxy 侧关系 |
| ZIDL | OpenHarmony 中一类 IDL/代码生成约定；生成的 C++ 常带有 Stub、Proxy 和 `Handle...` 函数 | 解释为什么源码类名和 IDL 名称可能不一样 |
| `bundle.json` | 组件的描述/清单文件，不是 IPC 请求本身 | 帮助识别模块和源码范围 |
| `BUILD.gn` | GN 构建系统的配置文件，列出目标和源文件 | 帮助知道哪些源码属于一个构建目标 |
| GN | OpenHarmony 常用的构建配置/构建描述系统 | `BUILD.gn` 使用的语法和工具体系 |
| SA（System Ability） | OpenHarmony 中注册并提供系统能力的服务，可以粗略理解为系统级服务 | 本文只把它作为可选元数据，不在 OH-17A 中展开 |
| Ability | OpenHarmony 中承载应用或组件能力的一类运行单元/生命周期对象 | 本文截止点之前不修改 Ability 入口规则 |
| C pipeline | VulnFounder 中负责 C/C++ 扫描的流水线，不是 OpenHarmony 的一个系统组件 | 执行扫描、抽取、调用图和 Unit 生成 |
| Tree-sitter | VulnFounder 使用的源码语法解析器，像“读懂 C++ 句子结构的扫描器” | 抽取函数和调用表达式 |
| 调用图（call graph） | 函数之间“谁调用谁”的地图 | OH-17A 用它确认真实 handler |
| semantic graph | 把 IDL、transaction、stub、handler 连接起来的语义关系图 | 生成 `semantic_graph.json` |
| resolver | “关系解析器”，根据多种证据判断两个节点是否真的对应 | 本文的 OpenHarmony IPC resolver 负责 IDL/native 关联 |
| edge kind | 边的类型名称，例如 `stub_to_transaction` | 说明这条关系具体表示什么 |
| Unit | VulnFounder 交给后续分析的一个分析单元，通常包含一个主函数和有限上下文 | 生成 `dataset.json` |
| `context_functions` | 为了理解主函数而附带的相关函数，不代表它们一定单独产生漏洞结论 | 把 handler 放进主函数上下文 |
| orphan | resolver 暂时无法可靠连接的关系记录 | 诊断信息，不等于漏洞，也不等于代码错误 |

### 0.2 用“快递”比喻一次 IPC 请求

可以把一次请求想成寄快递：

```text
客户端业务代码
  -> proxy：填写寄件信息
  -> SendRequest：把快递发出
  -> IPC / MessageParcel：运输中的快递箱
  -> stub：服务端收件并拆箱
  -> OnRemoteRequest：查看请求编号并分拣
  -> handler：真正处理这件事
```

例如客户端调用 `GetCutoutInfo()`，服务端可能执行：

```text
GetCutoutInfo 请求
  -> ScreenSessionManagerLiteStub::OnRemoteRequest
  -> ScreenSessionManagerLiteStub::HandleGetCutoutInfo
```

VulnFounder 的工作不是运行这段请求，而是从 IDL、C++ 函数和静态调用图中把这条路径复原出来。

### 0.3 为什么本文会出现很多“图”和“节点”

这里的“图”不是图片，而是程序员常用的关系数据结构：

```text
节点（node） = 一个 interface、transaction 或函数
边（edge）  = 两个节点之间的一种关系
```

例如：

```text
IDisplayManagerLite
  --interface_to_transaction-->
GetCutoutInfo transaction
  --transaction_to_handler-->
HandleGetCutoutInfo
```

理解这三条线，就能理解 OH-17A 的主要修改。

### 0.4 建议的阅读顺序

如果你是第一次看 OpenHarmony 源码，不需要从头记住所有英文名词，可以按这个顺序读：

1. 先看本节的“快递”比喻，理解客户端、服务端、stub 和 handler；
2. 再看第 5 节，理解函数调用图只是“谁调用谁”；
3. 再看第 6、7 节，理解 IDL method 怎样对应到 C++ handler；
4. 最后看第 9 节的完整小例子，把抽象节点换回真实代码。

`SA`、Ability、GN 等词如果暂时不理解，不会妨碍你理解 OH-17A 的主线；它们不是本阶段建立 `transaction_to_handler` 的必要前提。

## 1. 当前已实现的一句话流程

```text
repo_path
  -> OpenHarmony 平台扫描与源码范围识别
  -> C/C++ 文件筛选
  -> Tree-sitter 函数抽取
  -> native 正向/反向调用图
  -> IDL 解析：interface / transaction
  -> IPC resolver：proxy / stub / handler 关系
  -> semantic_graph.json
  -> UnitGenerator 合并 context_functions
  -> dataset.json
```

本阶段的关键变化是：

```text
旧逻辑：IDL + 函数记录
        -> 主要依靠名称、owner 和函数体文本匹配 handler

新逻辑：IDL + 函数记录 + native call_graph
        -> 优先使用 OnRemoteRequest 出发的有界调用路径
        -> 再回退到原有词法匹配
```

## 2. 本阶段的输入和输出

这一阶段可以理解为“先把源码整理成几张可查询的表”：一张函数表、一张函数调用关系表、一张 IPC 业务关系表，最后再把它们拼成供安全分析使用的 Unit。

### 2.1 输入

OpenHarmony C pipeline 的主要输入是一个本地仓库目录：

```text
repo_path = /path/to/openharmony_component
platform = openharmony
```

`repo_path` 不是某个 C++ 文件，而是一个目录。VulnFounder 会在这个目录下面递归寻找源码、IDL 和构建文件。`platform = openharmony` 相当于告诉扫描器：“这里的目录和入口规则要按 OpenHarmony 组件来理解”。

仓库中可能参与本阶段的文件包括：

- C/C++ 源文件：`.c`、`.cc`、`.cpp`、`.h`、`.hpp` 等；
- `bundle.json`：组件和模块元数据；
- `BUILD.gn`：目标与 source 列表；
- `.idl`：IPC interface 和 method 声明；
- 可选的 OpenHarmony 目录角色、SA 或其他平台元数据。

### 2.2 主要中间产物

```text
analyzer_output.json   # 函数记录和解析统计
call_graph.json        # native 正向/反向调用图
semantic_graph.json    # IDL 与 native IPC 语义关系
dataset.json           # 最终分析单元
```

这些文件由程序确定性写出。`semantic_graph.json` 中的关系证据来自 IDL、native 代码或 native call graph，不是模型直接生成的。

可以把四个文件分别理解为：

```text
analyzer_output.json  = “有哪些函数、函数在哪里、函数代码是什么”
call_graph.json       = “这些函数互相怎么调用”
semantic_graph.json   = “IDL 里的远程功能对应哪些 native 函数”
dataset.json          = “后续安全分析每次要看的函数包”
```

## 3. OpenHarmony 平台扫描

这一节还没有分析漏洞。它做的事情更像整理仓库目录：判断哪些文件是源码、哪些文件是测试或依赖、哪些文件属于哪个 OpenHarmony 组件。

### 3.1 文件筛选

`RepositoryScanner` 负责枚举源码文件，并根据平台模式识别 OpenHarmony 的源码范围和目录角色。平台模式由 C pipeline 传入：

```python
scanner_options = {
    "skip_tests": self.skip_tests,
    "platform": self.platform,
}
```

OpenHarmony 扫描阶段还会读取构建和组件信息，供后续平台上下文使用。当前阶段的目标是确定哪些文件进入 C/C++ 函数抽取，并不是直接把所有仓库文件都当作漏洞分析目标。

### 3.2 `bundle.json` 和 BUILD 信息的作用

对小白来说，可以把它们看成两种不同的目录说明：`bundle.json` 更像组件的身份证，`BUILD.gn` 更像“这个组件编译时要把哪些源文件装进哪个目标”的清单。

它们主要用于：

- 识别模块和组件；
- 确定 source 范围；
- 记录文件角色和目标归属；
- 生成 UnitGenerator 使用的平台上下文。

它们不直接决定 `transaction_to_handler`。IPC handler 关系仍然需要 IDL、native 函数和调用图证据。

## 4. C/C++ 函数抽取

Tree-sitter 解析 C/C++ 文件，生成函数记录。你可以把它理解成“先不运行程序，只把源码中的函数边界和函数名字标出来”。例如它会识别出：这是一个类的方法、它从第几行开始、函数体在哪里。

典型字段包括：

```json
{
  "name": "HealthSensorServiceStub::OnRemoteRequest",
  "file_path": "services/health_sensor_service_stub.cpp",
  "start_line": 10,
  "end_line": 30,
  "code": "...完整函数体...",
  "unit_type": "method"
}
```

函数 ID 通常由仓库相对路径和函数名组成，例如：

```text
services/health_sensor_service_stub.cpp:HealthSensorServiceStub::OnRemoteRequest
```

该 ID 必须在 `analyzer_output.json`、`call_graph.json`、`semantic_graph.json` 和 `dataset.json` 之间保持一致，否则后续语义上下文无法回填到正确的分析单元。

这里的 `owner` 可以简单理解为“这个函数属于哪个类”。例如：

```text
HealthSensorServiceStub::OnRemoteRequest
~~~~~~~~~~~~~~~~~~~~~~~
        owner
```

OH-17A 正是因为发现“IDL interface 名称”和 native 函数 owner 可能不是同一个字符串，才进一步使用调用图。

## 5. native 调用图

调用图回答的是一个非常直观的问题：**函数 A 的函数体里调用了函数 B 吗？**

### 5.1 调用图构建

`CallGraphBuilder` 基于已经抽取的函数记录重新解析函数体，建立：

```text
call_graph[caller_id] = [callee_id, ...]
reverse_call_graph[callee_id] = [caller_id, ...]
```

例如真实 OpenHarmony ZIDL 代码中可能得到：

```text
ScreenSessionManagerLiteStub::OnRemoteRequest
  -> ScreenSessionManagerLiteStub::HandleGetCutoutInfo
```

这是 OH-17A 使用的核心证据。resolver 不需要重新执行 C++ 代码，只消费这张已经构建好的静态图。

这里的两个英文词容易混淆：

```text
caller = 发起调用的函数，也叫调用者
callee = 被调用的函数，也叫被调用者
```

所以：

```text
OnRemoteRequest -> HandleGetCutoutInfo
```

表示 `OnRemoteRequest` 是 caller，`HandleGetCutoutInfo` 是 callee。`reverse_call_graph` 则把箭头反过来保存，方便查询“谁调用了这个函数”。

### 5.2 为什么不能只依赖函数名

OpenHarmony 中经常出现以下情况：

```text
IDL interface                 native class
IDisplayManagerLite           ScreenSessionManagerLiteStub
IHealthSensorService          HealthSensorServiceStub / HealthSensorService
```

IDL 名称、stub 类名和业务 service 类名不一定相同。仅按 interface stem 或 owner 匹配会在进入 handler 判定前就丢失真实关系。

同时，仓库中可能存在多个同名函数：

```text
Display::GetCutoutInfo
ScreenSessionManagerLiteStub::HandleGetCutoutInfo
```

同名本身不足以证明哪个函数是 IPC dispatch handler，因此需要结合调用边和调用路径。

## 6. IDL 到 semantic graph

IDL 可以先理解成“跨进程服务的接口说明书”。它只描述服务允许别人调用什么，不等于具体的 C++ 实现：

```idl
interface OHOS.Health.IHealthSensorService {
    int EnableSensor();
}
```

这句话的意思是：有一个叫 `IHealthSensorService` 的远程服务，它对外提供 `EnableSensor` 方法。真正读取 `MessageParcel`、检查权限、修改系统状态的代码仍然在 C++ 中。

### 6.1 IDL 基础节点

IDL parser 将 interface 和 method 转换为语义节点：

```text
idl:interface:OHOS.Health.IHealthSensorService
idl:transaction:OHOS.Health.IHealthSensorService:EnableSensor
```

基础关系为：

```text
idl_interface -> ipc_transaction
```

对应 edge kind：

```text
interface_to_transaction
```

`transaction` 在这里不是数据库事务。它表示一次 IPC 请求的“编号/身份”。客户端发送请求时会带上某个 code，服务端根据这个 code 判断应该执行哪个 IDL method。不同仓库的 code 可能来自常量、枚举或生成代码，所以 resolver 还会结合方法名和调用图，而不是只依赖一个固定数字。

### 6.2 Proxy 和 Stub

如果用“电话”来比喻：

```text
Proxy = 客户端手里的电话听筒，负责拨号和发送内容
Stub  = 服务端接电话的人，负责接收内容并转给业务处理函数
```

proxy 不是最终业务实现，stub 也通常不是最终业务实现；stub 更像一层分拣代码，真正做事的函数通常是后面找到的 handler。

resolver 继续从 native 函数中寻找：

- proxy 侧的 `SendRequest(...)`；
- server 侧的 `OnRemoteRequest(...)` 或 transaction table；
- 与 IDL method、transaction token 或 method variant 相关的证据。

得到的关系可能是：

```text
Proxy::EnableSensor -> ipc_transaction
Stub::OnRemoteRequest -> ipc_transaction
```

对应 edge kind：

```text
proxy_to_transaction
stub_to_transaction
```

如果证据不足，不会仅凭一个同名函数强行建立边，而是记录 `unresolved_ipc_proxy` 或 `unresolved_ipc_stub` orphan。

## 7. OH-17A：调用图补全 transaction → handler

这一节是本次修改的核心。先记住三种函数角色：

```text
proxy function          客户端发请求
OnRemoteRequest         服务端统一收请求、看请求编号
handler function        处理某一个具体请求
```

例如服务端收到“获取刘海区域信息”的请求后，可能先进入总入口，再进入具体 handler：

```text
OnRemoteRequest(code = GET_CUTOUT_INFO)
  -> HandleGetCutoutInfo(data, reply)
```

`data` 和 `reply` 通常是 `MessageParcel`。`data` 里装着请求方传来的参数，`reply` 用来装服务端返回的结果。对安全分析来说，`data` 是外部输入的重要来源。

把一个常见的服务端入口拆开看，大致是这样：

```cpp
int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    // 1. 确认来电者使用的是正确接口
    if (!data.ReadInterfaceToken(GetDescriptor())) {
        return ERR_TRANSACTION_FAILED;
    }

    // 2. 从跨进程“快递箱”中读取请求参数
    int32_t sensorId = data.ReadInt32();

    // 3. 根据 code 或 switch 分辨具体远程方法
    if (code == CMD_ENABLE_SENSOR) {
        // 4. 进入真正的业务处理函数
        return EnableSensor(sensorId, reply);
    }
    return ERR_INVALID_DATA;
}
```

这里的 `code` 可以理解为“菜单编号”，`CMD_ENABLE_SENSOR` 表示菜单中的某一项；`sensorId` 是从外部请求读出的数据。VulnFounder 需要把第 3 步的请求编号和第 4 步的函数对应起来，这正是 `transaction_to_handler` 想表达的关系。

### 7.1 旧逻辑

原 resolver 的 handler 逻辑主要是：

1. 根据 IDL method 生成方法变体：

   ```text
   Enable
   HandleEnable
   EnableInner
   HandleEnableInner
   EnableImpl
   HandleEnableImpl
   ```

2. 在函数记录中寻找同 interface owner 的候选；
3. 要求候选函数 owner 通常与 stub owner 相同；
4. 再根据 stub 函数体是否出现 handler 名称进行确认。

其中 `interface stem` 是把 interface 名称简化后的核心部分。例如：

```text
OHOS.Rosen.IDisplayManagerLite
                         -> DisplayManagerLite
```

旧逻辑会尝试用这个核心字符串和 C++ 类名比较。这是一种便宜、速度快的初筛，但它隐含了“IDL 名称和 C++ 类名相似”的假设，而 OpenHarmony 的生成代码并不总是满足这个假设。

这对以下代码有效：

```cpp
int HealthServiceStub::OnRemoteRequest(...) {
    return HandleEnableInner(data, reply);
}

int HealthServiceStub::HandleEnableInner(...) {
    return Enable(data);
}
```

但对以下真实形态不够：

```cpp
int ScreenSessionManagerLiteStub::OnRemoteRequest(...) {
    HandleGetCutoutInfo(data, reply);
}

int ScreenSessionManagerLiteStub::HandleGetCutoutInfo(...) {
    return GetCutoutInfo(displayId);
}
```

因为 `ScreenSessionManagerLiteStub` 不包含 `IDisplayManagerLite` 的完整 interface stem，旧 owner 过滤可能在 handler 解析之前排除它。

### 7.2 新逻辑的调用顺序

现在 resolver 的处理顺序是：

```text
IDL method
  -> 查找 proxy
  -> 查找原有 lexical/native stub
  -> 查找 call_graph dispatch candidate
  -> 查找 call_graph handler candidate
  -> 若调用图未确认，再回退到旧 owner/名称匹配
  -> 建立 transaction_to_handler 或记录 orphan
```

C pipeline 的调用方式变为：

```python
semantic_graph = OpenHarmonyIPCResolver().resolve(
    idl_result,
    extract_result,
    call_graph=graph_result,
).to_dict()
```

`graph_result` 中的 `functions` 和 `call_graph` 使用相同的函数 ID，因此 resolver 可以直接把调用边目标映射回函数记录。

这里的“优先”不是把旧逻辑删除，而是：如果调用图能给出更直接的证据，就先使用它；如果调用图没有相关边，仍然尝试原来的词法和 owner 规则。这样旧仓库不会因为没有 `call_graph` 字段而完全失效。

### 7.3 有界调用路径

resolver 只从 leaf 为 `OnRemoteRequest` 的函数出发，执行有界 BFS：

```text
最大深度：3
每个 dispatch 最多保留目标：256
```

例如：

```text
depth 0: ServiceStub::OnRemoteRequest
depth 1: ServiceStub::OnRemoteRequestInner
depth 2: ServiceStub::HandleEnableSensor
```

这样可以覆盖常见 wrapper，同时避免把整个仓库的可达函数都当成 IPC handler。

`wrapper` 可以理解为“中间转发函数”。它本身不处理业务，只把请求再交给下一层：

```cpp
int OnRemoteRequest(...) {
    return OnRemoteRequestInner(code, data, reply);
}
```

如果不沿调用图继续走，VulnFounder 只能看到 `OnRemoteRequestInner`，看不到最后的 `Handle...`。但如果无限制地继续走，又可能把大量普通业务函数全部带进来，所以这里使用固定最大深度。

### 7.4 方法变体约束

调用图可达并不自动等于 handler。目标函数 leaf 还必须匹配当前 IDL method 的有限变体：

```text
Method
HandleMethod
MethodInner
HandleMethodInner
MethodImpl
HandleMethodImpl
```

例如 `OnRemoteRequest` 调用了 `CheckPermission`，即使该函数可达，也不会因为“可达”而被错误标记为 `transaction_to_handler`。

这条限制很重要：`CheckPermission` 可能是安全检查函数，`ReadInt32` 可能是参数读取函数，`GetCutoutInfo` 可能是业务函数；它们都可能出现在调用路径上，但只有名字与当前 IDL method 对得上的函数，才有资格成为这个 transaction 的 handler 候选。

### 7.5 直接边和路径边

直接调用：

```text
OnRemoteRequest -> HandleEnable
```

证据示例：

```json
{
  "source": "call_graph",
  "signal": "direct_dispatch_call",
  "matched": "HandleEnable",
  "caller": "HealthSensorServiceStub::OnRemoteRequest",
  "call_path": [
    "HealthSensorServiceStub::OnRemoteRequest",
    "HealthSensorService::HandleEnable"
  ]
}
```

经过 wrapper 的调用：

```text
OnRemoteRequest
  -> OnRemoteRequestInner
  -> HandleEnableInner
```

证据中的 `signal` 会变为 `dispatch_call_path`，并保留完整的 `call_path`。

### 7.6 接口变体过滤

为了避免 Lite 和普通接口之间的同名误连，resolver 会比较 interface stem 与 native 文件/owner 中的显式变体：

```text
IDisplayManagerLite
  ↔ screen_session_manager_lite_stub.cpp

IDisplayManager
  ↛ screen_session_manager_lite_stub.cpp
```

当前重点过滤的变体包括：

```text
lite、client、server、agent、listener、callback、scheduler、observer
```

变体冲突时宁可保留 unresolved orphan，也不把一个确定属于 Lite 的 handler 复用到普通 interface。

这里的 `Lite` 不是“安全等级”，而通常是同一类功能的轻量版本或精简接口。例如普通显示管理接口和显示管理 Lite 接口可能拥有同名方法，但由不同 native stub 处理。过滤的目的只是区分“属于哪个接口”，不是判断功能是否安全。

### 7.7 最终语义边

当 stub 和 handler 都被确认时，resolver 写入：

```text
ipc_transaction -> native handler function
```

edge kind：

```text
transaction_to_handler
```

关系示例：

```text
idl:transaction:OHOS.Rosen.IDisplayManagerLite:GetCutoutInfo
  -> function:...:ScreenSessionManagerLiteStub::HandleGetCutoutInfo
```

如果候选为多个，写入 `ambiguous_ipc_handler`；如果没有候选，写入 `unresolved_ipc_handler`。这使得“没有边”能够区分为覆盖不足、名称不一致、调用图未解析或候选冲突，而不是静默丢失。

对小白来说，可以这样读 orphan：

```text
unresolved_ipc_handler = “我看到了可能的服务入口，但没有足够证据确定具体处理函数”
ambiguous_ipc_handler  = “我找到了多个可能处理函数，当前规则不敢擅自选一个”
```

它们是分析过程的“待核对清单”，不是漏洞报告，也不表示源码一定有问题。

## 8. semantic_graph 如何进入分析单元

到这里，VulnFounder 已经有两张不同用途的地图：

```text
native call graph  = C/C++ 函数之间的普通调用关系
semantic graph     = IDL 远程方法与 native IPC 函数之间的语义关系
```

前者回答“函数调用了谁”，后者回答“这个跨进程请求对应哪一个函数”。两张图不是互相替代，而是叠加使用。

### 8.1 UnitGenerator 输入

OpenHarmony C pipeline 在生成 Unit 前将语义图放入 options：

```python
opts["semantic_graph"] = semantic_graph
generator = UnitGenerator(graph_result, opts)
```

UnitGenerator 同时保留原生调用图：

```text
graph_result.call_graph
graph_result.reverse_call_graph
```

语义图是额外的跨 IDL/native 关系，不会替换原生调用图。

### 8.2 `context_functions`

当主函数对应的语义节点能够沿以下边到达 handler：

```text
stub_to_transaction
transaction_to_handler
```

UnitGenerator 会把 handler 作为语义上下文加入当前 Unit：

```json
{
  "metadata": {
    "context_functions": [
      {
        "id": "...HealthService::Enable",
        "edge_kinds": [
          "stub_to_transaction",
          "transaction_to_handler"
        ]
      }
    ]
  }
}
```

这意味着后续分析目标仍然是主函数；handler 作为理解输入校验、权限检查和危险操作之间数据流的上下文，不会自动变成另一个独立漏洞结论。

例如主目标是：

```text
HealthSensorServiceStub::OnRemoteRequest
```

而 `HealthSensorService::EnableSensor` 被放进 `context_functions`，意思是：

```text
请分析主入口，但允许参考这个后续函数来理解数据如何继续流动。
```

它不是把两个函数合并成一个函数，也不是因为 handler 被加入上下文就断言存在漏洞。

### 8.3 Prompt 前的边界

到 OH-17A 为止，本文只覆盖语义上下文被组装进 Unit 的阶段。后续 vulnerability prompt、Stage 1、Stage 2 和报告如何使用这些字段，不属于本次文档截止范围。

## 9. 一个完整的最小例子

下面的例子故意使用简化代码。真实 OpenHarmony 生成代码可能还会有 descriptor、权限、返回码、序列化和错误处理，但核心关系相同。

### 9.1 Native 代码

```cpp
int32_t HealthSensorServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply)
{
    switch (code) {
        case CMD_ENABLE_SENSOR:
            // code 表示“这次远程请求要调用哪个 method”
            return EnableSensor();
        default:
            return -1;
    }
}

int32_t HealthSensorService::EnableSensor()
{
    // 真实服务中这里可能继续读取参数、检查权限或操作系统资源
    return CheckPermission();
}
```

抽取后的调用图：

```text
HealthSensorServiceStub::OnRemoteRequest
  -> HealthSensorService::EnableSensor
```

### 9.2 IDL

```idl
interface OHOS.Health.IHealthSensorService {
    int EnableSensor();
}
```

### 9.3 semantic graph

```text
idl:interface:OHOS.Health.IHealthSensorService
  -> idl:transaction:OHOS.Health.IHealthSensorService:EnableSensor
  -> function:...:HealthSensorService::EnableSensor
```

其中第二条边是：

```text
transaction_to_handler
evidence[0].source = call_graph
```

### 9.4 结果意义

后续 Unit 的主目标可以是：

```text
HealthSensorServiceStub::OnRemoteRequest
```

而 `HealthSensorService::EnableSensor` 作为 `context_functions` 被一并提供。这样分析器能够同时看到：

```text
外部 IPC 请求
  -> transaction code
  -> handler
  -> 权限检查 / 参数处理 / 业务操作
```

## 10. 当前测试和真实仓库验证

本阶段测试记录见：

[`test_records/openharmony/OH-17A-ipc-callgraph-handler-2026-08-22.md`](test_records/openharmony/OH-17A-ipc-callgraph-handler-2026-08-22.md)

当前已验证：

- resolver 调用图参数的红灯测试和实现后回归；
- Stub/Service owner 分离；
- ZIDL Lite interface 与 native stub 名称不一致；
- C pipeline 把真实 `graph_result` 传入 resolver；
- semantic graph 到 Unit `context_functions` 的接线；
- OpenHarmony 与 C pipeline 相关测试：`102 passed, 6 skipped`；
- 真实 `window_window_manager`：新增 3 条 `stub_to_transaction` 和 3 条 `transaction_to_handler`，证据均来自 `call_graph`。

## 11. 当前截止点和未覆盖内容

本文有意停在 OH-17A，以下内容没有在本阶段修改：

1. IDL 中 `[ipccode N]` 前缀导致 method 解析不足的问题；
2. SA profile 与 IPC interface 的进一步绑定；
3. OpenHarmony 入口种子和 library mode 的策略调整；
4. 大仓库 `platform_context` 的逐函数×逐 target 性能瓶颈；
5. Stage 1/Stage 2、LLM prompt、动态测试和最终报告。

这些内容应分别进入后续小阶段，并继续遵循“先说明旧/新逻辑、先写失败测试、修改后单独测试并记录”的流程。

其中 `[ipccode N]` 可以先理解为“在 IDL 里显式写出了请求编号 N”。当前阶段还没有修改这类写法的解析规则，所以文中所有关于 transaction 的例子都只表示已经被当前 parser 识别出的 method 关系。
