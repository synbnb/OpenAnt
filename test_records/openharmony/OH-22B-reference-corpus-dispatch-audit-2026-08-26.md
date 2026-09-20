# OH-22B OpenHarmony 参考仓库原生分派审计记录

## 1. 审计目的

本次审计只针对以下目录中的仓库：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

目标不是修改解析器，而是回答两个问题：

1. 当前 OH-22B 原生分派解析器能否覆盖参考仓库中的实际 C/C++ 分派写法；
2. 当前调用图和语义图是否已经把 Binder/SA 外部入口连接到真实处理函数。

本次没有启用 LLM，也没有把测试目录纳入生产代码解析；所有结论都通过本地源码和本次流水线产物交叉核对。

## 2. 执行范围与产物

- 平台：`openharmony`
- 处理级别：`all`
- 测试目录：跳过（`skip-tests`）
- LLM：未启用
- 仓库数：9
- 产物根目录：

  ```text
  /Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22B-reference-corpus-20260826-run1
  ```

每个仓库均成功完成 C/C++ 扫描、tree-sitter 函数提取、原生调用图和 dataset 生成。每个仓库目录中包含 `call_graph.json`、`call_graph_residuals.json`、`semantic_graph.json`（若产生）、`dataset.json` 和 `pipeline_results.json`。

## 3. 九个仓库的实际结果

表中“原生调用图边”是普通 C/C++ 调用图边；“分派残留”是当前诊断器发现的间接调用点；“诊断分派赋值”是当前诊断器实际记录的函数表赋值，不等于源码中所有函数表赋值。

| 仓库 | 文件数 | 提取函数数 | 原生调用图边 | 分派残留 | 诊断分派赋值 | 语义图边 |
|---|---:|---:|---:|---:|---:|---:|
| `communication_netmanager_base` | 730 | 7,587 | 6,394 | 16 | 220 | 56（IDL） |
| `developtools_hdc` | 196 | 2,077 | 2,831 | 0 | 0 | 0 |
| `hiviewdfx_faultloggerd` | 359 | 3,020 | 3,415 | 0 | 0 | 0 |
| `hiviewdfx_hilog` | 117 | 864 | 851 | 0 | 0 | 0 |
| `hiviewdfx_hiview` | 1,054 | 7,059 | 5,687 | 0 | 0 | 30（IDL） |
| `multimedia_audio_framework` | 1,514 | 23,246 | 33,816 | 53 | 33 | 703（IDL） |
| `startup_appspawn` | 120 | 1,205 | 2,267 | 1 | 0 | 0 |
| `startup_init` | 343 | 2,728 | 4,929 | 0 | 0 | 9（IDL） |
| `telephony_core_service` | 540 | 6,913 | 7,196 | 0 | 0 | 21（IDL） |

九个仓库全部跑通，但本次产物中 `native_dispatch_to_handler` 和 `native_dispatch_to_service` 的数量均为 0。已有语义图边全部来自 IDL/接口语义解析器，不能证明原生函数表分派已经接通。

## 4. 源码核对结果

### 4.1 `communication_netmanager_base`：高影响遗漏

该仓库是本次最重要的证据，因为它同时包含网络服务和多个 Binder 回调 Stub。

#### 4.1.1 `NetsysNativeServiceStub` 的 `opToInterfaceMap_`

源码位置：

```text
services/netmanagernative/src/netsys_native_service_stub.cpp
```

- 初始化阶段有 146 个明确赋值，例如 `opToInterfaceMap_[...] = &NetsysNativeServiceStub::CmdSetResolverConfig`；
- `OnRemoteRequest` 在约第 503 行通过 `opToInterfaceMap_.find(code)` 查找；
- 约第 544 行通过

  ```cpp
  return (this->*(interfaceIndex->second))(data, reply);
  ```

  调用选中的处理函数；
- 当前原生调用图中 `NetsysNativeServiceStub::OnRemoteRequest` 只连到权限检查等少量直接调用，没有连接这 146 个 `Cmd*` 处理函数；
- 当前诊断器虽然记录了 146 个赋值，但没有记录对应的间接调用点，因为它只识别简单的 `this->*变量`，不能识别 `this->*(迭代器->second)`。

这是确定的调用图漏边，不是 tree-sitter 没有解析文件，而是后续间接分派模式没有建模。

#### 4.1.2 `NetConnServiceStub` 的带权限元组函数表

源码位置：

```text
services/netconnmanager/src/stub/net_conn_service_stub.cpp
```

- 生产源码中有约 87 个 `memberFuncMap_` 条目；
- 每个条目不是简单指针，而是带权限集合的二元组，例如：

  ```cpp
  memberFuncMap_[...] = {
      &NetConnServiceStub::OnRegisterNetConnCallback,
      {Permission::GET_NETWORK_INFO}};
  ```

- `OnRemoteRequest` 先取 `itFunc->second.first`，再执行 `(this->*requestFunc)(data, reply)`；
- 当前诊断器没有记录这些条目：赋值右侧是 `initializer_list`，不是单独的 `pointer_expression`；
- 当前残留记录中只看到一个“无函数表”的间接调用点，原因是本地流分析不认识 `.second.first`。

这部分不仅是普通漏边，还丢失了与处理函数绑定的权限元数据。后续恢复时必须把权限集合保留在边的 evidence/attributes 中，不能只提取第一个函数名。

#### 4.1.3 `memberFuncMap_` 回调 Stub

例如：

```text
services/netmanagernative/src/netfirewall_callback_stub.cpp
```

构造函数中有：

```cpp
memberFuncMap_[...] = &NetFirewallCallbackStub::CmdOnIntercept;
```

`OnRemoteRequest` 通过 `find(code)`、`itFunc->second` 和 `(this->*requestFunc)(data, reply)` 调用。该仓库生产代码中当前诊断器记录了 74 个这类 `memberFuncMap_` 指针赋值，分布在 15 个回调/服务 Stub 中；这些 Stub 的 `OnRemoteRequest` 原生调用图出度大多为 0，说明处理函数边没有被普通调用图恢复。

### 4.2 `telephony_core_service`：lambda 函数表完全未进入诊断

核心源码：

```text
services/core/src/core_service_stub.cpp
```

- 生产代码中 `CoreServiceStub::memberFuncMap_` 有 237 个 lambda 条目；
- 条目形如：

  ```cpp
  memberFuncMap_[uint32_t(CoreServiceInterfaceCode::GET_IMEI)] =
      [this](MessageParcel &data, MessageParcel &reply) {
          return OnGetImei(data, reply);
      };
  ```

- `CoreServiceStub::OnRemoteRequest` 通过 `find(code)` 取出 `std::function`，再执行 `memberFunc(data, reply)`；
- 当前诊断器要求赋值右侧必须是 `&Class::Method` 指针，因此 237 条 lambda 赋值全部被忽略；
- 当前调用图中 `CoreServiceStub::OnRemoteRequest` 只有 descriptor、计时器和取消计时器等直接边，没有连接这些 `OnGet*`/`OnSet*` 处理函数。

此外，IMS 和卫星回调 Stub 还有 6 个 `requestFuncMap_` lambda 条目，同样没有进入诊断。这个例子说明“无残留”不代表“没有间接调用”，也可能代表当前识别器根本没有识别出该类间接调用。

### 4.3 `multimedia_audio_framework`：`dumpFuncMap` 应单独建模

源码位置包括：

```text
services/audio_policy/server/service/service_main/src/audio_policy_server.cpp
services/audio_service/server/src/audio_server_dump.cpp
services/audio_service/server/src/audio_server_hpae_dump.cpp
```

- 共发现 33 个 `dumpFuncMap[u"..."] = &Class::...` 条目；
- 调用形式为 `(this->*dumpFuncMap[para])(dumpString)`；
- 入口是 `Dump(fd, args)`/`ArgDataDump`，参数来自系统 dump/hidumper 命令，而不是 Binder `OnRemoteRequest`；
- 因此不能把它们直接当作 IPC handler 接入 Binder 可达性，否则会产生错误的攻击面归类；
- 但如果 VulnFounder 的安全范围包含 hidumper 命令参数，则应新增独立的“Dump 参数入口”类型，而不是丢弃这些边。

同仓库的 53 个残留还包括 Taihe 回调中的裸函数指针和 `OHAudioSuiteEngine` 成员函数指针。它们没有稳定的本地函数表绑定证据，当前阶段不应按名字猜目标。

### 4.4 `startup_appspawn`：`dlsym` 是真实的不可静态解析边界

源码：

```text
modules/common/appspawn_common.c:291-313
```

`InitDebugParams` 通过 `dlsym(handle, "InitEnvironmentParam")` 获得 `initParam`，再执行 `(*initParam)(processName)`。目标实现位于动态库，不在当前仓库函数索引中。这里应保留“外部动态符号调用”的未解析记录，不能为了让图看起来完整而虚构一个仓库内目标。

## 5. 当前 OH-22B 实现的实际覆盖边界

当前 `native_dispatch.py` 只接受 `baseFuncs_`/`baseFuncs`/`base_funcs_` 家族，并且依赖如下证据链：

1. 函数表赋值是 `table[selector] = &Class::Method`；
2. `OnRemoteRequest` 中存在简单的 `(this->*member)(...)`；
3. 可从同一个表和同一个 Stub 类确定唯一目标；
4. 如需连接到具体服务类，再用明确的继承关系和处理函数中的直接调用确认。

这个边界在 `sensors_medical_sensor` 的 `baseFuncs_` 例子上是有效的，但不覆盖本次 9 个参考仓库中的主要写法。当前问题不是“把 `baseFuncs_` 正则再加几个名字”这么简单，至少还要处理：

- `opToInterfaceMap_` 的嵌套迭代器成员访问：`interfaceIndex->second`；
- 带元组的 `memberFuncMap_`：`itFunc->second.first`；
- `std::function` lambda 的函数表赋值和 lambda 体内直接调用；
- `dumpFuncMap` 的非 Binder 外部命令边界；
- `dlsym`/裸函数指针等无法从本仓库确定目标的情况。

## 6. 下一小阶段建议（待确认，不在本次实施）

建议先实施 **OH-22B-2A：通信网络 Binder 分派恢复**，只处理高置信、可由源码直接证明的 IPC 形式：

1. 支持 `opToInterfaceMap_` 的指针表和 `interfaceIndex->second` 调用；
2. 支持 `memberFuncMap_` 的简单成员函数指针表；
3. 支持 `memberFuncMap_` 的 `{&Handler, permission-set}` 元组，并把权限集合写入边证据；
4. 保留表名、selector、赋值位置、`OnRemoteRequest` 调用位置和权限检查位置；
5. 对 `dumpFuncMap`、lambda 表和动态 `dlsym` 暂不猜测，分别记录为待处理类别。

该阶段只重新跑 `communication_netmanager_base`，预计能直接验证约 146 + 87 + 74 个高置信原生分派目标是否进入语义图；通过后再单独做 **OH-22B-2B：telephony lambda 分派**，避免一次改动同时改变多种语义。

## 7. 结论

本次 9 仓库流水线本身全部成功，但不能据此认为 OpenHarmony 原生入口调用图已经完整。实际源码审计证明：当前实现对参考语料的主要 IPC 分派形式存在系统性漏边，尤其是 `communication_netmanager_base` 和 `telephony_core_service`。下一步应优先恢复网络服务的指针表/权限元组分派，并在每个小阶段后只重跑对应仓库、保存新的测试记录，再决定是否扩大到 lambda、Dump 命令和动态符号边界。

