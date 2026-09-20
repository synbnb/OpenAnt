# OH-23A：OpenHarmony 音频策略 IPC 生成产物核验

日期：2026-08-28  
阶段：阶段 0（只读核验）  
模型调用：0 次  
代码修改：0 个解析器文件

## 1. 核验目的

确认 `IAudioPolicy::UnexcludeOutputDevices` 对应的 IPC Stub/Proxy 是否存在于当前
扫描输入、VulnFounder 工作区或本机的 OpenHarmony 构建产物中，并确认
`AudioPolicyStub::OnRemoteRequest` 是否能够作为已经观察到的源码符号使用。

## 2. 核验范围

- OpenHarmony 参考源码：
  `/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`
- VulnFounder 复制的源码：
  `/Users/shiyu/学习/hyl/new/VulnFounder/source_code_base`
- VulnFounder 工作区及本地构建缓存：
  `/Users/shiyu/学习/hyl/new/VulnFounder`
- 本次扫描产物：
  `/Users/shiyu/.openant/webui/347d903282351b35`

## 3. 原逻辑与本阶段逻辑

原逻辑把函数名为 `OnRemoteRequest` 的函数识别为 OpenHarmony Binder 入口，并要求
原生调用图或语义图中存在 Stub 分派证据。生成代码不在源码输入时，IDL 事务会被
记录为 `unresolved_ipc_stub`，但不会自动连接到业务 handler。

本阶段不改变上述逻辑，只检查生成文件和构建信息，避免在没有证据时把推断当成
真实源码。后续阶段再决定是否增加“IDL 契约推断”回退。

## 4. 已确认的源码证据

### 4.1 服务类依赖 Stub

`audio_policy_server.h`：

- 第 44 行引入 `audio_policy_stub.h`；
- 第 79～81 行声明 `AudioPolicyServer` 继承 `AudioPolicyStub`；
- 第 213～214 行声明 `UnexcludeOutputDevices(...) override`。

### 4.2 IDL 事务存在

`services/audio_policy/idl/IAudioPolicy.idl` 第 244 行声明：

```idl
void UnexcludeOutputDevices(
    [in] int audioDevUsage,
    [in] List<sharedptr<AudioDeviceDescriptor>> audioDeviceDescriptors);
```

`audio_policy_ipc_interface_code.h` 第 200 行包含 `UNEXCLUDE_OUTPUT_DEVICES` 事务枚举。

### 4.3 测试代码使用了 IPC 调用接口

`audio_policy_stub_fuzzer.cpp`：

- 第 321 行调用 `AudioPolicyStub::GetDescriptor()`；
- 第 327 行调用 `server->OnRemoteRequest(code, data, reply, option)`。

这证明工程预期存在名为 `AudioPolicyStub` 的接口基类和 `OnRemoteRequest` 调用接口，
但该测试代码不是生产 Binder 分派实现本身。

## 5. 生成代码和构建产物搜索结果

### 5.1 精确文件名搜索

在参考源码、VulnFounder `source_code_base`、VulnFounder 工作区和相关本地缓存中搜索：

```text
audio_policy_stub.h
audio_policy_stub.cpp
audio_policy_proxy.h
audio_policy_proxy.cpp
```

结果：0 个文件。

### 5.2 构建输出搜索

在当前工作区搜索 `compile_commands.json`、`build.ninja`、`args.gn` 及音频策略
生成文件，结果：没有找到完整 OpenHarmony 构建输出或对应生成目录。

当前两个源码根目录均不包含完整 OpenHarmony 根目录中的
`build/config/components/idl_tool/idl.gni`，因此它们是部分仓库，不是可直接生成
全部系统中间产物的完整源码树。

### 5.3 GN 生成规则

`services/audio_service/idl/BUILD.gn`：

- 第 90～96 行定义 `idl_gen_interface("audio_policy_idl_interface")`，输入包括
  `IAudioPolicy.idl`；
- 第 109～116 行把 `target_gen_dir` 加入头文件搜索路径；
- 第 129～137 行的 `audio_policy_sa_idl_config` 同样引用 `target_gen_dir`。

因此，Stub/Proxy 很可能由完整构建过程生成到 `target_gen_dir`，而不是作为该部分
仓库的普通源文件提交。

## 6. 本次扫描产物观察

扫描目录：`/Users/shiyu/.openant/webui/347d903282351b35`

- `call_graph.json` 能找到
  `AudioPolicyServer::UnexcludeOutputDevices`；
- `dataset.json` 中没有该函数，因为 reachable 过滤前没有得到从 IPC 事务到 handler
  的有效边；
- `semantic_graph.json` 能识别
  `idl:transaction:IAudioPolicy:UnexcludeOutputDevices`；
- 该事务仍有 `unresolved_ipc_stub` 和 `unresolved_ipc_proxy` orphan；
- 当前没有 `transaction_to_handler` 边；
- 原生调用图没有记录生成的 Stub 分派函数。

## 7. 结论

1. `AudioPolicyStub` 和 `OnRemoteRequest` 是当前工程明确依赖的 IPC 接口形式，不是
   凭空命名。
2. 但是，当前源码快照中没有 `AudioPolicyStub::OnRemoteRequest` 的定义或函数体；
   不能把这个具体限定名说成“已经从源码直接确认”。
3. 更准确的描述是：当前输入包含 IDL 和服务端 handler，但缺少构建生成的 IPC
   分派胶水代码。运行时完整系统可能拥有该代码，当前静态扫描输入没有。
4. 当前扫描漏掉该函数属于“缺少跨生成边”的解析覆盖问题，不代表该函数不是外部
   可调用的 IPC handler。

## 8. 阶段 0 验收

- [x] 检查参考源码和 VulnFounder 复制源码；
- [x] 检查本地构建输出和生成目录；
- [x] 检查 GN 的 IDL 生成配置；
- [x] 对照扫描产物确认缺失边的具体表现；
- [x] 未修改解析器、调用图或扫描结果；
- [x] 未调用大模型。

## 9. 下一阶段建议

阶段 1 增加通用的 IDL 契约回退：当生成 Stub 不可见时，根据 IDL 方法、服务类的
Stub 继承关系、`override` handler、参数形状和 GN 目标关系建立一条带有
`idl_handler_contract` 证据的语义边。该边不伪造 `AudioPolicyStub::OnRemoteRequest`
源码，也不改写原生调用图，只用于安全的 reachable 计算。
