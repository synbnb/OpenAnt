# 单函数 Stage 2 待定结果补证测试记录

日期：2026-08-30  
对象：`AudioPolicyServer::UnexcludeOutputDevices`  
类型：单函数真实模型测试；未重新执行 Stage 1、解析器或整仓库扫描

## 测试目的

验证 Stage 2 `FindingVerifier` 能否在第一阶段只给出 `inconclusive` 时，使用已有函数
索引和工具继续追踪下游实现，并判断该函数是否存在安全影响。

## 实际输入

本次没有把整个数据集送入模型，而是临时构造了一个只有一条结果的 `results.json`：

```json
{
  "results": [{
    "unit_id": "services/audio_policy/server/service/service_main/src/audio_policy_server.cpp:AudioPolicyServer::UnexcludeOutputDevices",
    "route_key": "services/audio_policy/server/service/service_main/src/audio_policy_server.cpp:AudioPolicyServer::UnexcludeOutputDevices",
    "finding": "inconclusive",
    "verdict": "INCONCLUSIVE",
    "reasoning": "Stage 1 could not establish whether the caller-derived vector and enum reach a dangerous operation because the downstream EventEntry and AudioSelectInterfaceService implementations were not included.",
    "attack_vector": "An authorized IPC caller may provide an empty or null-containing descriptor vector, an invalid enum value, or a large repeated request."
  }]
}
```

其中目标函数源码和 `code_by_route` 来自既有真实扫描产物中的
`analyzer_output.json`，不是重新解析生成的；函数源码为扫描时保存的修复前版本。

同时复用了：

- 真实函数索引：此前 `multimedia_audio_framework` 扫描生成的 `analyzer_output.json`，共 22,037 个函数；
- 真实 OpenHarmony 应用上下文：此前扫描生成的 `application_context.json`；
- 项目配置中的 `autodl-openai / gpt-5.6-luna`；
- 本地仓库目录：`source_code_base/multimedia_audio_framework`。

因此，Stage 2 可以通过 `search_definitions`、`search_usages`、`read_function`、
`list_functions` 在真实索引中查找下游函数，但不会重新判定其他 1,090 个分析单元。

## 运行结果

- Stage 2 输入：1 条 `inconclusive`；
- API 调用：1 次；
- 工具循环：模型报告执行 8 轮推理/工具交互；
- 总 token：59,961；
- 费用：¥0.058371；
- 最终结论：`inconclusive -> vulnerable`；
- 需人工审阅：0；
- 错误：0。

模型恢复的主要调用链为：

```text
AudioPolicyServer::UnexcludeOutputDevices
  -> AudioCoreService::EventEntry::UnexcludeOutputDevices
  -> AudioCoreService::UnexcludeOutputDevices
  -> AudioSelectInterfaceService::UnexcludeOutputDevices
  -> AudioSelectInterfaceService::UnexcludeOutputDevicesInner
  -> AudioRouterSelectStrategy::UnexcludeDevices
  -> AudioRouterInfra::UnexcludeDevice
```

模型指出 `audioDevUsageIn` 被直接转换为 `AudioDeviceUsage`，服务端没有验证枚举/位掩码；
例如 `-1` 转换后可能使下游 `excludedUsage & ~usage` 清除所有排除位，从而造成音频路由
状态被非预期修改。模型同时核对到空 vector、首元素为空和后续空元素在下游的处理，未将
这些场景未经证据支持地判定为空指针崩溃。

## 本地源码核验

对照本地源码后确认：

1. `audio_select_interface_service.cpp:707-708` 检查 vector 非空和首元素非空；
2. `audio_select_interface_service.cpp:749-750` 仍未检查 `AudioDeviceUsage` 的合法范围；
3. `audio_router_select_strategy.cpp:389-397` 跳过空元素并将 usage 继续下传；
4. `audio_router_infra.cpp:866-884` 使用 `it->second & ~usage` 修改排除状态；
5. `audio_info.h:1117-1168` 定义了有限的 `AudioDeviceUsage` 值；
6. 客户端 `AudioPolicyManager` 的数量限制不能替代服务端验证。

所以模型报告的“存在未验证 enum/bitmask 输入并影响状态”的主路径有源码依据；空指针
崩溃和超大 vector 属于次要或依赖条件更强的风险，不能与主结论混为一谈。

## 结论和边界

这次实验验证了“只对一个 Stage 1 待定函数运行 Stage 2”的可行性，也验证了 Stage 2
确实能够补齐下游调用上下文并将待定结果升级为漏洞。它不是一次完整端到端扫描：没有
验证 Stage 1 是否会自动把该函数判为 `inconclusive`，也没有执行动态测试或把恢复出的
边写回调用图。后续可以用相同方式批量抽取少量重点 `inconclusive` 条目做成本可控的真实
复核。
