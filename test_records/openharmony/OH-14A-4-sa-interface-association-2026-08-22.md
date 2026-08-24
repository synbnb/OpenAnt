# OH-14A-4：SA profile ↔ IDL/interface 关联

日期：2026-08-22  
阶段：OH-14A-4  
范围：在 OpenHarmony 语义图中增加 System Ability（SA）profile 与 IDL interface 的可审计关联；不接入 scanner/reachability 主流程。

## 1. 原逻辑与修改逻辑

OH-14A-1～OH-14A-3 已能表达 IDL interface、IPC transaction、Proxy、Stub 和 native handler，但 SA profile 仍然是独立的构建/运行时元数据。原图无法回答“哪个 SA/process/libpath 提供这个 IPC interface”，也无法区分一个 SA profile 是否没有对应的 IDL 证据。

本阶段修改为：

1. 将 `SAParseResult`/`SAProfile` 或等价字典归一化为按 `sa_id` 分组的记录；保留 profile 路径、process、libpath、权限、extension、启动/分布式/重启/dump 元数据；
2. 为每个 SA 创建稳定节点 `sa:<sa_id>`，节点类型为 `system_ability`；同一 SA ID 出现在多个 profile 时合并集合，避免重复节点；
3. 基于 IDL interface stem 与 SA `libpath`/process 的规范化 token 生成 `system_ability_to_interface` 边；若 libpath/process 证据不足，则允许以“interface owner 出现在 SA native 路径”作为较低置信度的次级证据；
4. 直接匹配时置信度为 `0.95`，native 路径次级匹配时为 `0.85`。每条边保留 profile 路径、SA ID、process、libpath、匹配 token/信号和权限；
5. 一个 interface 匹配多个 SA、interface 没有匹配证据、SA 没有匹配 interface 时分别写入 `ambiguous_system_ability_interface`、`unresolved_interface_system_ability`、`unresolved_system_ability_interface` orphan，不根据名称静默猜测；
6. 修正 owner 匹配：保留 owner 与 interface stem 的原始精确匹配，再处理 `Stub/Proxy/Impl/Service` 等后缀，避免 `AudioService` 这类合法 owner 被过早截断。

当前 resolver 仍以“有方法的 IDL interface”为图中的接口集合；无方法/仅前向声明的 interface 仍属于后续覆盖项。

## 2. 修改文件

- `libs/openant-core/core/platforms/openharmony/ipc_graph.py`
  - 增加 SA 记录归一化、SA 节点属性和接口匹配辅助逻辑；
  - `OpenHarmonyIPCResolver.resolve`/`resolve_dict` 增加可选 `sa_result` 参数；
  - 增加 SA 节点、`system_ability_to_interface` 边和三类 SA/interface orphan；
  - 保持原有 IDL→transaction、Proxy、Stub、handler 解析行为。
- `libs/openant-core/tests/platforms/test_openharmony_sa_ipc_graph.py`
  - 覆盖 libpath/process 正例、权限/生命周期元数据保留、native 路径次级证据、歧义/未匹配 orphan、序列化字典输入。

## 3. 定向测试结果

语法检查与 SA/IPC 专项测试：

```text
../../.venv/bin/python -m py_compile core/platforms/openharmony/ipc_graph.py
../../.venv/bin/python -m pytest \
  tests/platforms/test_openharmony_sa_ipc_graph.py \
  tests/platforms/test_openharmony_ipc_graph.py -q
11 passed in 0.02s
```

OpenHarmony 与 C parser 回归：

```text
../../.venv/bin/python -m pytest \
  tests/platforms tests/openharmony tests/parsers/c -q
182 passed, 6 skipped in 0.53s
```

另外检查了 `git diff --check`，无空白错误。

## 4. 真实 OpenHarmony 仓库验证

验证仓库：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_wifi
```

流程：

```text
RepositoryScanner(platform="openharmony", skip_tests=True)
→ C/C++ FunctionExtractor
→ OpenHarmonyIDLParser.collect
→ OpenHarmonySAProfileParser.collect
→ OpenHarmonyIPCResolver.resolve(..., sa_result)
```

结果：

| 项目 | 数量 |
|---|---:|
| production C/C++ 文件 | 683 |
| 跳过的测试文件 | 403 |
| native 函数 | 9,263 |
| IDL 文件 | 5 |
| IDL interface | 6 |
| IDL methods | 43 |
| SA profile 文件 | 4 |
| SA ability | 4 |
| 图节点 | 51 |
| 图边 | 47（43 `interface_to_transaction`、4 `system_ability_to_interface`）|
| orphan | 88（43 `unresolved_ipc_proxy`、43 `unresolved_ipc_stub`、2 `unresolved_system_ability_interface`）|

识别到的真实 SA/interface 关联：

```text
sa:1121 → OHOS.Wifi.IWifiHotspot
sa:1121 → OHOS.Wifi.IWifiHotspotMgr
sa:1124 → OHOS.Wifi.IWifiScan
sa:1124 → OHOS.Wifi.IWifiScanMgr
```

四条边置信度均为 `0.95`，证据来自真实 profile：

```text
wifi/services/wifi_standard/sa_profile/1121.json
  libwifi_hotspot_ability.z.so

wifi/services/wifi_standard/sa_profile/1124.json
  libwifi_scan_ability.z.so
```

`1120/libwifi_device_ability.z.so` 和 `1123/libwifi_p2p_ability.z.so` 在这组 IDL 中没有可确定匹配，因此保留为 `unresolved_system_ability_interface`，没有伪造边。

## 5. 结论与边界

OH-14A-4 已完成 SA profile 到 IDL interface 的独立语义关联，并在真实 `communication_wifi` 仓库上产生了可复核的四条跨边界边。SA 的 process/libpath/权限/生命周期信息现在可以沿语义图查询，未匹配和歧义关系也不会静默丢失。

本阶段没有改变入口筛选、scanner 的文件范围、reachability、LLM 分析或报告主流程；后续阶段再决定如何把语义图作为入口上下文和可达性证据消费。
