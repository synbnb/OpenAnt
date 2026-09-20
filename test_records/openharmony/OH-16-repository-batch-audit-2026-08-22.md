# OH-16：16 个 OpenHarmony 仓库批量效果审计记录

## 1. 审计结论

本轮没有修改 VulnFounder 源码，只对用户提供的 16 个仓库执行静态验证。

- 15 个原始仓库完成了 OpenHarmony C/C++ pipeline：扫描、tree-sitter 函数提取、调用图、数据集生成和 `reachable` 入口过滤均成功。
- `arkui_ace_engine` 的全量尝试完成了 OpenHarmony 扫描、tree-sitter 提取、调用图和语义图构建，但在生成 143,121 个函数对应的数据集阶段耗时过长，人工中断；因此不能计为全量 pipeline 成功。
- 为了及时观察该大仓库的入口效果，从 `arkui_ace_engine` 选取 `adapter/ohos`、`interfaces/inner_api` 和 `component_ext` 建立临时样本，638 个文件的完整 pipeline 成功。样本结果只用于代表性验证，不替代全量结果。
- 所有运行均未启用 LLM、Agentic 或 CodeQL，命令只读源仓库，输出写入 `/private/tmp/openant-oh16-repo-audit`。

## 2. 实际执行命令

15 个全量仓库使用同一命令（仓库名按表格替换）：

```bash
VulnFounder/.venv/bin/python VulnFounder/libs/vulnfounder-core/parsers/c/test_pipeline.py \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output /private/tmp/openant-oh16-repo-audit/<repo> \
  --platform openharmony --skip-tests --processing-level reachable
```

`arkui_ace_engine` 样本使用同一 pipeline，输入临时目录 `/private/tmp/openant-oh16-ace-sample.J44DMx`，样本内容来自原仓库的 `adapter/ohos`、`interfaces/inner_api`、`component_ext`，并保留顶层 `bundle.json` 与 `BUILD.gn`。

## 3. 15 个全量仓库的 pipeline 指标

| 仓库 | 生产文件 | 函数 | 调用边 | 入口 | 可达单元 | 过滤比例 | 解析秒 | 语义节点/边/孤儿 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| window_window_manager | 1,089 | 24,033 | 33,862 | 52 | 2,647 | 88.9% | 263.00 | 89/86/168 |
| security_device_auth | 508 | 3,957 | 13,141 | 13 | 207 | 94.8% | 25.59 | 0/0/0 |
| security_certificate_manager | 252 | 1,526 | 3,266 | 7 | 174 | 88.6% | 5.46 | 0/0/0 |
| multimedia_video_processing_engine | 192 | 1,531 | 1,344 | 2 | 9 | 99.4% | 2.27 | 10/9/18 |
| multimedia_camera_framework | 1,092 | 13,771 | 13,356 | 18 | 179 | 98.7% | 74.39 | 0/0/0 |
| multimedia_audio_framework | 1,507 | 23,083 | 33,402 | 29 | 286 | 98.8% | 308.64 | 625/604/1,204 |
| filemanagement_storage_service | 349 | 3,355 | 4,568 | 53 | 161 | 95.2% | 59.38 | 2/1/2 |
| filemanagement_dfs_service | 570 | 4,223 | 4,592 | 56 | 181 | 95.7% | 45.93 | 76/74/145 |
| communication_ipc | 251 | 2,607 | 2,765 | 12 | 86 | 96.7% | 10.43 | 0/0/0 |
| systemabilitymgr_samgr | 97 | 1,153 | 989 | 31 | 91 | 92.0% | 3.59 | 0/0/0 |
| drivers_hdf_core | 1,096 | 8,139 | 12,394 | 347 | 1,852 | 77.2% | 30.39 | 0/0/0 |
| drivers_interface | 121 | 1,038 | 1,984 | 1 | 2 | 99.8% | 3.10 | 0/0/0 |
| ability_ability_runtime | 2,905 | 28,759 | 34,515 | 445 | 3,393 | 88.2% | 1,414.31 | 65/59/118 |
| arkui_napi | 217 | 3,508 | 4,779 | 4 | 7 | 99.8% | 5.86 | 0/0/0 |
| distributeddatamgr_datamgr_service | 619 | 4,668 | 5,313 | 91 | 403 | 91.4% | 57.66 | 0/0/0 |
| **合计** | **10,865** | **125,351** | **170,270** | **1,161** | **9,678** | **92.2%（按单元总量）** | **2,310.00** | **867/833/1,655** |

这里的“解析秒”是 pipeline 的 C parser stage，不包含仓库下载；`reachable` 过滤阶段合计约 17.33 秒。15 个仓库均生成了 `pipeline_results.json`，且结果中的必需 stage 成功。

## 4. 入口检测实际命中情况

15 个全量仓库最终保留的 1,161 个入口按检测原因归类如下：

| 入口类别 | 数量 | 说明 |
|---|---:|---|
| `platform:openharmony:binder_ipc` | 142 | `SendRequest`、IPC proxy 等边界 |
| `platform:openharmony:system_ability_lifecycle` | 166 | System Ability 生命周期入口 |
| `platform:openharmony:ability_lifecycle` | 205 | Ability/Extension 生命周期入口 |
| `platform:openharmony:hdf_dispatch` | 59 | HDF 服务/驱动分发入口 |
| `platform:openharmony:hdf_registration` | 272 | HDF 注册入口 |
| `input_pattern:*` | 293 | `Query`、`open`、`gets`、`File` 等外部输入/系统资源模式 |
| `unit_type:main` | 24 | 传统 `main` 入口 |

这说明平台无关的 `main`/输入模式和 OpenHarmony 专用入口已经同时生效；`drivers_hdf_core` 是 HDF 规则最明显的命中仓库（59 个分发入口、272 个注册入口）。

每个全量 pipeline 输出的可达单元都附带了 OpenHarmony `platform_context`（平台、source role、component、target、boundary、guard、evidence 等字段）；15 个仓库中可达单元全部有该上下文。

## 5. IPC/IDL 语义解析效果

直接调用当前 `OpenHarmonyIDLParser` 对 16 个原始仓库的结果如下（`arkui_ace_engine` 也单独做了只读 parser 检查）：

| 仓库 | IDL 文件 | 接口 | 方法 | 语义图结果 |
|---|---:|---:|---:|---|
| window_window_manager | 3 | 6 | 85 | 已生成 |
| multimedia_video_processing_engine | 1 | 1 | 9 | 已生成 |
| multimedia_camera_framework | 39 | 46 | **0** | 未生成有效事务 |
| multimedia_audio_framework | 30 | 28 | 602 | 已生成 |
| filemanagement_storage_service | 4 | 4 | 1 | 已生成 |
| filemanagement_dfs_service | 2 | 2 | 73 | 已生成 |
| drivers_hdf_core | 51 | 36 | 0 | HDF/IDL 方言尚未形成事务 |
| drivers_interface | 611 | 340 | 0 | HDF 接口描述，未形成事务 |
| ability_ability_runtime | 8 | 9 | 59 | 已生成 |
| arkui_ace_engine | 56 | 159 | 507 | 全量中断前已生成部分语义图 |
| 其余仓库 | 0 | 0 | 0 | 无 IDL |

15 个全量仓库中有 9 个产生语义图，累计 867 个节点、833 条边、1,655 个孤儿端点。边类型几乎全部是 `interface_to_transaction`（829 条），只有 2 条 `proxy_to_transaction` 和 2 条 `stub_to_transaction`；当前没有产生 `transaction_to_handler` 边。

更重要的是：15 个全量数据集的 `units_with_semantic_context` 均为 **0**。因此当前 resolver 已经能输出独立的 IPC 语义图，但这些事务边还没有真正注入到数据集单元的 `context_functions`/语义依赖中；这不是“函数没有上下游”的证明，而是当前语义图到 unit context 的连接仍未完成。

`multimedia_camera_framework` 是一个明确的覆盖缺口：其 39 个 IDL 文件能解析出接口和枚举，但所有接口方法都是 0。抽查真实文件 `services/camera_service/idls/ICameraService.idl` 可见方法带有 `[ipccode N]` 注解；当前词法规则没有消费这种方法前缀，所以静默丢失方法（无 parse failure）。这应作为后续 IDL parser 小阶段优先修复项。

## 6. `arkui_ace_engine` 全量与样本记录

全量扫描阶段的实际结果：

- 发现 19,089 个仓库文件，其中 10,853 个生产 C/C++ 文件进入解析；测试文件 5,844 个被跳过。
- tree-sitter 成功提取 143,121 个函数，未报告解析失败。
- 调用图生成 193,639 条边，43,397 个孤立函数。
- OpenHarmony IDL parser 发现 56 个 IDL、159 个接口、507 个方法；语义图生成 579 个节点、508 条边、1,014 个孤儿。
- 在生成数据集时人工中断，堆栈显示耗时集中在 `unit_generator.py:_platform_context_for_function()` 对每个函数重复解析 GN target source；因此没有全量 `dataset.json`、入口过滤和可达率结果。

受限样本（638 个文件、7,768 个函数）完整成功：

- 调用图 7,167 条边；入口 64 个；可达单元 358 个；过滤 95.3%。
- 样本不包含可解析 IDL 方法，因此语义图为 0；它只验证了 Ace 代码形态能通过 tree-sitter、OpenHarmony context 和入口过滤。

## 7. 结论与下一步建议

当前实现已经可以在 15 个真实 OpenHarmony 子仓库上稳定完成静态解析，并且平台入口检测确实命中了 Binder、SA/Ability 生命周期、HDF dispatch/registration 和输入模式；但从本轮实测应明确区分三件事：

1. **普通 C/C++ 解析和入口过滤：可用。** 15 个仓库全部成功，平均按单元保留约 7.8%。
2. **IDL/IPC 图构建：部分可用。** 9 个仓库产出图，但大量端点仍 unresolved，且尚未注入 unit 的 semantic context。
3. **大仓库性能：需要单独优化。** Ace 全量在 context 组装阶段出现明显的重复匹配开销；在修复前不应把全量 Ace 的结果用于覆盖率结论。

建议后续按以下顺序进入新的小阶段：先修复 `[ipccode ...]` 等 OpenHarmony IDL 方法前缀并为 camera 建立单独测试；再把 IPC semantic graph 映射到 unit 的 `context_functions`，用一个已知 proxy/stub 对做断言；最后优化 GN target source 的索引化匹配，再重新跑 `arkui_ace_engine` 全量。

## 8. 库型仓库 `--library-mode` 对照

本轮默认命令没有启用 `--library-mode`。对两个明显的库/接口型仓库做只读对照后，结果如下：

| 仓库 | 默认入口/可达 | `--library-mode` 入口/可达 | 结论 |
|---|---:|---:|---|
| drivers_interface | 1 / 2 | 993 / 1,034 | 默认结果严重裁剪公共接口 |
| arkui_napi | 4 / 7 | 2,053 / 2,213 | 默认结果严重裁剪公共 N-API 表面 |

因此后续 OpenHarmony pipeline 需要根据仓库类型自动选择库模式，或至少在报告中明确提示：当仓库没有可执行程序入口、但存在大量导出 API/接口定义时，不能直接把默认 `reachable` 结果当作完整攻击面。
