# OH-13B：新增 16 个 OpenHarmony 仓库原生入口逐仓审计记录

日期：2026-08-22  
阶段：OH-13B（只读审计，不修改生产代码）  
目标：验证 OH-13 已实现的 OpenHarmony C/C++ 原生入口检测在新增仓库上的实际效果，并识别下一阶段必须补齐的入口类型。

## 1. 测试范围与流程

本次对新下载的 16 个仓库逐一执行同一条流水线：

1. `RepositoryScanner(platform="openharmony", skip_tests=True)`：只纳入 OpenHarmony production scope 的 C/C++ 文件；
2. `FunctionExtractor.extract_from_scan`：使用 tree-sitter 提取函数；
3. `EntryPointDetector(platform="openharmony")`：执行通用入口检测和 OH-13 原生入口检测；
4. 汇总提取错误、全部入口种子、平台原生匹配及其类别。

说明：`entries` 是检测器产生的全部入口种子，包含通用输入模式；`platform_categories` 只统计 OH-13 的平台证据，因此两者不应直接相等。测试目录/fuzz 目录没有进入 production pipeline，但另行做了静态覆盖审计。

## 2. 逐仓实际测试结果

| 仓库 | eligible C/C++ 文件 | 提取函数 | 提取错误 | 全部入口种子 | OH 原生匹配 | 平台类别 |
|---|---:|---:|---:|---:|---:|---|
| window_window_manager | 1,089 | 23,875 | 0 | 46 | 40 | binder 28；SA 生命周期 12 |
| security_device_auth | 508 | 3,950 | 0 | 13 | 11 | binder 3；SA 生命周期 8 |
| security_certificate_manager | 252 | 1,524 | 0 | 7 | 5 | binder 1；SA 生命周期 4 |
| multimedia_video_processing_engine | 192 | 1,528 | 0 | 12 | 12 | SA 生命周期 12 |
| multimedia_camera_framework | 1,092 | 13,691 | 0 | 24 | 22 | binder 3；SA 生命周期 19 |
| multimedia_audio_framework | 1,507 | 23,015 | 0 | 29 | 17 | binder 2；SA 生命周期 15 |
| filemanagement_storage_service | 349 | 3,322 | 0 | 53 | 11 | SA 生命周期 11 |
| filemanagement_dfs_service | 570 | 4,205 | 0 | 56 | 35 | binder 13；SA 生命周期 22 |
| communication_ipc | 251 | 2,604 | 0 | 12 | 8 | binder 8 |
| systemabilitymgr_samgr | 97 | 1,136 | 0 | 31 | 30 | binder 5；SA 生命周期 25 |
| drivers_hdf_core | 1,096 | 8,132 | 0 | 75 | 61 | binder 2；HDF dispatch 59 |
| drivers_interface | 121 | 1,036 | 0 | 1 | 0 | 无 |
| ability_ability_runtime | 2,905 | 28,718 | 0 | 332 | 195 | binder 67；SA 生命周期 128 |
| arkui_napi | 217 | 3,483 | 0 | 4 | 0 | 无 |
| arkui_ace_engine | 10,853 | 142,227 | 0 | 103 | 29 | binder 9；SA 生命周期 20 |
| distributeddatamgr_datamgr_service | 619 | 4,659 | 0 | 91 | 22 | binder 10；SA 生命周期 12 |

汇总：16/16 仓库完成，16/16 扫描和提取成功，0 个提取错误，0 个超时；共处理 21,718 个 production C/C++ 文件和 267,105 个函数，检测到 498 个 OH-13 平台原生匹配（按函数匹配计数）。

## 3. 对检测效果的判断

### 已验证有效的部分

- Binder/IPC：在 window、security、filemanagement、communication、ability、distributed data 等仓库实际命中了 `OnRemoteRequest`；
- System Ability：在 SAMgr、ability、window、multimedia 等服务中命中了 `OnAddSystemAbility`、`OnRemoveSystemAbility`、`OnStart`、`OnStop`，并对具备上下文的 `OnDump` 进行了限制；
- HDF dispatch：在 `drivers_hdf_core` 实际命中了 59 个带 HDF 签名或驱动路径证据的 dispatch 函数；
- tree-sitter 对这 16 个仓库的 production C/C++ 文件没有产生提取错误，说明当前解析链路可运行。

### 已确认需要补齐的覆盖缺口

1. **HDF 注册入口仍未检测**：`drivers_hdf_core` 中静态发现 274 处 `HDF_INIT/HdfDriverEntry` 使用（分布在 110 个文件），当前检测器只看到部分 dispatch 函数，不能把文件级驱动注册和 `HdfDriverEntry` 生命周期作为证据。
2. **Ability 生命周期不完整**：`ability_ability_runtime` 中静态发现大量 `OnForeground/OnBackground/OnNewWant/OnConnect/OnDisconnect` 等回调；当前只覆盖 `OnStart/OnStop/OnDump/OnAddSystemAbility/OnRemoveSystemAbility`，会漏掉应用/扩展 Ability 的真实框架回调。
3. **N-API/ANI/FFI/Taihe 注册未建模**：window、camera、audio、ability、arkui_napi、ace_engine 等仓库含大量 N-API 注册和桥接代码，但当前 OH-13 不会把注册函数、导出函数与其回调建立入口证据。
4. **ETS/ArkTS/Cangjie 未进入本次 native detector**：新增仓库中存在大量 ETS 文件（尤其 `arkui_ace_engine`、`ability_ability_runtime`）以及少量 Cangjie 文件；C/C++ 检测不能覆盖这些语言侧入口，也不能表达 ETS → native 的桥接关系。
5. **Fuzz/test 角色需要单独标记**：仓库包含大量 fuzz/test 文件。它们可以作为测试入口统计，但不应默认当作生产外部入口；当前 production scope 会排除它们，尚未输出独立的“测试入口/生产入口”证据层。

### 已确认的误报风险

当前 `OnStart/OnStop` 对所有同名函数直接给出高置信 SA 生命周期证据。`multimedia_video_processing_engine` 中的 `VideoProcessingNativeBase::OnStart/OnStop` 以及多个 `*VideoNative::OnStart/OnStop` 实际是视频处理对象的 Start/Stop 操作，并非 System Ability 回调，但已被当前规则命中。说明这两个通用名称不能继续无上下文高置信处理，应增加 SA/service 上下文约束并区分普通对象生命周期。

## 4. 结论与下一步建议

结论：**OpenHarmony 原生入口检测现在仍需要修改**。OH-13 已经在真实仓库上验证了 Binder、SA 部分生命周期和 HDF dispatch 的可用性，但还不能宣称“入口检测全面”，并且存在 `OnStart/OnStop` 的可观测误报。

建议不要直接进入 OH-14，而是先进行一个新的小阶段 OH-13C（需用户确认后修改）：

1. 先收紧 `OnStart/OnStop` 的 SA 上下文判定，补充回归样例，避免把普通组件 Start/Stop 当成 SA 根；
2. 增加文件/宏级 HDF 注册证据（`HDF_INIT`、`HdfDriverEntry`），与函数级 `hdf_dispatch` 分开记录；
3. 增加 Ability 生命周期回调白名单及上下文分类；
4. 明确 N-API/ANI/FFI/Taihe 的桥接证据模型，暂不把所有普通导出函数无条件当入口；
5. 再决定是否扩展 ETS/Cangjie 解析器和跨语言边；这属于后续阶段，不应在本次 C/C++ 规则修补中混入。

本记录对应的仓库克隆与提交信息见：[OH-13-corpus-expansion-2026-08-22.md](OH-13-corpus-expansion-2026-08-22.md)。
