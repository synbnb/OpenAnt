# OH-13C-3：Ability 生命周期回调分类

日期：2026-08-22  
阶段：OH-13C-3  
范围：只增加 C/C++ Ability 生命周期回调分类；不处理 N-API、ANI、FFI、ETS/Cangjie 入口。

## 1. 原逻辑与修改逻辑

原逻辑已经能够识别 Binder `OnRemoteRequest`、System Ability 生命周期以及 HDF dispatch/registration，但没有单独识别 Ability 生命周期回调。因而 `OnForeground`、`OnBackground`、`OnNewWant`、`OnConnect`、`OnDisconnect` 等回调会被遗漏；另一方面，直接按方法名识别 `OnStart/OnStop` 会把普通组件或名称含 Ability 的 System Ability 错误标记为系统能力入口。

修改后增加独立的 `ability_lifecycle` 证据类别：

1. 仅对 `OnStart`、`OnStop`、`OnForeground`、`OnBackground`、`OnNewWant`、`OnConnect`、`OnDisconnect`、`OnCommand`、`OnContinue`、`OnSaveData`、`OnRestoreData` 等受控回调名继续判断；
2. 需要同时满足 Ability/Extension 类名、`Want`/`SessionInfo`/`AbilityTransactionCallbackInfo` 等上下文，或 OpenHarmony Ability 相关目录路径；
3. System Ability 上下文优先级更高。检测到 `SystemAbility`、注册/发布调用或 `_sa.cpp` 等证据时，`OnStart/OnStop` 归入 `system_ability_lifecycle`，不再归入 Ability；
4. 普通 `VideoProcessingNativeBase::OnStart/OnStop`、`ShellCommand::OnCommand` 等无 Ability 上下文的方法保持不匹配；
5. 该类别表示框架生命周期运行时根，不宣称回调本身就是攻击者直接输入点。`OnNewWant`、`OnConnect` 等参数可能携带外部请求数据，后续仍需通过参数/调用链和 IPC/权限模型判断可控性。

## 2. 修改文件

- `libs/vulnfounder-core/utilities/agentic_enhancer/openharmony_entry_point_detector.py`
  - 增加 Ability 上下文、类名和路径规则；
  - 增加 `ability_lifecycle` 匹配；
  - 增加 System Ability 优先级，修正名称含 Ability 的系统服务误报。
- `libs/vulnfounder-core/tests/platforms/test_openharmony_entry_points.py`
  - 增加 Ability 回调、System Ability 优先级和无关 `OnCommand` 的回归用例。

本阶段复用了 OH-13C-2 已建立的文件证据传递链路；没有改变 generic 平台的默认检测行为。

## 3. 定向测试结果

执行目录：`libs/vulnfounder-core`

```text
../../.venv/bin/python -m pytest tests/platforms tests/openharmony tests/parsers/c -q
168 passed, 6 skipped in 0.52s
```

另外执行：

```text
../../.venv/bin/python -m py_compile \
  utilities/agentic_enhancer/openharmony_entry_point_detector.py \
  utilities/agentic_enhancer/entry_point_detector.py \
  parsers/c/call_graph_builder.py parsers/c/test_pipeline.py \
  core/parser_adapter.py
git diff --check
```

两项均通过。

## 4. 16 个真实 OpenHarmony 仓库审计

每个仓库执行同一条实际链路：

```text
RepositoryScanner(platform="openharmony", skip_tests=True)
→ FunctionExtractor
→ CallGraphBuilder(platform="openharmony")
→ EntryPointDetector(file_evidence=...)
```

表中“Ability”是新增 `ability_lifecycle` 数量；“SA”是 `system_ability_lifecycle`；“Binder”是 `binder_ipc`；HDF 两列仅适用于 HDF 注册/dispatch。

| 仓库 | production 文件 | 函数 | 提取错误 | Ability | SA | Binder | HDF dispatch | HDF 注册 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| window_window_manager | 1,089 | 23,875 | 0 | 8 | 10 | 28 | 0 | 0 |
| security_device_auth | 508 | 3,950 | 0 | 0 | 8 | 3 | 0 | 0 |
| security_certificate_manager | 252 | 1,524 | 0 | 0 | 4 | 1 | 0 | 0 |
| multimedia_video_processing_engine | 192 | 1,528 | 0 | 0 | 2 | 0 | 0 | 0 |
| multimedia_camera_framework | 1,092 | 13,691 | 0 | 0 | 13 | 3 | 0 | 0 |
| multimedia_audio_framework | 1,507 | 23,015 | 0 | 0 | 15 | 2 | 0 | 0 |
| filemanagement_storage_service | 349 | 3,322 | 0 | 0 | 11 | 0 | 0 | 0 |
| filemanagement_dfs_service | 570 | 4,205 | 0 | 0 | 22 | 13 | 0 | 0 |
| communication_ipc | 251 | 2,604 | 0 | 0 | 0 | 8 | 0 | 0 |
| systemabilitymgr_samgr | 97 | 1,136 | 0 | 0 | 25 | 5 | 0 | 0 |
| drivers_hdf_core | 1,096 | 8,132 | 0 | 0 | 0 | 2 | 59 | 272 |
| drivers_interface | 121 | 1,036 | 0 | 0 | 0 | 0 | 0 | 0 |
| ability_ability_runtime | 2,905 | 28,718 | 0 | 197 | 44 | 67 | 0 | 0 |
| arkui_napi | 217 | 3,483 | 0 | 0 | 0 | 0 | 0 | 0 |
| arkui_ace_engine | 10,853 | 142,227 | 0 | 24 | 6 | 9 | 0 | 0 |
| distributeddatamgr_datamgr_service | 619 | 4,659 | 0 | 0 | 12 | 10 | 0 | 0 |

汇总：16/16 个仓库成功；21,718 个 production C/C++ 文件；267,105 个函数；0 个提取错误。新增 Ability 分类共 229 个，分布在 `window_window_manager`、`ability_ability_runtime` 和 `arkui_ace_engine`；其余仓库没有被无上下文规则误报。HDF 数量沿用 OH-13C-2 的验证结果：`drivers_hdf_core` 有 59 个 dispatch、272 个注册回调。

## 5. 代表性样例

- `ability_ability_runtime`：`OnForeground`、`OnBackground`、`OnNewWant`、`OnConnect`、`OnContinue` 等均按 `ability_lifecycle` 输出；其中 `OnNewWant` 的 `Want` 参数提供了明确 Ability 上下文。
- `window_window_manager`：`JsWindowExtension::OnStart`、`OnNewWant`、`OnConnect` 等被识别为 Ability 生命周期，而非 System Ability。
- `security_device_auth`：`DeviceAuthAbility::OnStart/OnStop` 位于 `deviceauth_sa.cpp`，具有 `SystemAbility`/`Publish` 语义，最终只输出 `system_ability_lifecycle`；这验证了 System Ability 优先级修正。
- `ShellCommand::OnCommand`：没有 Ability 类、参数或路径上下文，结果为空。

## 6. 结论与边界

OH-13C-3 已完成：Ability 生命周期回调现在与 System Ability 生命周期分层，真实仓库审计没有出现因方法名泛化造成的跨组件误报，测试与语法检查均通过。

本阶段仍只覆盖 C/C++ 方法。N-API/ANI/FFI 桥接函数、IDL 生成代码以及 ETS/Cangjie Ability 实现需要后续阶段单独建模；同时应继续把“框架生命周期根”和“直接接收外部输入”作为不同证据层处理。
