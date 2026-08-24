# OH-13C-1：收紧 `OnStart`/`OnStop` 的 SA 上下文判定

日期：2026-08-22  
阶段：OH-13C-1  
范围：只调整 System Ability 生命周期入口的上下文门控；不涉及 HDF 注册、Ability 新回调、N-API、ETS/Cangjie。

## 1. 原逻辑与修改逻辑

原逻辑：函数叶名称为 `OnStart` 或 `OnStop` 时，无论所属类、函数体和路径是什么，都直接标记为高置信度 `system_ability_lifecycle`。这会把普通组件的生命周期方法误认为 System Ability 入口。

修改后：

- `OnStart`/`OnStop` 必须满足较强的 SA/Service 上下文之一：
  - `SystemAbility`、`SystemAbilityManager`、`REGISTER_SYSTEM_ABILITY` 等明确符号；
  - `*Service`、`*ServiceStub`、`*ServiceProxy`、`*ServiceImpl` 类名约定；
  - `sa`、`system_ability`、`systemability`、`service/services` 路径段；
- 普通 `Ability`、`ExtensionAbility` 和视频处理对象的 `OnStart`/`OnStop` 不再自动命中；
- `OnAddSystemAbility`、`OnRemoveSystemAbility` 保留原有精确回调规则；
- `OnDump` 保留原有较宽松的上下文规则。

这是入口证据的收紧，不是污点分析：被识别为 SA 生命周期入口只表示它是框架运行根，不代表该函数自身一定直接接收攻击者字节。

## 2. 代码变更

- `libs/openant-core/utilities/agentic_enhancer/openharmony_entry_point_detector.py`
  - 新增 `_SA_LIFECYCLE_CONTEXT_RE`；
  - `OnStart`/`OnStop` 使用 `_has_sa_lifecycle_context`；
  - 保持其他 OpenHarmony 入口类别行为不变。
- `libs/openant-core/tests/platforms/test_openharmony_entry_points.py`
  - 新增普通视频组件 `VideoProcessingNativeBase::OnStart/OnStop` 不应命中的回归测试；
  - 新增 `JsWindowExtension::OnStart` 不应命中的回归测试。

## 3. 定向测试结果

### 3.1 单元和 OpenHarmony 回归

```text
tests/platforms/test_openharmony_entry_points.py       10 passed
tests/openharmony + 原生入口相关测试                  34 passed, 1 skipped
tests/platforms                                       50 passed, 4 skipped
```

### 3.2 16 个真实仓库复测

所有仓库均使用：

```text
RepositoryScanner(platform="openharmony", skip_tests=True)
→ FunctionExtractor
→ EntryPointDetector(platform="openharmony")
```

| 仓库 | 文件 | 函数 | 提取错误 | 全部入口种子 | OH 平台匹配 | SA 生命周期 |
|---|---:|---:|---:|---:|---:|---:|
| window_window_manager | 1,089 | 23,875 | 0 | 43 | 37 | 9 |
| security_device_auth | 508 | 3,950 | 0 | 11 | 9 | 6 |
| security_certificate_manager | 252 | 1,524 | 0 | 7 | 5 | 4 |
| multimedia_video_processing_engine | 192 | 1,528 | 0 | 2 | 2 | 2 |
| multimedia_camera_framework | 1,092 | 13,691 | 0 | 18 | 16 | 13 |
| multimedia_audio_framework | 1,507 | 23,015 | 0 | 29 | 17 | 15 |
| filemanagement_storage_service | 349 | 3,322 | 0 | 53 | 11 | 11 |
| filemanagement_dfs_service | 570 | 4,205 | 0 | 56 | 35 | 22 |
| communication_ipc | 251 | 2,604 | 0 | 12 | 8 | 0 |
| systemabilitymgr_samgr | 97 | 1,136 | 0 | 31 | 30 | 25 |
| drivers_hdf_core | 1,096 | 8,132 | 0 | 75 | 61 | 0 |
| drivers_interface | 121 | 1,036 | 0 | 1 | 0 | 0 |
| ability_ability_runtime | 2,905 | 28,718 | 0 | 248 | 111 | 44 |
| arkui_napi | 217 | 3,483 | 0 | 4 | 0 | 0 |
| arkui_ace_engine | 10,853 | 142,227 | 0 | 89 | 15 | 6 |
| distributeddatamgr_datamgr_service | 619 | 4,659 | 0 | 91 | 22 | 12 |

汇总：16/16 仓库成功，21,718 个 production C/C++ 文件，267,105 个函数，0 个提取错误，379 个 OH 平台匹配。

关键验证：`multimedia_video_processing_engine` 的 SA 生命周期匹配从 OH-13 的 12 个降为 2 个；保留 `VideoProcessingServer::OnStart/OnStop`，去除了 `VideoProcessingNativeBase` 和多个 `*VideoNative` 普通对象的误报。

### 3.3 完整测试集

```text
3,054 passed, 40 skipped, 23 failed
```

23 个失败与本阶段无关：

- 1 个 Go conformance 测试因环境中没有 `go` 可执行文件失败；
- 其余为既有 Python parser/样例仓库测试，样例扫描得到 0 个 Python 文件，随后触发 `standalone_functions` 缺失等错误；
- 失败堆栈未涉及本次 OpenHarmony detector 文件或 C/C++ pipeline。

## 4. 结论

OH-13C-1 达到阶段目标：收紧了已确认的 `OnStart`/`OnStop` 误报，同时保留真实 System Ability 服务的命中，且 16 个真实仓库均无 C/C++ 提取错误。

下一阶段仍应单独处理 HDF_INIT/HdfDriverEntry、Ability 生命周期回调和 N-API/ANI/FFI 桥接，不在本阶段扩大修改范围。

