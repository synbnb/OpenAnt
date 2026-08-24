# OH-13C-2：HDF 文件级注册入口证据

日期：2026-08-22  
阶段：OH-13C-2  
范围：只增加 `HDF_INIT/HdfDriverEntry` 注册证据，不处理 Ability、N-API、ETS/Cangjie。

## 1. 原逻辑与修改逻辑

原逻辑只把函数元数据交给 `EntryPointDetector`。`HDF_INIT(g_entry)` 是文件级宏调用，通常位于函数定义之外，因此不会进入任何函数的 tree-sitter body；已有规则只能识别带 HDF 参数/路径的 `*Dispatch` 函数。

修改后：

1. C 调用图阶段在 OpenHarmony 模式下对已扫描文件做有界、只读文本检查；
2. 识别实际的 `HDF_INIT(entry)` 调用；
3. 查找同文件 `struct HdfDriverEntry entry = { ... }` 中的 `.Bind/.Init/.Release` 函数指针；
4. 将结果写入 `call_graph.json` 的 `openharmony_file_evidence`；
5. 入口检测器只标记被注册结构实际引用的回调函数，类别为 `hdf_registration`，不会把整个文件的普通函数全部标记为入口；
6. `NULL/nullptr` 函数指针不计为回调；generic 平台不产生 OpenHarmony 文件证据字段。

该证据代表 HDF 框架注册/调用边界，是运行时根，不等同于函数本身一定直接接收攻击者数据。

## 2. 修改文件

- `utilities/agentic_enhancer/openharmony_entry_point_detector.py`
  - 新增 HDF 注册文本识别、回调关联和 `hdf_registration` 证据；
  - 新增有界路径校验和文件读取；
  - 排除 `NULL/nullptr` 回调。
- `utilities/agentic_enhancer/entry_point_detector.py`
  - 增加可选 `file_evidence` 参数，并按函数文件路径合并平台证据。
- `parsers/c/call_graph_builder.py`
  - OpenHarmony 模式收集文件证据并持久化到调用图；generic 模式保持原输出形态。
- `parsers/c/test_pipeline.py`、`core/parser_adapter.py`
  - 将调用图中的 OpenHarmony 文件证据传递给入口检测器。
- `tests/platforms/test_openharmony_entry_points.py`
  - 增加单元、调用图持久化和完整 C pipeline 回归测试。

## 3. 测试结果

### 3.1 定向回归

```text
tests/platforms/test_openharmony_entry_points.py       13 passed
OpenHarmony + C parser 相关测试                         125 passed, 2 skipped
```

另外执行了 `py_compile` 和 `git diff --check`，均通过。

### 3.2 16 个真实仓库

每个仓库执行：

```text
RepositoryScanner(platform="openharmony", skip_tests=True)
→ FunctionExtractor
→ CallGraphBuilder(platform="openharmony")
→ EntryPointDetector(file_evidence=...)
```

| 仓库 | production 文件 | 函数 | 提取错误 | HDF 注册文件 | 注册数 | 回调数 | 回调命中 |
|---|---:|---:|---:|---:|---:|---:|---:|
| window_window_manager | 1,089 | 23,875 | 0 | 0 | 0 | 0 | 0 |
| security_device_auth | 508 | 3,950 | 0 | 0 | 0 | 0 | 0 |
| security_certificate_manager | 252 | 1,524 | 0 | 0 | 0 | 0 | 0 |
| multimedia_video_processing_engine | 192 | 1,528 | 0 | 0 | 0 | 0 | 0 |
| multimedia_camera_framework | 1,092 | 13,691 | 0 | 0 | 0 | 0 | 0 |
| multimedia_audio_framework | 1,507 | 23,015 | 0 | 0 | 0 | 0 | 0 |
| filemanagement_storage_service | 349 | 3,322 | 0 | 0 | 0 | 0 | 0 |
| filemanagement_dfs_service | 570 | 4,205 | 0 | 0 | 0 | 0 | 0 |
| communication_ipc | 251 | 2,604 | 0 | 0 | 0 | 0 | 0 |
| systemabilitymgr_samgr | 97 | 1,136 | 0 | 0 | 0 | 0 | 0 |
| drivers_hdf_core | 1,096 | 8,132 | 0 | 101 | 101 | 272 | 272 |
| drivers_interface | 121 | 1,036 | 0 | 0 | 0 | 0 | 0 |
| ability_ability_runtime | 2,905 | 28,718 | 0 | 0 | 0 | 0 | 0 |
| arkui_napi | 217 | 3,483 | 0 | 0 | 0 | 0 | 0 |
| arkui_ace_engine | 10,853 | 142,227 | 0 | 0 | 0 | 0 | 0 |
| distributeddatamgr_datamgr_service | 619 | 4,659 | 0 | 0 | 0 | 0 | 0 |

汇总：16/16 仓库成功；21,718 个 production C/C++ 文件；267,105 个函数；0 个提取错误。只有 `drivers_hdf_core` 包含 HDF 注册，识别到 101 个真实 `HDF_INIT` 调用、272 个非空回调引用，272 个回调全部关联到函数入口。

## 4. 真实样例验证

以 `drivers_hdf_core/framework/sample/platform/uart/src/uart_sample.c` 为例：

```c
struct HdfDriverEntry g_sampleUartDriverEntry = {
    .Bind = SampleUartDriverBind,
    .Init = SampleUartDriverInit,
    .Release = SampleUartDriverRelease,
};
HDF_INIT(g_sampleUartDriverEntry);
```

检测结果将 `SampleUartDriverBind`、`SampleUartDriverInit`、`SampleUartDriverRelease` 标记为 `platform:openharmony:hdf_registration`，而同文件的普通 `SampleUartHost*` 辅助函数不会因位于同一文件而被标记。

## 5. 结论

OH-13C-2 达到目标：HDF 文件级注册已经进入 OpenHarmony 入口证据链，并且通过了真实 `drivers_hdf_core` 仓库验证；没有对其他 15 个仓库产生误报。

下一阶段可以处理 Ability 生命周期回调分类，但应继续保持“框架注册/回调证据”和“直接外部输入入口”分层，不能把所有 Ability 方法无条件视为攻击者输入入口。

