# OH-22B-2D：文件级初始化列表 Lambda 观测测试记录

日期：2026-08-27
平台：OpenHarmony
验证仓库：`telephony_core_service`
验证路径：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/telephony_core_service`

## 1. 本阶段目的

OH-22B-2C 已经能够把不同函数中的字段写入和字段读取关联起来，但真实源码中仍有 4 个调用点没有候选目标：

```text
services/core/src/core_service_common_event_hub.cpp:CoreServiceCommonEventHub::OnReceiveEvent
services/network_search/src/cell_info.cpp:CellInfo::ProcessNeighboringCellInfo
services/network_search/src/network_search_handler.cpp:NetworkSearchHandler::ProcessEvent
services/sim/src/sim_state_handle.cpp:SimStateHandle::ProcessEvent
```

检查源码后确认，这些表的 Lambda 注册不是函数体中的 `table[key] = lambda`，而是全局/静态初始化列表，或者函数体中的 `table = {{key, lambda}, ...}`。此前函数抽取结果只保存函数单元，因此全局静态表没有进入可供诊断复查的输入。

本阶段的目标是补充这类注册的“观察证据”，而不是把它们直接提升为 Native 调用图边。

## 2. 原逻辑与修改后逻辑

### 原逻辑

函数抽取器只导出：

- 函数记录及函数源码；
- include、宏、原型和类继承信息。

Lambda 诊断器随后只遍历函数源码中的赋值表达式。例如下列函数体内写法可以被识别：

```cpp
memberFuncMap_[code] = [](Event event) {
    return HandleEvent(event);
};
```

但下面的真实 OpenHarmony 写法不属于任何函数单元：

```cpp
const std::map<int, Handler> NetworkSearchHandler::memberFuncMap_ = {
    {READY, [](NetworkSearchHandler *handler, const Event &event) {
        handler->HandleEvent(event);
    }}
};
```

因此原逻辑既看不到表声明，也无法把它与 `ProcessEvent` 中的 `find`/`second` 调用关联。

### 修改后逻辑

1. C/C++ 函数抽取器新增轻量 `source_files` 索引，只保存已成功处理的仓库相对路径和语言，不在抽取结果中重复保存整份源码。
2. OpenHarmony 诊断器对这些已校验的路径重新读取源码，并用 tree-sitter 遍历文件级初始化列表。
3. 只接受结构明确的 `{selector, lambda}` 条目；通过初始化列表前的 `=` 恢复 `Class::field` 表达式。
4. Lambda 参数类型与类名用于解析 `handler->HandleEvent(...)` 等调用；目标函数仍须在函数索引中唯一解析成功。
5. 函数体中的 `table = {{selector, lambda}, ...}` 也统一使用相同的证据格式，并增加 `registration_form` 区分来源：

   - `subscript_assignment`：`table[key] = lambda`；
   - `initializer_list`：函数体内的 `table = {{key, lambda}}`；
   - `file_initializer_list`：文件级/静态表初始化。

6. 所有结果继续写入 `call_graph_residuals.json` 的 `lambda_dispatch`，不进入 `dispatch_assignments`，不会未经审核修改 Native 调用图、可达性结果或语义图。

## 3. 自动化测试

### 3.1 定向诊断测试

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py
```

本阶段新增并验证：

- 文件级静态 map 的 Lambda 能被观察；
- `memberFuncMap_` 不会被错误地加入函数单元；
- `handler->HandleEvent` 能通过 Lambda 参数类型解析；
- 函数体初始化列表和原有下标赋值共用相同证据字段；
- 观察结果能与调用点候选目标关联。

结果：`11 passed`。

### 3.2 OpenHarmony/IPC/C 解析回归

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py \
  libs/vulnfounder-core/tests/parsers/c
```

结果：`212 passed, 2 skipped`。

### 3.3 代码质量检查

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/ruff check \
  libs/vulnfounder-core/parsers/c/function_extractor.py \
  libs/vulnfounder-core/core/platforms/openharmony/call_graph_diagnostics.py \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py
```

结果：`All checks passed`。

## 4. 真实仓库解析

为避免大模型费用，只执行解析阶段：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/telephony_core_service \
  --output debug_outputs/OH-22B-2D-telephony-initializer-lambda-20260827-parse-c \
  --platform openharmony --language c --level all --fresh
```

本次真实解析结果：

| 指标 | 数值 |
| --- | ---: |
| 发现文件 | 1,056 |
| 纳入 C/C++ 解析文件 | 540 |
| 成功解析文件 | 540 |
| 解析失败 | 0 |
| C/C++ 函数抽取记录 | 6,913 |
| 生成分析单元 | 6,842 |
| 原生调用图边 | 7,196 |
| 跳过测试角色文件 | 240 |
| 跳过 fuzz 角色文件 | 71 |
| 源码总大小 | 4,958,097 bytes |
| 解析耗时 | 37.12 秒 |
| 大模型调用 | 0 |

## 5. Lambda 诊断结果

本次 `call_graph_residuals.json` 的 `lambda_dispatch.summary` 为：

```json
{
  "dispatch_assignments": 347,
  "call_sites": 16,
  "candidate_edges": 320,
  "unresolved_without_candidates": 0,
  "orphan_assignments": 17,
  "field_alias_matches": 108
}
```

与 OH-22B-2C 基线相比：

| 指标 | OH-22B-2C | OH-22B-2D | 变化 |
| --- | ---: | ---: | ---: |
| Lambda 注册记录 | 243 | 347 | +104 |
| 调用点 | 16 | 16 | 0 |
| 候选目标边 | 241 | 320 | +79 |
| 无候选调用点 | 4 | 0 | -4 |
| 字段关联证据 | 43 | 108 | +65 |
| orphan 注册记录 | 0 | 17 | +17 |

新增注册来源分布：

| 注册形式 | 记录数 | 说明 |
| --- | ---: | --- |
| `subscript_assignment` | 243 | 原有函数体内 `table[key] = lambda` |
| `initializer_list` | 22 | `CoreServiceCommonEventHub::InitHandlersFunc` 的事件表 |
| `file_initializer_list` | 82 | 3 个静态成员表和 `EventSender` 的 4 个全局表 |

## 6. 4 个原无候选调用点的源码核对

本次所有调用点均已保留，且都获得了候选目标：

| 源码调用点 | 表 | 候选目标数 | 注册记录数 |
| --- | --- | ---: | ---: |
| `CoreServiceCommonEventHub::OnReceiveEvent:304` | `actionHandlersMap_` | 22 | 22 |
| `CellInfo::ProcessNeighboringCellInfo:111` | `memberFuncMap_` | 6 | 6 |
| `NetworkSearchHandler::ProcessEvent:466` | `memberFuncMap_` | 42 | 45 |
| `SimStateHandle::ProcessEvent:834` | `memberFuncMap_` | 9 | 14 |

`NetworkSearchHandler` 的 45 条注册对应 42 个不同目标函数，`SimStateHandle` 的 14 条注册对应 9 个不同目标函数，原因是多个事件选择器复用同一个处理函数，并非解析丢失。

源码中对应的文件级表均被观察到：

- `services/network_search/src/network_search_handler.cpp:41`：45 条；
- `services/network_search/src/cell_info.cpp:36`：6 条；
- `services/sim/src/sim_state_handle.cpp:52`：14 条；
- `services/core/src/core_service_common_event_hub.cpp:108`：22 条函数体初始化记录。

## 7. orphan 记录的解释

新增的 17 条 orphan 来自 `services/network_search/src/network_utils.cpp` 中 `EventSender::mapFunctions_`、`mapFunctionsInt_`、`mapFunctionsIntInt_` 和 `mapFunctionsIntString_` 的文件级 Lambda。

这些 Lambda 的调用目标形如：

```text
ITelRilManager::GetNetworkSelectionMode
ITelRilManager::SetPreferredNetwork
```

当前函数索引中没有可唯一解析的 `ITelRilManager` 实现函数，因此记录为 `unknown_target_function`，而不是伪造目标 ID。它们证明文件级扫描确实覆盖到了更广泛的初始化表，同时也暴露出接口声明/实现跨仓库解析仍需后续补充。这 17 条记录不会生成 Native 调用图边。

## 8. 调用图与语义图不变性

本阶段是观察层改动，验证结果如下：

- `call_graph.json` 仍为 6,842 个函数节点、7,196 条边；
- 将调用图边按 `(caller, callee)` 排序后，与 OH-22B-2C 基线的 SHA-256 均为：
  `0b833014a978829984779cfac69ac5d0123e0cd5417c9c9c6e2a0527b786c93b`；
- `semantic_graph.json` 仍为 22 个节点、21 条边、42 条 orphan；
- `dataset.json` 中新增信息只位于 `metadata.openharmony_call_graph_diagnostics.lambda_dispatch`。

解析命令控制台中的 `Indirect-call diagnostics: 11 residuals, 0 candidates` 仍是旧 Native 成员指针诊断摘要，不包含 Lambda 诊断。Lambda 的真实摘要应以 `call_graph_residuals.json` 为准。

## 9. 结论与边界

本阶段成功补上了真实 OpenHarmony 源码中 4 个初始化列表分派点的候选观测，消除了 Lambda 诊断层的 4 个无候选调用点，并保持了原 Native/语义图不变。

当前实现仍不是完整 C++ 别名分析，尚未覆盖：

- `std::bind`、`emplace`、`insert` 等非 Lambda 注册方式；
- 宏展开后生成的初始化列表；
- 多层对象字段、复杂指针别名和跨仓库接口实现解析；
- 需要人工确认的候选是否应正式提升为调用图边。

对应产物：

- [call_graph_residuals.json](../../debug_outputs/OH-22B-2D-telephony-initializer-lambda-20260827-parse-c/call_graph_residuals.json)
- [call_graph.json](../../debug_outputs/OH-22B-2D-telephony-initializer-lambda-20260827-parse-c/call_graph.json)
- [semantic_graph.json](../../debug_outputs/OH-22B-2D-telephony-initializer-lambda-20260827-parse-c/semantic_graph.json)
- [dataset.json](../../debug_outputs/OH-22B-2D-telephony-initializer-lambda-20260827-parse-c/dataset.json)
- [parse.report.json](../../debug_outputs/OH-22B-2D-telephony-initializer-lambda-20260827-parse-c/parse.report.json)
