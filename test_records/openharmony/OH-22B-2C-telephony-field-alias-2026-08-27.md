# OH-22B-2C：跨函数字段关联测试记录

日期：2026-08-27
平台：OpenHarmony
验证仓库：`telephony_core_service`
验证路径：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/telephony_core_service`

## 1. 本阶段目的

OH-22B-2B 已经能够识别 Lambda 注册点和 Lambda 内部调用的目标函数，但注册和调用可能位于不同函数中，且两边的字段表达式不一定相同。

本阶段增加一个保守的跨函数字段关联：只有当注册点和调用点的字段名相同，并且接收者类型能够从 `this` 或简单函数参数中确定且完全一致时，才输出 `field_alias_matches`。该结果仍然是诊断证据，不会修改 Native 调用图。

## 2. 原逻辑与修改后逻辑

### 原逻辑

例如：

```cpp
void SimFileInit::InitMemberFunc(SimFile &simFile)
{
    simFile.memberFuncMap_[READY] =
        [&](const Event &event) { return simFile.ProcessReady(event); };
}
```

```cpp
void SimFile::ProcessEvent(const Event &event)
{
    auto itFunc = memberFuncMap_.find(event.id);
    auto memberFunc = itFunc->second;
    memberFunc(event);
}
```

之前会分别识别出：

- `simFile.memberFuncMap_` 注册了 `SimFile::ProcessReady`；
- `memberFuncMap_` 被读取并执行；
- 但由于原始字段表达式不同、所属函数和所属类也不同，两者无法连接。

### 修改后逻辑

解析器为两个表达式生成规范化字段身份：

```json
{
  "field": "memberFuncMap_",
  "receiver_type": "SimFile"
}
```

其中：

- `simFile.memberFuncMap_` 的 `SimFile` 类型来自参数 `SimFile &simFile`；
- `memberFuncMap_` 的 `SimFile` 类型来自调用函数的类名；
- 字段名和接收者类型一致时，生成一条带证据的字段关联；
- 类型未知、字段不一致或接收者类型不同，则不匹配。

## 3. 单元测试

### 定向测试

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py
```

结果：

```text
9 passed
```

新增了两个边界测试：

1. `SimFileInit` 的参数字段与 `SimFile::ProcessEvent` 的 `this` 字段能够关联；
2. 字段名相同但接收者类型不同的 `OtherFile` 不会错误关联到 `SimFile`。

### OpenHarmony/IPC 回归测试

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py
```

结果：

```text
111 passed, 2 skipped
```

### 代码质量检查

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/ruff check \
  libs/vulnfounder-core/core/platforms/openharmony/call_graph_diagnostics.py \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py
git diff --check
```

结果：Ruff 和空白检查均通过。

## 4. 真实仓库解析

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/telephony_core_service \
  --output debug_outputs/OH-22B-2C-telephony-field-alias-20260827-parse-c \
  --platform openharmony --language c --level all --fresh
```

解析结果：

| 指标 | 结果 |
| --- | ---: |
| 发现文件 | 1056 |
| 纳入 C/C++ 解析文件 | 540 |
| 成功解析文件 | 540 |
| 解析失败 | 0 |
| 提取函数 | 6913 |
| 原生调用图边 | 7196 |
| 生成单元 | 6842 |
| LLM 调用 | 0 |
| 解析耗时 | 约 36.16 秒 |

## 5. 关联结果

`call_graph_residuals.json` 中的 Lambda 诊断摘要为：

```json
{
  "dispatch_assignments": 243,
  "call_sites": 16,
  "candidate_edges": 241,
  "unresolved_without_candidates": 4,
  "orphan_assignments": 0,
  "field_alias_matches": 43
}
```

### SimFile 关联

源码中的注册点位于：

```text
services/sim/src/sim_file_init.cpp
```

真实源码通过 `SimFile &simFile` 参数写入 `simFile.memberFuncMap_`，共有 43 个 Lambda 注册点，分布在：

- `SimFileInit::InitBaseMemberFunc`：11 个；
- `SimFileInit::InitObtainMemberFunc`：24 个；
- `SimFileInit::InitPlmnMemberFunc`：8 个。

调用点位于：

```text
services/sim/src/sim_file.cpp:SimFile::ProcessEvent:189
```

该调用点读取 `memberFuncMap_` 并执行 `memberFunc(event)`。新逻辑生成 43 条字段关联，覆盖 42 个不同目标函数；其中两个不同事件选择器都指向 `SimFile::ProcessIccLocked`，所以注册记录数比去重后的目标函数数多 1。

### 其他可调用表

本次解析中，以下调用点也获得了候选目标：

| 调用类/函数 | 字段 | 候选目标数 |
| --- | --- | ---: |
| `CoreServiceStub::OnRemoteRequest` | `memberFuncMap_` | 109 |
| `IEsimServiceCallbackStub::OnEsimServiceCallback` | `memberFuncMap_` | 16 |
| `INetworkSearchCallbackStub::OnNetworkSearchCallback` | `memberFuncMap_` | 11 |
| `ImsCoreServiceCallbackStub::OnRemoteRequest` | `requestFuncMap_` | 2 |
| `SatelliteCoreCallbackStub::OnRemoteRequest` | `requestFuncMap_` | 4 |
| `EsimFile::ProcessEvent` | `memberFuncMap_` | 28 |
| `IsimFile::ProcessEvent` | `memberFuncMap_` | 6 |
| `IccDiallingNumbersHandler::ProcessEvent` | `memberFuncMap_` | 5 |
| `RadioProtocolController::ProcessEvent` | `memberFuncMap_` | 8 |
| `RuimFile::ProcessEvent` | `memberFuncMap_` | 6 |
| `UsimDiallingNumbersService::ProcessEvent` | `memberFuncMap_` | 4 |

## 6. 仍未解析的 4 个调用点

以下调用点没有 Lambda 候选目标：

```text
services/core/src/core_service_common_event_hub.cpp:CoreServiceCommonEventHub::OnReceiveEvent
services/network_search/src/cell_info.cpp:CellInfo::ProcessNeighboringCellInfo
services/network_search/src/network_search_handler.cpp:NetworkSearchHandler::ProcessEvent
services/sim/src/sim_state_handle.cpp:SimStateHandle::ProcessEvent
```

它们不应直接被解释为本阶段失败：

- `actionHandlersMap_` 属于普通事件处理表；
- 部分 `memberFuncMap_` 使用的是函数指针、静态初始化或其他非 Lambda 注册形式；
- 当前阶段只处理 Lambda/std::function 观测，不覆盖 `std::bind`、复杂容器插入和任意函数指针传播。

## 7. 对调用图的影响

本阶段没有修改：

- `call_graph.json` 中的 Native 调用图；
- `semantic_graph.json` 中的语义图；
- 原有 `dispatch_assignments` 和 `unresolved_call_sites` 结果。

`semantic_graph.json` 仍为 22 个节点、21 条边、42 个 orphan。这是预期行为，因为本阶段只新增 `lambda_dispatch.field_alias_matches` 诊断证据，还没有进入正式调用图边提升阶段。

解析命令输出中的 `Indirect-call diagnostics: 11 residuals, 0 candidates` 仍指旧的 Native 成员指针诊断摘要；Lambda 关联结果位于 `call_graph_residuals.json` 的 `lambda_dispatch` 节点中，二者不能混为一谈。

## 8. 结论与边界

本阶段成功解决了真实源码中的一个明确缺口：

```text
SimFileInit::Init*MemberFunc
  → simFile.memberFuncMap_[event]
  → SimFile::*处理函数

SimFile::ProcessEvent
  → memberFuncMap_.find(id)
  → memberFunc(event)
```

现在两部分可以通过“字段名 + 接收者类型”关联，并且真实仓库中产生了 43 条可审计证据。

但这不是完整的 C++ 别名分析，尚未覆盖：

- `std::bind`、`emplace`、`insert` 等注册方式；
- 多层对象字段和指针别名；
- 模板类型推导；
- 函数返回的可调用对象；
- 动态字段名或运行时注册；
- 虚函数和复杂继承关系。

因此，本阶段适合作为后续调用图恢复或 LLM 复核的输入，不应单独宣称已经恢复全部 Lambda 调用边。

## 9. 产物

- [call_graph_residuals.json](../../debug_outputs/OH-22B-2C-telephony-field-alias-20260827-parse-c/call_graph_residuals.json)
- [call_graph.json](../../debug_outputs/OH-22B-2C-telephony-field-alias-20260827-parse-c/call_graph.json)
- [semantic_graph.json](../../debug_outputs/OH-22B-2C-telephony-field-alias-20260827-parse-c/semantic_graph.json)
- [parse.report.json](../../debug_outputs/OH-22B-2C-telephony-field-alias-20260827-parse-c/parse.report.json)
