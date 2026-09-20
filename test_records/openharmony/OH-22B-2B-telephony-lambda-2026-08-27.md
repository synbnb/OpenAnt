# OH-22B-2B：lambda/std::function 分派观察阶段验证记录

日期：2026-08-27
仓库：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/telephony_core_service`
目的：验证 OpenHarmony 中用 lambda 填充 `std::function` 映射表、再通过查找结果调用的分派形式，并确认观察结果不会未经审核直接改变 native 语义调用图。

## 1. 原逻辑与本阶段逻辑

此前的分派诊断只处理成员函数指针，例如：

```cpp
table[CODE] = &Stub::Handle;
auto fn = iterator->second;
(this->*fn)(data, reply);
```

telephony 核心服务实际使用的是：

```cpp
memberFuncMap_[CODE] =
    [this](MessageParcel &data, MessageParcel &reply) {
        return OnGetNetworkState(data, reply);
    };

auto itFunc = memberFuncMap_.find(code);
auto memberFunc = itFunc->second;
return memberFunc(data, reply);
```

本阶段没有把 lambda 直接提升为 native 语义边，而是新增独立的 `lambda_dispatch` 观察结果，记录：

1. 表下标、选择器和 lambda 源码；
2. lambda 捕获列表及其内部调用；
3. `find`、`second` 到可调用变量的局部数据流；
4. 通过 enclosing class、参数接收者类型和调用参数个数解析目标函数；
5. 无法确定时的候选或 orphan 证据。

这样可以先供人工或后续 LLM 复核，避免把普通事件回调误认为 Binder 入口。

## 2. 自动化测试

定向测试：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py
```

结果：`7 passed`。

新增覆盖：

- lambda 注册单独进入 `lambda_dispatch`；
- lambda 结果不会进入 `dispatch_assignments`，因此不会触发 native 边提升；
- `SimFile &simFile` 形式的接收者类型提示；
- 同名重载通过调用参数个数消歧；
- 原有成员函数指针、二元权限注册和 orphan 行为保持不变。

OpenHarmony/IPC 回归：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py
```

结果：`109 passed, 2 skipped`。

Ruff 检查：`All checks passed`。

## 3. 真实仓库解析

为避免大模型费用，使用只执行解析阶段的命令：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/telephony_core_service \
  --output debug_outputs/OH-22B-2B-telephony-lambda-20260827-parse-c \
  --platform openharmony --language c --level all --fresh
```

解析结果：

| 指标 | 数值 |
|---|---:|
| C/C++ 文件 | 540 |
| 函数记录 | 6,913 |
| native call graph 原有边 | 7,196 |
| 分析单元 | 6,842 |
| 解析失败 | 0 |
| 解析耗时 | 36.23 秒 |
| 大模型调用 | 0 |

## 4. 与源码事实对照

对生产源码（排除 `test/tests`）统计：

| 源码事实 | 数量 |
|---|---:|
| `memberFuncMap_[...]` lambda 注册 | 237 |
| `requestFuncMap_[...]` lambda 注册 | 6 |
| 两类 IPC/事件 lambda 注册合计 | 243 |
| `memberFunc/requestFunc(...)` 调用点 | 15 |

解析产物 `call_graph_residuals.json` 中的结果：

```json
{
  "unresolved_call_sites": 11,
  "dispatch_assignments": 0,
  "candidate_edges": 0,
  "lambda_dispatch": {
    "dispatch_assignments": 243,
    "call_sites": 16,
    "candidate_edges": 199,
    "unresolved_without_candidates": 5,
    "orphan_assignments": 0
  }
}
```

其中 16 个查找后可调用点包括 15 个显式 `memberFunc/requestFunc` 调用，以及 1 个 `actionHandlersMap_` 的 `iterator->second` 调用。243 个 lambda 注册全部解析到唯一的函数 ID，未产生 lambda assignment orphan。

## 5. IPC 入口覆盖

下列 IPC/回调分派点均被识别，并且候选数与其 lambda 注册数一致：

| 分派函数 | 表 | 候选数 |
|---|---|---:|
| `CoreServiceStub::OnRemoteRequest` | `memberFuncMap_` | 109 |
| `IEsimServiceCallbackStub::OnEsimServiceCallback` | `memberFuncMap_` | 16 |
| `INetworkSearchCallbackStub::OnNetworkSearchCallback` | `memberFuncMap_` | 11 |
| `ImsCoreServiceCallbackStub::OnRemoteRequest` | `requestFuncMap_` | 2 |
| `SatelliteCoreCallbackStub::OnRemoteRequest` | `requestFuncMap_` | 4 |

这五组共覆盖 142 个 IPC/回调 lambda 目标。`IEsimServiceCallback` 和 `INetworkSearchCallback` 虽然函数名不是 `OnRemoteRequest`，但其参数来自 `MessageParcel`、先校验/读取请求码，再按映射调用回调，同样属于 IPC 回调边界；本阶段只观察，不自动提升。

## 6. 普通事件分派与剩余边界

另外识别到 `EsimFile`、`IccDiallingNumbersHandler`、`IsimFile`、`RadioProtocolController`、`RuimFile`、`UsimDiallingNumbersService` 等普通事件映射，共贡献 57 个候选目标。这些不是 Binder 入口，暂不写入 native 语义图。

`SimFileInit` 中有 43 个 lambda 注册，目标函数已通过 `SimFile &simFile` 参数类型解析成功，但其注册表表达式是 `simFile.memberFuncMap_`，调用点位于另一个函数中的 `memberFuncMap_`。当前阶段没有跨函数追踪同一对象字段，因此这 43 个注册暂未与 `SimFile::ProcessEvent` 调用点合并；这是待处理的跨函数数据流缺口，不是目标解析失败。

另有 5 个查找后调用点没有候选，主要来自普通事件表的全局初始化或 `actionHandlersMap_`，当前抽取范围没有保存与调用点配对的注册表达式，因此保留为待复核观察项。

## 7. 语义图不变性验证

本次解析生成的 `semantic_graph.json`：

| 指标 | 数值 |
|---|---:|
| 节点 | 22 |
| 边 | 21 |
| `native_dispatch_to_handler` | 0 |
| `native_dispatch_to_service` | 0 |

这证明 `lambda_dispatch` 目前是独立观察数据，不会把不确定 lambda 关系直接写入 native 调用图。后续若要改善可达性，需要再增加“仅对高置信 IPC 分派提升”或 LLM 辅助复核阶段。

对应产物：

- [call_graph_residuals.json](../../debug_outputs/OH-22B-2B-telephony-lambda-20260827-parse-c/call_graph_residuals.json)
- [semantic_graph.json](../../debug_outputs/OH-22B-2B-telephony-lambda-20260827-parse-c/semantic_graph.json)
- [parse.report.json](../../debug_outputs/OH-22B-2B-telephony-lambda-20260827-parse-c/parse.report.json)
