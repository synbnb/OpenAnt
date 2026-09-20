# OH-22B-2A：通用原生分派恢复真实仓库验证记录

日期：2026-08-27
仓库：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_netmanager_base`
目的：验证本阶段是否能在不依赖 `baseFuncs_` 固定名称的情况下，恢复 OpenHarmony C/C++ 服务中的成员函数表分派边。

## 1. 本阶段的逻辑变化

原逻辑只识别名称类似 `baseFuncs_` 的函数指针表，并且主要覆盖：

```cpp
baseFuncs_[CODE] = &Stub::Handle;
auto member = iterator->second;
return (this->*member)(data, reply);
```

这会漏掉表名为 `memberFuncMap_`、`opToInterfaceMap_` 的实现，也不能稳定处理“函数指针 + 权限元数据”的二元注册项，以及 `iterator->second.first` 这种嵌套取值。

本阶段改为依据结构而不是表名：

1. 识别形如 `任意表表达式[事务码] = 成员函数指针` 的注册。
2. 识别 `{&Stub::Handler, 元数据}` 形式，并保留权限字段。
3. 在局部数据流中连接 `table.find(code)`、`iterator->second`、`iterator->second.first`。
4. 当 tree-sitter 将 `this->*(...)` 放入 `ERROR` 节点时，使用保留行号的词法兜底，仅记录明确的成员指针调用。
5. 只将 `OnRemoteRequest` 中有注册表证据的候选提升为 `native_dispatch_to_handler` 语义边；普通函数调用图不被改写。
6. 同一处理函数被多个事务码注册时，语义边合并，但在 `selectors` 和 `registrations` 属性中保留所有注册项。

## 2. 自动化测试

执行命令：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_native_dispatch.py \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py
```

结果：`10 passed`。

覆盖内容包括：

- 任意表名不再被名称白名单拒绝；
- `index->second` 和 `index->second.first` 能正确回溯表；
- 成员函数指针二元注册能提取权限；
- 未解析目标保留为 orphan，不伪造边；
- 同一个处理函数对应多个事务码时，两个事务码都保存在边属性中；
- 语义边可进入单元上下文，但不修改原始 native call graph。

完整 OpenHarmony/IPC 回归：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py
```

结果：`107 passed, 2 skipped`。

静态检查：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/ruff check \
  libs/vulnfounder-core/core/platforms/openharmony/call_graph_diagnostics.py \
  libs/vulnfounder-core/core/platforms/openharmony/native_dispatch.py \
  libs/vulnfounder-core/tests/openharmony/test_call_graph_diagnostics.py \
  libs/vulnfounder-core/tests/openharmony/test_native_dispatch.py
```

结果：`All checks passed`。

## 3. 真实仓库解析

为避免调用大模型，使用只执行解析阶段的命令：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_netmanager_base \
  --output debug_outputs/OH-22B-2A-communication-generic-dispatch-20260827-parse-c \
  --platform openharmony --language c --level all --fresh
```

解析结果：

| 指标 | 数值 |
|---|---:|
| C/C++ 文件 | 730 |
| 函数记录 | 7,587 |
| native call graph 原有边 | 6,394 |
| 分析单元 | 7,563 |
| 解析失败 | 0 |
| 解析耗时 | 42.14 秒 |

本次命令明确选择 `--language c`，因此只验证 C/C++ 分派；仓库中的 Rust、ETS 等文件被记录为未选中的覆盖范围，不把它们误算成 C/C++ 解析失败。

## 4. 与源码事实的对照

对同一仓库的生产源码（排除 `test/tests` 目录）执行文本计数，得到：

| 源码事实 | 数量 |
|---|---:|
| `opToInterfaceMap_[...]` 注册 | 146 |
| `memberFuncMap_[...]` 注册 | 161 |
| 其中直接成员函数指针 | 74 |
| 其中“成员函数指针 + 权限元数据”二元注册 | 87 |
| `this->*` 成员指针调用点 | 17 |
| 两类表注册总数 | 307 |

解析产物 `call_graph_residuals.json`：

```json
{
  "unresolved_call_sites": 17,
  "dispatch_assignments": 307,
  "candidate_edges": 306,
  "unresolved_without_candidates": 0,
  "orphan_assignments": 0
}
```

这说明：

- 17 个成员指针调用点全部被观察到；
- 307 个表注册全部被提取；
- 306 是去重后的目标函数数，因为 `NetConnServiceStub::OnQueryTraceRoute` 被两个不同事务码注册；
- 两个事务码均保存在该语义边的 `selectors`/`registrations` 中，不是漏边；
- 没有出现“注册项存在但目标函数无法解析”的 assignment orphan；
- 每个残留调用点都有至少一个候选目标。

对应产物：

- [call_graph_residuals.json](../../debug_outputs/OH-22B-2A-communication-generic-dispatch-20260827-parse-c/call_graph_residuals.json)
- [semantic_graph.json](../../debug_outputs/OH-22B-2A-communication-generic-dispatch-20260827-parse-c/semantic_graph.json)
- [parse.report.json](../../debug_outputs/OH-22B-2A-communication-generic-dispatch-20260827-parse-c/parse.report.json)

## 5. 语义图结果

`semantic_graph.json` 中共有：

| 类型 | 数量 |
|---|---:|
| 节点 | 660 |
| 总边 | 642 |
| `native_dispatch_to_handler` | 306 |
| `native_dispatch_to_service` | 280 |
| semantic orphan | 45 |

其中处理函数边按表统计为：

- `opToInterfaceMap_`：146 条；
- `memberFuncMap_`：160 条（161 个注册项合并了 1 个重复目标）。

45 个 semantic orphan 主要是回调处理函数调用同名服务方法时存在多个可能的具体实现，属于“服务实现选择不唯一”，不是注册表目标丢失。实现保留这些证据，未强行选择一个目标。

## 6. 与修改前基线对比

修改前同一仓库的基线产物为：
`debug_outputs/OH-22B-reference-corpus-20260826-run1/communication_netmanager_base/`。

| 指标 | 修改前 | 修改后 |
|---|---:|---:|
| 残留调用点 | 16 | 17 |
| 提取的注册项 | 220 | 307 |
| 候选目标 | 74 | 306 |
| 无候选调用点 | 1 | 0 |
| native 分派语义边 | 0 | 306 |

残留调用点从 16 增加到 17 是因为本阶段把原来 tree-sitter `ERROR` 子树中的 `netsys_native_service_stub.cpp` 分派调用也记录出来；这不是新增源码调用，而是提高了观察完整性。

## 7. 当前边界

本阶段仍然是确定性的静态恢复，没有调用大模型。当前实现覆盖了本仓库实际出现的“下标注册 + `find` 查找 + 成员函数指针调用”三段结构，但尚未处理：

- 通过 `std::function` 或 lambda 注册的分派；
- `emplace`、`insert` 等非下标注册 API；
- `dlsym` 等运行时动态符号解析；
- 音频仓库中 `Dump` 一类非 Binder 的命令分派。

这些情况不能仅凭函数名安全猜测，后续应作为独立阶段加入更通用的数据流分析和受控的大模型残余复核。本阶段的结论仅针对上述真实仓库和已列明的结构化分派形式。
