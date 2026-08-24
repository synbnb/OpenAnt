# OH-15A-4：Semantic IPC Context Functions 接入 Unit 测试记录

日期：2026-08-22
阶段：OH-15A-4
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段解决 OH-15A-3 中暴露的一个真实缺口：Prompt 只有在 Unit 的 `primary_code` 已包含上下文函数时才会显示 context functions，但 OpenHarmony 的 `OnRemoteRequest` 经常通过函数指针/transaction table 动态分派，普通 C/C++ 调用图无法恢复这条关系。

本阶段只接入已经由 `OpenHarmonyIPCResolver` 以证据支持的 semantic IPC 边：

```text
stub/proxy function
    ──stub_to_transaction / proxy_to_transaction──>
IPC transaction
    ──transaction_to_handler──>
native handler function
```

不把 semantic edge 混入普通 C/C++ `call_graph`，不根据同名函数猜测 handler，也不把 transaction 节点当作源码函数内联。

## 2. 修改前后逻辑

### 修改前

- `UnitGenerator` 只根据 `call_graph` 和 `reverse_call_graph` 拼接上游依赖/下游 caller。
- `OnRemoteRequest` 中的函数指针注册和动态调用不会产生普通语言调用边，因此 Unit 可能只有目标函数本身。
- `CPipelineTest` 不收集 IDL/native semantic graph，Prompt 无法看到已解析的 IPC handler 上下文。

### 修改后

1. `UnitGenerator` 接收可选 `semantic_graph` overlay。
2. 只保留 `stub_to_transaction`、`proxy_to_transaction`、`transaction_to_handler` 三类有明确端点的边。
3. 从目标 native function 沿 semantic edge 正向/反向查找关联 native function；transaction 节点只作为路径，不内联到源码。
4. 选择确定性、置信度最高且路径最短的关联路径，并在 `metadata.context_functions` 中保留 edge kind、置信度和 evidence。
5. semantic context function 追加到 `primary_code` 的文件边界之后，因此现有 Prompt 会把它放入 `Context (for understanding only...)` 区域。
6. `primary_origin` 和 `dependency_metadata` 新增 semantic context 数量/ID；普通 native call graph 字段保持原值。
7. OpenHarmony C pipeline 自动收集 IDL，运行 `OpenHarmonyIPCResolver`，保存 `semantic_graph.json`，并把 graph 传给 UnitGenerator；没有可用 IDL 时继续生成普通 dataset。
8. malformed/unsupported semantic graph 条目被忽略，不阻断旧 pipeline。

## 3. 修改文件

- `libs/openant-core/parsers/c/unit_generator.py`
  - semantic graph overlay 归一化；
  - IPC context function 路径解析和代码内联；
  - context metadata/statistics。
- `libs/openant-core/parsers/c/test_pipeline.py`
  - OpenHarmony IDL 收集、IPC resolver 调用和 `semantic_graph.json` 产物；
  - dataset metadata 增加 semantic graph 摘要。
- `libs/openant-core/tests/openharmony/test_unit_semantic_context.py`
  - Unit overlay、Prompt context section、resolver→Unit 和真实 pipeline 临时仓库集成测试。

## 4. TDD 记录

### RED

先加入 Unit semantic context 测试后运行：

```text
OpenAnt/.venv/bin/pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony/test_unit_semantic_context.py
```

结果：`2 failed`。Unit 尚没有 `semantic_context_inlined` 和 semantic context metadata。

补充 C pipeline 集成测试后再次运行，结果为 `4 passed, 1 failed`；失败是预期的 `semantic_graph.json` 尚未生成，证明 pipeline 尚未接入 resolver。

### GREEN

实现 Unit overlay 和 pipeline wiring 后：

```text
OpenAnt/.venv/bin/pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony/test_unit_semantic_context.py
```

结果：`5 passed`。

覆盖项：

- `stub_to_transaction → transaction_to_handler` 路径可把 handler 内联到 Unit；
- 普通 native call graph 和 reverse call graph 不被修改；
- 没有 semantic edges 时不猜测 context function；
- resolver 的真实输出可以直接喂给 UnitGenerator；
- 临时仓库式 C pipeline 能从 bundle/GN/IDL/C++ 源码生成 semantic graph，并让 handler 出现在 Unit context code 中；
- Prompt 能把内联 handler 放入 context functions 区域。

## 5. 回归测试

OpenHarmony、IPC resolver、C parser：

```text
OpenAnt/.venv/bin/pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_entry_points.py \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_sa_ipc_graph.py \
  OpenAnt/libs/openant-core/tests/parsers/c
```

结果：`153 passed, 2 skipped`。

Prompt、语言、注入和多语言兼容回归：`69 passed`。

质量检查：相关生产文件与测试文件的 `ruff check`、`py_compile`、空白检查均通过。

## 6. 真实 OpenHarmony 仓库验证

验证仓库：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_wifi
```

命令：

```text
OpenAnt/.venv/bin/python \
  OpenAnt/libs/openant-core/parsers/c/test_pipeline.py \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_wifi \
  --output /private/tmp/openant-oh15a4-communication_wifi-final \
  --platform openharmony --skip-tests --processing-level all
```

结果：pipeline 成功，耗时 `89.50s`。

| 指标 | 数量 |
|---|---:|
| 生产 C/C++ 文件 | 683 |
| 提取函数 | 9,263 |
| Unit | 9,204 |
| semantic graph 节点 | 47 |
| semantic graph 边 | 43 |
| semantic graph orphan | 86 |
| `transaction_to_handler` 边 | 0 |
| 带 semantic context function 的 Unit | 0 |

该真实仓库当前解析到的 43 条边全部是 `interface_to_transaction`；43 个 proxy 和 43 个 stub 均记录为 unresolved。由于没有确定的 native `stub_to_transaction`/`transaction_to_handler` 路径，系统没有伪造 context function。这正是本阶段需要的保守行为。

pipeline 同时生成：

```text
/private/tmp/openant-oh15a4-communication_wifi-final/semantic_graph.json
```

## 7. 阶段边界与后续

本阶段已经打通“resolver 输出 → Unit context function → Prompt context 区域”的链路，但真实仓库是否产生 handler context 取决于源码中是否存在可解析的 Stub dispatch 和 handler 证据。后续若要扩大覆盖，应优先改进 IDL/生成 Stub 与真实源码的关联，而不是放宽到仅凭函数同名猜测。
