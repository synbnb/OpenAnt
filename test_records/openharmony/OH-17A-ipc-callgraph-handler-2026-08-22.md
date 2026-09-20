# OH-17A：调用图补全 IPC transaction → handler 测试记录

日期：2026-08-22  
范围：仅处理 OpenHarmony IPC 语义图中 `transaction_to_handler` 缺失问题。未修改 IDL `[ipccode]` 解析、入口检测策略或大仓库 `platform_context` 性能逻辑。

## 1. 基线与目标

原逻辑有两层限制：

1. C pipeline 在构建 `graph_result` 后，只把 `extract_result`（函数、代码、文件信息）传给 `OpenHarmonyIPCResolver`，没有传递真实 native call graph。
2. resolver 的 handler 匹配要求 handler 与 stub 使用同一 owner。OpenHarmony 生成代码常见的形态是 `XxxStub::OnRemoteRequest` 调用 `HandleMethod`，或者 Stub 调用 sibling `XxxService::Method`，因此会被 owner 过滤排除。

目标是：

- resolver 接收 C pipeline 的 `call_graph`；
- 从 `OnRemoteRequest` 出发，在有界深度内查找 `Method`、`HandleMethod`、`MethodInner`、`MethodImpl` 等方法变体；
- 直接调用图证据优先于旧的 owner/词法回退；
- 对 `Lite`、`Client` 等接口变体做路径一致性过滤，避免把同名 stub 错连到另一个接口；
- 新边证据明确标记为 `source: call_graph`，保持可审计。

## 2. 测试驱动过程

### 2.1 先确认失败

新增测试：

`tests/platforms/test_openharmony_ipc_graph.py::test_resolver_uses_call_graph_when_handler_owner_differs_from_stub`

执行：

```text
VulnFounder/.venv/bin/python -m pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py \
  -k 'call_graph_when_handler_owner_differs'
```

结果：失败（预期）。旧接口不接受 `call_graph=`，报错：

```text
TypeError: OpenHarmonyIPCResolver.resolve() got an unexpected keyword argument 'call_graph'
```

### 2.2 实现后定向测试

执行：

```text
VulnFounder/.venv/bin/python -m pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py
```

结果：`10 passed`。

覆盖内容包括：

- sibling Service owner 与 Stub owner 不同；
- ZIDL 风格 `ScreenSessionManagerLiteStub` 与 `IDisplayManagerLite` 名称不一致；
- `Lite` stub 不得复用到非 Lite interface；
- 原有 proxy、dispatch table、注释/字符串过滤、重载和 orphan 行为保持通过。

## 3. 实现内容

### 3.1 resolver 接收调用图

`OpenHarmonyIPCResolver.resolve(..., call_graph=...)` 和 `resolve_dict` 新增可选参数，兼容旧调用方式。resolver 只读取 `call_graph` 正向边，不执行源码、构建文件或回调。

### 3.2 有界 dispatch 路径索引

从 leaf 为 `OnRemoteRequest` 的函数开始，最多遍历 3 层、每个 dispatch 最多保留 256 个目标。仅把 IDL 方法名变体作为候选，避免“只要可达就当 handler”的过度推断。

### 3.3 变体一致性过滤

对 `lite`、`client`、`server`、`agent`、`listener` 等显式接口变体比较 interface stem 与 native 文件/owner 路径。变体冲突时不建立边，保留 unresolved orphan，优先保证不误连。

### 3.4 C pipeline 接线

`CPipelineTest` 在构建 `graph_result` 后调用：

```text
OpenHarmonyIPCResolver().resolve(
    idl_result,
    extract_result,
    call_graph=graph_result,
)
```

新增集成测试验证 owner 分离场景下，最终 `semantic_graph.json` 的 `transaction_to_handler` 证据来自 `call_graph`。

## 4. 回归结果

### 4.1 OpenHarmony 与 C pipeline 测试

执行：

```text
VulnFounder/.venv/bin/python -m pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony \
  VulnFounder/libs/vulnfounder-core/tests/platforms/test_openharmony_*.py \
  VulnFounder/libs/vulnfounder-core/tests/test_c_pipeline.py \
  VulnFounder/libs/vulnfounder-core/tests/report/test_build_pipeline_output_return_contract.py
```

结果：`102 passed, 6 skipped`。

语法检查：

```text
VulnFounder/.venv/bin/python -m py_compile \
  VulnFounder/libs/vulnfounder-core/core/platforms/openharmony/ipc_graph.py \
  VulnFounder/libs/vulnfounder-core/parsers/c/test_pipeline.py \
  VulnFounder/libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_unit_semantic_context.py
```

结果：通过。

### 4.2 真实小仓库完整 pipeline

仓库：`openharmony_reference/openharmony_source_code/multimedia_video_processing_engine`

输出：`/private/tmp/openant-oh17a-multimedia-video`

结果：

- 192 个源码文件；1531 个函数；1344 条 native 调用边；
- 1528 个 dataset units；pipeline 成功；
- semantic graph：10 nodes、9 edges、18 orphans；
- 该仓库的 IDL 与 native stub 没有可匹配 dispatch 关系，因此没有新增 handler 边，属于样本覆盖结果，不是运行失败。

### 4.3 真实 `window_window_manager` 语义回归

使用上一轮真实抽取产物：

- `analyzer_output.json`：23875 个函数；
- `call_graph.json`：包含 `ScreenSessionManagerLiteStub::OnRemoteRequest` 到 `HandleGetCutoutInfo` 等真实边；
- IDL 来源：`openharmony_reference/openharmony_source_code/window_window_manager`。

旧 semantic graph：

- 89 nodes、86 edges、168 orphans；
- 只有 1 条 `proxy_to_transaction` 和 85 条 `interface_to_transaction`；
- `transaction_to_handler`：0。

当前 resolver 重新解析：

- 92 edges、165 orphans；
- `stub_to_transaction`：3；
- `transaction_to_handler`：3；
- 新增相关证据 6 条，全部 `source: call_graph`；
- 代表性关系：

```text
OHOS.Rosen.IDisplayManagerLite:GetCutoutInfo
  -> ScreenSessionManagerLiteStub::HandleGetCutoutInfo
```

其余新增方法为 `GetDefaultDisplayInfo` 和 `RegisterDisplayManagerAgent`。同时，Lite stub 未被复用到普通 `IDisplayManager` transaction，反向回归测试已覆盖。

### 4.4 大仓库已知限制记录

曾对 `multimedia_audio_framework` 做完整 pipeline 尝试：扫描 1507 文件、抽取 23083 函数、构建 33402 调用边均成功；在旧有 `platform_context` 逐函数×逐 target 匹配阶段耗时过长而中止。这不是 OH-17A resolver 失败，后续应作为独立性能阶段处理。

## 5. 当前边界与后续建议

- 当前只追踪 `OnRemoteRequest` 出发的最多 3 层调用路径；更深 wrapper、函数指针、宏生成或动态分发仍会产生 orphan。
- IDL 文件使用 `[ipccode N]` 前缀时的 method 解析缺口未在本阶段修改，应单独进入 OH-17B。
- 真实仓库仍可能因 IDL 与 native stub 不在同一子仓库而没有 handler 边；此时应审阅 orphan 证据，不应仅凭同名函数强行连边。

