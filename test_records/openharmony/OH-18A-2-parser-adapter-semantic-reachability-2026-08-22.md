# OH-18A-2：通用 parser_adapter 语义 reachable 接入测试记录

日期：2026-08-22  
阶段：OpenHarmony 正常服务仓库支持（第二个小阶段）  
状态：通过

## 1. 本阶段目的

第一阶段只覆盖 C parser 自己的 `CPipelineTest.apply_reachability_filter()`。
但 scanner 在 LLM 阶段结束后，会通过通用
`core.parser_adapter.apply_reachability_filter()` 再做一次过滤。如果这里仍
只使用 native reverse call graph，第二次过滤可能再次移除第一阶段发现的 IPC
handler。

本阶段复用同一个 OpenHarmony semantic overlay，并保持以下边界：

- 只有 `platform == "openharmony"` 才读取 `semantic_graph.json`；
- generic、Python 和其它平台路径不读取该文件；
- 入口检测和 native `call_graph.json` 不变；
- semantic graph 缺失或损坏时回退原 native 逻辑；
- 合并后的集合不得小于 native reachable 集合。

## 2. 修改内容

- 修改 `libs/openant-core/core/parser_adapter.py`
  - 在 native reachable 结果计算后加载输出目录中的
    `semantic_graph.json`；
  - 复用 `core.platforms.openharmony.reachability` 的构图和合并函数；
  - 为 OpenHarmony reachable 元数据增加：
    `native_reachable_units`、`semantic_reachable_added`、`semantic_overlay`；
  - 对 malformed semantic graph 做安全回退并记录 stderr warning。
- scanner 无需重复修改，因为它已有统一后置调用：
  `core.scanner -> core.parser_adapter.apply_reachability_filter`。
- 扩展
  `libs/openant-core/tests/openharmony/test_semantic_reachability_overlay.py`
  覆盖通用入口和 generic 隔离行为。

## 3. TDD 记录

### RED

先添加通用入口测试并运行：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_semantic_reachability_overlay.py
```

结果：C 专用测试和 generic 隔离测试通过，但通用 OpenHarmony 测试失败：

```text
5 tests collected: 4 passed, 1 failed
expected units {main, bridge, handle}, got {main, bridge}
```

这证明 parser_adapter 尚未接入 semantic graph，测试确实捕获了缺口。

### GREEN

实现后运行同一测试文件：

```text
6 passed in 0.03s
```

阶段相关回归测试：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_semantic_reachability_overlay.py \
  libs/openant-core/tests/test_reachability_empty_seed.py \
  libs/openant-core/tests/test_reachability_prune_telemetry.py \
  libs/openant-core/tests/test_parser_adapter_platform.py \
  libs/openant-core/tests/openharmony/test_c_pipeline_platform.py \
  libs/openant-core/tests/test_scanner.py
```

结果：

```text
30 passed in 0.61s
```

OpenHarmony 测试目录回归：

```text
./.venv/bin/python -m pytest -q libs/openant-core/tests/openharmony
```

结果：

```text
46 passed, 2 skipped in 0.58s
```

## 4. 通用入口合成验证

native 图：

```text
main -> bridge
```

semantic 图：

```text
bridge -> transaction -> handle
```

OpenHarmony 过滤结果：

- native reachable units：2；
- semantic 新增 reachable units：1；
- `semantic_overlay.edges_added`：1；
- `monotonicity_violation`：`false`；
- `dead` 单元仍被过滤。

generic 过滤结果只保留 `main`、`bridge`，不会读取同目录 semantic graph，证明
平台隔离有效。

## 5. 当前结论

两条 reachable 入口（C 专用入口和通用后置入口）现在都使用同一套“只增不减”
语义边逻辑。后续可以在正常 OpenHarmony 服务仓库上运行真实对照，重点观察
`semantic_reachable_added` 是否为正以及 native 集合是否始终保持不变。

## 6. 真实仓库对照

### `filemanagement_storage_service`

运行命令：

```text
./.venv/bin/python libs/openant-core/parsers/c/test_pipeline.py \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/filemanagement_storage_service \
  --output /private/tmp/openant-oh18a-storage-reachable \
  --processing-level reachable --platform openharmony --skip-tests
```

结果：

| 指标 | 数值 |
| --- | ---: |
| C/C++ 文件 | 349 |
| 函数 | 3355 |
| Units | 3322 |
| 入口点 | 53 |
| native reachable | 161 |
| 最终 reachable | 161 |
| semantic 新增 | 0 |
| reduction | 95.2% |

该仓库生成了 `semantic_graph.json`，但 157 条语义边全部是
`interface_to_transaction`，因此 `ignored_edge_count=157`、
`edges_added=0`，符合“接口声明不进入函数可达性”的设计。

### `security_device_auth`

运行命令：

```text
./.venv/bin/python libs/openant-core/parsers/c/test_pipeline.py \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/security_device_auth \
  --output /private/tmp/openant-oh18a-device-auth-reachable \
  --processing-level reachable --platform openharmony --skip-tests
```

结果：

| 指标 | 数值 |
| --- | ---: |
| C/C++ 文件 | 508 |
| 函数 | 3957 |
| Units | 3950 |
| 入口点 | 13 |
| native reachable | 207 |
| 最终 reachable | 207 |
| semantic 新增 | 0 |
| reduction | 94.8% |

该仓库本次没有生成 semantic graph，过滤器安全回退 native 路径。

真实运行证明当前接入不会缩小正常服务仓库原有 reachable 范围；是否能在某个
具体仓库中新增 handler，取决于该仓库同时具备可解析的 IDL、匹配的 stub/handler
函数节点以及 resolver 能建立的三类允许语义边。

## 7. 全量测试说明

额外运行：

```text
./.venv/bin/python -m pytest -q libs/openant-core/tests
```

结果：`3132 passed, 23 failed, 40 skipped`。

23 个失败不是本阶段引入：

- 1 项 Go conformance 因当前环境没有 `go` 可执行文件；
- 其余失败集中在既有 Python parser 测试，表现为 sample fixture 扫描为 0
  文件以及 extractor 缺少 `standalone_functions` 统计字段；
- 没有失败来自 OpenHarmony semantic reachability 测试，也没有失败来自本次
  修改的 C reachable 或通用 parser_adapter 专项测试。
