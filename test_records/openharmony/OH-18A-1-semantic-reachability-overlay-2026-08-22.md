# OH-18A-1：语义 IPC 边叠加到 C reachable 的专项测试记录

日期：2026-08-22  
阶段：OpenHarmony 正常服务仓库支持（第一个小阶段）  
状态：通过

## 1. 本阶段目的

原来的 C/C++ reachable 过滤只根据 Unit 元数据中的 `direct_callers` 重建
native reverse call graph。OpenHarmony 的 IPC resolver 已经能产出
`stub_to_transaction` 和 `transaction_to_handler`，但这些语义节点不会进入
native 调用图，因此一个 IPC stub 到 handler 的跨文件/跨生成代码路径可能在
reachable 阶段被裁掉。

本阶段只做“附加”处理：

1. 保留原来的入口检测规则和 native 调用图；
2. 只允许 `proxy_to_transaction`、`stub_to_transaction`、
   `transaction_to_handler` 三类语义边；
3. 将已知 native function 节点之间的语义路径折叠为临时 reachability 边；
4. 合并时复制图，不修改 `call_graph.json`、`direct_calls` 或
   `direct_callers`；
5. 检查合并后的 reachable 集合必须包含原 native reachable 集合。

`interface_to_transaction` 仅表示接口声明关系，本阶段明确不用于函数可达性。

## 2. 修改内容

- 新增 `libs/openant-core/core/platforms/openharmony/reachability.py`
  - `build_semantic_reachability_overlay()`：校验语义节点、过滤不允许的边并
    折叠 function → transaction → function 路径；
  - `merge_reachability_graph()`：以副本方式把临时边加入 forward/reverse 图，
    重复调用保持幂等。
- 修改 `libs/openant-core/parsers/c/test_pipeline.py`
  - OpenHarmony C reachable 过滤先计算 native 集合，再计算 semantic overlay
    集合；
  - 新增 `native_reachable_units`、`semantic_reachable_added` 和
    `semantic_overlay` 诊断字段；
  - 语义图缺失或格式错误时回退 native 流程，并打印警告。
- 新增测试
  - `libs/openant-core/tests/openharmony/test_semantic_reachability_overlay.py`

## 3. TDD 记录

### RED

先添加测试后运行：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_semantic_reachability_overlay.py
```

结果：收集阶段失败，`core.platforms.openharmony.reachability` 尚不存在：

```text
ModuleNotFoundError: No module named 'core.platforms.openharmony.reachability'
```

### GREEN

实现辅助模块和 C 过滤器接入后重新运行同一命令：

```text
3 passed in 0.04s
```

再运行本阶段相关回归测试：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_semantic_reachability_overlay.py \
  libs/openant-core/tests/openharmony/test_unit_semantic_context.py \
  libs/openant-core/tests/parsers/c/test_empty_seed_keep_all.py
```

结果：

```text
13 passed in 0.07s
```

## 4. 验证要点

合成 IPC 图中：

```text
Main -> OnRemoteRequest                 native edge
OnRemoteRequest -> transaction          stub_to_transaction
transaction -> Service::Enable           transaction_to_handler
```

过滤后保留 `Main`、`OnRemoteRequest`、`Service::Enable`，删除无关的
`unused`。同时验证：

- native reachable 集合 `{Main, OnRemoteRequest}` 是合并集合的子集；
- `semantic_reachable_added == 1`；
- `semantic_overlay.edges_added == 1`；
- `semantic_overlay.monotonicity_violation == false`；
- 仅有 `interface_to_transaction` 时不会产生函数可达边。

## 5. 尚未覆盖

通用 `core/parser_adapter.apply_reachability_filter()` 以及 scanner 的
后置 LLM re-filter 入口还没有接入该 overlay。下一小阶段会在保持 generic、
Python 等平台行为不变的前提下，复用同一个 OpenHarmony 辅助模块接入这两个
入口，并单独测试。

