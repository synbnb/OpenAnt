# OH-17C：直接数字 IPC code 匹配与 Unit 上下文测试记录

日期：2026-08-22  
范围：使用 IDL `[ipccode N]` 匹配 native `OnRemoteRequest` 中的直接数字 `case N`，以及 proxy `SendRequest(N, ...)`，并验证匹配结果进入 `Unit.context_functions`。未处理枚举、宏、变量和跨文件常量求值。

## 1. 为什么这个阶段会影响 Unit 上下文

OH-17B 已经把 IDL 数值保存为 transaction metadata，但旧 resolver 仍主要依赖方法名、`CMD_*` token 和调用图：

```text
IDL [ipccode 7]
    -> transaction.ipc_code = 7
    -> native dispatch 关系仍可能缺少
    -> UnitGenerator 找不到 transaction -> handler 路径
    -> context_functions 缺失
```

当 native 侧写成 `case 7` 或 `SendRequest(7, ...)` 时，OH-17C 可以补出：

```text
native proxy/stub
  --proxy_to_transaction / stub_to_transaction-->
transaction(ipc_code=7)
  --transaction_to_handler-->
handler
```

## 2. 测试驱动过程

### 2.1 RED：确认旧逻辑失败

新增测试：

```text
tests/platforms/test_openharmony_ipc_graph.py::test_resolver_matches_ipccode_literal_in_native_stub_dispatch
tests/platforms/test_openharmony_ipc_graph.py::test_resolver_matches_ipccode_literal_in_proxy_send_request
tests/platforms/test_openharmony_ipc_graph.py::test_resolver_rejects_mismatched_or_masked_ipccode_literals
tests/openharmony/test_unit_semantic_context.py::test_numeric_ipccode_proxy_path_reaches_unit_context
```

旧代码执行数字匹配测试：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py \
  -k 'ipccode_literal'
```

结果：`2 failed, 1 passed, 11 deselected`。`case 7` 和 `SendRequest(7, ...)` 都没有生成对应 native IPC 边。

旧代码执行 Unit 上下文测试：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony/test_unit_semantic_context.py \
  -k 'numeric_ipccode_proxy_path'
```

结果：`1 failed, 6 deselected`。proxy 没有连到 transaction，proxy Unit 的 `context_functions` 为空。

## 3. 实现内容

文件：`libs/openant-core/core/platforms/openharmony/ipc_graph.py`

### 3.1 直接数字识别

新增受限匹配：

- `OnRemoteRequest` 函数中的 `case 7:`；
- `SendRequest(7, ...)` 或带简单后缀的 `SendRequest(7U, ...)`。

匹配前先屏蔽注释和字符串，因此注释或字符串中的 `case 7`、`SendRequest(7, ...)` 不会成为证据。

### 3.2 严格边界

只接受非负十进制 `ipc_code`。本阶段不解析：

- `COMMAND_START_USER` 等枚举标识符；
- `#define COMMAND_START_USER 7`；
- 变量间接传递；
- 跨文件常量、宏展开和复杂表达式；
- 普通业务函数中的 `case 7`。

新增证据示例：

```json
{
  "source": "native",
  "signal": "ipc_code_literal",
  "matched": "7",
  "ipc_code": 7
}
```

已有方法名、transaction token 和调用图匹配逻辑保持不变。

## 4. 定向测试结果（GREEN）

执行：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py \
  OpenAnt/libs/openant-core/tests/openharmony/test_unit_semantic_context.py
```

结果：

```text
21 passed in 0.04s
```

覆盖：Stub `case 7`、Proxy `SendRequest(7, ...)`、数字不一致、注释/字符串屏蔽，以及 `proxy -> transaction -> handler -> Unit.context_functions` 链路。

语法检查：

```text
OpenAnt/.venv/bin/python -m py_compile \
  OpenAnt/libs/openant-core/core/platforms/openharmony/ipc_graph.py \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py \
  OpenAnt/libs/openant-core/tests/openharmony/test_unit_semantic_context.py
```

结果：通过。

## 5. OpenHarmony 相关回归

执行：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_*.py \
  OpenAnt/libs/openant-core/tests/test_c_pipeline.py \
  OpenAnt/libs/openant-core/tests/report/test_build_pipeline_output_return_contract.py
```

结果：`108 passed, 6 skipped in 0.61s`。

## 6. 真实仓库统计

对 `openharmony_reference/openharmony_source_code` 下当前 22 个仓库做只读统计，解析 IDL 方法和数值 `ipccode`，再扫描 C/C++ 文本中的直接十进制 `case` / `SendRequest` 字面量。

| 项目 | 结果 |
|---|---:|
| 仓库数 | 22 |
| 含数值 `ipccode` 方法的仓库数 | 4 |
| 含数值 `ipccode` 的方法数 | 362 |
| 直接数字 `SendRequest(N, ...)` 出现次数 | 0 |
| 与仓库内任意数字 `case` 值有交集的仓库 | 3 |

重点仓库：

| 仓库 | 数值 `ipccode` 方法 | native 数字 `case` 次数 | code 值粗粒度交集 |
|---|---:|---:|---:|
| `filemanagement_storage_service` | 149 | 14 | 3 |
| `multimedia_camera_framework` | 197 | 9 | 3 |
| `multimedia_audio_framework` | 15 | 92 | 2 |
| `window_window_manager` | 1 | 16 | 0 |

“粗粒度交集”只是仓库级候选上限，数字 `case` 可能属于普通业务逻辑，不等于 resolver 已建立 IPC 边。实际 resolver 仍要求 `OnRemoteRequest`/`SendRequest` 语境、函数 owner 和 IDL code 同时满足。

当前真实仓库中没有直接数字 `SendRequest`，说明 proxy 侧主要仍使用枚举或宏；OH-17C 对现有仓库的即时收益取决于是否存在可解析的数字 dispatch，而不是所有 362 个方法都会自动增加上下文。

## 7. 对 Unit 上下文的实际影响与边界

OH-17C 能改善 Unit 上下文的条件是：

1. IDL 有 `[ipccode N]`；
2. native dispatch/proxy 使用直接数字 `N`；
3. handler 已被抽取，并能通过现有调用图或方法变体规则确认。

满足条件时，路径为：

```text
ipc_code_literal
  -> stub/proxy_to_transaction
  -> transaction_to_handler
  -> Unit.metadata.context_functions
  -> Prompt Context 区域
```

如果 native 使用枚举/宏、生成 Stub 不在源码仓，或者只有 proxy 没有 handler，系统仍保留 orphan，不会强行填充上下文。

## 8. 结论

OH-17C 已完成一个小而安全的覆盖增强：在直接数字 IPC code 场景下补齐 semantic edge，并在 handler 证据存在时改善 `Unit.context_functions`。它没有改变原有名称/调用图匹配的误报边界。

后续若要继续提升真实 OpenHarmony 覆盖，优先实现枚举/宏常量解析，而不是放宽到任意相同数字匹配。

