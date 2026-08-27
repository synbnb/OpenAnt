# OH-22B-2E：Lambda 分派投影到 SemanticGraph 测试记录

- 日期：2026-08-27
- 阶段：OH-22B-2E
- 目标仓库：`openharmony_reference/openharmony_source_code/telephony_core_service`
- 解析语言：C/C++（本次命令使用 `--language c`）
- 本阶段不调用大模型，不修改原生 `call_graph.json`。

## 1. 原逻辑与本阶段修改后的逻辑

### 原逻辑

Tree-sitter 已经能观察到一部分 C++ Lambda 分派信息，并将信息写入
`call_graph_residuals.json` 的 `lambda_dispatch` 节点，包括：

- Lambda 注册点，例如 `memberFuncMap_[code] = [this](...) { Handler(...); }`；
- 调用点，例如从 map 查找 `it->second(...)`；
- 根据 selector 找到的候选目标函数。

但是，原来的 `native_dispatch.py` 只消费顶层的直接函数指针/成员函数指针分派诊断，
不会消费嵌套的 `lambda_dispatch`。因此 Lambda 信息只能作为残留诊断保存，不能形成
SemanticGraph 边，也不会进入 Unit 的语义上下文或 reachable 过滤。OH-22B-2D 的同一
真实仓库结果为 `semantic_context_functions=0`，SemanticGraph 只有 21 条 IDL 边。

### 新逻辑

本阶段在不改写原生调用图的前提下，将 Lambda 候选作为一个有证据的语义覆盖层：

1. 读取 `lambda_dispatch.assignments`（注册点）和 `lambda_dispatch.call_sites`（调用点）。
2. 对每个候选执行严格匹配：
   - 候选目标 ID 必须存在于函数索引中；
   - selector 必须与注册点一致；
   - dispatch table 必须一致；
   - 如果两边有 field identity，则 field、receiver type 必须一致；
   - 兼容缺少 identity 的旧诊断时，只在 table 相同且 owner class 与调用者类已证实时接受；
   - 无法完成证据闭合的候选只保留在残留诊断中，不进入图。
3. 复用已有 `native_dispatch_to_handler` 边类型，增加
   `attributes.callable_kind=lambda`，并保留注册点与调用点的双重 source evidence。
4. SemanticGraph 产生的边由现有 Unit 上下文和 semantic reachable overlay 消费；原生
   `call_graph.json` 保持不变。

## 2. 自动化测试

### 定向回归测试

```text
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/openharmony/test_native_dispatch.py \
  libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py
```

结果：`18 passed in 0.04s`。

覆盖内容包括：

- Lambda 候选能投影为 SemanticGraph 边；
- 边包含 `callable_kind`、dispatch table、selector、registration form；
- 注册点与调用点证据都被保留；
- 该边能进入 semantic reachability overlay 和 Unit `context_functions`；
- 未知目标不会创建语义边；
- 原生调用图输入对象不会被修改。

### 相关回归测试集

```text
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/openharmony \
  libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py \
  libs/openant-core/tests/parsers/c
```

结果：`214 passed, 2 skipped in 1.02s`。

### 静态检查

- Ruff：通过（`All checks passed!`）。
- `git diff --check`：通过。

## 3. 真实 OpenHarmony 仓库验证

### 3.1 All 模式解析

命令：

```text
PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli parse \
  openharmony_reference/openharmony_source_code/telephony_core_service \
  --output debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c \
  --platform openharmony --language c --level all --fresh
```

结果文件：

- [parse.report.json](../../debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c/parse.report.json)
- [call_graph.json](../../debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c/call_graph.json)
- [call_graph_residuals.json](../../debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c/call_graph_residuals.json)
- [semantic_graph.json](../../debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c/semantic_graph.json)
- [dataset.json](../../debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c/dataset.json)

解析成功，关键指标如下：

| 指标 | 结果 |
|---|---:|
| 发现文件 | 1056 |
| 生产文件（eligible/parsed） | 540 / 540 |
| C/C++ 函数单元 | 6842 |
| 原生调用图边 | 7196 |
| SemanticGraph 节点/边 | 358 / 341 |
| 其中 Lambda 分派边 | 320 |
| 其中 IDL transaction 边 | 21 |
| SemanticGraph orphan 节点 | 42 |
| Lambda 注册点 | 347 |
| Lambda 调用点 | 16 |
| Lambda 候选边 | 320 |
| 无候选的 Lambda 调用点 | 0 |
| 无法闭合的注册点 | 17 |
| field alias 匹配 | 108 |

单条 Lambda 边的实际证据形态为：

```text
function:...INetworkSearchCallbackStub::OnNetworkSearchCallback
  --native_dispatch_to_handler / callable_kind=lambda-->
function:...INetworkSearchCallbackStub::OnGetManualNetworkScanStateCallback
```

该边的属性包含 `memberFuncMap_`、具体 selector、`subscript_assignment`、receiver
type `INetworkSearchCallbackStub`，证据同时来自 `lambda_dispatch_assignment` 和
`lambda_dispatch_call_site`。

### 3.2 与 OH-22B-2D 的原生调用图不变性

对 OH-22B-2D 与本阶段 `call_graph.json` 的 `(source_id, target_id)` 有序边集计算
SHA-256：

```text
OH-22B-2D：0b833014a978829984779cfac69ac5d0123e0cd5417c9c9c6e2a0527b786c93b
OH-22B-2E：0b833014a978829984779cfac69ac5d0123e0cd5417c9c9c6e2a0527b786c93b
```

两者均为 6842 个函数、7196 条原生调用图边，说明本阶段是附加语义图，不会污染
原有 tree-sitter 原生调用图。

### 3.3 Unit 上下文变化

本阶段 all 模式的 `dataset.json.statistics`：

```text
units_with_semantic_context = 336
semantic_context_functions  = 640
units_enhanced              = 4725
```

OH-22B-2D 同一仓库对应值为：

```text
units_with_semantic_context = 0
semantic_context_functions  = 0
units_enhanced              = 4661
```

真实样例：

- `CoreServiceCommonEventHub::OnReceiveEvent` 获得 22 个 Lambda 处理器上下文；
- `CellInfo::ProcessNeighboringCellInfo` 获得 6 个邻近小区处理器上下文。

这证明新增的边已经被 Unit 上下文消费，而不是只写入独立的诊断文件。

### 3.4 Reachable 模式解析

命令：

```text
PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli parse \
  openharmony_reference/openharmony_source_code/telephony_core_service \
  --output debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-reachable \
  --platform openharmony --language c --level reachable --fresh
```

结果文件：[reachable dataset.json](../../debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-reachable/dataset.json)

reachable 元数据记录：

```text
原始单元数                 = 6842
入口数                     = 50
仅原生调用图可达单元       = 113
语义边新增可达单元         = 318
最终保留单元               = 431
过滤单元                   = 6411
缩减比例                   = 93.7%
overlay 候选边             = 320
overlay 实际新增边         = 319
非法端点                   = 0
monotonicity_violation     = false
```

`monotonicity_violation=false` 且最终 431 大于原生可达的 113，说明语义覆盖层只扩大
可达集合，不会因本阶段接入而裁剪掉原来通过原生调用图能够到达的单元。

## 4. 结果判断与边界

### 已验证有效

1. 真实 telephony 仓库中 320 条有注册点、调用点、目标函数和 selector 证据闭合的
   Lambda 分派边已经进入 SemanticGraph。
2. Unit 语义上下文由 0 增至 336 个单元，证明下游消费链路已接通。
3. reachable 结果保持单调，原生调用图边集及哈希完全不变。
4. 未知目标和无法闭合的候选不会被强行写成图边，仍可在 residual 诊断中追踪。

### 尚未宣称解决

- 17 个 orphan 注册点仍需要后续分析，当前没有把它们猜测性加入图；
- 顶层非 Lambda 间接调用仍有 11 个 residual call site；
- 本阶段没有接入 LLM，也没有处理 `std::bind`、跨文件别名传播等更高阶情况；
- 320 条边证明了当前仓库的覆盖改善，但不能据此宣称所有 OpenHarmony 仓库的 Lambda
  形态都已完整覆盖。

## 5. 可复现输出目录

```text
debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-parse-c/
debug_outputs/OH-22B-2E-telephony-semantic-lambda-20260827-reachable/
```
