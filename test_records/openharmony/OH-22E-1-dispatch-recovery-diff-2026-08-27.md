# OH-22E-1：调用边恢复差异报告与可达性单调性纯函数

日期：2026-08-27  
平台：OpenHarmony  
仓库：`/Users/shiyu/学习/hyl/new/OpenAnt`

## 1. 本阶段目的

OH-22D 已经可以根据确定性的 OpenHarmony 语法和数据流证据生成
SemanticGraph 恢复边，但原流水线没有单独的产物回答以下问题：

1. 原生 C/C++ 调用图有哪些边；
2. SemanticGraph 投影出了哪些边，哪些是新增边；
3. 每个新增边对应哪些语义边类型和残余调用点；
4. 接入语义边后，reachable 集合是否至少包含原生 reachable 集合。

本阶段只实现离线、纯函数形式的报告生成器，不改变原始调用图、不调用
大模型、不连接网络，也尚未把文件写入现有 C/C++ 流水线。

## 2. 原逻辑与修改后逻辑

### 原逻辑

- `call_graph.json` 保存原生调用图；
- `call_graph_residuals.json` 保存未解析的间接调用和候选目标；
- `semantic_graph.json` 保存 IDL/native dispatch 等语义关系；
- reachability 过滤器在内存中把经过验证的语义关系投影为临时边，并已有
  防御性单调性检查；
- 但是这些信息分散在不同文件中，没有统一、稳定排序的差异报告。

### 修改后逻辑

新增：

`libs/openant-core/core/platforms/openharmony/dispatch_recovery_diff.py`

公开函数：

```python
build_dispatch_recovery_diff(
    call_graph_result,
    diagnostics,
    semantic_graph,
    baseline_reachable=None,
    recovered_reachable=None,
)
```

函数会：

- 从 `call_graph` 和 `reverse_call_graph` 的并集提取原生边，避免某一方向
  缺失导致报告不完整；
- 调用现有的 `build_semantic_reachability_overlay` 生成经过已知函数 ID
  校验的投影边；
- 将投影边与原生边按 `(source_id, target_id)` 比较，产出
  `projected_edges`、`added_edges`、`retained_edges`；
- 合并普通间接调用和 `lambda_dispatch.call_sites`，保留文件、行号、表达式、
  原因和候选函数 ID；
- 合并普通 orphan 与 lambda orphan，保留来源类型和源位置；
- 当同时提供 baseline/recovered reachable 集合时，计算新增、缺失函数并将
  状态标为 `preserved` 或 `violation`；只提供一侧时标为
  `not_evaluated`；
- 对输入做复制/规范化，忽略格式错误的记录并在 `ignored_records` 中计数，
  不修改调用方对象；所有列表采用稳定排序，便于审计、测试和 Web 展示。

报告主要字段：

| 字段 | 含义 |
| --- | --- |
| `native_edges` | 原生调用图边的有序列表 |
| `semantic_edges` | 语义图边及其可选 confidence/evidence |
| `projected_edges` | 可达性 overlay 投影到函数 ID 后的边 |
| `added_edges` | overlay 中原生图没有的新增边 |
| `retained_edges` | overlay 与原生图已重合的边 |
| `residual_sites` | 仍需关注的普通/λ 间接调用点及候选数 |
| `orphans` | 无法解析到已知函数的登记项 |
| `reachability` | baseline 与 recovered 的单调性结果 |
| `summary` | 各类数量统计 |
| `ignored_records` | 被安全忽略的格式错误记录数 |

## 3. TDD 执行记录

### RED

先新增测试：

`libs/openant-core/tests/openharmony/test_dispatch_recovery_diff.py`

执行：

```bash
pytest -q tests/openharmony/test_dispatch_recovery_diff.py
```

结果：失败（预期）。测试收集阶段报：

```text
ModuleNotFoundError: No module named
'core.platforms.openharmony.dispatch_recovery_diff'
```

这证明测试针对的是尚不存在的功能，而不是误把已有行为当作通过。

### GREEN

新增纯函数模块后执行：

```bash
pytest -q tests/openharmony/test_dispatch_recovery_diff.py
```

结果：

```text
3 passed in 0.02s
```

覆盖的行为：

1. 新增投影边、残余调用点、lambda 残余和 orphan 的确定性汇总；
2. baseline 是 recovered 子集时报告 `preserved`；
3. recovered 丢失 baseline 函数时报告 `violation`；
4. 缺失 reachable 输入和畸形记录时安全降级；
5. 输入对象和集合保持不变。

### REFACTOR/静态检查

执行：

```bash
./.venv/bin/ruff check \
  libs/openant-core/core/platforms/openharmony/dispatch_recovery_diff.py \
  libs/openant-core/tests/openharmony/test_dispatch_recovery_diff.py
git diff --check
```

结果：

```text
All checks passed!
```

`git diff --check` 无输出，表示没有空白错误。

### OpenHarmony 回归

执行：

```bash
./.venv/bin/pytest -q libs/openant-core/tests/openharmony
```

结果：

```text
126 passed, 2 skipped in 0.45s
```

OH-22A～OH-22D 的现有测试未受到影响。

## 4. 当前边界

- 本阶段模块已经可以被其他 Python 代码直接调用，但还没有在
  `parsers/c/test_pipeline.py` 中自动写出 `dispatch_recovery_diff.json`；
- 因而本阶段没有声称 Web 或命令行扫描会自动出现该新文件；
- reachable 单调性报告只在调用方同时传入两套集合时判定；
- 投影边的精确语义证据仍以 `semantic_edges` 中的 evidence 和
  `residual_sites` 中的源位置为准，本阶段不猜测语义路径；
- 下一小阶段 OH-22E-2 将先审查 C/C++ 流水线的已有生命周期，在不影响普通
  平台的前提下写出 `dispatch_recovery_diff.json`，再用
  `sensors_medical_sensor` 等真实仓库验证内容。

## 5. 结论

OH-22E-1 已完成并通过专门测试及 OpenHarmony 回归。它提供了一个不改变分析
结果的审计层，为下一阶段流水线接入和真实仓库对比提供稳定契约。
