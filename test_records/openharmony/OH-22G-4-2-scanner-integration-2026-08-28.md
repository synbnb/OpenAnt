# OH-22G-4-2：逐轮调用图恢复接入扫描器

## 测试日期

2026-08-28

## 原项目逻辑

扫描器只有一次性 OpenHarmony 残余审核路径：读取每种语言的
`call_graph_residuals.json`，调用一次 `run_recovery_review`，写入
`llm_call_graph_recovery.json`。投影阶段只认识一次性审核和候选审核文件，不能
消费逐轮报告。

## 本阶段修改逻辑

- 新增显式 Python/Go CLI 选项 `--llm-call-graph-iterative-recovery`；默认值为关闭；
- `scan_repository` 在该选项开启时调用入口驱动的
  `run_iterative_recovery_review`，同时传入函数索引、原生调用图和已有语义图；
- 迭代结果写入 `llm_call_graph_recovery_rounds.json`，每种语言保留轮次、前沿、审核、
  投影和预算摘要；旧选项仍写入原来的 `llm_call_graph_recovery.json`；
- `llm_call_graph_projection` 新增轮次文件输入，但会重新对每轮 `review` 执行
  `project_recovery_overlay`，不会直接信任轮次文件中的合并图；
- `ScanResult` 和最终 `scan.report.json` 增加 `llm_call_graph_rounds_path`；
- OpenHarmony 以外的平台安全跳过；模型失败、缺少语义图或残余文件不会中断已有扫描。

## 自动化测试

执行环境：VulnFounder `.venv`（Python 3.13，含 tree-sitter 依赖）。

### 扫描器和 CLI 回归

```text
.venv/bin/python -m pytest -q \
  libs/vulnfounder-core/tests/test_scanner_llm_recovery_integration.py
```

结果：`17 passed`。

覆盖：

- 新 CLI 选项默认关闭并正确转发；
- 迭代扫描写入轮次文件，而不是覆盖旧的一次性文件；
- 投影阶段重新校验每一轮审核并生成 overlay；
- `ScanResult` 和 `scan.report.json` 暴露轮次文件路径；
- generic 平台不会调用 OpenHarmony 迭代逻辑。

### OpenHarmony 全套回归

```text
.venv/bin/python -m pytest -q libs/vulnfounder-core/tests/openharmony
```

结果：`156 passed, 2 skipped`。

### 组合结果

扫描器集成与 OpenHarmony 套件合计：`173 passed, 2 skipped`。

### 静态检查

```text
.venv/bin/python -m py_compile \
  libs/vulnfounder-core/core/scanner.py \
  libs/vulnfounder-core/core/schemas.py \
  libs/vulnfounder-core/openant/cli.py \
  libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_rounds.py
.venv/bin/ruff check \
  libs/vulnfounder-core/core/scanner.py \
  libs/vulnfounder-core/core/schemas.py \
  libs/vulnfounder-core/openant/cli.py \
  libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_rounds.py \
  libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_recovery.py \
  libs/vulnfounder-core/core/platforms/openharmony/llm_call_graph_projection.py \
  libs/vulnfounder-core/tests/test_scanner_llm_recovery_integration.py
git diff --check
```

结果：全部通过。当前环境没有 Go 工具链，因此 Go 单测未执行；Go flag 测试文件已
同步更新，待具备 Go 工具链的 CI/开发环境执行。

## 真实 sensors_medical_sensor 离线回放

输入：`debug_outputs/OH-22F-2-real-sensors-20260827/` 中真实解析得到的
`call_graph.json`、`call_graph_residuals.json`、`semantic_graph.json` 和
`dataset.json`，对应 340 个函数、7 个结构化入口、3 个残余调用点。回放使用离线
completion，仅返回 `keep_unresolved`，不产生 API 请求。

默认残余模式：

```text
worklist_sites=2, rounds=2, sites_scheduled=0, sites_reviewed=0,
unreviewed_sites=2, llm_calls=0, projected_edges=0,
termination_reason=frontier_exhausted
```

包含候选模式：

```text
worklist_sites=3, rounds=2, sites_scheduled=1, sites_reviewed=1,
unreviewed_sites=2, llm_calls=1, projected_edges=0,
termination_reason=frontier_exhausted
```

源码检查确认 3 个残余调用点的文件均存在于
`source_code_base/sensors_medical_sensor`，caller ID 均存在于函数索引。两个无候选
callback 残余不属于当前入口可达范围，因此不会被迭代器盲目提交给模型。

## 结论

扫描器接入保持了旧路径兼容性，迭代模式只有显式开启才会增加模型调用。轮次文件
可以被投影阶段安全消费，原始 `call_graph.json` 不被修改。下一阶段应在真实仓库上
用小预算比较一次性与逐轮模式的边召回、未解析残余和费用。
