# OH-22E-2：调用边恢复差异报告接入流水线

日期：2026-08-27  
平台：OpenHarmony  
仓库：`/Users/shiyu/学习/hyl/new/VulnFounder`  
真实验证仓库：`source_code_base/sensors_medical_sensor`

## 1. 本阶段目标

将 OH-22E-1 的纯报告函数接入 C/C++ OpenHarmony 流水线，使扫描产物目录
自动出现 `dispatch_recovery_diff.json`，并且在执行 reachability 过滤后刷新
其中的 baseline/recovered 集合。

## 2. 原逻辑与修改后逻辑

### 原逻辑

- C/C++ parser 阶段写出 `call_graph.json`、`call_graph_residuals.json`、
  `semantic_graph.json` 和 `dataset.json`；
- reachability 阶段把 SemanticGraph 投影边临时合并到 BFS 图中；
- 没有统一的调用边差异文件，也无法从阶段产物直接审计 reachable 是否
  发生意外裁剪。

### 修改后逻辑

修改 `libs/vulnfounder-core/parsers/c/test_pipeline.py`：

1. `CPipelineTest` 新增 `dispatch_recovery_diff_file` 产物路径；
2. OpenHarmony parser 阶段在原生调用图、诊断和语义图准备完成后写入初始
   `dispatch_recovery_diff.json`，此时 reachable 状态是 `not_evaluated`；
3. OpenHarmony reachability 阶段在“无入口保留全部单元”的既有安全兜底之后，
   用最终的 native/recovered 集合覆盖同一报告；
4. dataset metadata 和阶段 summary 都登记该文件的相对路径、状态和数量；
5. 报告生成是可选审计输出，异常只打印 warning，不阻断原 parser/reachability
   结果；
6. generic/其他平台不创建该产物，原有调用图仍不被修改。

## 3. TDD 与自动化测试

### 集成 RED

先新增两个集成测试，执行：

```bash
./.venv/bin/pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_dispatch_recovery_pipeline.py
```

结果：2 个测试失败，原因都是旧流水线没有生成
`dispatch_recovery_diff.json`，符合预期的 RED 阶段。

### GREEN

接入 parser/reachability 后：

```text
3 passed in 0.05s
```

额外增加了一个回归测试，覆盖“没有结构化入口时保留全部单元”的安全兜底，
并确认报告中的 `recovered_count` 与最终保留单元一致。

### 回归

```bash
./.venv/bin/pytest -q libs/vulnfounder-core/tests/openharmony
```

结果：

```text
129 passed, 2 skipped in 0.46s
```

```bash
./.venv/bin/pytest -q libs/vulnfounder-core/tests/parsers/c
```

结果：

```text
99 passed in 0.43s
```

```bash
./.venv/bin/ruff check \
  libs/vulnfounder-core/parsers/c/test_pipeline.py \
  libs/vulnfounder-core/core/platforms/openharmony/dispatch_recovery_diff.py \
  libs/vulnfounder-core/tests/openharmony/test_dispatch_recovery_pipeline.py
git diff --check
```

结果：Ruff `All checks passed!`，空白检查通过。

## 4. 真实仓库离线验证

没有启用 LLM，没有连接设备，只执行本地 parser。

### 4.1 ALL 级别

命令：

```bash
./.venv/bin/python libs/vulnfounder-core/parsers/c/test_pipeline.py \
  source_code_base/sensors_medical_sensor \
  --output debug_outputs/OH-22E-2-sensors-all-20260827 \
  --processing-level all --platform openharmony --skip-tests
```

流水线结果：

| 指标 | 数值 |
| --- | ---: |
| 扫描文件 | 67 |
| 提取函数 | 408 |
| 原生调用边 | 227 |
| SemanticGraph 边 | 16 |
| 投影边 | 16 |
| 新增边 | 16 |
| 残余调用点 | 3 |
| 有候选的残余点 | 1 |
| 候选边 | 8 |
| orphan | 0 |
| reachable 状态 | `not_evaluated` |

产物：

- [dispatch_recovery_diff.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-all-20260827/dispatch_recovery_diff.json)
- [call_graph.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-all-20260827/call_graph.json)
- [semantic_graph.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-all-20260827/semantic_graph.json)
- [call_graph_residuals.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-all-20260827/call_graph_residuals.json)
- [run.log](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-all-20260827/run.log)

### 4.2 REACHABLE 级别

命令：

```bash
./.venv/bin/python libs/vulnfounder-core/parsers/c/test_pipeline.py \
  source_code_base/sensors_medical_sensor \
  --output debug_outputs/OH-22E-2-sensors-reachable-20260827 \
  --processing-level reachable --platform openharmony --skip-tests
```

流水线结果：

| 指标 | 数值 |
| --- | ---: |
| 结构化入口 | 7 |
| 原始 dataset 单元 | 408 |
| native reachable | 11 |
| 增强后 reachable | 47 |
| Semantic overlay 新增可达单元 | 36 |
| 最终过滤单元 | 47 |
| 原生 reachable 被移除 | 0 |
| 单调性 | `preserved` |

产物：

- [dispatch_recovery_diff.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-reachable-20260827/dispatch_recovery_diff.json)
- [dataset.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-reachable-20260827/dataset.json)
- [pipeline_results.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-reachable-20260827/pipeline_results.json)
- [run.log](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-2-sensors-reachable-20260827/run.log)

### 4.3 源码证据抽查

`semantic_graph.json` 中的 16 条新增边均来自实际源码证据：

- `medical_service_stub.cpp:68` 的
  `MedicalSensorServiceStub::OnRemoteRequest` 通过 `baseFuncs_` 分派到
  8 个 `*Inner` handler；
- 同一文件的第 39～46 行登记了 8 个成员函数指针；
- 头文件第 39 行表明 `MedicalSensorService` 继承
  `MedicalSensorServiceStub`；
- 第 86、100、115、129、143、149、184、194 行的 stub handler 调用被
  解析为对应的 `MedicalSensorService::*` 方法。

报告没有把两个无法解析的 callback 成员函数指针强行连到某个目标：

1. `compatible_connection.cpp:147`：`cacheData_`，无候选；
2. `sensor_event_callback.cpp:55`：`reportDataCb_`，无候选。

这说明报告保留了当前未知边，而不是为了提高数量而制造幽灵节点。

## 5. 当前边界

- 报告已自动写入 parser/reachability 输出目录，但 Web 展示仍沿用现有产物
  浏览逻辑，尚未增加专门的差异图视图；
- `ALL` 级别没有执行 reachability，因此报告的 reachable 状态正确地保持为
  `not_evaluated`；
- 3 个残余调用点仍需要后续更强的数据流分析或 OH-22F 的 LLM 审核，不能把
  本阶段结果解释为调用图已经完整；
- 本阶段只验证了 `sensors_medical_sensor`，尚未批量跑完全部参考仓库。

## 6. 结论

OH-22E-2 已完成：差异报告现在会随 OpenHarmony C/C++ 流水线自动产生，
reachability 阶段会用最终集合刷新，并且真实仓库验证确认没有裁剪原生
reachable 函数。报告仍诚实保留未解析残余，后续可据此决定是否进入 LLM 边审核。
