# OH-22F-2：scanner/CLI 接入 LLM 间接调用审核测试记录

**日期**：2026-08-27  
**阶段**：OH-22F-2 第一小阶段  
**范围**：为 OpenHarmony 扫描流程增加可选的 LLM 间接调用审核阶段  
**阶段边界**：只接入执行和产物生成，不把模型建议写回调用图、SemanticGraph、reachable 或 dataset。

## 1. 原有逻辑

scanner 原有流程可以解析源码、建立调用图、生成
`call_graph_residuals.json`，然后继续执行增强、漏洞检测、验证、报告和动态测试。

此前的 `run_recovery_review()` 只能作为独立 Python 函数调用，scanner 和 CLI 不会主动
触发它，也不会在扫描目录中生成审核产物。已有的 `--llm-reachability` 只负责审核函数
是否可能是入口点，不负责判断残余间接调用边。

## 2. 本阶段修改

### CLI

新增可选开关：

```text
--llm-call-graph-recovery
```

默认值为关闭。`openant scan` 会把该选项透传到
`core.scanner.scan_repository()`。

### scanner

开启后，在解析阶段之后、增强和漏洞检测之前增加：

```text
OpenHarmony residual diagnostics
    → run_recovery_review()
    → llm_call_graph_recovery.json
```

单语言扫描读取输出根目录下的：

```text
call_graph.json
call_graph_residuals.json
```

多语言扫描通过已有的 `call_graphs.json` 索引逐语言读取对应目录，最后在扫描根目录
生成一个汇总产物。

阶段复用现有 `llm_reach` PhaseBinding，不新增 API Key 或配置格式。模型审核结果保持
advisory（建议性）性质，后续阶段仍使用原始调用图。

### 新增产物

```text
llm_call_graph_recovery.json
llm-call-graph-recovery.report.json
```

汇总产物包括：

- 每个语言分区的审核状态；
- 对应调用图和 residual 文件的相对路径；
- worklist 数量、模型调用次数、重试次数；
- `accepted`、`kept_unresolved`、`rejected` 数量；
- 缺失产物和分区级错误。

`ScanResult` 和最终 `scan.report.json` 增加
`llm_call_graph_recovery_path`，便于 CLI/Web 定位文件。

### 非 OpenHarmony 行为

如果用户在 generic 或未识别为 OpenHarmony 的扫描中误开该选项：

- 不调用 OpenHarmony 审核器；
- 不发送模型请求；
- 阶段报告标记为 `skipped`，原因是 `unsupported_platform`；
- 其余扫描流程继续执行。

## 3. TDD 测试过程

测试文件：

```text
libs/openant-core/tests/test_scanner_llm_recovery_integration.py
```

### RED

在生产代码未增加开关和阶段前运行：

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py
```

结果：

```text
3 failed
```

失败原因分别为 CLI Namespace 没有新字段、`scan_repository()` 不接受新参数，符合
预期的 RED 阶段。

### GREEN

补充生产实现后运行同一命令：

```text
3 passed in 0.38s
```

覆盖内容：

1. 开关默认关闭，并能透传为 `True`；
2. OpenHarmony 真实格式的调用图/residual 夹具能触发审核器并写出两个产物；
3. generic 扫描开启开关时安全跳过，不调用审核器。

测试中的审核器使用本地 fake reviewer，不产生真实 API 请求或费用。

## 4. 回归测试

### scanner/CLI/schema/artifact 相关

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py \
  libs/openant-core/tests/test_scanner.py \
  libs/openant-core/tests/test_cli_platform_flags.py \
  libs/openant-core/tests/test_schemas_multilang.py \
  libs/openant-core/tests/test_artifact_serialization_contract.py
```

结果：

```text
39 passed in 0.57s
```

### OpenHarmony 测试集

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/openharmony
```

结果：

```text
132 passed, 2 skipped in 0.49s
```

### 静态检查

```bash
.venv/bin/ruff check \
  libs/openant-core/core/scanner.py \
  libs/openant-core/core/schemas.py \
  libs/openant-core/openant/cli.py \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py
git diff --check
```

结果：

```text
All checks passed!
```

### 全量测试环境限制

执行整个 `libs/openant-core/tests` 时，既有 Go conformance 用例在当前环境首先失败：

```text
FileNotFoundError: [Errno 2] No such file or directory: 'go'
```

这是测试环境缺少 Go 工具链导致的前置失败，不是本阶段 Python 代码的失败；本阶段相关
定向回归和 OpenHarmony 全量回归均已通过。

## 5. 尚未进行的工作

- 没有调用真实 GPT/Claude API；
- 没有将审核通过的边投影到调用图；
- 没有改变 reachable 过滤结果；
- 没有增加 Web 开关或友好视图；
- 没有执行真实 OpenHarmony 仓库的付费 scanner 运行。

下一小阶段应先讨论是否把 `llm_call_graph_recovery.json` 纳入 Web 阶段菜单和结果查看，
然后再考虑真实模型运行与投影策略。
