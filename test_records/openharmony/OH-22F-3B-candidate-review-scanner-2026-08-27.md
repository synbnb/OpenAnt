# OH-22F-3B：候选边审核扫描接入测试记录

**日期**：2026-08-27  
**阶段**：OH-22F-3B  
**范围**：将 OH-22F-3A 的候选边审核协议接入 scanner/CLI，提供独立、默认关闭的审核开关。  
**模型调用**：本阶段仅使用 pytest 假模型，不调用真实 API，不产生模型费用。

## 1. 原逻辑与本阶段目标

原有 `--llm-call-graph-recovery` 只审核没有确定候选目标的 residual 间接调用点。
因此，`OnRemoteRequest()` 这类已经由规则识别出多个候选 handler 的分发点不会进入
LLM 审核。

本阶段增加独立选项：

```text
--llm-call-graph-candidate-review
```

开启后，scanner 会在 OpenHarmony 平台上读取同一份
`call_graph_residuals.json` 和 `call_graph.json`，调用已有审核器并传入
`include_candidate_sites=True`。审核结果单独写入：

```text
llm_call_graph_candidate_review.json
llm-call-graph-candidate-review.report.json
```

该结果仍是 advisory（建议性）产物，不会修改：

```text
call_graph.json
dataset.json
reachable 结果
```

原有 `--llm-call-graph-recovery` 的默认行为和产物保持不变；两个开关同时开启时，
两轮审核分别执行，API 成本也分别统计。

## 2. 实现内容

### Scanner

- `scan_repository()` 新增 `llm_call_graph_candidate_review` 参数。
- 新增独立的 `llm-call-graph-candidate-review` 阶段。
- 只在 `effective_platform == "openharmony"` 时执行；通用平台安全跳过，不把通用代码
  发送给 OpenHarmony prompt。
- 汇总每种语言的审核状态、worklist、调用次数、accepted/rejected 等统计。
- 在 `ScanResult` 和 `scan.report.json` 的 outputs 中暴露
  `llm_call_graph_candidate_review_path`。
- `_count_steps()` 和扫描 banner 会显示该阶段，避免进度总数与实际阶段不一致。

### CLI

新增：

```text
openant scan <repo> --llm-call-graph-candidate-review
```

默认解析结果为 `False`，不影响普通扫描费用和流程。

### 设计边界

本阶段没有把 accepted 边投影回调用图。这样可以先观察模型对多目标分发点的判断，
确认结果质量后，再单独讨论数字 `code` 证据提炼和图投影策略。

## 3. TDD 测试过程

测试文件：

```text
libs/openant-core/tests/test_scanner_llm_recovery_integration.py
```

### RED

在生产代码接入前运行：

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py
```

结果：

```text
3 failed, 2 passed
```

失败原因符合预期：CLI 没有候选审核参数，scanner 不接受新参数，默认 Namespace 也没有
对应字段。

### GREEN

接入 scanner、CLI、ScanResult 后运行：

```bash
PYTHONPATH=libs/openant-core .venv/bin/pytest -q \
  libs/openant-core/tests/test_scanner_llm_recovery_integration.py \
  libs/openant-core/tests/openharmony
```

结果：

```text
141 passed, 2 skipped in 0.53s
```

覆盖内容包括：

1. CLI 开关默认关闭并能正确透传到 scanner；
2. OpenHarmony 候选审核会调用 `include_candidate_sites=True`；
3. 测试 residual 确实包含候选目标，候选审核会生成独立 JSON 和阶段报告；
4. 通用平台开启该开关时只记录 `unsupported_platform`，不会调用 OH 审核器；
5. 既有 residual recovery、候选边协议和执行器测试不回归。

## 4. 静态检查

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

CLI 帮助中已出现两个独立选项：

```text
--llm-call-graph-recovery
--llm-call-graph-candidate-review
```

补充说明：另有一组包含历史 scanner/模型代理测试的扩展回归在本机代理上长时间等待
网络响应，未纳入本阶段通过数，已主动终止；本阶段实际依赖的 scanner 集成测试和
OpenHarmony 测试均已完成并通过。

## 5. 尚未完成

- 尚未对真实 `sensors_medical_sensor` 调用真实模型；
- 尚未自动提炼 `code == n` 与注册语句之间的结构化证据；
- 尚未把 accepted 候选边投影到 `call_graph.json` 或 reachable；
- 尚未在 Web 页面增加该独立开关；
- 仍需基于真实模型结果评估是否会误加候选边。

下一阶段应先运行一次真实 `sensors_medical_sensor` 候选审核，检查 8 个
`OnRemoteRequest` handler 是否被完整、准确地返回，再决定是否进入证据投影阶段。
