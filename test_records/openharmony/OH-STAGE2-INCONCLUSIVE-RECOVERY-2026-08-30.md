# Stage 2 待定结果补证复核测试记录

日期：2026-08-30  
范围：标准扫描流程中的 Stage 2 `FindingVerifier` 入口与结果合并逻辑  
类型：离线回归测试，无真实大模型调用、无真实仓库改动

## 本阶段目标

验证 Stage 1 输出为 `inconclusive` 时，是否可以进入 Stage 2，利用
`search_definitions`、`search_usages`、`read_function`、`list_functions` 等工具
补充下游证据，并且不会因为 Stage 2 的结果把原条目重复计数或误计为安全。

## 修改后的行为

1. 标准扫描在 `--verify` 下将 `vulnerable`、`bypassable` 和
   `inconclusive` 作为 Stage 2 候选；`safe`、`protected` 和硬错误仍然排除。
2. Stage 2 提示词对 `inconclusive` 进入证据恢复模式，要求优先查找未解析的下游
   函数、成员分派、参数转发和指针/容器/枚举的第一次下游使用。
3. 每个验证结果保存 `verification.stage1_finding`，用于区分原始结论和最终结论。
4. 汇总使用 `results_verified.json` 的最终结论桶，避免出现
   `inconclusive -> vulnerable/safe` 后仍保留旧待定计数的问题。
5. 对待定条目单独记录：输入数量、升级为漏洞数量、已解决数量、仍待定数量。
6. Stage 2 将待定条目升级为漏洞时，报告阶段不会再把它误标为 `rejected` 并丢弃。
7. Stage 2 调用异常时，错误状态优先于原始 `finding`，不会把失败条目误计为漏洞或待定。

## 离线测试结果

执行命令：

```bash
PYTHONPATH=libs/vulnfounder-core pytest -q \
  libs/vulnfounder-core/tests/test_stage2_inconclusive_recovery.py \
  libs/vulnfounder-core/tests/test_generalized_vulnerability_prompt.py \
  libs/vulnfounder-core/tests/report/test_poisoned_results_substrate.py \
  libs/vulnfounder-core/tests/test_pr69_round5_unverified.py \
  libs/vulnfounder-core/tests/test_e2e_model_propagation.py \
  libs/vulnfounder-core/tests/openharmony/test_stage2_platform_context.py \
  libs/vulnfounder-core/tests/test_scanner.py \
  libs/vulnfounder-core/tests/test_reporter_status_fidelity.py
```

结果：`75 passed in 0.53s`。

覆盖内容：

- 候选筛选包含 `inconclusive`，且不包含 `safe/protected/error`；
- 待定结果升级为 `vulnerable`、解决为 `protected`、保持待定和验证不完整等分支；
- 最终结果桶不重复计数；
- Stage 2 待定补证提示词内容；
- 模拟 FindingVerifier 的工具调用结果并验证结果文件；
- 验证升级后的条目可以进入报告，不会被错误标记为 `rejected`；
- 验证带有 `error` 的条目最终只进入 `errors` 统计桶，不会沿用第一阶段结论；
- 既有 Stage 2 不完整、扫描器、报告器和 OpenHarmony 平台上下文回归测试。

## 完整测试集状态

执行 `PYTHONPATH=libs/vulnfounder-core pytest -q libs/vulnfounder-core/tests` 时，测试在收集阶段
因本机环境缺少已有项目依赖而中止，主要包括：

- `tree_sitter_c`、`tree_sitter_php`、`tree_sitter_rust`、`tree_sitter_zig`；
- Google `genai` SDK。

该失败发生在测试模块导入阶段，未进入本阶段改动的测试逻辑。后续补齐项目开发依赖后，
需要重新执行完整测试集。

## 当前限制

本阶段只让 `inconclusive` 进入已有 Stage 2 工具循环，没有新增参数流专用工具，也没有
把 Stage 2 恢复出的调用边写回原生调用图。对于复杂的虚函数、宏、跨仓库调用，模型仍可能
返回 `inconclusive`，这时结果会被保留并标记为需要人工审阅。
