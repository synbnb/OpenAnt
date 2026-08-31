# OH-22G-12 Web 实时中文决策日志测试记录

日期：2026-08-28  
范围：扫描器到 Web SSE 的实时日志链路  

## 目标

在不改写原有英文诊断输出、不改变扫描判定和产物格式的前提下，让 Web 的运行日志窗口能够解释主要阶段、输入、筛选、降级、模型和产物决策。

## 实现内容

- 新增 `core/observability.py`，统一输出单行、立即刷新的 `【运行说明】`、`【检测决策】`、`【验证结果】` 等中文日志。
- `core/scanner.py` 在扫描准备、平台选择、解析、应用上下文、LLM 可达性、OpenHarmony 调用图恢复/投影、增强、检测、验证、汇总输出、动态验证、报告和收尾阶段追加中文说明。
- `core/analyzer.py`、`core/verifier.py`、`core/enhancer.py`、`core/dynamic_tester.py` 和 `core/llm_reachability.py` 追加实际筛选、重试、检查点、模型、结果统计等决策说明。
- `context/application_context.py` 追加上下文预算、超大文件截断、手工覆盖、来源收集和降级原因说明，能够解释此前 `README.md` 超过读取上限时发生了什么。
- `openant/cli.py` 的 `report-data` 追加 HTML 报告数据准备、动态结果关联、统计和修复建议决策说明。
- `core/step_report.py` 在阶段报告写入和异常时追加中文记录；原英文 `[step] Report`、`[step] ERROR` 原样保留。
- Web 仍通过现有 `InvokeCtxCapture` → SSE `/scan/{id}/logs` → `scan.html` 日志窗口接收这些 stderr 行，因此不需要改变 SSE 协议。

## 验证命令与结果

1. 语法检查：

   ```text
   python -m py_compile core/observability.py core/scanner.py core/step_report.py
   core/analyzer.py core/verifier.py core/enhancer.py core/dynamic_tester.py
   core/llm_reachability.py openant/cli.py
   ```

   结果：通过。

2. 静态规则检查：

   ```text
   .venv/bin/ruff check <上述修改文件>
   ```

   结果：`All checks passed!`。

3. 中文日志专用回归测试：

   ```text
   python -m pytest tests/test_chinese_runtime_logs.py -q
   ```

   结果：`3 passed`。覆盖单行输出、阶段报告写入，以及一个离线完整编排流程同时保留英文和中文日志。

   上下文预算回归测试：

   ```text
   python -m pytest tests/test_application_context_sources.py -q
   ```

   结果：`3 passed`。覆盖大文件截断和总预算行为。

4. 扫描编排和阶段报告回归测试：

   ```text
   python -m pytest tests/test_chinese_runtime_logs.py tests/test_scanner.py \
     tests/test_step_report_currency.py tests/test_silent_401.py \
     tests/test_llm_reachability.py -q
   ```

   结果：`48 passed`。

5. 报告数据边界回归测试：

   ```text
   python -m pytest tests/report/test_poisoned_results_substrate.py \
     tests/report/test_poisoned_confirmed_findings_and_findings_fa18.py \
     tests/report/test_sibling_result_iteration_guard_fa16.py -q
   ```

   结果：`22 passed`。

6. 本阶段合并回归（中文日志、扫描编排、上下文预算、LLM 可达性、阶段报告和报告数据边界）：

   结果：`73 passed`；语法检查和 Ruff 检查也均通过。

## 环境限制

`tests/test_scanner_platform_profile.py` 的真实 C 解析用例在本机单独运行时因当前 Python 环境缺少 `tree_sitter_c` 而失败；失败发生在 C 解析器导入阶段，与本次日志代码无关。该依赖补齐后应再补跑平台画像和真实 OpenHarmony 仓库扫描。

本次没有重新启动正在运行的真实扫描，也没有重新发起模型请求；已经启动的进程会继续使用启动时加载的代码，新启动的 Web 扫描会使用本次日志实现。

## 预期 Web 效果

日志窗口会交错显示原英文行和中文说明，例如：

```text
[1/8] Parsing repository...
【运行说明】阶段 1/解析：正在扫描源码文件，提取函数单元、入口标记、原生调用图和平台相关注册信息，后续漏洞分析只消费这里生成的结构化数据。
【运行说明】解析参数决策：实际语言=c，请求范围=reachable，实际首轮解析范围=all，测试目录过滤=开启。
  Parsed: 91 units (c)
【运行说明】解析结果：生成 91 个函数单元，主语言为 c；发现 1 个调用图目录。解析器错误数=0。
```

英文行仍用于兼容已有排障和历史记录，中文行用于解释“为什么执行、输入是什么、结果如何、为什么跳过或降级”。
