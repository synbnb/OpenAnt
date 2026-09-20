# OH-24 披露报告完整性修复测试记录

日期：2026-08-28

## 1. 问题样本

使用已有的真实扫描产物进行回归检查：

- 扫描目录：`/Users/shiyu/.openant/webui/347d903282351b35`
- 仓库：`multimedia_audio_framework`
- 第一阶段结果：`results.json` 含 273 个 `code_by_route` 源码条目
- 第二阶段结果：旧版 `results_verified.json` 未保留 `code_by_route`
- 旧披露文件：8 个文件均没有 `## Vulnerable Code`，8 个文件的 `Affected` 含 `[NOT PROVIDED]`，其中 4 个 `Suggested Fix` 含 `[REQUIRES MANUAL INPUT]`

## 2. 根因

1. 验证阶段写 `results_verified.json` 时只复制了结果列表，没有复制第一阶段的源码映射。
2. 报告构建器只从当前结果文件读取源码，读取旧版验证结果时无法定位源码，因此传给披露生成器的 `vulnerable_code_section` 为空。
3. 披露提示词中的元数据占位符没有统一替换；模型返回短文本或模板占位符时，原流程没有确定性的章节兜底。

## 3. 本阶段修改

1. 验证结果现在保留 `code_by_route`；没有映射时会从合并结果中的源码字段重建。
2. 报告构建器会按以下顺序读取源码：当前结果文件、同目录 `results.json`、同目录 `call_graph.json`。源码记录支持字符串和函数记录两种格式。
3. 对历史 `pipeline_output.json` 增加内存回填：重新生成披露时会读取同目录的旧结果，不改写原始 JSON。
4. 披露提示词现在显式填充标题、产品、CWE、扫描版本、平台、日期、验证方式、代码语言和修复字段。
5. 披露生成后增加确定性完整性检查：保证元数据、`Vulnerable Code`、`Summary`、`Steps to Reproduce`、`Impact`、`Suggested Fix` 均存在；对 `[NOT PROVIDED]` 和 `[REQUIRES MANUAL INPUT]` 进行替换。源码不可用时明确标记“源码未保存在扫描产物中”，不伪造源码。

## 4. 自动化测试

先按 TDD 写入回归测试，旧实现下 3 项均失败；完成修改后新增完整性测试全部通过。

```text
.venv/bin/python -m pytest -q libs/vulnfounder-core/tests/report
62 passed in 0.11s

.venv/bin/python -m pytest -q \
  libs/vulnfounder-core/tests/report \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/test_reporter_coercion.py \
  libs/vulnfounder-core/tests/test_reporter_exploit_path_shape.py \
  libs/vulnfounder-core/tests/test_reporter_status_fidelity.py \
  libs/vulnfounder-core/tests/test_verifier_verdictonly_confirmed_drop.py
261 passed, 2 skipped in 0.74s

.venv/bin/python -m py_compile \
  libs/vulnfounder-core/core/reporter.py \
  libs/vulnfounder-core/core/verifier.py \
  libs/vulnfounder-core/report/generator.py
通过
```

全量 `libs/vulnfounder-core/tests` 未作为本阶段通过依据：该集合包含需要 Go 工具链的 conformance 测试，当前环境在第一个失败处报 `FileNotFoundError: go`；这与本次 Python 报告修改无关。仓库根目录全量收集还会进入 `source_code_base` 中的 OpenHarmony 自带测试，并因缺少 `distributed`、`selenium`、`CppHeaderParser` 及同名测试模块冲突而停止。

## 5. 真实扫描产物回归

将旧版 `results_verified.json` 作为输入，在临时输出目录重建 `pipeline_output.json`：

```text
findings=8
with_code=8
with_code_section=8
missing_description=0
missing_steps=0
missing_fix=0
```

随后用离线假适配器逐条生成 8 个披露文本，五个必需章节全部存在，且源码片段来自同目录真实 `results.json`，没有调用真实模型、没有产生额外费用。

另外直接读取该扫描目录中原有的旧版 `pipeline_output.json` 做回填测试：8/8 条目恢复源码，8/8 生成文本包含五个必需章节，且不再出现 `[NOT PROVIDED]` 或 `[REQUIRES MANUAL INPUT]`。

## 6. 审阅结论

本次缺失不是单一的大模型截断问题，主要是验证结果丢失源码映射以及报告层缺少确定性完整性兜底；模型短回复和模板占位符会放大问题。修复后新扫描和历史扫描重新生成报告都能保留源码证据，并在信息缺失时明确提示人工复核，不把未知信息伪装成已验证事实。
