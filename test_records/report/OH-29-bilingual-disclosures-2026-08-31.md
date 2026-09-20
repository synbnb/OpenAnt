# OH-29 中文漏洞披露报告测试记录

日期：2026-08-31  
阶段：报告生成层（双语独立披露文件）

## 变更范围

- 保留原英文披露目录 `report/disclosures/`。
- 新增同编号中文披露目录 `report/disclosures.zh-CN/`。
- `generate_disclosure(..., language="zh-CN")` 使用中文专用提示词。
- 中文版本的标题、元数据字段、摘要、复现步骤、影响、建议修复、源码标题、证据上下文和调用图标题由报告层统一渲染。
- 漏洞源码、文件路径、行号、调用链和调用图证据仍由确定性报告层追加，不由模型改写。
- 扫描器报告阶段和 `python -m report all/disclosures` 均使用同一双语输出约定。
- 本阶段未修改 Web 展示层。

## 测试命令与结果

### 1. 双语报告定向回归

```text
cd libs/vulnfounder-core
../../.venv/bin/python -m pytest -q \
  tests/report/test_bilingual_disclosures.py \
  tests/report \
  tests/openharmony/test_disclosure_platform_context.py \
  tests/test_pr69_report_llmconfig_forwarding.py
```

结果：`76 passed in 0.62s`。

覆盖内容：

- 中文提示词要求简体中文且没有未替换的运行时占位符。
- 中文输出包含 `## 摘要`、`## 漏洞代码`、`## 复现步骤`、`## 影响`、`## 建议修复` 和 `## 证据上下文`。
- 中文文件保留真实文件路径、函数名、源码和调用链证据。
- `generate_all` 同时写入英文和中文同编号文件。
- 扫描器使用的 `core.reporter.generate_disclosure_docs` 包装器同样写入两个目录。
- 原有英文披露源码保真、文件名安全、OpenHarmony 上下文和修复片段测试未回归。

### 2. 语法、格式和静态检查

```text
python -m py_compile \
  libs/vulnfounder-core/report/generator.py \
  libs/vulnfounder-core/core/reporter.py \
  libs/vulnfounder-core/report/__main__.py \
  libs/vulnfounder-core/core/scanner.py \
  libs/vulnfounder-core/tests/report/test_bilingual_disclosures.py
```

结果：通过。

```text
./.venv/bin/ruff check \
  libs/vulnfounder-core/report/generator.py \
  libs/vulnfounder-core/core/reporter.py \
  libs/vulnfounder-core/report/__main__.py \
  libs/vulnfounder-core/core/scanner.py \
  libs/vulnfounder-core/tests/report/test_bilingual_disclosures.py
```

结果：`All checks passed!`。

```text
git diff --check
```

结果：通过。

### 3. 完整测试集说明

```text
../../.venv/bin/python -m pytest -q
```

该命令在当前工作区约 96% 进度处出现多项与本阶段无关的既有测试失败/阻塞，涉及解析器扩展和部分外部 SDK 环境；系统 Python 还会直接缺少 `tree_sitter_c`、`tree_sitter_php`、`tree_sitter_ruby`、`tree_sitter_zig` 与 `google.genai`。为避免继续占用进程，已停止该完整测试进程。报告层定向测试使用项目 `.venv` 并全部通过。

## 预期产物

对一个有资格披露的问题 `DISCLOSURE_01_EXAMPLE.md`，报告目录中应同时存在：

```text
report/disclosures/DISCLOSURE_01_EXAMPLE.md
report/disclosures.zh-CN/DISCLOSURE_01_EXAMPLE.md
```

两份文件使用相同的漏洞编号、源码证据、文件/行号和调用链；叙述语言和章节标签分别为英文、简体中文。
