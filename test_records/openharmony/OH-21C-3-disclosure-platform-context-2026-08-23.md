# OH-21C-3：单漏洞披露接入 OpenHarmony 攻击模型

日期：2026-08-23  
阶段：OH-21C-3  
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段只改造单漏洞披露这一报告 LLM 调用点：

```text
pipeline_output.json
  -> disclosure finding
  -> report phase adapter
  -> DISCLOSURE_*.md
```

本阶段没有修改漏洞判定、披露 eligibility、动态测试、HTML remediation 或源码片段
插入逻辑，也没有调用真实 LLM。

## 2. 修改前逻辑

`generate_disclosure()` 只接收：

```text
vulnerability_data, product_name, binding
```

披露 Prompt 只看到当前 finding，没有看到：

- OpenHarmony 的 IPC/SA 边界；
- 本地无特权 IPC 调用者；
- Parcel、调用身份和设备输入；
- 应用上下文 provenance。

因此披露文档可能按照通用 Web/远程攻击模型描述前置条件和影响。

## 3. 修改后逻辑

### 3.1 传入 pipeline provenance

`generate_disclosure()` 增加一个可选的 `pipeline_data` 参数，旧的三参数调用仍然
兼容：

```python
generate_disclosure(
    vulnerability_data,
    product_name,
    binding,
    pipeline_data=None,
)
```

以下三个生产入口都会传入完整 pipeline 数据：

- `core/reporter.generate_disclosure_docs()`；
- `report.generator.generate_all()`；
- `python -m report disclosures`。

### 3.2 OpenHarmony 披露上下文

披露 Prompt 复用报告阶段的有界 `PlatformPromptContext` 投影，加入：

- Binder/SA/IDL/HDF 等边界信息（当前 pipeline provenance 中存在的部分）；
- `openharmony_local_ipc_caller` 攻击者 profile；
- `openharmony_binder_parcel` 等输入源；
- baseline 证据。

上下文通过字段白名单、列表限制、换行折叠、长度限制和安全反引号围栏处理，
并明确标记为平台证据而非指令。

OpenHarmony 披露 Prompt 使用：

```text
OpenHarmony local IPC/SA caller; Parcel, caller identity, and device-facing inputs are untrusted until validated.
```

generic 直接调用仍使用原来的远程攻击者描述。

### 3.3 源码片段行为保持不变

漏洞源码仍然不会交给 LLM 重新编写。`vulnerable_code_section` 继续由程序在
LLM 输出之后确定性插入，避免披露文档生成伪造源码。

## 4. 修改文件

- `libs/vulnfounder-core/report/generator.py`
  - 报告上下文 helper 改为可供 summary 和 disclosure 共用；
  - `generate_disclosure()` 增加可选 `pipeline_data`；
  - disclosure Prompt 填充平台上下文和攻击者模型。
- `libs/vulnfounder-core/report/prompts/disclosure.txt`
  - 增加 `{platform_context}` 和 `{attacker_model}`。
- `libs/vulnfounder-core/core/reporter.py`
  - 并行披露生成传入 pipeline provenance。
- `libs/vulnfounder-core/report/__main__.py`
  - standalone disclosures 命令传入 pipeline provenance。
- `libs/vulnfounder-core/tests/openharmony/test_disclosure_platform_context.py`
  - 新增 OpenHarmony、generic 和 Prompt 注入测试。
- `libs/vulnfounder-core/tests/test_llm_builtins.py`
  - 更新 binding 转发 fake，使其接受新增的可选上下文参数。

## 5. 测试记录

### 5.1 聚焦测试

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_disclosure_platform_context.py \
  tests/openharmony/test_report_platform_context.py \
  tests/report/test_disclosure_source_fidelity.py \
  tests/test_llm_builtins.py \
  tests/report/test_disclosure_filename_safety.py -q
```

结果：

```text
36 passed
```

覆盖内容：

- OpenHarmony disclosure Prompt 含本地 IPC/SA 攻击模型；
- generic disclosure Prompt 保持旧模型；
- 恶意 baseline 换行不能伪造 Prompt 标题；
- 源码片段仍由程序确定性插入；
- report binding 仍正确转发；
- disclosure 文件名不能路径穿越。

### 5.2 报告和 OpenHarmony 回归

```text
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/report \
  tests/test_evidence_tier.py \
  tests/test_llm_builtins.py \
  tests/test_pr69_report_llmconfig_forwarding.py \
  tests/test_pr69_round5_unverified.py \
  tests/test_bughunt2_regressions.py \
  tests/test_F3_verdict_taxonomy_shared_constant.py \
  tests/test_verifier_consistency_disclosure_dropped_downgrade.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_analysis_prompt_injection.py -q
```

结果：

```text
216 passed, 2 skipped
```

### 5.3 Scanner 和调用链回归

```text
../../.venv/bin/python -m pytest \
  tests/test_scanner.py \
  tests/test_scanner_platform_profile.py \
  tests/test_scanner_threat_model_integration.py \
  tests/test_scanner_multilang.py \
  tests/test_e2e_model_propagation.py -q
```

结果：

```text
50 passed
```

### 5.4 质量检查

```text
../../.venv/bin/ruff check \
  report/generator.py \
  report/__main__.py \
  core/reporter.py \
  tests/openharmony/test_disclosure_platform_context.py \
  tests/test_llm_builtins.py
```

结果：`All checks passed!`

```text
../../.venv/bin/python -m compileall -q \
  report/generator.py \
  report/__main__.py \
  core/reporter.py \
  tests/openharmony/test_disclosure_platform_context.py
```

结果：退出码 `0`。

```text
git diff --check
```

结果：通过。

## 6. 已验证行为

- 三个披露入口均能传入 pipeline provenance；
- OpenHarmony disclosure 能识别本地 IPC/SA 攻击模型；
- generic disclosure 不出现 OpenHarmony 区块；
- 平台字段不能形成新的 Markdown/Prompt 标题；
- 旧的三参数 `generate_disclosure()` 调用仍兼容；
- Disclosure eligibility、文件名安全和源码确定性插入保持不变。

## 7. 阶段边界和后续工作

本阶段只覆盖单漏洞披露。尚未适配的报告相关 LLM 调用包括：

- HTML remediation guidance；
- 动态测试生成和失败重试；
- 仓库探索、威胁模型辅助生成等其他 LLM 调用。
