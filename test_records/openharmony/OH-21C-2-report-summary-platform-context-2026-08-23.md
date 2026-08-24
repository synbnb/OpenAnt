# OH-21C-2：总结报告接入 OpenHarmony 攻击模型

日期：2026-08-23  
阶段：OH-21C-2  
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段只修改总结报告这一报告 LLM 调用点：

```text
generate_summary_report()
  -> report/prompts/summary.txt
  -> report phase adapter
```

本阶段没有修改单漏洞披露、动态测试生成、HTML remediation、Stage 1/Stage 2
判定或动态结果合并逻辑，也没有调用真实 LLM。

## 2. 修改前逻辑

总结报告模板固定写入：

```text
Attacker model: Remote attacker with browser access, no server-side access, no admin credentials.
```

这对 Web 仓库是合理的默认描述，但对 OpenHarmony 服务不准确。OpenHarmony 的
最低平台基线要求至少考虑能够访问 Binder/System Ability 的本地无特权调用者，
并把 Parcel、调用身份和设备侧数据作为需要验证的边界输入。

此外，`pipeline_output.json` 的应用上下文 provenance 只用于确定性 header，
没有以结构化、有限长度的形式送入总结报告 Prompt。

## 3. 修改后逻辑

### 3.1 报告平台上下文

新增报告阶段的 OpenHarmony 上下文投影：

- 读取 `application_context_provenance.platform_baseline`；
- 仅在 `applied: true` 时使用完整 baseline 信息；
- 使用共享 `PlatformPromptContext` 渲染；
- 传递边界、攻击者 profile、输入源和 baseline 证据；
- 通过字段白名单、列表限制、换行折叠和长度自适应围栏防止 Prompt 注入；
- 报告上下文最多 2,400 个字符。

报告 Prompt 新增两个占位符：

```text
{platform_context}
{attacker_model}
```

### 3.2 OpenHarmony 报告模型

当有效 OpenHarmony baseline 存在时，报告 Prompt 会使用：

```text
OpenHarmony local IPC/SA caller; Parcel, caller identity, and device-facing inputs are untrusted until validated.
```

并额外向模型提供：

```text
## OpenHarmony Platform Context
```

该区块明确标注为 mandatory platform evidence，而不是指令。

### 3.3 无上下文降级路径

显式选择：

```text
--platform openharmony --no-context
```

时，scanner 现在仍会把 `application_type` 写为
`openharmony_component`，而不是旧的默认 `web_app`。

如果此时没有 provenance，报告使用最小 Binder baseline：

- boundary：`binder_ipc`；
- attacker：`openharmony_local_ipc_caller`；
- input：`openharmony_binder_parcel`。

因此不会在 OpenHarmony 扫描中误显示为远程浏览器攻击模型。

对于 generic pipeline，原有远程攻击者描述保持不变。

## 4. 修改文件

- `libs/openant-core/report/generator.py`
  - 新增报告阶段 OpenHarmony baseline 投影；
  - 新增报告平台上下文长度限制；
  - 根据平台选择攻击者模型；
  - 增加无 provenance 的 OpenHarmony 最小降级上下文。
- `libs/openant-core/report/prompts/summary.txt`
  - 增加 `{platform_context}` 和 `{attacker_model}`；
  - 删除固定的 OpenHarmony 不适用远程攻击模型。
- `libs/openant-core/core/scanner.py`
  - 显式 OpenHarmony 且没有应用上下文时，pipeline output 的应用类型仍写为
    `openharmony_component`。
- `libs/openant-core/tests/openharmony/test_report_platform_context.py`
  - 新增 OpenHarmony、generic、降级和 Prompt 注入测试。
- `libs/openant-core/tests/test_scanner_platform_profile.py`
  - 新增显式 OpenHarmony 无上下文时的报告类型测试。

## 5. TDD 和阶段测试记录

### 5.1 RED：旧逻辑失败

修改前运行新测试：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_report_platform_context.py -q
```

结果：

```text
2 failed, 1 passed
```

其中一条失败暴露出旧逻辑完全没有把 OpenHarmony 平台上下文加入报告 Prompt；
另一条同时触发了已有的确定性 baseline header，这是旧行为，不是本阶段新增错误。

### 5.2 GREEN：聚焦测试

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_report_platform_context.py \
  tests/test_scanner_platform_profile.py -q
```

结果：

```text
12 passed
```

### 5.3 报告和 OpenHarmony 回归

```text
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/report \
  tests/test_evidence_tier.py \
  tests/test_artifact_serialization_contract.py \
  tests/test_reporter_status_fidelity.py \
  tests/test_reporter_reachable_units.py \
  tests/test_reporter_fence.py \
  tests/test_bughunt2_regressions.py \
  tests/test_pr69_report_llmconfig_forwarding.py \
  tests/test_llm_builtins.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_analysis_prompt_injection.py -q
```

结果：

```text
220 passed, 2 skipped
```

### 5.4 Scanner 和配置转发回归

```text
../../.venv/bin/python -m pytest \
  tests/test_scanner.py \
  tests/test_scanner_platform_profile.py \
  tests/test_scanner_threat_model_integration.py \
  tests/test_scanner_multilang.py \
  tests/test_e2e_model_propagation.py \
  tests/test_pr69_report_llmconfig_forwarding.py -q
```

结果：

```text
51 passed
```

### 5.5 质量检查

```text
../../.venv/bin/ruff check \
  report/generator.py \
  core/scanner.py \
  tests/openharmony/test_report_platform_context.py \
  tests/test_scanner_platform_profile.py
```

结果：`All checks passed!`

```text
../../.venv/bin/python -m compileall -q \
  report/generator.py \
  core/scanner.py \
  tests/openharmony/test_report_platform_context.py \
  tests/test_scanner_platform_profile.py
```

结果：退出码 `0`。

```text
git diff --check
```

结果：通过。

## 6. 全量 pytest 说明

额外运行了：

```text
../../.venv/bin/python -m pytest -q
```

结果为：

```text
3189 passed, 23 failed, 40 skipped
```

23 个失败不涉及本阶段修改的报告代码，主要集中在：

- conformance 测试启动 `go`，当前运行环境找不到 `go` 可执行文件；
- Python parser 的 `sample_python_repo` 在当前工作区被扫描为 0 个文件，随后触发
  既有的 `standalone_functions` 缺失和空函数图断言；
- 这些失败在本阶段针对报告、OpenHarmony 和 scanner 的回归集合中没有出现。

因此本阶段结论以聚焦测试和相关回归为准，不把环境依赖失败记为报告 Prompt 回归。

## 7. 已验证行为

- OpenHarmony summary Prompt 包含本地 IPC/SA 攻击模型；
- baseline 的 boundaries、attacker profiles 和 input sources 会进入 Prompt；
- generic summary Prompt 仍使用原远程攻击模型；
- 恶意 baseline 字段不会形成新的 Prompt 标题；
- 平台上下文最多 2,400 个字符；
- 显式 OpenHarmony 且无上下文时不会退回 `web_app`；
- 确定性 OpenHarmony provenance header 仍保留；
- 单漏洞披露和动态测试逻辑未被本阶段改变。

## 8. 阶段边界和后续工作

本阶段只覆盖总结报告。下一阶段可单独处理单漏洞披露 Prompt，决定是否将
OpenHarmony 的 boundary、攻击者和验证方式注入每个 disclosure，同时保持源码片段
仍由程序确定性插入。
