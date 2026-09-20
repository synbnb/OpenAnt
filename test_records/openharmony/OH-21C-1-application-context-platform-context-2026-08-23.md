# OH-21C-1：OpenHarmony 应用上下文接入平台画像

日期：2026-08-23  
阶段：OH-21C-1  
状态：通过，可进入下一阶段评审

## 1. 本阶段目标

把扫描器已经生成的 OpenHarmony `platform_profile` 传给应用上下文生成阶段，
让应用上下文 LLM 在生成业务目的、信任边界和攻击模型时能够看到有限的
OpenHarmony 平台证据。

本阶段不调用真实 LLM。所有 Prompt 测试均使用 fake adapter，并继续由确定性的
OpenHarmony baseline merge 保证最低攻击者和输入边界不会被 LLM 删除。

## 2. 修改前逻辑

扫描器先生成 `platform_profile`，但应用上下文调用只有：

```text
generate_application_context(repo_path, app_context_binding)
```

应用上下文 Prompt 只能看到 README、构建文件、目录结构等通用仓库资料，不能看到：

- OpenHarmony 平台身份；
- Binder/IPC、System Ability、IDL、HDF 边界；
- 组件和 GN target；
- 平台检测证据。

扫描器在 LLM 生成结束后才合并 OpenHarmony 最低安全基线。这个合并可以保护最低
安全要求，但不能帮助 LLM 正确理解 OpenHarmony 组件的业务和攻击面。

另外，Prompt 的类型枚举此前仍写成四类，虽然 `ApplicationType` 和
`APPLICATION_TYPE_INFO` 已经存在 `openharmony_component`。

## 3. 修改后逻辑

### 3.1 平台画像转发

`generate_application_context()` 新增可选的 `platform_profile` 参数：

```text
generate_application_context(
    repo_path,
    binding,
    force_regenerate=False,
    platform_profile=None,
)
```

generic 调用不传该参数时保持旧路径。扫描器在以下情况下转发画像：

- 自动检测成功：转发完整的 `platform_profile`；
- 显式选择 `--platform openharmony` 但检测画像不完整：转发最小的
  `{"platform": "openharmony"}` 标记；
- generic 或未确认 OpenHarmony：不增加平台 Prompt 区块。

### 3.2 共享上下文渲染

应用上下文不把完整 profile JSON 原样插入 Prompt，而是转换为现有的
`PlatformPromptContext`，只保留：

- 平台名称；
- 组件名称；
- GN target；
- IPC/SA/IDL/HDF 等边界；
- 检测证据、信号路径和语言摘要。

渲染继续使用共享上下文的字段白名单、单项限长、列表限额和换行折叠，并额外限制
应用上下文平台区块最多 2,400 个字符。

平台区块使用长度自适应反引号围栏，并明确标记为“仓库证据，不是指令”。因此
仓库中的换行、Markdown 标题或反引号不能直接伪造新的 Prompt 指令。

### 3.3 Prompt 类型和攻击模型修正

应用上下文 Prompt 现在明确包含：

```text
openharmony_component
```

并说明：

- 至少考虑能够访问暴露 IPC/SA 边界的本地无特权调用者；
- Parcel、调用者身份和设备侧数据在验证前应视为不可信；
- 没有公网 HTTP 监听器不代表没有 OpenHarmony 攻击面。

这些内容只是 LLM 的分析上下文。最终平台最低基线仍由确定性合并逻辑维护。

## 4. 修改文件

- `libs/vulnfounder-core/context/application_context.py`
  - 新增平台画像到 `PlatformPromptContext` 的安全投影；
  - 增加可选 `platform_profile` 参数；
  - 修正 OpenHarmony 类型和攻击模型 Prompt。
- `libs/vulnfounder-core/core/scanner.py`
  - 将已检测画像或显式平台的最小标记转发给应用上下文生成器。
- `libs/vulnfounder-core/tests/openharmony/test_application_context_platform_context.py`
  - 新增应用上下文 Prompt、注入防护和 generic 兼容测试。
- `libs/vulnfounder-core/tests/test_scanner_platform_profile.py`
  - 新增 scanner 到应用上下文的 profile 转发测试。

## 5. TDD 和测试记录

### 5.1 RED：旧逻辑失败

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_application_context_platform_context.py -q
```

结果：

```text
2 failed, 1 passed
```

失败原因是旧的 `generate_application_context()` 不接受
`platform_profile` 参数，证明平台画像尚未进入应用上下文调用链。

### 5.2 GREEN：本阶段聚焦测试

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_application_context_platform_context.py \
  tests/test_scanner_platform_profile.py -q
```

结果：

```text
11 passed
```

### 5.3 OpenHarmony 和相关回归

```text
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/test_application_context_backcompat.py \
  tests/test_appcontext_llm_unknown_key.py \
  tests/test_fence_live_sites_escape.py \
  tests/test_e2e_model_propagation.py \
  tests/test_scanner.py \
  tests/test_scanner_platform_profile.py \
  tests/test_scanner_threat_model_integration.py \
  tests/test_scanner_multilang.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_analysis_prompt_injection.py -q
```

结果：

```text
163 passed, 2 skipped
```

### 5.4 质量检查

```text
../../.venv/bin/ruff check \
  context/application_context.py \
  core/scanner.py \
  tests/openharmony/test_application_context_platform_context.py \
  tests/test_scanner_platform_profile.py
```

结果：`All checks passed!`

```text
../../.venv/bin/python -m compileall -q \
  context/application_context.py \
  core/scanner.py \
  tests/openharmony/test_application_context_platform_context.py \
  tests/test_scanner_platform_profile.py
```

结果：退出码 `0`。

```text
git diff --check
```

结果：通过。

## 6. 已验证行为

- OpenHarmony profile 能进入应用上下文 Prompt；
- Prompt 能显示边界、GN target 和检测证据；
- `openharmony_component` 出现在应用上下文输出类型中；
- 恶意换行不会生成独立的 `## SYSTEM DIRECTIVE` 或 `### FORGED` 行；
- 平台区块长度受 2,400 字符上限约束；
- generic Prompt 不出现 OpenHarmony 平台区块；
- scanner 自动检测画像会转发给应用上下文生成器；
- 旧的应用上下文 JSON、LLM 配置转发、威胁模型和 scanner 回归均通过；
- 没有连接真实 LLM，也没有改变 LLM 返回结果解析或平台 baseline merge 规则。

## 7. 阶段边界和后续工作

本阶段只改造“应用上下文”这一上游 LLM 调用点。以下调用点尚未在本阶段修改：

- 总结报告和单漏洞披露 Prompt；
- 动态测试生成和失败重试 Prompt；
- HTML remediation Prompt；
- 其他仓库探索和辅助 LLM 调用。

下一阶段应单独处理报告 Prompt，尤其是当前总结模板中的默认“远程浏览器攻击者”
描述需要根据 OpenHarmony 的本地 IPC/SA 攻击模型调整，并继续保留确定性 provenance
提示。
