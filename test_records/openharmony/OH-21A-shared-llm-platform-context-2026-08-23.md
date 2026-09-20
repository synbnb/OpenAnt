# OH-21A：共享 LLM 平台上下文与 Stage 1 Prompt 适配

日期：2026-08-23  
阶段：OH-21A  
状态：通过（定向回归）

## 1. 阶段边界

本阶段只建立一个可复用、有限长度的 LLM 平台上下文契约，并把它接入现有
Stage 1 漏洞分析 Prompt。上下文只作为静态仓库证据，不直接创建调用图边、证明
权限检查成立，也不改变 Finding 判定。

本阶段明确不做：

- Stage 2 验证 Prompt、Context Enhancer、LLM Reachability 的接入；
- 新增 OpenHarmony 漏洞规则或改变规则命中逻辑；
- 调用真实远程 LLM/API；
- 修改 generic Prompt 的默认内容。

## 2. 原项目逻辑与修改后逻辑

### 修改前

OpenHarmony unit 已经可以携带字典形式的平台字段，但 Stage 1 Prompt 中的
OpenHarmony 渲染逻辑集中在 `prompts/vulnerability_analysis.py`。如果以后让
Stage 2、报告或其它 LLM 调用点也使用平台证据，各模块容易各自解释字段、遗漏
长度限制或产生不同的注入防护行为。

### 修改后

1. 新增 `core.platforms.prompt_context.PlatformPromptContext` 作为共享契约；
2. `from_mapping()` 只接收明确批准的字段：平台、source role、组件、构建目标、
   边界、guard、证据、semantic edge 和 attacker profile；未知嵌套字段会被忽略；
3. 所有列表最多保留 8 项，单项最多 160 个字符，最终 Prompt 区块最多 4000 个
   字符；仓库中的换行会折叠成普通空格，避免伪造 Prompt 标题或指令；
4. `to_dict()` 输出稳定的 JSON 兼容结构，便于跨阶段传递和审计；
5. `render_for_phase()` 目前保持旧 Stage 1 OpenHarmony 区块格式，generic 平台
   返回空字符串；attacker profile 只在后续 verify/report 阶段预留显示，不进入
   当前 analyze 阶段；
6. 原有 `format_openharmony_context_for_prompt()` 保留为兼容包装函数，因此旧
   调用者不需要立即迁移，Stage 1 通过共享对象渲染；
7. `get_analysis_prompt(..., platform_context=...)` 和 `analysis_core.analyze_unit`
   的现有传递链保持不变。

## 3. 修改文件

- `libs/vulnfounder-core/core/platforms/prompt_context.py`
  - 新增版本化、限长、单行化的共享上下文对象；
  - 新增 guard、证据和 semantic edge 的受控结构化表示；
  - 提供 JSON 序列化和按 LLM 阶段渲染接口。
- `libs/vulnfounder-core/prompts/vulnerability_analysis.py`
  - 删除重复的 OpenHarmony 字段渲染实现；
  - 保留兼容函数并委托 `PlatformPromptContext`；
  - Stage 1 Prompt 接收共享上下文。
- `libs/vulnfounder-core/tests/openharmony/test_prompt_context_contract.py`
  - 新增共享契约的 generic 隔离、字段白名单、Prompt 注入防护、阶段渲染和长度
    限制测试。

## 4. 测试环境

| 项目 | 值 |
|---|---|
| 系统 | macOS arm64 |
| Python | VulnFounder `.venv` Python 3.11 |
| 工作目录 | `libs/vulnfounder-core` |
| 真实远程 LLM | 未调用 |

## 5. 阶段级测试结果

### 5.1 OH-21A 直接相关测试

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony/test_prompt_context_contract.py \
  tests/openharmony/test_prompt_platform_context.py \
  tests/openharmony/test_unit_platform_context.py -q
```

结果：

```text
13 passed in 0.08s
```

### 5.2 OpenHarmony 与 Prompt 安全回归

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/test_analysis_prompt_injection.py \
  tests/test_application_context_backcompat.py \
  tests/test_application_context_entry_points_anchored.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_threat_model_prompts.py \
  tests/test_verification_prompt_injection.py -q
```

结果：

```text
102 passed, 2 skipped in 0.56s
```

### 5.3 质量检查

以下检查均通过：

```bash
../../.venv/bin/ruff check \
  core/platforms/prompt_context.py \
  prompts/vulnerability_analysis.py \
  tests/openharmony/test_prompt_context_contract.py \
  tests/openharmony/test_prompt_platform_context.py

git diff --check
../../.venv/bin/python -m compileall -q \
  core/platforms/prompt_context.py \
  prompts/vulnerability_analysis.py \
  tests/openharmony/test_prompt_context_contract.py
```

另有一个独立 smoke check 确认 `to_dict()` 可以被 `json.dumps()` 序列化，且
OpenHarmony 组件信息能够出现在 Stage 1 Prompt 中。

## 6. 全量回归说明

曾执行：

```bash
../../.venv/bin/python -m pytest -q
```

结果为 `3154 passed, 23 failed, 40 skipped`。失败项不来自本阶段新增的共享
上下文或 OpenHarmony Prompt 测试，主要是当前工作区既有环境/解析器问题：

- 1 项 Go conformance 测试在 Python 子进程环境中找不到 `go`；
- 其余失败集中在既有 Python parser 测试，表现为 sample Python fixture 扫描为
  0 个文件以及 extractor 缺少 `standalone_functions` 统计字段。

因此本阶段的验收依据是上面的定向回归、OpenHarmony 全目录回归和静态检查，
而不是把受环境影响的全量结果宣称为通过。

## 7. 结论与下一步

OH-21A 已完成。现在 Stage 1 使用统一、限长、可审计的 OpenHarmony 平台上下文，
generic Prompt 保持原有空上下文行为，旧的渲染函数仍可兼容调用。

下一步候选为 OH-21B：在用户确认后，把同一上下文契约分别接入 Context Enhancer、
LLM Reachability 和 Stage 2 验证 Prompt，并为每个调用点定义只传递当前路径相关
证据的边界；本记录不把这些尚未实现的阶段写成已完成能力。
