# OH-21B-2B：Agentic Context Enhancer 接入 OpenHarmony 平台上下文

日期：2026-08-23  
阶段：OH-21B-2B  
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段把 OH-21A 定义的共享 `PlatformPromptContext` 接入 agentic Context Enhancer 的首轮分析 Prompt。范围只覆盖 agentic 调用链：

```text
enhance_unit_with_agent()
  -> ContextAgent.analyze_unit()
    -> get_user_prompt()
      -> LLM adapter 的首轮消息
```

本阶段不调用真实 LLM，不修改工具定义、工具执行器、finish 协议、agent 迭代次数、`agent_context` 输出结构或 reachability 逻辑。

## 2. 修改前后逻辑

### 修改前

- `enhance_unit_with_agent()` 从 Unit 读取代码、Unit 类型、静态依赖和静态调用者。
- `ContextAgent.analyze_unit()` 只把上述字段以及 entry-point/reachability 信息传给 `get_user_prompt()`。
- agentic Prompt 没有 `language` 或 `platform_context` 参数，因此 OpenHarmony Unit 的 component、target、boundary、guard 和 evidence 不会进入 agentic 首轮消息。
- 代码围栏没有语言 info-string；generic Prompt 使用历史裸围栏。

### 修改后

1. `enhance_unit_with_agent()` 读取 Unit 的 `language`，并优先读取 `platform_context`，缺失时兼容读取历史 `platformContext`。
2. `ContextAgent.analyze_unit()` 增加两个末尾可选参数，并原样转发给 `get_user_prompt()`；旧调用无需增加参数。
3. `get_user_prompt()` 使用 `PlatformPromptContext.from_mapping()` 归一化上下文，只在平台为 `openharmony` 时渲染 `render_for_phase("enhance")` 的受限证据区段。
4. OpenHarmony 代码围栏增加语言标识，当前 C/C++ Unit 默认使用 `cpp`；语言值先折叠换行，不能伪造新的 Prompt 行。
5. generic 或无上下文调用继续使用历史裸代码围栏，不渲染 OpenHarmony 区段。
6. 共享上下文仍然是静态证据而不是指令；guard 仍然只是线索，不被解释为路径覆盖证明。

## 3. 修改文件

- `libs/openant-core/utilities/agentic_enhancer/prompts.py`
  - 增加可选 `language`、`platform_context` 参数；
  - 复用 `PlatformPromptContext` 的字段白名单、单行折叠、列表/总长度限制；
  - 为 OpenHarmony 首轮 Prompt 添加上下文区段和语言围栏；
  - generic 分支保留裸围栏和原有 Prompt 形状。
- `libs/openant-core/utilities/agentic_enhancer/agent.py`
  - 在 `ContextAgent.analyze_unit()` 中转发新参数；
  - 在 `enhance_unit_with_agent()` 中读取 snake_case/camelCase 平台上下文。
- `libs/openant-core/tests/openharmony/test_agentic_prompt_platform_context.py`
  - 新增 Prompt、参数转发、fake adapter 和上下文边界测试。

## 4. TDD 与阶段测试记录

### RED

先加入 Prompt 契约测试后运行：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_agentic_prompt_platform_context.py -q
```

结果：`2 failed, 1 passed`。失败证明旧 `get_user_prompt()` 尚未接受 `language` 和 `platform_context`；generic 兼容测试先通过。

加入 agent 转发测试后再次运行，结果为：`3 passed, 2 failed`。失败点是 `ContextAgent` 和 Unit helper 尚未转发新参数。

### GREEN

agentic Prompt、agent loop 和既有安全围栏测试：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_agentic_prompt_platform_context.py \
  tests/test_agent_degenerate_exit.py \
  tests/test_agent.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_e2e_model_propagation.py \
  tests/test_enhance_resilience.py \
  tests/test_enhancer_tools.py \
  tests/test_entrypoint_bindings.py -q
```

结果：`67 passed`。

OpenHarmony、agentic 和模型传播阶段回归：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/test_agent.py \
  tests/test_agent_degenerate_exit.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_enhance_resilience.py \
  tests/test_enhancer_tools.py \
  tests/test_entrypoint_bindings.py \
  tests/test_e2e_model_propagation.py -q
```

结果：`126 passed, 2 skipped`。

上下文增强器相关回归：

```text
../../.venv/bin/python -m pytest \
  tests/test_context_enhancer_diff_scope.py \
  tests/test_enhance_limit.py \
  tests/test_enhancer_parse_failure_counted.py \
  tests/test_enhance_failed_context_error_key.py \
  tests/test_threat_model_agent.py -q
```

结果：`23 passed`。

质量检查：

```text
../../.venv/bin/ruff check \
  utilities/agentic_enhancer/prompts.py \
  utilities/agentic_enhancer/agent.py \
  tests/openharmony/test_agentic_prompt_platform_context.py
```

结果：`All checks passed!`

另外执行相关文件 `compileall` 和 `git diff --check`，均通过。

## 5. 具体验证项

- OpenHarmony Prompt 包含 component、target、boundary、guard 和 evidence；
- `permission_check` 以 `permission_check (matched: CheckPermission)` 形式作为证据显示，不被改写为“已完成权限校验”；
- C/C++ agentic 代码使用 `cpp` info-string；
- generic Prompt 不出现 OpenHarmony 区段，仍使用裸代码围栏；
- 平台字段中的换行不会形成新的 Markdown 标题或指令行；
- 上下文列表和总渲染长度继续受 `PlatformPromptContext` 的共享上限约束；
- fake adapter 实际接收的首轮 user message 已包含 OpenHarmony 上下文；
- `platform_context` 和 `platformContext` 两种 Unit 字段名均可传递；
- 工具定义、工具调用结果、finish 协议和 `agent_context` schema 未变化。

## 6. 阶段边界

本阶段没有扩大 OpenHarmony guard 规则覆盖率，也没有建立跨函数 guard 摘要；因此 `permission_check` 仍然只是局部静态线索。没有 guard 信号时，Unit 不会因此被裁剪或自动判定为安全，agent 仍可读取原始代码和静态依赖。

本阶段也没有把 semantic graph 接入 agentic Prompt，避免在共享上下文契约尚未定义阶段把复杂图数据重复注入每个 agent 会话。

