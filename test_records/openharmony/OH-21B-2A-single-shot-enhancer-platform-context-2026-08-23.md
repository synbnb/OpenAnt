# OH-21B-2A：single-shot Context Enhancer 接入 OpenHarmony 平台上下文

日期：2026-08-23  
阶段：OH-21B-2A  
状态：通过

## 1. 阶段边界

本阶段只修改 Context Enhancer 的 single-shot 模式：

```text
ContextEnhancer.enhance_unit()
  → get_context_enhancement_prompt()
  → simple_text()
```

本阶段不修改：

- agentic Context Enhancer；
- ContextAgent 的工具调用和 `agent_context` schema；
- LLM Reachability；
- Stage 1/Stage 2 的 verdict 逻辑；
- generic 平台的既有 Prompt 结构；
- 真实远程 LLM 调用。

## 2. 原项目逻辑与修改后逻辑

### 修改前

single-shot Prompt 固定使用 JavaScript/TypeScript 描述和 `javascript` code fence：

```text
You are analyzing a JavaScript/TypeScript function ...
```

`ContextEnhancer.enhance_unit()` 只提取函数代码、函数类型、静态依赖、静态调用者
和同文件函数，不传递 unit 中已有的 `language` 或 OpenHarmony `platform_context`。

### 修改后

1. `enhance_unit()` 读取 `language` 和 `platform_context`，并兼容读取历史
   `platformContext` 字段；
2. `get_context_enhancement_prompt()` 使用共享的
   `PlatformPromptContext.from_mapping()`；
3. OpenHarmony unit 使用 `render_for_phase("enhance")` 将组件、GN target、边界、
   guard 和证据加入 Prompt；
4. OpenHarmony code fence 和自然语言标签使用 unit 的语言，例如 `cpp`；
5. generic 或 malformed 上下文继续使用历史的
   `JavaScript/TypeScript` 描述和 `javascript` fence；
6. LLM 返回 JSON 的字段、增强结果写回 `llm_context` 的逻辑和错误处理不变；
7. 平台上下文仍只是静态证据，不直接修改依赖图或调用者图。

## 3. 修改文件

- `libs/vulnfounder-core/utilities/context_enhancer.py`
  - 增加可选 `language`、`platform_context` 参数；
  - single-shot unit 到 Prompt 的字段传递；
  - OpenHarmony 语言标签、code fence 和共享上下文区块。
- `libs/vulnfounder-core/tests/openharmony/test_single_shot_enhancer_platform_context.py`
  - 新增 Prompt 构造、generic 隔离、malformed 回退和 ContextEnhancer 转发测试；
  - LLM 调用全部使用 monkeypatch，不访问网络。

本阶段复用 OH-21A/21B-1 已建立的
`core.platforms.prompt_context.PlatformPromptContext`，没有修改 agentic Prompt。

## 4. TDD 过程

新增测试第一次运行时发现 generic 兼容性问题：

```text
expected: You are analyzing a JavaScript/TypeScript function
actual:   You are analyzing a javascript function
```

原因是实现把 code fence 的语言标识同时用于自然语言标签。修正为两个独立值：

- generic：自然语言仍为 `JavaScript/TypeScript`，fence 为 `javascript`；
- OpenHarmony：两者使用真实 unit 语言，例如 `cpp`。

修正后重新执行，全部通过。

## 5. 测试结果

### 5.1 single-shot 专项

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony/test_single_shot_enhancer_platform_context.py -q
```

结果：

```text
4 passed in 0.02s
```

覆盖：

- OpenHarmony `cpp` 标签和平台上下文渲染；
- generic 历史 Prompt 句式和 fence；
- malformed 上下文安全回退；
- `ContextEnhancer.enhance_unit()` 将 unit 上下文转发给 Prompt。

### 5.2 Context Enhancer 与 OpenHarmony 回归

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/openharmony/test_single_shot_enhancer_platform_context.py \
  tests/test_context_enhancer_diff_scope.py \
  tests/test_enhance_failed_context_error_key.py \
  tests/test_enhance_limit.py \
  tests/test_enhance_resilience.py \
  tests/test_enhancer_parse_failure_counted.py \
  tests/test_enhancer_tools.py \
  tests/test_agent_degenerate_exit.py \
  tests/test_checkpoint_singleshot_error_key.py \
  tests/test_entrypoint_bindings.py -q
```

结果：

```text
109 passed, 2 skipped in 0.60s
```

### 5.3 静态与编译检查

以下检查均通过：

```bash
../../.venv/bin/ruff check \
  utilities/context_enhancer.py \
  core/platforms/prompt_context.py \
  tests/openharmony/test_single_shot_enhancer_platform_context.py

git diff --check
../../.venv/bin/python -m compileall -q \
  utilities/context_enhancer.py \
  core/platforms/prompt_context.py \
  tests/openharmony/test_single_shot_enhancer_platform_context.py
```

## 6. 代表性结果

OpenHarmony unit 输入：

```text
language = cpp
platform_context.platform = openharmony
platform_context.boundary = binder_ipc
platform_context.guard = permission_check / CheckPermission
```

single-shot Prompt 中出现：

````text
You are analyzing a cpp function ...
```cpp
...
```

## OpenHarmony Platform Context
- Platform: openharmony
- Boundary signals: binder_ipc
- Guard signals: permission_check (matched: CheckPermission)
````

generic unit 仍出现历史的：

````text
You are analyzing a JavaScript/TypeScript function ...
```javascript
...
```
````

## 7. 结论与下一步

OH-21B-2A 已完成。single-shot Context Enhancer 能够识别 OpenHarmony unit 的真实
语言并获得统一平台证据，同时 generic Prompt 保持兼容。

下一阶段候选为 OH-21B-2B：接入 agentic Context Enhancer。该模式使用独立的
`ContextAgent → agentic_enhancer.prompts.get_user_prompt()` 链路，必须单独设计
上下文位置、OpenHarmony C/C++ 语言提示和工具探索边界。
