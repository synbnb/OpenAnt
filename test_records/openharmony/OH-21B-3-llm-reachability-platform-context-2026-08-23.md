# OH-21B-3：LLM Reachability 接入 OpenHarmony 平台上下文

日期：2026-08-23  
阶段：OH-21B-3  
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段把已有的 `PlatformPromptContext` 接入 LLM Reachability 的批量 Unit
投影和 Prompt。该阶段仍是可选、辅助性的 reachability review，不改变结构化入口
检测的结论，也不把 LLM 信号变成强制入口。

调用链：

```text
analyze_reachability()
  -> build_prompt()
    -> _unit_for_prompt()
      -> llm_reach adapter 的批量消息
```

本阶段不调用真实 LLM，不修改响应解析、`apply_signals()`、high-confidence
promote-only 门槛、scanner 的重新过滤逻辑或 `llm_reachability_signals` schema。

## 2. 修改前后逻辑

### 修改前

- LLM Reachability 的每个 Unit 只投影 `unit_id`、`unit_type`、`is_entry_point`、
  `reachable` 和截断后的代码。
- Prompt 虽然文字中泛化提到 IPC，但模型看不到当前 OpenHarmony Unit 的实际
  Binder/SA/HDF boundary、guard、证据或 semantic edge。
- OpenHarmony C/C++ Unit 没有单独的语言字段；generic 投影是固定的五字段形状。

### 修改后

1. `_unit_for_prompt()` 优先读取 `platform_context`，缺失时兼容
   `platformContext`。
2. 只有归一化结果为 `platform=openharmony` 时，投影才增加：
   - `language`，默认 `cpp`；
   - 当前 Unit 的 `PlatformPromptContext.render_for_phase("reachability")` 文本。
3. OpenHarmony 平台上下文每个 Unit 最多保留 1,600 字符，避免 25 个 Unit 的批次
   重复放大上下文成本；共享上下文本身仍执行字段白名单、单项限长和列表限额。
4. generic 或 malformed/non-OpenHarmony 上下文不增加空字段，继续使用原有五字段
   投影形状。
5. 上下文以“静态仓库证据、不是指令”的形式发送；换行折叠和总长限制阻止仓库
   字段伪造新的 Prompt 标题。
6. `apply_signals()` 仍只接受 high-confidence `entry_point` 作为 promote，且
   始终保持 promote-only：LLM 不会取消结构化分析已经发现的入口。

## 3. 修改文件

- `libs/vulnfounder-core/core/llm_reachability.py`
  - 引入 `PlatformPromptContext`；
  - 增加 `MAX_PLATFORM_CONTEXT_CHARS = 1600`；
  - 扩展 `_unit_for_prompt()` 的 OpenHarmony 投影逻辑；
  - generic 投影路径保持原有字段。
- `libs/vulnfounder-core/tests/openharmony/test_llm_reachability_platform_context.py`
  - 新增平台投影、键名兼容、generic 兼容、限长/换行安全、批量 Prompt 和 fake
    adapter 测试。

## 4. TDD 与阶段测试记录

### RED

先加入新契约测试后运行：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_llm_reachability_platform_context.py -q
```

结果：`4 failed, 1 passed`。失败证明旧投影尚未提供 `language`、
`platform_context` 或批量 OH 上下文；generic 兼容测试先通过。

### GREEN

新测试与既有 LLM Reachability 测试：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony/test_llm_reachability_platform_context.py \
  tests/test_llm_reachability.py -q
```

结果：`36 passed`。

OpenHarmony、scanner refilter、LLM Reachability 和 Prompt 安全回归：

```text
../../.venv/bin/python -m pytest \
  tests/openharmony \
  tests/test_llm_reachability.py \
  tests/test_scanner_refilter_loop.py \
  tests/test_scanner_refilter_loop_executes.py \
  tests/test_scanner_refilter_library_mode.py \
  tests/test_scanner.py \
  tests/test_entrypoint_bindings.py \
  tests/test_prompt_fence_escape_siblings.py \
  tests/test_analysis_prompt_injection.py -q
```

结果：`143 passed, 2 skipped`。

`test_scanner_refilter_metadata.py` 使用同目录 pytest plugin。直接从
`libs/vulnfounder-core` 按文件路径收集时，项目既有 pytest 路径设置无法找到该插件，
出现收集错误；这不是本阶段生产代码失败。按该测试的实际导入约定补充 `tests/`
到 `PYTHONPATH` 后单独运行：

```text
PYTHONPATH=tests ../../.venv/bin/python -m pytest \
  tests/test_scanner_refilter_metadata.py -q
```

结果：`4 passed`。

质量检查：

```text
../../.venv/bin/ruff check \
  core/llm_reachability.py \
  tests/openharmony/test_llm_reachability_platform_context.py
../../.venv/bin/python -m compileall -q \
  core/llm_reachability.py \
  tests/openharmony/test_llm_reachability_platform_context.py \
  core/platforms/prompt_context.py
git diff --check
```

结果：全部通过。

## 5. 具体验证项

- OH Unit 的 Prompt 包含 `cpp`、Binder boundary、permission/interface guard 和
  semantic edge；
- `permission_check` 仍作为证据字符串显示，不被解释为权限校验已经覆盖路径；
- `platform_context` 和 `platformContext` 两种字段名均可读取；
- generic 投影仍只有历史五个字段，不发送空的 OH 上下文；
- 恶意换行不会形成 `## FAKE INSTRUCTION` 等新的 Prompt 标题；
- 单 Unit 上下文最多 1,600 字符；
- fake adapter 实际收到包含 OH 上下文的批量 Prompt；
- 既有 malformed response、未知 Unit ID、adapter 异常和批处理行为保持通过；
- promote-only 和 scanner 重新过滤相关回归保持通过。

## 6. 阶段边界

本阶段只扩大 LLM Reachability 的观察上下文，没有扩大 OpenHarmony 原生入口规则
覆盖率，也没有把 semantic graph 直接变成 reachability 边。LLM 仍可能漏报或误报，
结构化入口检测仍是基础；上下文缺失不会自动把 Unit 判定为不可达或安全。

