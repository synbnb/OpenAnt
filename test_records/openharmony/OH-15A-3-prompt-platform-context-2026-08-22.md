# OH-15A-3：OpenHarmony 平台上下文 Prompt 消费测试记录

日期：2026-08-22
阶段：OH-15A-3
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段把 OH-15A-2 已写入 Unit 的 `platform_context` 传递给 Stage-1 分析 Prompt。本阶段不接入 semantic graph、规则引擎、Finding 融合或 Stage-2 验证工具。

Prompt 中只消费当前 Unit 的有限字段：component、build target、source role、boundary、guard 和精简 evidence；不把整个 repository profile 或语义图重复发送给每个 Unit。

## 2. 修改前后逻辑

### 修改前

- `analysis_core.analyze_unit()` 只读取语言、route、文件列表和可选应用威胁模型。
- Unit 虽然已有 `platform_context`，但 Prompt 组装链路完全忽略它。
- `get_analysis_prompt()` 不接受平台上下文参数。

### 修改后

1. `analysis_core` 从 Unit 读取 `platform_context` 并传入 Prompt selector。
2. `prompt_selector` 和 `vulnerability_analysis` 增加可选参数，保持原有调用方式兼容。
3. OpenHarmony 上下文渲染为独立的 `## OpenHarmony Platform Context` 区段，并明确标注为静态仓库证据而非指令。
4. 所有仓库控制的字符串都经过单行折叠和单值长度限制；列表最多保留 8 项，总上下文最多 4,000 字符；任意非预期嵌套对象直接忽略。
5. 注释/字符串中的换行不能伪造新的 Prompt 标题或指令行；generic、旧 Unit、无上下文 Unit 的 Prompt 形状保持不变。

## 3. 修改文件

- `libs/vulnfounder-core/core/analysis_core.py`
  - 转发 Unit `platform_context`。
- `libs/vulnfounder-core/prompts/prompt_selector.py`
  - 增加可选 `platform_context` 参数并继续向下转发。
- `libs/vulnfounder-core/prompts/vulnerability_analysis.py`
  - 新增受限 OpenHarmony 上下文渲染器和注入防护；
  - 无上下文时保留原 `context_section` 组装逻辑。
- `libs/vulnfounder-core/tests/openharmony/test_prompt_platform_context.py`
  - 新增 Prompt 传递、限长、换行注入和 generic 兼容测试。

## 4. TDD 记录

### RED

先新增测试后运行：

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_prompt_platform_context.py
```

结果：`3 failed, 1 passed`。失败分别证明 Prompt API 尚未接收平台上下文、`analysis_core` 尚未转发上下文、以及上下文限长/注入防护尚未生效；generic 无上下文测试先通过。

### GREEN

实现后运行：

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_prompt_platform_context.py
```

结果：`4 passed`。

覆盖项：

- OpenHarmony context 区段包含 component、target、boundary、guard 和 evidence；
- `analysis_core` 能把 Unit 上下文传入真实 Prompt；
- 换行、伪造标题和 prompt 指令被压成单行，列表和总长度受限；
- 没有上下文时不出现 OpenHarmony 区段。

## 5. 回归测试

Prompt、语言和威胁模型回归：

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_prompt_platform_context.py \
  VulnFounder/libs/vulnfounder-core/tests/test_unit_language_metadata.py \
  VulnFounder/libs/vulnfounder-core/tests/test_analysis_prompt_injection.py \
  VulnFounder/libs/vulnfounder-core/tests/test_threat_model_prompts.py \
  VulnFounder/libs/vulnfounder-core/tests/test_threat_model_untrusted_input_gate.py
```

结果：`43 passed`。

Prompt 注入、CWE、Stage-2 相关兼容测试：`48 passed`。

OpenHarmony/C parser 回归：

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony \
  VulnFounder/libs/vulnfounder-core/tests/platforms/test_openharmony_entry_points.py \
  VulnFounder/libs/vulnfounder-core/tests/parsers/c
```

结果：`137 passed, 2 skipped`。

质量检查：相关三个生产文件和测试文件的 `ruff check`、`py_compile`、空白检查均通过。

## 6. 真实 OpenHarmony Unit 验证

复用 OH-15A-2 对本地 `communication_wifi` 生成的 dataset：

```text
/private/tmp/openant-oh15a2-communication_wifi-final/dataset.json
```

从其中选择带 guard 的真实 Unit：

```text
wifi/base/shared_util/wifi_notification_util.cpp:WifiNotificationUtil::StartAbility
```

无 LLM 直接调用 Prompt renderer，结果：

- Prompt 包含 `## OpenHarmony Platform Context`；
- 正确显示 `wifi` component、`wifi_base` target、`binder_ipc` boundary 和 `WriteInterfaceToken` guard；
- Prompt 长度为 9,395 字符；
- 没有出现伪造的 `## SYSTEM DIRECTIVE` 换行；
- 上下文只来自当前 Unit，不读取整个仓库 profile。

## 7. 阶段边界与后续

本阶段只让 Prompt 看见已经存在的静态上下文，不把 guard 直接解释为“已完成权限校验”，也没有新增 transaction/IDL 字段。后续如需把 IPC transaction、字段读写、规则命中证据放入 Prompt，应先建立对应的确定性字段和条目级限额，再单独实施和测试。
