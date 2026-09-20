# OH-SL-19：LLM 语义检索默认 20 轮

日期：2026-08-29

## 变更

- Web 源码定位页面的“启用 LLM 语义检索”提示改为最多 20 轮。
- Python worker 的 `max_llm_actions` 默认值和硬上限从 10 调整为 20。
- CLI 创建的语义规划器预算调整为最多 20 个动作，并保留 1 次修复调用，即最多 21 次模型调用。
- 规划器允许的 `max_model_calls` 校验上限从 16 提高到 32，以容纳 20 轮动作和必要的重试。
- 20 轮仍然是保护上限，不保证一定执行满 20 轮；模型重复、工具错误、证据不足或状态机完成时仍可提前结束。

## 验证

- `tests/source_locator`：**249 passed**。
- `PlannerBudget(max_actions=20, max_model_calls=21)` 实例化及 worker 默认/越界截断检查：**通过**。
- `apps/vulnfounder-cli`：`go test ./...` **全部通过**。
- `source-locator.html` 内嵌脚本：`node --check` **通过**。
- Web 重建并重启后，页面可访问 `http://127.0.0.1:18080/source-locator`，提示显示“最多 20 轮”。

