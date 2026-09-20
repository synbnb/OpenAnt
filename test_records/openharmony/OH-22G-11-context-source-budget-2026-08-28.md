# OH-22G-11：应用上下文文件读取上限测试记录

日期：2026-08-28  
对象：应用上下文阶段的仓库说明文件收集  
测试方式：本地单元测试 + 真实 OpenHarmony 仓库离线验证（无模型调用）

## 1. 问题

原逻辑在 `context/application_context.py` 中使用 `read_repo_file(...,
max_bytes=10_000)`，且默认拒绝超限文件。`multimedia_audio_framework/README.md`
实际约 18 KB，因此扫描时出现：

```text
Warning: Could not read README.md: README.md is too large (... > 10000); refusing to read
```

该限制来自 VulnFounder 的仓库安全读取层，不是模型 API 的输入限制。它保护内存和请求预算，但
会把仍然有价值的 README 整份排除。

## 2. 修改后的逻辑

- 单个优先上下文文件上限从 10,000 提高到 20,000 字节；
- 超过单文件上限时采用受控截断并加入 `[... truncated ...]` 标记，不再静默丢弃；
- 所有优先上下文文件共享 120,000 字节总预算，预算耗尽后停止读取并加入 `[context_budget]`
  说明；
- symlink、FIFO/设备文件、路径越界等 `read_repo_file` 安全检查保持不变；
- 该调整只影响应用上下文输入，不改变 C/C++ 解析、调用图或漏洞判定规则。

## 3. 测试结果

- 新增读取上限回归测试 3 个；
- 应用上下文、OpenHarmony 平台上下文和提示词围栏测试合计：`19 passed`；
- Ruff：`All checks passed`；
- `git diff --check`：通过。

覆盖场景：

1. 18,090 字节 README 在 20,000 上限内完整保留；
2. 超过 20,000 的文件被截断并显式标记；
3. 总预算耗尽后，后续优先文件不再读取且预算状态可见。

## 4. 真实源码离线验证

仓库：`openharmony_reference/openharmony_source_code/multimedia_audio_framework`  
文件：`README.md`

- 新单文件上限：20,000；
- 新总预算：120,000；
- README 已成功读取，约 18,014 字符；
- 未出现 `[... truncated ...]`；
- 未出现 `Could not read README.md`；
- 当前收集到 `README.md` 和目录结构，未触发总预算标记。

## 5. 结论与边界

该调整解决了当前 18 KB README 被整份跳过的问题，并保留明确的单文件和总量安全边界。
已经启动的扫描进程在启动时加载旧代码，不会自动获得新上限；后续重新扫描时才会生效。
总量上限仍可能导致大型仓库的低优先级说明文件被跳过，模型上下文不应被视为完整仓库副本。
