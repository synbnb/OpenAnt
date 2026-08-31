# OH-22H：路径归因过滤与 LLM 角色复核测试记录

日期：2026-08-29

## 本阶段目标

- 仅将明确的测试、self-test、unittest、fuzz 路径排除在服务端/客户端归因之外。
- 保留 `kernel`、`third_party`、`generated`、`out`、`build` 等路径，交给证据和 LLM 语义判定继续分析。
- 在显式启用 `--llm-search` 时，对已读取的源码证据执行一次服务端/客户端角色复核。
- 模型只能引用现有 `evidence_id`，不能生成路径、仓库 URL 或隐藏调用关系。

## 变更摘要

- `PathClassification` 增加 `path_signals` 和 `attribution_eligible`，识别路径的多重信号。
- `ServiceAttributor`、`ClientLocator` 过滤测试/fuzz 证据，并保留 `excluded_evidence_ids` 供审计。
- 新增 `llm_role_attributor.py`，严格校验模型 JSON、角色状态、证据 ID 和输出字段。
- source-locator worker 保存 `llm_role_attribution.json`，并将有效决策合并到服务端/客户端归因结果。
- Manifest 候选排序会对 LLM 已确认或可能的服务端 evidence_id 增加小幅锚点分，避免语义识别出的生成/内核实现被普通字面量噪声压过。
- CLI 的 `--llm-search` 同时启用检索规划器和角色复核器；没有该选项时不增加模型调用。

## 自动化测试

执行命令：

```text
PYTHONPATH=libs/openant-core pytest -q libs/openant-core/tests/source_locator
```

结果：`258 passed in 26.83s`（加入语义证据的仓库排序锚点后再次执行）

覆盖内容：

- Linux kernel self-test 路径同时具有 `kernel` 与 `test` 信号，`attribution_eligible=false`。
- 单独的 kernel、third-party、generated、out、build 路径仍保持 `attribution_eligible=true`。
- 测试路径中的 `accept/send` 证据仍保存在证据库，但不会满足服务端/客户端谓词。
- LLM 确认只能引用已提供的证据；未知或被排除的 ID 会被拒绝。
- worker 只调用一次角色模型，保存结构化结果，不保存原始响应或隐藏思维链。
- 原有 source-locator 状态机、检索规划、补证和仓库确认测试全部通过。

另外对本地 OpenHarmony 参考仓库做了只读路径盘点：共识别 8,080 个 C/C++ 源文件，其中 4,942 个生产路径、2,364 个测试路径、742 个 fuzz 路径、4 个生成路径、23 个日志路径和 5 个策略路径。只有 3,106 个明确测试/fuzz 文件被标记为不可参与角色归因，其余路径仍然保留为可分析候选。

## 环境限制

尝试执行全量 `libs/openant-core/tests` 时，当前环境缺少既有项目依赖（如 `tree_sitter_c`、`tree_sitter_php`、`tree_sitter_rust`、`tree_sitter_zig` 以及 Google GenAI SDK），导致测试收集阶段失败；这与本阶段 source-locator 修改无关。本记录以完整 source-locator 测试套件结果为准。

## 结论

本阶段通过。路径筛选不再把内核、第三方或构建产物一概视为无效；明确测试/fuzz 证据被隔离但不会从审计产物删除，LLM 角色复核具备证据闭环和失败回退能力。
