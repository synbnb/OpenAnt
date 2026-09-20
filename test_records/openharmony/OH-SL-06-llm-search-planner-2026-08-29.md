# OH-SL-06 受限 LLM Search Planner 测试记录

日期：2026-08-29
阶段：SL-06（受限 LLM Search Planner）
测试方式：本地离线夹具；未调用真实大模型、OpenGrok、Git 或开发板。

## 1. 本阶段验证目标

原来的源码定位器只有确定性的固定查询执行器。新增的 planner 只负责从已有
证据中提出“一条下一步检索动作”，再把动作交给后续确定性执行器。它不会直接
执行查询，也不会执行 shell、clone、checkout 或任意本地文件读取。

## 2. 已实现的门禁

- 动作 `kind` 仅允许 `search_full`、`search_definition`、`search_symbol`、
  `search_path`、`read_file`。
- 每个动作必须引用上下文中已经存在的 `evidence_id`；没有证据时跳过模型，
  保持固定初始查询路径。
- 搜索词、源路径、提示词长度、引用数量、动作轮次和模型调用次数都有硬上限。
- 拒绝 URL、路径穿越、反斜杠、命令控制字符、本机路径以及未知字段。
- 重复动作返回 `REPEATED`，不会再次进入执行器。
- 模型格式错误最多触发一次格式修复；修复仍失败返回 `NEEDS_REVIEW`。
- 没有模型适配器或模型调用失败返回 `PARTIAL`，不会让定位流程崩溃。
- 客户端通信边界完成后，`find_business_callers` 仍被列为禁止动作。
- 提示词把 OpenGrok 源码标记为不可信数据，并要求不输出隐藏思维链；结果中不
  保存模型原始响应。

## 3. 测试命令和结果

在 `libs/vulnfounder-core` 目录执行：

```text
../../.venv/bin/pytest tests/source_locator/test_llm_search_planner.py -q
23 passed in 0.07s

../../.venv/bin/pytest tests/source_locator -q
205 passed in 0.12s

../../.venv/bin/ruff check core/source_locator tests/source_locator/test_llm_search_planner.py
All checks passed!
```

此外执行了全项目 `pytest -x -q` 的环境检查。该命令在已有的 Go 一致性测试处
停止，原因是当前机器找不到 `go` 可执行文件（`FileNotFoundError: [Errno 2]
No such file or directory: 'go'`），不是 SL-06 代码或测试失败。该环境问题不影响
上面的 205 个源码定位器测试结果。

## 4. 测试覆盖摘要

| 场景 | 结果 |
| --- | --- |
| 合法结构化动作和确定性 `LocatorQuery` 转换 | 通过 |
| JSON 代码围栏/动作 envelope | 通过 |
| clone、shell、任意本地读、生成 URL、业务 caller 等禁止动作 | 通过 |
| 未知 evidence ID、未知字段 | 通过 |
| URL、命令注入、路径穿越和本机路径 | 通过 |
| 无证据时不调用模型 | 通过 |
| 没有模型适配器时降级为 `PARTIAL` | 通过 |
| 一次格式修复和二次失败 | 通过 |
| 重复动作和上下文历史 | 通过 |
| 动作预算耗尽 | 通过 |
| 不可信数据围栏和隐藏思维链不落盘 | 通过 |

## 5. 当前边界

本阶段还没有把 planner 接入持久化状态机，也没有让它直接调用 OpenGrok。下一
阶段需要在用户确认的前提下实现状态转换、暂停/恢复、用户拒绝反馈，以及把
`READY` 动作交给已有的确定性 SearchPlanner 执行；仓库 URL 推断和 clone 仍
必须由确定性模块完成。
