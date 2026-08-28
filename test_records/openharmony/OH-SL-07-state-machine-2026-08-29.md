# OH-SL-07 持久化状态机与用户反馈测试记录

日期：2026-08-29
阶段：SL-07
测试方式：本地临时目录和离线 handler；未调用真实模型、OpenGrok、Git 或开发板。

## 原逻辑与新逻辑

此前定位器的模块只能分别完成标准化、搜索、证据和归因，缺少一个可以暂停、
恢复和等待用户确认的统一生命周期。此次新增 `LocatorSession`、事件日志、
原子 checkpoint 和有界编排器：状态按固定顺序推进，用户确认前不能进入 CLONE；
拒绝时保留原证据图，只追加排除路径、排除仓库和所需角色等约束。

## 实现内容

- `events.py`：追加式 `events.jsonl`，校验连续 `seq`、session 归属、事件大小、
  artifact 相对路径和 evidence ID；不保存源码全文、模型原始响应或凭据。
- `state_machine.py`：固定状态转换、取消/失败/确认/拒绝、查询去重、查询预算、
  三轮拒绝上限和恢复读取。
- `orchestrator.py`：注入确定性 stage handler；缺 handler、非法结果、异常或步数
  超限时进入 `NEEDS_REVIEW`，不死循环。

## 测试命令和结果

```text
../../.venv/bin/pytest tests/source_locator/test_state_machine.py -q
10 passed in 0.08s

../../.venv/bin/pytest tests/source_locator -q
216 passed in 0.18s

../../.venv/bin/ruff check core/source_locator tests/source_locator/test_state_machine.py
All checks passed!
```

覆盖内容包括：

1. session 创建、事件和 checkpoint 同时落盘；
2. 严格状态顺序和等待用户确认；
3. 标准化异常与缺失 handler 的安全降级；
4. 非法跳转和终态继续执行拦截；
5. 重启后 query 历史恢复、重复 query 不执行；
6. 查询预算耗尽进入 `PARTIAL`；
7. 用户拒绝保留旧 evidence graph 并追加约束；
8. 第四轮拒绝进入 `NEEDS_REVIEW`；
9. 只有确认才能进入 `CLONE`；
10. 事件序号断裂和 artifact 路径穿越被拒绝。

## 当前边界

本阶段的 stage handler 仍由调用方注入，尚未连接 CLI/Web，也不会自行调用网络或
Git。SL-09 将把这些操作封装成单步 JSON worker，SL-10 再接入 Web session/SSE。
