# OH-SL-20：缺失服务端谓词仍进入仓库确认

日期：2026-08-29

## 目的

验证 OpenHarmony 源码定位在已有 `resolved` GitCode 仓库映射、但服务端证据缺少
`socket_acquire_or_bind` 时，不会因为确定性谓词硬门禁直接进入 `PARTIAL` 终态。
缺失条件应作为可审计提示保留，并等待用户明确决定是否拉取仓库。

## 修改

- `VERIFY_EVIDENCE` 在有 resolved 映射时把缺失谓词视为 advisory（提示），最终进入
  `AWAIT_USER_CONFIRMATION`。
- `verification.json` 和 `confirmation_summary.json` 保存
  `missing_server_predicates` / `missing_predicates` 及 `predicate_gate=advisory`。
- 服务端 `confirmed=false`、谓词值、证据和事件详情保持不变，便于人工复核。
- 语义补证不可用或没有新动作时回到最终校验，不再把“暂时无法补证”直接当作定位终态。
- 仍没有 resolved 映射时保持 `NEEDS_REVIEW`；只有用户调用确认操作才会进入 `CLONE`。

## 测试场景

离线构造包含以下证据的参数服务候选：

- socket identity：目标字面量和服务配置；
- server consumer：`recv` 与协议分派；
- 故意不提供 socket 创建/绑定证据；
- 提供 `startup_init` 的 resolved Manifest 映射。

## 执行命令

```text
python -m pytest OpenAnt/libs/openant-core/tests/source_locator/test_worker.py -q
python -m pytest OpenAnt/libs/openant-core/tests/source_locator -q
ruff check OpenAnt/libs/openant-core/core/source_locator/worker.py OpenAnt/libs/openant-core/tests/source_locator/test_worker.py
```

## 结果

- worker 定向测试：15 passed。
- source-locator 全量测试：250 passed（26.27s）。
- Ruff：All checks passed。
- 断言确认：状态为 `AWAIT_USER_CONFIRMATION`；服务端仍为
  `confirmed=false`；确认摘要列出 `socket_acquire_or_bind`；事件类型为
  `verification.await_confirmation` 且 `predicate_gate=advisory`。
- 进一步调用状态机 `confirm()` 才转换为 `CLONE`，仅调用 `advance()` 不会自动拉取。

## 结论

该硬门禁已改为“证据质量提示”，不会再因单个未满足谓词让已有仓库候选烂尾；
仓库拉取仍受 resolved 映射、仓库策略和用户显式确认三重约束。
