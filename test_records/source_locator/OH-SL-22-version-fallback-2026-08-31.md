# OH-SL-22：Git 拉取失败后的远程版本候选与可恢复暂停

## 测试目的

验证源码定位在 Git 拉取失败或拉取后验证失败时，不再只进入不可恢复的失败状态，
而是通过同一份经过 Manifest/GitCode 白名单校验的仓库映射，执行只读
`git ls-remote --heads --tags --refs`，生成可供用户选择的版本候选产物。

本阶段尚未实现 Web 版本下拉框、选择后的重试和旧 checkout 清理；候选不会自动应用。

## 修改前逻辑

1. `CLONE` 阶段只要 `RepositoryManager.ensure_repository()` 返回非成功状态，
   就写入 `clone_results.json` 并转换到终态 `CLONE_FAILED`。
2. `POST_CLONE_VERIFY` 只要有一项检查缺失或出错，就写入
   `post_clone_verification.json` 并转换到终态 `POST_CLONE_VERIFY_FAILED`。
3. 终态不能继续推进，用户只能重新创建 session，无法在当前 session 内查看可用
   branch/tag 并选择替代 revision。

## 修改后逻辑

1. 新增 `repository_versions.py`，使用固定参数和非 shell runner 执行只读远程引用查询。
2. 只接受 `refs/heads/*` 和 `refs/tags/*`，过滤 peeled tag、非法 ref、非法 commit，
   最多保留 32 个候选；优先当前请求 revision，其次 LTS、Release、main/master 等稳定引用。
3. 每个失败场景生成 `repository_version_candidates.json`，记录查询状态、候选 revision、
   commit、原始失败阶段和有限命令摘要。
4. session 新增 `version_selection` 摘要，并从 `CLONE` 或 `POST_CLONE_VERIFY` 进入
   可恢复的 `VERSION_SELECTION_REQUIRED` 暂停状态；不会自动切换 revision，也不会覆盖已有目录。
5. `SourceLocatorRuntime` 支持注入固定 `git_runner`，便于离线测试；生产默认仍使用
   内置非 shell Git runner。

## 自动化测试

执行目录：`libs/vulnfounder-core`

```text
../../.venv/bin/pytest -q \
  tests/source_locator/test_repository_versions.py \
  tests/source_locator/test_state_machine.py \
  tests/source_locator/test_worker.py
结果：33 passed in 0.31s
```

回归测试：

```text
../../.venv/bin/pytest -q \
  tests/source_locator tests/openharmony tests/platforms tests/report \
  tests/parsers/c/test_header_language_detection.py \
  tests/test_application_context_sources.py tests/test_chinese_runtime_logs.py \
  tests/test_generalized_vulnerability_prompt.py \
  tests/test_scanner_llm_recovery_integration.py \
  tests/test_stage2_inconclusive_recovery.py
结果：621 passed, 6 skipped in 24.42s
```

## 关键验证点

- 模拟远程引用包含 `OpenHarmony-6.1-LTS`、Release、master、peeled tag、路径穿越
  ref 和非法 commit；最终只保留 3 个安全候选。
- 模拟 HTTP 301 拉取失败时，worker 状态为 `VERSION_SELECTION_REQUIRED`，候选产物
  包含失败阶段 `clone` 和两个安全 revision。
- 状态 checkpoint 重新加载后仍保留 `version_selection`，并允许后续显式选择动作
  从暂停状态回到 `CLONE`。
- 远程查询失败或无候选时仍生成 `status=unavailable` 产物，不猜测或拼接未验证 revision。
- 所有 Git 命令均禁用 shell、`protocol.ext`、`protocol.file` 和自动 HTTP 重定向。

## 真实 GitCode 只读验证

使用 `startup_appspawn` 的已验证 Manifest 映射对
`https://gitcode.com/openharmony/startup_appspawn` 执行了一次
`git ls-remote`（不 clone、不 checkout、不修改工作区）。查询返回成功，发现 32
个有界候选，其中当前 `OpenHarmony-6.1-LTS` 被标记为推荐，并解析到 commit
`1f0ac5a68509cb12653eb636d3b4fb45b9eb6681`。这证明 GitCode 当前的 branch/tag
查询协议可用；候选列表超出上限时会明确记录截断警告。

## 当前限制与下一阶段

当前产物已经提供了候选版本和失败原因，但还没有将候选版本呈现在 Web，也没有实现
“用户选择 revision → 重新确认 → 安全重试拉取 → 再次验证”的完整动作。下一阶段将
增加对应的 CLI/API 状态操作和 Web 选择界面，并保留每次尝试的审计记录。
