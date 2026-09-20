# OH-SL-16：10 轮默认语义循环真实 smoke

日期：2026-08-29  
目标：`/dev/unix/socket/fd_holder`  
Session：`loc_fdholderllmr10`  

## 1. 执行配置

本次创建 session 时没有设置 `max_llm_actions`，使用代码默认值 10：

```bash
python -m openant.cli source-locator create /dev/unix/socket/fd_holder \
  --root /private/tmp/openant-live-source-locator/fd-holder-llm-r10 \
  --target-revision OpenHarmony-6.1-LTS \
  --budget-json '{"max_queries":20,"max_results":20,"max_hits_per_file":3}' \
  --session-id loc_fdholderllmr10

python -m openant.cli source-locator run loc_fdholderllmr10 \
  --root /private/tmp/openant-live-source-locator/fd-holder-llm-r10 \
  --config-path VulnFounder/config/openant/config.json \
  --project-root VulnFounder --max-steps 32 --max-paths 32 \
  --llm-search --llm-config openharmony-live-gpt
```

## 2. 实际结果

- 真实模型完成 4 个有效动作，`llm_search.json` 记录 `round_count=5`；
- 动作序列为：
  `search_full(/dev/unix/socket/fd_holder)` →
  `read_file(fd_holder_internal.h)` →
  `search_symbol(INIT_HOLDER_SOCKET_PATH)` →
  `read_file(fd_holder_internal.c)`；
- 模型给出的 tree-relative 路径均被安全转换为 OpenGrok 的
  `/openharmony/...` 路径后成功读取；
- 第 5 轮模型引用了当前上下文不存在的 evidence ID，schema 校验拒绝该动作，
  session 按安全策略停止为 `PARTIAL`；没有把模型判断升级成仓库确认，也没有 clone。

## 3. 结论

默认 10 轮表示最多允许 10 个模型动作，不保证机械执行满 10 轮。模型动作无效、
重复、工具失败或证据不足时可以提前停止。本次循环已证明真实模型能够连续调用搜索、
读文件并读取新增证据；同时暴露出后续可优化点：跨轮上下文投影应尽量保持证据 ID
稳定，并可为后续轮次提供更可靠的格式修复机会。

