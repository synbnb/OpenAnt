# OH-SL-15：真实模型 Agentic Loop smoke

日期：2026-08-29  
目标：`/dev/unix/socket/fd_holder`  
目的：验证模型是否能在确定性初始检索后自主选择源码读取动作，并把工具结果纳入后续上下文。  

## 1. 执行方式

本次 smoke 为控制成本显式使用 2 轮预算，并不是最终默认配置：

```bash
python -m openant.cli source-locator create /dev/unix/socket/fd_holder \
  --root /private/tmp/openant-live-source-locator/fd-holder-llm-r9 \
  --target-revision OpenHarmony-6.1-LTS \
  --budget-json '{"max_queries":20,"max_results":20,"max_hits_per_file":3,"max_llm_actions":2}' \
  --session-id loc_fdholderllmr9

python -m openant.cli source-locator run loc_fdholderllmr9 \
  --root /private/tmp/openant-live-source-locator/fd-holder-llm-r9 \
  --config-path VulnFounder/config/openant/config.json \
  --project-root VulnFounder --max-steps 32 --max-paths 32 \
  --llm-search --llm-config openharmony-live-gpt
```

当前代码已将未配置预算时的默认语义动作数改为 10，session 级硬上限也为 10；本
记录沿用 2 轮仅用于低成本验证失败处理。

## 2. 实际结果

- 确定性检索、证据图、服务端/客户端归因和 Manifest 解析均正常完成；
- 模型第 1 轮选择了白名单 `read_file` 动作：
  `/base/startup/init/interfaces/innerkits/fd_holder/fd_holder.c`；
- OpenGrok 返回 HTTP 404，原因是索引实际源码路径带有 `/openharmony` 前缀；
- 工具错误被记录在 `llm_search.json`，worker 没有伪造证据，也没有继续猜测路径；
- session 最终为 `PARTIAL`，`round_count=1`，没有执行 Git clone。

## 3. 结论

Agentic Loop 已真实调用模型并正确执行白名单与失败降级。此次没有用满 2 轮，不是
轮数不足，而是第 1 个工具动作失败后按安全策略停止。该 smoke 暴露了一个可泛化的
接口问题：模型看到的证据路径与 OpenGrok `read_source` 要求的规范路径需要统一。
下一步应在读取动作入口增加项目根前缀的可验证规范化，或把合法路径格式明确提供给
模型；不能把 404 当作“源码不存在”。

该问题已在后续修复：读取动作现在会依据已有 evidence 或可信的 OpenGrok project
前缀重试规范路径；修复后的默认 10 轮 smoke 见 `OH-SL-16`。
