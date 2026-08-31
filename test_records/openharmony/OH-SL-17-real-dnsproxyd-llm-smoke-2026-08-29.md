# OH-SL-17：真实 `dnsproxyd` socket 定位 smoke

日期：2026-08-29  
目标：`/dev/unix/socket/dnsproxyd`  
Session：`loc_dnsproxydllmr10`  
OpenGrok 项目：`openharmony`  
模型配置：`openharmony-live-gpt`（`gpt-5.6-luna`）  

## 1. 执行命令

```bash
cd /Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core

../../.venv/bin/python -m openant.cli source-locator create /dev/unix/socket/dnsproxyd \
  --root /private/tmp/openant-live-source-locator/dnsproxyd-llm-r10 \
  --target-revision OpenHarmony-6.1-LTS \
  --budget-json '{"max_queries":20,"max_results":20,"max_hits_per_file":3}' \
  --session-id loc_dnsproxydllmr10

../../.venv/bin/python -m openant.cli source-locator run loc_dnsproxydllmr10 \
  --root /private/tmp/openant-live-source-locator/dnsproxyd-llm-r10 \
  --config-path /Users/shiyu/学习/hyl/new/OpenAnt/config/openant/config.json \
  --project-root /Users/shiyu/学习/hyl/new/OpenAnt --max-steps 32 --max-paths 32 \
  --llm-search --llm-config openharmony-live-gpt
```

没有设置 `max_llm_actions`，因此使用默认最多 10 轮语义动作。

## 2. 真实运行结果

- session 最终状态：`AWAIT_USER_CONFIRMATION`；
- `llm_search.json`：7 个有效动作，第 8 轮识别为重复动作后停止；
- 模型动作包含 `search_full`、`search_symbol` 和 `read_file`，读文件结果成功写回
  evidence，并被后续轮次继续使用；
- 最终复核（`verification.json`）服务端归因：`HIGH`，分数 85；socket identity、
  获取/绑定、消费、协议分派和 Manifest 映射谓词均满足；
- 注意：`server_attribution.json` 是 Manifest 映射前的中间归因产物，因此仍显示
  `PARTIAL/75`；不能用它替代最终的 `verification.json`；
- 客户端归因：`PARTIAL`，分数 80；已找到 connect/send 和 endpoint，但缺少更强的
  协议构造证据；
- 主仓库映射：`communication_netmanager_base`；
- 没有执行 Git clone，因为确认门要求用户先确认候选仓库。

## 3. 人工源码核验

对真实 OpenGrok 源码行进行只读核验：

- `services/netmanagernative/include/netsys/dns_config_client.h:32-33`：
  `DNS_SOCKET_PATH`/`DNS_SOCKET_NAME`；
- `frameworks/js/napi/netstats/src/dns_resolv_listen.cpp:363`：
  `GetControlSocket(DNS_SOCKET_NAME)`；
- 同文件 `:370`：listener `listen`；
- 同文件 `:404-426`：请求命令分派；
- `frameworks/js/napi/netpolicy/src/netsys_client.c:88`、`:180`：客户端
  `connect` 和发送。

这些行与 worker 保存的 evidence ID 和 `communication_netmanager_base` Manifest
映射一致。`HIGH` 在此处表示“服务端候选已满足定位谓词”，不是自动确认漏洞，也不
绕过用户确认或仓库拉取门禁。

## 4. 结论

真实模型、真实 OpenGrok 和 10 轮默认上限的定位流程已经可以跑通一个 socket。模型
在遇到重复动作时提前结束，说明 10 轮是上限而不是强制调用次数；当前结果可交给用户
确认后继续 clone/handoff。候选列表中仍会出现测试、生成物和通用 helper 的噪声，完整
证据保存在 session 的 `evidence.json`，不能只依据候选数量判断服务归属。

## 5. 本轮代码回归

- `tests/source_locator`：**240 passed in 23.36s**；
- `ruff check core/source_locator tests/source_locator openant/cli.py`：**All checks passed**。
