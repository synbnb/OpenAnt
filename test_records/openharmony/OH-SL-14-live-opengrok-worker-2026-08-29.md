# OH-SL-14：真实 OpenGrok source-locator worker 回归

日期：2026-08-29  
目的：验证源码定位器不是只在离线夹具中工作，并检查 22 个 Unix Socket 目标的
仓库归因、服务端证据和失败边界。  
目标来源：`/Users/shiyu/学习/hyl/new/socket.txt`。  
OpenGrok：用户提供的只读实例，项目 `openharmony`。  
版本：`OpenHarmony-6.1-LTS`；Manifest 文件位于项目 `config/openharmony/`。

## 1. 接口探测

已实际探测：

- 根页面、`system/ping`、`system/indextime`、`suggest/config` 和 `search` 返回可用响应；
- `/api/v1/file/content` 在当前部署返回 HTTP 401；
- `/raw/<source-path>` 和 `/xref/<source-path>` 可读取，因此客户端使用只读 raw
  回退，并在 `probe.json` 记录能力差异；
- 所有请求都由 `OpenGrokClient` 施加超时、重试、响应大小和路径校验；没有把远程
  返回的文本当作本机路径或命令执行。

## 2. 实际执行

每个目标都单独创建 session，然后执行：

```bash
python -m openant.cli source-locator create <socket> --root <session-root> \
  --target-revision OpenHarmony-6.1-LTS
python -m openant.cli source-locator run <session-id> --root <session-root> \
  --config-path VulnFounder/config/openant/config.json \
  --project-root VulnFounder --max-steps 32 --max-paths 32
```

`run` 在 `AWAIT_USER_CONFIRMATION`、`PARTIAL` 或 `NEEDS_REVIEW` 停止；本次没有
调用 `confirm`，所以没有触发 Git clone。session 目录和 `evidence.json` 保留在
`/private/tmp/openant-live-source-locator/`，用于复核而不是项目运行时依赖。

## 3. 汇总

| 结果 | 数量 | 说明 |
| --- | ---: | --- |
| 服务端 HIGH | 5 | `faultloggerd.server`、`faultloggerd.sdkdump.server`、`faultloggerd.crash.server`、`dnsproxyd`、`fwmarkd`；均停在用户确认门 |
| PARTIAL/待复核 | 17 | 包含高噪声名称、缺少 listener/consumer、跨仓映射不完整或当前索引没有足够证据 |
| 自动 clone | 0 | 硬门禁行为符合预期 |
| session 崩溃 | 0 | 事件、证据和阶段产物均保持可读取 |

## 4. 人工抽查

### `dnsproxyd`

在真实索引结果中核对到：

- `foundation/communication/netmanager_base/.../dns_config_client.h:32-33`：路径和
  服务名宏；
- `.../dns_resolv_listen.cpp:363`：`GetControlSocket(DNS_SOCKET_NAME)`；
- `.../dns_resolv_listen.cpp:370`：`listen`；
- `.../dns_resolv_listen.cpp:404-426`：按命令分派请求；
- `.../netsys_client.c:88`、`:180`：客户端 `connect` 和发送。

仓库映射为 `communication_netmanager_base`，与 Manifest 前缀一致。

### `fwmarkd`

- `.../fwmark.h:43`：`FWMARK_SERVER_PATH` 完整路径；
- `.../fwmark_network.cpp:179/181`：获取控制 fd 并 `listen`；
- `.../fwmark_client.cpp:62/86`：`connect` 和 `sendmsg`。

仓库映射为 `communication_netmanager_base`，没有依赖 basename 猜测。

### `faultloggerd.*`

三项目标都回到同一真实仓库核对了 socket 常量、公共 listener helper、
`fault_logger_server.cpp:110` 的 `read` 和 `fault_logger_service.cpp:242` 的
请求 `switch`。三项共享服务实现，但仍分别保留目标常量和证据 ID，避免把一个
socket 的结论静默复制给另一个目标。

### `fd_holder` 的误报修复

第一轮结果曾因 `/out/.../*.d` 依赖文件中的 `handler` 字样错误满足
`protocol_dispatch`。修复后重新执行 `loc_fdholderr8`：

- `/base/startup/init/services/init/standard/init.c` 的 `FdHolderSockInit` 和
  `bind` 被保留为创建/绑定证据；
- 生成物、构建依赖和测试路径不再贡献服务端谓词；
- 结果从错误 HIGH 降为 PARTIAL，并提示真实消费实现
  `fd_holder_service.c` 尚未被受限搜索召回。

随后只读检查该文件确认它包含 `HandlerFdHolder`、`ReceiveFds` 和
`ProcessFdHoldEvent`。这证明降级是“证据召回不足”的诚实提示，而不是把源码
不存在误报为安全；后续启用 LLM planner 时应根据头文件/注册符号继续搜索该文件。
启用 `--llm-search` 后，worker 会在初始搜索后执行有界多轮语义循环：每一轮模型只
选择一个白名单搜索或读文件动作，工具结果写回 evidence，再进入下一轮上下文；模型
不能直接把自然语言判断升级成仓库确认。

当初始搜索产生大量命中时，完整证据仍保存在 `evidence.json`；交给模型的上下文会
按目标相关性做有界投影，并在接近提示词上限时逐步缩短片段、减少可见行和对应的
evidence ID。这样不会因为高噪声索引响应而静默超限，也不会丢失可审计原始证据。

## 5. 结论与限制

当前实现已经能稳定完成：目标标准化、真实 OpenGrok 搜索/raw 读取、宏/常量补充
查询、带行号证据图、服务端/客户端归因、Manifest 仓库映射和用户确认门禁。结果
对高置信目标可复核，对泛化名称保持保守。

“PARTIAL”不等于服务不存在：它表示当前预算、索引响应或跨文件证据尚未满足
服务端强制谓词。尤其 `fd_holder`、`paramservice`、AppSpawn、hisysevent 和
`native` 仍需要语义 planner、更多源码仓库或用户补充约束。当前命令默认关闭
LLM，以避免无意产生费用；使用 `--llm-search` 时，默认最多进行 10 轮语义动作，模型只能在已有 evidence ID
上建议下一条白名单搜索/读文件动作，不能决定仓库、revision 或 clone。

## 6. 自动回归

```text
pytest -q tests/source_locator
240 passed in 22.43s

ruff check core/source_locator tests/source_locator openant/cli.py
All checks passed
```

本机没有 Go/gofmt，因此 Go Web 测试需在带 Go 工具链的环境补跑；这不影响上述
Python worker 和真实 OpenGrok session 的结果。
