# OH-22A P0：OpenHarmony native socket 入口种子测试记录

- 日期：2026-08-26
- 项目：VulnFounder
- 平台：OpenHarmony
- 阶段：P0 native socket 边界入口识别
- 状态：完成
- 新增实现：`libs/vulnfounder-core/utilities/agentic_enhancer/openharmony_entry_point_detector.py`
- 新增测试：`libs/vulnfounder-core/tests/platforms/test_openharmony_entry_points.py`
- 新产物：`debug_outputs/OH-22A-socket-corpus-p0/`

## 1. 原逻辑与本阶段修改

### 原逻辑

OpenHarmony 平台入口检测器识别 Binder `OnRemoteRequest`、System Ability 生命周期、Ability 生命周期和 HDF 入口。通用入口规则覆盖 Web、CLI、文件等输入，但没有 C/C++ socket 接收原语。

因此，在上一轮基线中，9 个仓库共发现 40 个直接调用 `accept/accept4/recv/recvfrom/recvmsg/recvmmsg` 的函数，但 0 个被标记为入口，只有 3 个通过其他入口的调用边碰巧可达。

### 本阶段逻辑

只在 OpenHarmony 平台检测器中加入强证据 native socket 入口：

1. 屏蔽 C/C++ 注释、字符串和字符字面量，避免日志或注释中的单词造成入口误报；
2. 匹配真实的 `accept`、`accept4`、`recv`、`recvfrom`、`recvmsg`、`recvmmsg` 调用；
3. 根据函数名、文件路径和函数代码中的地址族/凭据线索分类：
   - `network_socket`：`AF_INET`、`sockaddr_in` 等，信任级别 `untrusted`；
   - `local_socket`：`AF_UNIX`、`sockaddr_un`、`SO_PEERCRED` 等，信任级别 `semi_trusted`；
   - `kernel_socket`：`AF_NETLINK`、`sockaddr_nl`、uevent 等，信任级别 `semi_trusted`；
   - `unknown_socket`：地址族被宏或封装隐藏时，保守按 `untrusted` 处理；
4. 将原语、调用行号、socket 类型和信任级别写入已有 `platform_evidence`；
5. 不修改原生调用图边，不把普通 `read()` 直接视为 socket 输入。

该阶段的目标是补充 reachable 的入口种子，不宣称已经证明某个函数一定存在漏洞。

## 2. 单元测试

执行命令：

```bash
.venv/bin/python -m pytest \
  libs/vulnfounder-core/tests/platforms/test_openharmony_entry_points.py -q
```

结果：**20 passed in 0.08s**。

新增覆盖：

- IPv4/IPv6 风格网络 socket 的 `accept + recv`；
- Unix socket `accept` 及 `SO_PEERCRED` 的半可信分类；
- netlink/uevent 风格 kernel socket 的 `recvmsg`；
- 注释和字符串中的 `recv(`/`accept(` 不会被识别；
- 原有 Binder、SA、Ability、HDF 和 token-read 回归用例保持通过。

相关回归命令：

```bash
.venv/bin/python -m pytest \
  libs/vulnfounder-core/tests/openharmony \
  libs/vulnfounder-core/tests/test_entry_point_detector.py \
  libs/vulnfounder-core/tests/test_entry_point_detector_native_seeds.py -q
```

结果：**95 passed, 2 skipped in 0.60s**。

## 3. 真实仓库复测

对以下 9 个仓库使用相同命令复跑，输出写入新的 P0 目录：

```bash
./.venv/bin/python libs/vulnfounder-core/parsers/c/test_pipeline.py \
  <repository> \
  --output debug_outputs/OH-22A-socket-corpus-p0/<repository-name> \
  --platform openharmony \
  --processing-level all \
  --skip-tests
```

结果：**9/9 成功**，没有 LLM 调用。

| 仓库 | 入口数 | 原生可达数 | socket 接收函数 | socket 入口 | socket 可达 | 耗时 |
|---|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 79 | 300 | 18 | 18 | 18 | 40.20 s |
| developtools_hdc | 19 | 164 | 4 | 4 | 4 | 4.89 s |
| hiviewdfx_faultloggerd | 21 | 79 | 4 | 4 | 4 | 9.26 s |
| hiviewdfx_hilog | 22 | 79 | 4 | 4 | 4 | 0.96 s |
| hiviewdfx_hiview | 68 | 202 | 1 | 1 | 1 | 85.46 s |
| multimedia_audio_framework | 30 | 287 | 1 | 1 | 1 | 345.57 s |
| startup_appspawn | 18 | 81 | 1 | 1 | 1 | 7.62 s |
| startup_init | 48 | 628 | 7 | 7 | 7 | 15.78 s |
| telephony_core_service | 50 | 113 | 0 | 0 | 0 | 39.33 s |
| **合计** | **355** | **1,933** | **40** | **40** | **40** | — |

相对于基线：

- socket 入口：`0/40 → 40/40`；
- socket 原生可达：`3/40 → 40/40`；
- socket 未覆盖：`37 → 0`；
- 总入口数：`315 → 355`；
- 原生调用边数量仍为 `67,386`；
- 函数/Unit 总数仍为 `54,406`。

## 4. 图不变性回归

对每个仓库的基线和 P0 `call_graph.json`，将 `call_graph` 与 `reverse_call_graph` 的邻接数组排序后进行集合级比较，同时比较函数表和统计值。

结果：9 个仓库均报告 `graph/functions unchanged`。因此本阶段没有因为入口识别而伪造或删除调用边，reachable 增长完全来自新增 socket 入口种子。

## 5. 真实源码对应关系

以下源码均来自验收数据集：

- `communication_netmanager_base/services/netconnmanager/src/net_pac_local_proxy_server.cpp` 的 `ProxyServer::AcceptLoop` 调用 `accept` 并处理 `sockaddr_in`，被分类为网络 socket；
- `communication_netmanager_base/services/netmanagernative/src/netsys/dnsresolv/dns_proxy_listen.cpp` 的 `DnsProxyListen::GetRequestAndTransmit` 调用 `recvfrom`；
- `startup_init/services/loopevent/socket/le_socket.c` 的 `AcceptPipeSocket_` 使用 `sockaddr_un`，`AcceptTcpSocket_` 使用 `sockaddr_in`；
- `multimedia_audio_framework/services/audio_policy/server/domain/device/src/pnp/audio_socket_thread.cpp` 的 `AudioPnpReadUeventMsg` 使用 `sockaddr_nl` 和 `recvmsg`；
- `startup_appspawn/standard/appspawn_service.c` 的 `HandleRecvMessage` 调用 `recvmsg`，并在同一服务代码中校验 `SO_PEERCRED`。

这些结果说明新增种子不是仅对人工 fixture 生效，而是覆盖了网络、本地、kernel 三种真实 OpenHarmony socket 形态。

## 6. 限制与后续工作

- 本阶段仍是确定性入口种子，不负责恢复 socket 函数之间缺失的线程/回调/事件循环调用边；这属于后续 P2。
- `unknown_socket` 的 `untrusted` 是保守分析策略，不代表已经知道对端来自互联网。
- `accept/recv` 也可能出现在客户端读取服务端响应的路径；它仍是外部数据边界，但攻击者能力需要后续威胁模型判断。
- 没有把普通 `read()` 识别为 socket。后续若要覆盖 `read(fd, ...)`，需要 fd 来源追踪或人工/LLM 辅助，否则会把文件、管道和设备节点大量误报为 socket。
- 本阶段未执行 Detect/Analyze/Verify LLM 漏洞分析，不能据此评估漏洞检出率。

## 7. 判定

P0 达到目标：在不改变原生调用图的前提下，当前 9 个 socket 验收仓库中的 40 个直接 socket 接收函数全部进入 reachable。该阶段已解决最主要的“socket 边界没有入口种子”问题；下一阶段应在用户确认后处理确定性分发表和回调注册边。
