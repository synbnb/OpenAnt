# OH-22A native socket 入口逐条源码审计

- 日期：2026-08-26
- 审计对象：`debug_outputs/OH-22A-socket-corpus-p0/entry_reachability_audit.json`
- 输入源码：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`
- 审计方式：逐条打开函数对应源码文件，核对检测器报告的行号、调用符号和编译上下文
- 目的：验证 P0 识别出的 40 个 socket 入口是否确实是 OpenHarmony 目标中的外部数据边界

## 1. 审计结论

不能把当前结果表述为“40/40 都是直接 libc socket 接收入口”。准确结论为：

- **38 个**：源码中存在目标平台可执行的直接 `accept/recv/recvfrom/recvmsg` 调用，入口识别有效；
- **1 个**：`doTraceRoute` 的调用点名为 `recv`，但实际调用的是本仓库自定义的五参数 helper；helper 内部再调用 `recvfrom`。它是有效的间接 socket 输入路径，但当前证据把它误标成了直接 `recv`；
- **1 个**：HDC `Hdc::Base::CreateSocketPair` 的 `accept` 位于 `_WIN32` 条件分支，OpenHarmony 分支使用 `socketpair(AF_UNIX)`，且该函数建立的是内部自建连接，不应作为外部 socket 输入入口。

因此，按“入口语义”计算为 **39 个有效 socket 输入路径、1 个应排除条目**；按 P0 当前“直接原语”证据计算为 **38 个准确、1 个间接证据误标、1 个条件分支误报**。

## 2. 逐条核验结果

状态含义：

- `有效-直接`：报告调用行是目标平台中的真实 socket 接收原语；
- `有效-间接`：函数通过本仓库 helper 接收 socket 数据，入口语义成立，但不是报告的 libc 直接调用；
- `排除`：源码虽出现接收原语，但不是 OpenHarmony 目标的外部输入边界。

### communication_netmanager_base

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `interfaces/kits/c/netconnclient/src/net_probe.cpp:OHOS::NetManagerStandard::WaitResponse` | 126 | unknown_socket | 有效-直接 | `rc = recv(fd, ...)`，读取 ICMP probe 响应 |
| `services/netconnmanager/src/net_pac_local_proxy_server.cpp:ProxyServer::AcceptLoop` | 760 | network_socket | 有效-直接 | `accept(serverSocket_, ..., sockaddr_in)` 接受代理客户端 |
| `services/netconnmanager/src/net_pac_local_proxy_server.cpp:ProxyServer::ForwardData` | 663 | unknown_socket | 有效-直接 | `recv(fromSocket, ...)` 转发客户端/上游数据 |
| `services/netconnmanager/src/net_pac_local_proxy_server.cpp:ProxyServer::ReadRequestHeader` | 549 | unknown_socket | 有效-直接 | `recv(clientSocket, ...)` 读取请求头 |
| `services/netconnmanager/src/net_pac_local_proxy_server.cpp:ProxyServer::ReceiveResponseHeader` | 314 | unknown_socket | 有效-直接 | `recv(socket, ...)` 读取上游响应头 |
| `services/netconnmanager/src/net_pac_local_proxy_server.cpp:ProxyServer::TunnelData` | 287, 296 | unknown_socket | 有效-直接 | 分别从 client/server 两端 `recv` |
| `services/netconnmanager/src/net_trace_route_probe.cpp:OHOS::NetManagerStandard::ReSend` | 240 | network_socket | 有效-直接 | `recvfrom(sockfd, ...)` 读取探测响应 |
| `services/netconnmanager/src/net_trace_route_probe.cpp:OHOS::NetManagerStandard::doTraceRoute` | 351 | network_socket | 有效-间接 | 调用本文件自定义的五参数 `recv(info, ipinfo, sockfd, timeSend, family)`；其定义在 288 行，内部 294/302 行调用 `recvfrom` |
| `services/netconnmanager/src/net_trace_route_probe.cpp:OHOS::NetManagerStandard::recv` | 294, 302 | network_socket | 有效-直接 | helper 内部直接调用 `recvfrom` |
| `services/netmanagernative/src/manager/multi_vpn_manager.cpp:MultiVpnManager::StartMultiVpnSocketListen` | 510 | network_socket | 有效-直接 | `accept(serverfd, ..., sockaddr)` 接受 VPN 客户端 |
| `services/netmanagernative/src/manager/vpn_manager.cpp:VpnManager::StartUnixSocketListen` | 327 | network_socket | 有效-直接 | `accept(serverfd, ..., sockaddr_in)`；函数名虽含 Unix，实际接收地址结构是 IPv4 |
| `services/netmanagernative/src/netsys/clatd.cpp:Clatd::ReadV6Packet` | 294 | unknown_socket | 有效-直接 | `recvmsg(readSock6_, ...)` 读取 IPv6/隧道数据 |
| `services/netmanagernative/src/netsys/dnsresolv/dns_proxy_listen.cpp:DnsProxyListen::GetRequestAndTransmit` | 286, 290 | network_socket | 有效-直接 | IPv4/IPv6 两个 `recvfrom` 分支 |
| `services/netmanagernative/src/netsys/fwmark_network.cpp:OHOS::nmd::RunForClientFd` | 151 | unknown_socket | 有效-直接 | `recvmsg(clientSockfd, ...)` 读取 fwmark 客户端请求 |
| `services/netmanagernative/src/netsys/netlink_socket_diag.cpp:NetLinkSocketDiag::GetErrorFromKernel(int32_t fd,int32_t &kernelError)` | 172, 177 | kernel_socket | 有效-直接 | 两次 `recv` 读取 netlink kernel ACK/error |
| `services/netmanagernative/src/netsys/netsys_tcp_client.c:RecvWrapper` | 57 | unknown_socket | 有效-直接 | wrapper 内直接 `recv(fd, ...)` |
| `services/netmanagernative/src/netsys/netsys_udp_transfer.cpp:OHOS::nmd::RecvUdpWrapper` | 57 | unknown_socket | 有效-直接 | wrapper 内直接 `recvfrom(fd, ...)` |
| `services/netmanagernative/src/netsys/wrapper/data_receiver.cpp:DataReceiver::ReceiveMessage` | 86 | kernel_socket | 有效-直接 | `sockaddr_nl` + `recvmsg` 读取 netlink 数据 |

### developtools_hdc

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `credential/main.cpp:CreateSocketListen` | 448 | unknown_socket | 有效-直接 | `accept` 接受由 `CreateAndBindSocket` 建立的 Unix socket 客户端 |
| `src/common/base.cpp:Hdc::Base::CreateSocketPair` | 1919 | local_socket | **排除** | `accept` 位于 `#else` 的 `_WIN32` 分支；OpenHarmony 的 `#ifndef _WIN32` 分支在 1865/1881 行调用 `socketpair(AF_UNIX, ...)`，且是内部自建连接 |
| `src/common/credential_message.cpp:RecvMessageByUnixSocket` | 361 | unknown_socket | 有效-直接 | `recv(sockfd, ...)`；同文件发送端明确使用 `AF_UNIX` |
| `src/register/hdc_jdwp.cpp:HdcJdwpSimulator::ReadFromJdwp` | 214 | unknown_socket | 有效-直接 | epoll 就绪后 `recvmsg(rfd, ...)` 读取 JDWP 对端消息 |

### hiviewdfx_faultloggerd

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `frameworks/limited/faultlog_client.c:RecvMsgFromSocket` | 127 | unknown_socket | 有效-直接 | `recvmsg(sockfd, ...)` 读取 faultlog socket 消息 |
| `interfaces/innerkits/faultloggerd_client/faultloggerd_socket.cpp:FaultLoggerdSocket::ReadFileDescriptorFromSocket` | 254 | unknown_socket | 有效-直接 | `recvmsg(socketFd_, ...)` 读取 ancillary fd |
| `services/fault_logger_server.cpp:SocketServer::SocketServerListener::OnEventPoll` | 165 | local_socket | 有效-直接 | `sockaddr_un` + `accept`，随后校验 `SO_PEERCRED` |
| `tools/crasher_cpp/dfx_crasher.cpp:StartServer` | 398 | local_socket | 有效-直接 | `AF_LOCAL` server socket 上调用 `accept` |

### hiviewdfx_hilog

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `frameworks/libhilog/socket/socket.cpp:Socket::Recv` | 126 | unknown_socket | 有效-直接 | `recv(socketHandler, ...)` |
| `frameworks/libhilog/socket/socket_server.cpp:SocketServer::Accept` | 99 | unknown_socket | 有效-直接 | `accept(socketHandler, ...)`；构造/Init 函数在同文件使用 `AF_UNIX` |
| `frameworks/libhilog/socket/socket_server.cpp:SocketServer::Recv` | 75 | unknown_socket | 有效-直接 | `recv(socketHandler, ...)` |
| `frameworks/libhilog/socket/socket_server.cpp:SocketServer::RecvMsg` | 80 | unknown_socket | 有效-直接 | `recvmsg(socketHandler, ...)` |

### hiviewdfx_hiview

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `plugins/sysevent_source/event_server.cpp:SocketDevice::ReceiveMsg` | 219 | unknown_socket | 有效-直接 | `recvmsg(socketId_, ...)`，随后读取 credential 并校验消息 |

### multimedia_audio_framework

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `services/audio_policy/server/domain/device/src/pnp/audio_socket_thread.cpp:AudioSocketThread::AudioPnpReadUeventMsg` | 152 | kernel_socket | 有效-直接 | `sockaddr_nl` + `recvmsg`，并检查 `SCM_CREDENTIALS` |

### startup_appspawn

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `standard/appspawn_service.c:HandleRecvMessage` | 407 | unknown_socket | 有效-直接 | `recvmsg(socketFd, ...)`；同一连接流程校验 peer uid |

### startup_init

| 函数 | 源码行 | 报告分类 | 状态 | 核验依据 |
|---|---:|---|---|---|
| `interfaces/innerkits/fd_holder/fd_holder_internal.c:ReceiveFds` | 137 | unknown_socket | 有效-直接 | `recvmsg` 接收数据和 ancillary file descriptors |
| `services/loopevent/socket/le_socket.c:AcceptPipeSocket_` | 175 | local_socket | 有效-直接 | `sockaddr_un` + `accept` |
| `services/loopevent/socket/le_socket.c:AcceptTcpSocket_` | 186 | network_socket | 有效-直接 | `sockaddr_in` + `accept` |
| `services/loopevent/task/le_streamtask.c:HandleRecvMsg_` | 68 | unknown_socket | 有效-直接 | stream task 在无自定义回调时对 `GetSocketFd(taskHandle)` 调用 `recv`；该框架的 TASK_PIPE/TASK_TCP 均由 socket 层创建 |
| `services/param/linux/param_request.c:ReadMessage` | 101 | unknown_socket | 有效-直接 | `recv(fd, ...)` 读取参数服务消息 |
| `services/param/watcher/proxy/watcher_manager.cpp:WatcherManager::RunLoop` | 400 | unknown_socket | 有效-直接 | `GetServerFd` 明确通过 `socket(PF_UNIX, SOCK_STREAM, 0)` 连接后 `recv` |
| `ueventd/ueventd_socket.c:ReadUeventMessage` | 83 | kernel_socket | 有效-直接 | `recvmsg` 读取 uevent/netlink 消息 |

## 3. 分类审计

当前分类统计为：`network_socket` 8、`local_socket` 4、`kernel_socket` 4、`unknown_socket` 24。

其中 `unknown_socket` 不表示入口错误，只表示函数体/文件内没有足够的地址族或 fd 创建线索。例如 HDC 的 `CreateSocketListen` 通过另一个 helper 创建 Unix socket，Hilog 的 `Socket::Recv` 通过对象字段持有 Unix socket。后续可以增加跨函数 fd 来源追踪，但不应为了强行分类而取消入口。

需要优先修正的分类问题是 HDC `CreateSocketPair`：它当前被标为 `local_socket`，但该函数在 OpenHarmony 编译分支不执行 `accept`，并不应出现在 socket 输入入口集合中。

## 4. 对 P0 结果的修正解释

P0 运行产物中的 `socket_receive_functions=40` 是“检测器匹配数”，不是人工确认后的真值数。后续报告应同时展示：

- `detected_socket_candidates`：规则匹配数；
- `validated_socket_input_paths`：源码/条件编译审计后有效数；
- `excluded_non_target_or_internal`：条件分支或内部自建连接数；
- `wrapper_or_indirect_socket_paths`：通过 helper 间接接收的路径。

本次人工审计得到：

```text
detected_socket_candidates       = 40
validated_socket_input_paths     = 39
  direct libc receive paths      = 38
  wrapper/indirect receive paths = 1
excluded_non_target_or_internal  = 1
```

## 5. 后续修正建议

下一次代码修改应单独作为小阶段：

1. 让检测器识别目标平台的条件编译分支，至少排除 `_WIN32` 分支中的 socket 调用；
2. 对同一仓库内同名函数进行符号/参数解析，避免把自定义五参数 `recv` 误报告为 libc `recv`；
3. 对 helper 间接路径输出 `socket_wrapper` 证据，而不是伪装成直接原语；
4. 对 `socketpair`、loopback 自建连接和内部 eventfd 等内部通信增加“非外部输入”判定；
5. 修正后重新跑 9 个仓库，并将“规则候选数”和“源码确认数”分开记录。

本审计没有修改检测器代码，也没有重新生成扫描逻辑；它只修正对 P0 结果的解释。
