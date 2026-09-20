# 其余五个 OpenHarmony 仓库的 Socket 外部输入入口与完整调用链

版本：v0.1
日期：2026-09-04
状态：源码研究完成；尚未预埋任何新漏洞
用途：为后续构造 26 个预埋漏洞样本准备真实、可达、可复核的攻击链候选

## 1. 研究范围和结论

本次研究针对以下目录中的源码完成：

~~~text
/Users/shiyu/学习/hyl/new/VulnFounder/evaluation_dataset/
└── vulnerability/vulnerable_source_code_base/
    ├── communication_netmanager_base
    ├── hiviewdfx_faultloggerd
    ├── hiviewdfx_hilog
    ├── startup_appspawn
    └── startup_init
~~~

明确排除：

- developtools_profiler：已经使用官方修复前版本建立历史漏洞数据集；
- hiviewdfx_hiview：已经使用官方修复前版本建立历史漏洞数据集。

本文件只做源码研究，不改变以上五个仓库中的任何源文件，不删除文件，不提交
预埋变更。文档中出现的“候选预埋点”只是下一阶段的建议位置，不表示基线已经
存在漏洞，也不表示应当直接删除某个检查。

本次最重要的结论是：这五个仓库都能找到“外部主体 → Socket → 接收/解帧 →
命令分派 → 具体业务函数”的生产代码链路，但入口的可观察范围不同。

本项目的预埋范围还受到一个更严格的约束：漏洞所对应的 Socket 必须已经存在于
`evaluation_dataset/exposure/exposure_dataset.json`。因此，本文件中“源码中发现但
未出现在暴露面评测集”的 Socket 只能作为研究背景，不能直接用于本轮漏洞预埋。
每个漏洞样本都应额外记录“对应暴露面 Socket”，并与暴露面评测集中的
`socket名称`精确对应，不能只凭仓库或进程名称推断。

| 仓库 | 主要 Socket 家族 | 主要业务结果 | 外部主体的主要限制 | 适合作为预埋样本的方向 |
|---|---|---|---|---|
| communication_netmanager_base | fwmarkd、dnsproxyd、tunfd、multivpnfd（评测集）；DNS UDP/53、PAC 动态 TCP（源码存在但本轮不计入） | 网络标记、DNS 配置/缓存、VPN FD、代理转发 | UDS DAC/SELinux、服务内 UID、网络边界 | Parcel/二进制长度、SCM_RIGHTS、DNS 解析、SSRF、FD/资源 |
| hiviewdfx_faultloggerd | faultloggerd.server、faultloggerd.crash.server、faultloggerd.sdkdump.server | 文件/FD、崩溃事件、统计、信号、管道、coredump | Socket 文件权限较宽，但 SO_PEERCRED、UID、Socket 路由和配额共同限制 | 固定结构解析、身份绑定、FD/信号、路径和资源 |
| hiviewdfx_hilog | hilogInput、hilogOutput、hilogControl | 写日志、查询日志、持久化、流控和清理 | input 由写权限控制；output/control 再做 UID、PID 和命令校验 | 日志长度/类型、命令帧、过滤器、文件名和并发 |
| startup_appspawn | AppSpawn、NWebSpawn、NativeSpawn、HybridSpawn、CJAppSpawn（评测集）；AppSpawndf（源码存在但本轮不计入） | 创建进程、沙箱/挂载 Hook、调试和进程信息 | OnConnection 按 SO_PEERCRED UID 白名单放行 | TLV 长度/计数、FD 传递、Hook 参数、身份和资源 |
| startup_init | paramservice、init_control_fd、fd_holder，以及通用 loop-event Socket | 改系统参数、控制 FD、保存服务 FD | 参数服务由配置和安全策略限制；control_fd 仅 root；fd_holder 校验服务 PID | 消息分帧、参数/触发器、PTY/命令、FD 生命周期 |

下面的“完整调用链”统一包含六类节点：

1. 外部输入主体或上游客户端；
2. 具体 Socket 名称、路径、地址和创建配置；
3. accept/recv/recvmsg/recvfrom 等接收函数；
4. 长度、类型、凭据和协议解析；
5. 命令或消息分派；
6. 最终业务函数、系统调用、文件/FD/进程/状态副作用和响应。

## 2. 如何判断“可达”

### 2.1 不是看到 bind 就算应用可达

本文件把以下信息同时作为可达性证据：

- init 配置中的 Socket 名称、协议、权限、属主、属组和 SELinux 域；
- 服务代码中从控制 FD 或路径取得监听 FD 的位置；
- 监听器实际注册的回调；
- 接收函数如何形成一条消息；
- 消息如何到达业务处理函数；
- 身份或权限检查是否在业务副作用之前执行。

因此，某个 Socket 即使是 0666，也不能直接得出“任意三方应用可调用”的结论；
还要检查服务内的 SO_PEERCRED、UID/PID、命令类型、Socket 路由和开发者模式。
相反，Socket 文件权限较窄也不意味着没有攻击面，满足对应 UID、组或服务身份的
本地主体仍可能提交畸形输入。

### 2.2 调用链中的“业务汇点”

后续预埋漏洞应放在下列类型的汇点上，并保留从 Socket 入口到该函数的完整链路：

- 输入值进入 memcpy、字符串拼接、解析器、数组/容器索引、分配大小或循环边界；
- 输入值决定 setsockopt、ioctl、bind、路由/网络策略、文件创建或文件名；
- 输入值决定 fork、exec、信号、FD 传递、Hook 参数或服务状态转换；
- 输入值被保存到全局、缓存、回调、触发器或异步任务，之后在另一个线程使用。

仅仅位于测试、mock、fuzz、示例或生成产物中的函数不作为生产漏洞主体。
generated、out、build、third_party、kernel 目录本身不自动排除；是否使用它们
要看它是否是当前 Socket 生产链路中的真实实现，而不是测试副本或编译中间物。

## 3. communication_netmanager_base

### 3.1 Socket 配置和端点清单

服务配置位于 services/etc/init/netsysnative.cfg:11-74。服务名为 netsysnative，
运行 UID 为 netsysnative，附加组包括 netsys_socket、net_manager、system、shell、
root 等，SELinux 域为 u:r:netsysnative:s0。配置声明了四个命名 Unix Socket：

| 名称 | 规范路径 | 类型 | 权限/属主 | 代码用途 |
|---|---|---|---|---|
| dnsproxyd | /dev/unix/socket/dnsproxyd | AF_UNIX/SOCK_STREAM | 0660，netsysnative:netsys_socket | DNS resolver 控制请求 |
| fwmarkd | /dev/unix/socket/fwmarkd | AF_UNIX/SOCK_STREAM | 0660，netsysnative:netsys_socket | 给已有网络 FD 设置 SO_MARK |
| tunfd | /dev/unix/socket/tunfd | AF_UNIX/SOCK_STREAM | 0660，netsysnative:netsys_socket | VPN TUN FD 传递 |
| multivpnfd | /dev/unix/socket/multivpnfd | AF_UNIX/SOCK_STREAM | 0660，netsysnative:netsys_socket | 多 VPN FD 传递 |

此外还有两个代码中直接绑定的网络 Socket：

- DNS 代理：IPv4 INADDR_ANY:53 和 IPv6 [::]:53，UDP；
- PAC 本地代理：127.0.0.1 上由 FindAvailablePort(1024, 65535) 选择的动态 TCP
  端口，仅在 NETMANAGER_ENABLE_PAC_PROXY 功能开启并收到启动请求后出现。

这两个端点目前没有记录在 `evaluation_dataset/exposure/exposure_dataset.json` 中，
所以它们不属于本轮可预埋入口。除非先单独扩展暴露面评测集并重新定义金标准，后续
不得把 DNS UDP/53 或 PAC 动态端口样本计入 50 个漏洞目标。

仓库映射：预期为 https://gitee.com/openharmony/communication_netmanager_base；
本地研究版本为 e8a1f0df9。正式数据集仍应以该仓库的 manifest、分支和精确 revision
重新核验。

### 3.2 fwmarkd：携带 Socket FD 的二进制控制链

入口和服务端：

- 客户端路径和名称常量：interfaces/innerkits/netmanagernative/include/fwmark.h:42-43；
- 客户端创建、连接和发送：services/netmanagernative/fwmarkclient/src/fwmark_client.cpp:56-97；
- 服务端监听线程：services/netmanagernative/src/netsys/fwmark_network.cpp:178-195；
- 服务端接收回调：同文件 RunForClientFd:135-176；
- 实际修改网络标记：同文件 SetMark:90-133。

完整链路：

~~~text
具有 netsys_socket/对应 SELinux 访问能力的本地网络组件
  → socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
  → connect("/dev/unix/socket/fwmarkd")
  → FwmarkNetwork::StartListener
  → GetControlSocket("fwmarkd")
  → listen(…, MAX_CONCURRENT_CONNECTION_REQUESTS)
  → FwmarkEpollServer::Run
  → RunForClientFd(clientSockfd)
  → recvmsg，读取固定大小 FwmarkCommand 和 SCM_RIGHTS
  → 检查 cmsg_level、cmsg_type、cmsg_len，取出传入的网络 FD
  → SetMark(socketFd, FwmarkCommand)
  → getsockopt(SO_MARK)
  → 按 cmdId 分派 SELECT_NETWORK 或 PROTECT_FROM_VPN
  → 修改 Fwmark 字段
  → setsockopt(SO_MARK)
  → 关闭被传入的 FD，并向客户端写回结果
~~~

关键数据传播：

- command->cmdId 决定标记分支；
- command->netId 进入 fwmark.netId；
- SCM_RIGHTS 中的 FD 进入 getsockopt/setsockopt；
- 服务端只在收到有效的单个 SCM_RIGHTS 控制项后继续，未知 cmdId 当前进入
  默认分支后仍可能执行一次 setsockopt，后续分析应核实这是有意行为还是缺失拒绝。

可作为后续预埋研究对象的真实汇点：

1. RunForClientFd 中 cmsg 长度、多个控制消息、截断 recvmsg 和 FD 所有权；
2. SetMark 中 cmdId/netId 值域、未知命令分支和 setsockopt 错误路径；
3. 多连接快速建立导致 epoll、线程或 FD 资源增长。

这些位置必须先建立独立控制版本，再决定删除哪一个检查；不能把当前行为直接
标记成预埋漏洞。

### 3.3 dnsproxyd：命名 Unix Socket 的 resolver 控制链

端点证据：

- 名称和路径：services/netmanagernative/include/netsys/dns_config_client.h:29-38；
- 服务监听：services/netmanagernative/src/netsys/dnsresolv/dns_resolv_listen.cpp:394-420；
- 请求分派：同文件 ProcCommand:422-490；
- 长度后续接收器：ProcBindSocket:492-510、ProcGetKeyLengthForCache:513-532。

完整链路：

~~~text
受 netsysnative 访问控制保护的 resolver 客户端
  → netsys_client.c 创建 AF_UNIX/SOCK_STREAM
  → ConnectServer(clientFd, "/dev/unix/socket/dnsproxyd")
  → DnsResolvListenInternal::StartListen
  → GetControlSocket("dnsproxyd")
  → listen + MakeNonBlock
  → EpollServer(serverSockFd_, sizeof(RequestInfo), ProcCommand())
  → 先接收固定大小 RequestInfo
  → ProcCommand 检查 server_ 和 data.size()，memcpy 到 requestInfo
  → 读取 command、netId、uid
  → 按 command 注册第二段变长接收器或立即回复
~~~

主要分支的完整下游如下：

| 命令 | 追加输入 | 下游业务函数 | 主要副作用/返回 |
|---|---|---|---|
| GET_CONFIG | 固定 RequestInfo | ProcGetConfigCommand:181-229 | GetResolverConfig，复制受 MAX_SERVER_NUM 限制的 DNS 服务器并回写 |
| GET_CONFIG_EXT | 固定 RequestInfo | ProcGetConfigCommandExt:231-278 | 扩展 DNS 配置，同样受服务器数量和缓冲区约束 |
| GET_CACHE | nameLen + key | ProcGetCacheCommand:280-315 | 查询缓存，结果数量限制为 MAX_RESULTS 后回写 AddrInfo |
| SET_CACHE | nameLen + key + AddrInfoWithTtl 数组 | ProcSetCacheCommand:317-340 | 排序并写入 DnsParamCache，设置延迟任务 |
| SET/GET_NODATA_CACHE | nameLen + key | ProcSetNodataCacheCommand:342-345 或 ProcGetNodataCacheCommand:347-358 | 修改/查询 no-data 缓存和 IPv6 UID 黑名单 |
| POST_DNS_RESULT | 固定长度结果 | ProcPostDnsThreadResult 回调 | 写入 DNS 线程结果 |
| JUDGE_IPV4/IPv6 | 固定 RequestInfo | ProcJudgeIpv4Command:368-374 或 ProcJudgeIpv6Command:360-366 | 查询网络能力并回写 |
| GET_DEFAULT_NETWORK | 固定 RequestInfo | ProcGetDefaultNetworkCommand:376-384 | 返回默认 netId |
| BIND_SOCKET | 后续 int32 remoteFd | ProcBindSocket:492-510 → ProcBindSocketCommand:386-392 | 调用 FwmarkClient().BindSocket(remoteFd, netId) |

值得重点保留的输入边界：

- nameLen 在 ProcGetKeyLengthForCache:523-529 被限制为 MAX_HOST_NAME_LEN；
- BIND_SOCKET 的 remoteFd 来自 Socket 消息后续片段；
- RequestInfo 中的 uid 会传入 resolver/cache 逻辑，必须把“报文声明的 uid”和
  “Socket peer credential”区分开；
- ProcSetCacheCommand 对 resNum 个元素排序并写入缓存，后续需要确认 resNum 的
  上游边界和 AddrInfoWithTtl 数组来源。

### 3.4 DNS UDP/53：真正的网络数据面链

代码没有通过命名 UDS 接收 DNS 查询，而是在 dns_proxy_listen.cpp 中直接绑定 UDP
53：

- IPv4 建立和 bind：InitListenForIpv4:316-343；
- IPv6 建立和 bind：InitListenForIpv6:345-378；
- epoll 分派：StartListen:224-265；
- UDP 接收：GetRequestAndTransmit:268-302；
- 上游发送：DnsParseBySocket:68-88；
- 上游响应回传：SendDnsBack2Client:177-208。

完整链路：

~~~text
本机 DNS 客户端或可到达设备网络的请求方
  → UDP 127.0.0.1/本机地址:53（IPv4）
    或 UDP [::]:53（IPv6）
  → DnsProxyListen::StartListen
  → epoll_wait
  → GetRequestAndTransmit(AF_INET/AF_INET6)
  → recvfrom，最大读取 MAX_REQUESTDATA_LEN
  → 检查 questionLen > 0
  → CheckDnsQuestion
  → DnsParseBySocket
  → 从 DnsParamCache 取得上游 resolver
  → 向上游 DNS UDP 发送请求
  → epoll 发现上游响应
  → SendDnsBack2Client
  → PollUdpRecvData
  → CheckDnsResponse
  → DnsSendRecvParseData，将响应发回原始客户端
~~~

后续可研究的漏洞类别包括 DNS 报文长度/压缩指针/递归深度、请求响应关联、缓存
污染、放大和并发资源消耗。判断时要以 CheckDnsQuestion、CheckDnsResponse 以及
上游重试逻辑的真实源码为证据，不能仅凭“UDP 53”判定漏洞。

### 3.5 tunfd 和 multivpnfd：以连接建立为输入的 FD 传递链

这两个接口不是“客户端发送一段业务命令后解析”，而是“成功连接本身触发 FD
传递”。相关代码：

- tunfd：services/netmanagernative/src/manager/vpn_manager.cpp:308-349；
- tunfd 的 SendVpnInterfaceFdToClient：同文件约 264-305；
- multivpnfd：services/netmanagernative/src/manager/multi_vpn_manager.cpp:480-526；
- init 权限和 Socket 配置：services/etc/init/netsysnative.cfg:43-61。

tunfd 链：

~~~text
被允许使用 VPN 接口的本地组件
  → connect("/dev/unix/socket/tunfd")
  → StartVpnInterfaceFdListen 创建监听线程
  → StartUnixSocketListen
  → GetControlSocket("tunfd")
  → listen
  → accept
  → SendVpnInterfaceFdToClient
  → sendmsg(SCM_RIGHTS) 传递 tunFd_
  → 关闭服务端连接
~~~

multivpnfd 链：

~~~text
被允许使用多 VPN 接口的本地组件
  → connect("/dev/unix/socket/multivpnfd")
  → StartMultiVpnInterfaceFdListen 创建监听线程
  → StartMultiVpnSocketListen
  → GetControlSocket("multivpnfd")
  → listen
  → accept 一次
  → 加锁并 GetMultiVpnFd
  → SendMultiVpnInterfaceFdToClient
  → sendmsg(SCM_RIGHTS) 传递 FD
  → 重置状态并关闭连接
~~~

这类链的候选研究方向是连接洪泛、FD 关闭/复用、锁和状态复位、重复连接竞态，
而不是伪造一段不存在的请求体。

### 3.6 PAC 本地代理：动态 TCP 端口到出站连接

启动入口：

- NetConnService::StartPacLocalProxyServer：services/netconnmanager/src/net_conn_service.cpp:2949-2980；
- 代理监听：services/netconnmanager/src/net_pac_local_proxy_server.cpp:128-171；
- accept 和任务队列：同文件 AcceptLoop:739-769、WorkerThread:718-737；
- 请求解析：ParseConnectRequest:216-235、ParseHttpRequest:237-255；
- 业务路由：HandleClient:692-707、HandleConnectRequest:634-657、
  HandleHttpRequest:670-690；
- 出站连接：HandleDirectConnection:587-599、HandleProxyConnection:601-610。

完整链路：

~~~text
系统或本地应用请求启动 PAC 代理
  → NetConnService::StartPacLocalProxyServer
  → FindAvailablePort(1024, 65535)
  → ProxyServer(port, 0)
  → ProxyServer::Start
  → socket(AF_INET, SOCK_STREAM)
  → bind(127.0.0.1, 动态 port)
  → listen(BACKLOG)
  → AcceptLoop poll/accept
  → AddTask(ClientTask)
  → WorkerThread 从 taskQueue_ 取任务
  → HandleClient 读取请求头
  → GetRequestMethod / GetRequestUrl
  → CONNECT → ParseConnectRequest → GetProxyList → TryConnectWithProxyList
  → 普通 HTTP → ParseHttpRequest → GetProxyList → TryConnectWithProxyList
  → HandleDirectConnection 或 HandleProxyConnection
  → ConnectToServer / ConnectViaUpstreamProxy
  → TunnelData 或 ForwardData relay
  → 关闭客户端和服务端连接
~~~

这是一个重要的外部网络输入链。未来可以覆盖 SSRF/开放代理、Host/Port 校验、
请求头边界、连接队列耗尽和隧道生命周期，但必须先确认产品是否有意提供直接
出站代理能力，并把“预期功能”和“缺少安全约束”分开。

## 4. hiviewdfx_faultloggerd

### 4.1 端点、配置和通用分派

Socket 名称和路径定义在 interfaces/common/dfx_socket_request.h:27-35：

- /dev/unix/socket/faultloggerd.server；
- /dev/unix/socket/faultloggerd.crash.server；
- /dev/unix/socket/faultloggerd.sdkdump.server。

生产配置 services/config/faultloggerd.cfg:24-76 声明三者都是 AF_UNIX/SOCK_STREAM、
SO_PASSCRED、0666、属主 faultloggerd、属组 system，服务 SELinux 域为
u:r:faultloggerd:s0。Socket 文件权限宽并不等于所有请求都成功，服务代码仍做
Socket 路由和身份检查。

通用服务初始化和监听：

- SocketServer::Init：services/fault_logger_server.cpp:58-87，注册 FileDes、
  ExceptionReport、Stats、Coredump、Pipe、SDK Dump、Lite Dump、MiniDump 和
  BinderPids 等服务，并为三类 Socket 建立监听；
- AddServerListener：同文件:96-105，监听 backlog 为 30；
- SocketServerListener::OnEventPoll：同文件:162-197，accept、SO_PEERCRED、
  每 UID 连接数限制和 ClientRequestListener 创建；
- ClientRequestListener::OnEventPoll：同文件:133-154，读取最多 2048 字节，
  取 RequestDataHead.clientType 并分派；
- FaultLoggerService<T>::OnReceiveMsg：services/fault_logger_service.h:39-52，
  要求 nRead == sizeof(T)，再把字节缓冲区转换为固定结构并调用 OnRequest。

通用完整链：

~~~text
faultloggerd 客户端或被允许的本地诊断组件
  → FaultLoggerdSocket::StartConnect/InitSocket
  → connect("/dev/unix/socket/<named faultloggerd socket>")
  → SocketServer::AddServerListener/StartListen
  → SocketServerListener::OnEventPoll
  → accept + getsockopt(SO_PEERCRED)
  → 每 UID 连接数 <= 5
  → ClientRequestListener::OnEventPoll
  → read(max 2048)
  → RequestDataHead.clientType
  → GetTargetService
  → FaultLoggerService<T>::OnReceiveMsg
  → 固定结构长度检查 + reinterpret_cast
  → 具体服务 Filter
  → 具体服务 OnRequest
  → 创建文件、发送 FD、写 HiSysEvent、发信号、创建管道、fork/exec 或更新状态
  → response/SCM_RIGHTS 返回客户端
~~~

仓库映射：预期为 https://gitee.com/openharmony/hiviewdfx_faultloggerd；
本地研究版本为 bc87a6ec。

### 4.2 faultloggerd.server 的业务分支

server Socket 是生产功能最集中的端点。主要链路如下：

1. 文件描述符请求：

~~~text
客户端
  → faultloggerd.server
  → FileDesService::OnReceiveMsg<FaultLoggerdRequest>
  → FileDesService::Filter:319-331
  → CheckRequestCredential 或 crash 类型的 Socket 路由检查
  → FileDesService::OnRequest:280-317
  → TempFileManager::CreateFileDescriptor(type, pid, tid, time, filePath)
  → RecordFileCreation/RecordFdFileCreation
  → SendMsgToSocket + SendFileDescriptorToSocket
~~~

2. 普通异常报告：

~~~text
客户端
  → faultloggerd.server
  → ExceptionReportService::OnReceiveMsg<CrashDumpException>
  → Filter:125-138，检查 message 非空和 request uid == SO_PEERCRED uid
  → ExceptionReportService::OnRequest:140-160
  → HiSysEventWrite(RELIABILITY, CPP_CRASH_EXCEPTION, ...)
~~~

3. 统计请求：

~~~text
客户端/诊断组件
  → faultloggerd.server 或 crash.server
  → StatsService::Filter:204-218
  → PROCESS_DUMP 只允许 crash.server；DUMP_CATCHER 检查 CheckCallerUID
  → StatsService::OnRequest:247-276
  → stats_ 列表插入/查找、DelayTaskQueue 延迟报告
  → ReportDumpStats → HiSysEvent
~~~

4. coredump 管理：

~~~text
受允许 UID 的 coredump 客户端
  → faultloggerd.server
  → CoredumpManagerService::OnRequest
  → CoredumpRequestValidator::ValidateRequest
  → 检查 pid、SERVER_SOCKET_NAME、UID 列表和 crash 文件状态
  → HandleCreateEvent/HandleCancelEvent
  → 创建或取消 CoredumpRequest，会保存连接 FD 和异步状态
~~~

### 4.3 faultloggerd.crash.server 的高权限诊断分支

crash.server 不是普通日志 Socket，它承载崩溃处理和部分特殊 FD/信号操作：

1. SDK/崩溃管道：

~~~text
崩溃处理组件
  → faultloggerd.crash.server
  → PipeService::OnRequest:444-477
  → Filter:432-442，校验 pipeType；crash.server 分支允许直接通过 Socket 路由
  → FaultLoggerPipePair::Get/DelSdkDumpPipePair
  → SendFileDescriptorToSocket
~~~

2. Binder PIDs dump：

~~~text
crash 诊断请求
  → faultloggerd.crash.server
  → BinderPidsDumpService::OnRequest:834-871
  → Socket 名称检查
  → SendSignalToBinderPid:873-893，最多 MAX_BINDER_PIDS_COUNT
  → 创建 peer_binder_stack 临时文件
  → 通过 SCM_RIGHTS 返回文件 FD
~~~

3. process dump 统计：

~~~text
processdump
  → crash.server
  → StatsService::Filter 允许 PROCESS_DUMP
  → StatsService::OnRequest
  → stats_ 插入、延迟统计和清理
~~~

### 4.4 faultloggerd.sdkdump.server 的 SDK dump 分支

~~~text
被允许的系统诊断组件
  → FaultLoggerdClient::RequestSdkDump
  → connect("/dev/unix/socket/faultloggerd.sdkdump.server")
  → SocketServerListener/ClientRequestListener
  → SdkDumpService::OnReceiveMsg<SdkDumpRequestData>
  → SdkDumpService::Filter:334-351
  → pid > 0、Socket 名称匹配、CheckCallerUID、crash/repeat 检查
  → SdkDumpService::OnRequest:353-430
  → 创建管道、构造 siginfo、SendSignalToProcess
  → 向客户端返回 pipe FD
~~~

### 4.5 Lite dump、minidump 和路径/进程汇点

以下分支虽然可能由 server 或 crash Socket 分派，但都应保留到具体业务函数：

- LitePerfPipeService::Filter/OnRequest：479-513、542 起，检查 pipeType、请求
  UID 与 peer UID，并做设备/UID 级资源限制；
- LiteProcDumperPipeService::Filter/OnRequest：604-683，校验 peer PID/UID、进程
  名称和每日次数，创建 LimitedPipePair；
- LiteProcDumperService::Filter/OnRequest：686-751，校验 peer PID/UID、每日次数
  和 /proc 状态，随后 LaunchProcessDump:715-735，最终 execl processdump；
- MiniDumpService::Filter/OnRequest：753-790，要求 request pid/uid 与 peer 凭据
  一致，再调用 MinidumpManagerService::SetMiniDump；
- CoredumpCallbackService：处理 worker PID 和报告文件路径，必须沿 validator
  检查 Socket 路由、peer PID 与文件状态；
- FileDesService 中 filePath 进入 TempFileManager 和 unlink 清理路径，后续需要
  将文件名/类型/临时目录的传播单独画出。

### 4.6 适合作为后续样本的方向

建议至少覆盖以下不同类别，但本阶段不实施：

1. 固定结构 nRead/MsgHeader 边界和短读处理；
2. 请求 PID/UID 与 SO_PEERCRED 绑定缺失；
3. Socket 名称路由缺失导致 crash/server 能力混用；
4. FD/SCM_RIGHTS 数量、关闭和重复使用；
5. 临时文件名、文件大小和 unlink 路径；
6. 信号目标 PID、fork/exec 错误路径；
7. 每 UID 连接数、每日次数和异步任务资源上限。

## 5. hiviewdfx_hilog

### 5.1 三个命名 Socket 和权限

services/hilogd/etc/hilogd.cfg:16-60 声明 hilogd 服务：

| Socket | 路径 | 类型 | 权限/属主 | 用途 |
|---|---|---|---|---|
| hilogInput | /dev/unix/socket/hilogInput | AF_UNIX/SOCK_DGRAM | 0222，logd:log | 写入日志 |
| hilogOutput | /dev/unix/socket/hilogOutput | AF_UNIX/SOCK_SEQPACKET | 0666，logd:log | 查询/输出日志 |
| hilogControl | /dev/unix/socket/hilogControl | AF_UNIX/SOCK_SEQPACKET | 0660，logd:log | 持久化、流控、清理等控制 |

公共目录常量在 frameworks/libhilog/include/hilog_base.h:22-26。通用
SocketServer::Init 位于 frameworks/libhilog/socket/socket_server.cpp:36-71，
优先使用 init 传入的控制 FD，否则自行创建、设置 SO_PASSCRED 并 bind。

仓库映射：预期为 https://gitee.com/openharmony/hiviewdfx_hilog；
本地研究版本为 3863783。

### 5.2 hilogInput：日志写入数据面

启动和回调注册：

- HilogdEntry：services/hilogd/main.cpp:135-169；
- HilogInputSocketServer::ServingThread：frameworks/libhilog/socket/
  hilog_input_socket_server.cpp:61-85；
- DgramSocketServer::RecvPacket：frameworks/libhilog/socket/dgram_socket_server.cpp:22-68；
- LogCollector::onDataRecv 和 InsertLogToBuffer：services/hilogd/log_collector.cpp
  约 63-145。

完整链路：

~~~text
应用/Native 日志库或具有 hilogInput 写权限的本地主体
  → 向 /dev/unix/socket/hilogInput 发送 SOCK_DGRAM
  → HilogdEntry 创建 HilogInputSocketServer
  → SocketServer::Init 取得 init 提供的 hilogInput FD
  → RunServingThread
  → ServingThread::RecvPacket
  → 先读 uint16_t packetLen
  → packetLen > maxPacketLength 时丢弃数据报
  → recv/recvmsg 读取数据和可选 SO_PASSCRED
  → 以 ret-1 位置补 0
  → onDataReceive lambda
  → LogCollector::onDataRecv
  → 检查 dataLen >= sizeof(HilogMsg)
  → 解释 HilogMsg，要求 dataLen == msg.len
  → 校验 domain、流控和 tagLen
  → InsertLogToBuffer
  → HilogBuffer::Insert
  → 日志查询、统计或持久化线程可继续消费
~~~

输入参数主要有 packetLen、msg.len、domain、tagLen 和日志正文。未来样本可以覆盖
长度不一致、空/截断头、类型/域不合法、日志队列耗尽和重复发送，但要保留
packetLen 到 RecvPacket 再到 msg.len 的数据流证据。

### 5.3 hilogOutput：日志查询链

启动位置：services/hilogd/main.cpp:218-220 创建只允许 OUTPUT_RQST 的
CmdExecutor，并调用 MainLoop(OUTPUT_SOCKET_NAME)。

通用接收链：

~~~text
日志查询客户端
  → /dev/unix/socket/hilogOutput
  → CmdExecutor::MainLoop
  → SeqPacketSocketServer::StartAcceptingConnection/AcceptingLoop
  → accept + SO_PEERCRED
  → 为客户端创建 ServiceController
  → CommunicationLoop:867-968
  → GetMsgHeader:96-108
  → 验证 cmd 是否在 output executor 的 CmdList
  → RequestHandler<OutputRqst>
  → HandleOutputRqst:501-543
  → CheckOutputRqst:430-450
  → LogFilterFromOutputRqst:452-499
  → HilogBuffer::Query
  → WriteQueryResponse 返回日志
~~~

权限和过滤细节：

- domainCount、tagCount、pidCount 分别受 MAX_DOMAINS、MAX_TAGS、MAX_PIDS
  限制；
- 请求 PID 查询还要根据 peer UID 判断；
- 非 root/shell/logd/hiview/profiler 客户端会被限制为自身 PID 和父 PID；
- regex、tag、domain 和 noBlock 等字段会影响查询循环和返回量。

### 5.4 hilogControl：控制、持久化和文件路径链

启动位置：services/hilogd/main.cpp:198-216，control CmdExecutor 的命令列表包括
持久化、缓冲区大小、统计、流控、日志删除和 kmsg 开关。

完整链路：

~~~text
具有 hilogControl 访问权限的控制客户端
  → /dev/unix/socket/hilogControl
  → CmdExecutor::MainLoop
  → SeqPacketSocketServer::AcceptingLoop
  → SO_PEERCRED
  → ServiceController::CommunicationLoop
  → GetMsgHeader + IsValidCmd
  → 对应 RequestHandler<T>
  → HandlePersistStartRqst / HandlePersistStopRqst /
    HandleBufferSize* / HandleStats* / HandleDomainFlowCtrlRqst /
    HandleLogRemoveRqst / HandleLogKmsgEnableRqst
  → 状态、缓冲区、持久化任务或文件系统副作用
~~~

持久化启动链是最适合后续精确研究的一条：

~~~text
PersistStartRqst
  → CheckPersistStartRqst:545-565
  → CheckOutputRqst
  → 检查 jobId、fileSize、fileName、fileNum
  → IsValidFileName:88-94，拒绝路径分隔符等字符
  → PersistStartRqst2Msg:567-586
  → LOG_PERSISTER_DIR + fileName
  → StartPersistStoreJob:588-600
  → LogPersister::Init/Start
~~~

后续候选类别包括请求头短读、命令类型错配、过滤器数组、正则表达式资源消耗、
持久化文件名/大小、任务数量和并发客户端资源。任何预埋都必须保留 peer UID
和命令列表这两个防护事实，避免把“控制接口功能”误当成漏洞。

## 6. startup_appspawn

### 6.1 Socket 名称和配置

Socket 名称定义在 modules/module_engine/include/appspawn_msg.h:29-36：

- AppSpawn；
- NWebSpawn；
- NativeSpawn；
- HybridSpawn；
- CJAppSpawn；
- AppSpawndf。

路径前缀在 util/include/appspawn_utils.h:44-53：MUSL 构建通常为
/dev/unix/socket/，其他变体可能为 /dev/socket/。各服务配置文件给出了实际
权限和 SELinux 域：

| Socket | 配置文件 | 类型 | 典型权限/属主 | 启动条件 |
|---|---|---|---|---|
| AppSpawn | appspawn.cfg:30-58 | AF_LOCAL/SOCK_STREAM | 0660，root:appspawn | boot |
| NWebSpawn | nwebspawn.cfg:17-41 | AF_LOCAL/SOCK_STREAM | 0666，nwebspawn:nwebspawn | condition |
| NativeSpawn | nativespawn.cfg:2-27 | AF_LOCAL/SOCK_STREAM | 0660，root:appspawn | boot/ondemand |
| HybridSpawn | hybridspawn.cfg:17-41 | AF_LOCAL/SOCK_STREAM | 0660，root:appspawn | ondemand |
| CJAppSpawn | cjappspawn.cfg:2-27 | AF_LOCAL/SOCK_STREAM | 0660，root:appspawn | boot/ondemand |
| AppSpawndf | appspawndf.cfg:2-34 | AF_LOCAL/SOCK_STREAM | 0660，root:appspawn | boot |

standard/appspawn_main.c:31-50 将运行模式映射到 Socket 名称；客户端
interfaces/innerkits/client/appspawn_client.c:99-159 的 GetSocketName 和
CreateClientSocket 负责按类型连接对应 Socket。

虽然源码还定义了 `AppSpawndf`，但当前暴露面评测集没有
`/dev/unix/socket/AppSpawndf` 条目。因此本轮只能使用评测集中已有的 AppSpawn、
CJAppSpawn、NativeSpawn、HybridSpawn 和 NWebSpawn 五个入口。

仓库映射：预期为 https://gitee.com/openharmony/startup_appspawn；
本地研究版本为 660f1a39。

### 6.2 统一的 AppSpawn 接收链

服务端创建：

- CreateAppSpawnServer：standard/appspawn_service.c:1749-1771；
- 用 socketName 形成路径，调用 GetControlSocket(socketName)，再交给
  LE_CreateStreamServer；
- OnConnection：同文件:463-500，接受连接并取 SO_PEERCRED；
- OnConnectionUserCheck：同文件:440-461，仅允许 root、app_fwk_update、
  foundation、storage_manager，以及开发者模式下的 shell。

完整链路：

~~~text
被允许的 framework/foundation/系统服务客户端
  → GetSocketName(type)
  → CreateClientSocket
  → socket(AF_UNIX, SOCK_STREAM)
  → connect("/dev/unix/socket/<AppSpawn family>")
  → CreateAppSpawnServer
  → LE_CreateStreamServer
  → OnConnection
  → LE_AcceptStreamClient
  → getsockopt(SO_PEERCRED)
  → OnConnectionUserCheck UID 白名单
  → HandleRecvMessage
  → recvmsg + 可选 SCM_RIGHTS FD
  → OnReceiveRequest
  → GetAppSpawnMsgFromBuffer 处理 TCP/流式短包和拼包
  → DecodeAppSpawnMsg
  → CheckMsgTlv / CheckAppSpawnMsg
  → ProcessRecvMsg
  → 具体消息处理函数
~~~

### 6.3 消息完整性和 TLV 解析链

解析实现位于 standard/appspawn_msgmgr.c：

- CheckRecvMsg:126-136：检查 magic、msgLen、tlvCount 和 TLV 数量关系；
- AppSpawnMsgRebuild:138-156：按消息长度和 TLV 数量分配 buffer/offset；
- CheckAppSpawnMsg:185-214：检查 processName、必需 TLV、bundleName 中的路径字符；
- CheckMsgTlv:229-262：按 TLV 类型检查长度和扩展信息；
- DecodeAppSpawnMsg:264-303：逐个 TLV 检查并记录偏移；
- GetAppSpawnMsgFromBuffer:305-356：从流中拼接头部、正文和剩余消息。

因此，完整的输入传播是：

~~~text
Socket 字节流
  → HandleRecvMessage 的 recvmsg 缓冲区
  → OnReceiveRequest 的 buffLen
  → AppSpawnMsg.msgLen/tlvCount
  → GetAppSpawnMsgFromBuffer 分配和拷贝
  → DecodeAppSpawnMsg 的 tlvLen/tlvType
  → CheckMsgTlv 的长度计算
  → tlvOffset
  → CheckAppSpawnMsg 的 processName/bundle/domain/token/DAC
  → ProcessRecvMsg 的 msgType 分派
~~~

后续分析尤其应关注 tlvCount * sizeof(...)、扩展 TLV 的 dataLen/tlvLen、
流式剩余长度和 FD 数量之间的边界关系，而不是只看一个 memcpy_s。

### 6.4 进程创建主链

最重要的 MSG_APP_SPAWN 和 MSG_SPAWN_NATIVE_PROCESS 分支：

~~~text
外部 AppSpawn 客户端
  → ProcessRecvMsg:2372-2445
  → MSG_APP_SPAWN / MSG_SPAWN_NATIVE_PROCESS
  → ProcessSpawnReqMsg:1500-1555
  → CheckAppSpawnMsg
  → CreateAppSpawningCtx
  → STAGE_PARENT_MSG_DECODE Hook
  → STAGE_PARENT_PRE_FORK Hook
  → RunAppSpawnProcessMsg:1480-1490
  → AppSpawnProcessMsg:common/appspawn_server.c:196-215
  → fork 或 NWeb clone
  → AppSpawnChild:common/appspawn_server.c:83-134
  → 清理环境、cold start、spawning/pre-reply/post-reply Hook
  → 子进程处理器和结果通知
~~~

其他重要分支：

| 消息 | 下游 | 结果 |
|---|---|---|
| MSG_GET_RENDER_TERMINATION_STATUS | ProcessTerminationStatusMsg | 返回状态和 PID |
| MSG_DUMP | ProcessAppSpawnDumpMsg | 生成诊断响应 |
| MSG_BEGET_CMD | ProcessBegetCmdMsg:2063-2080 | 开发者模式下重建并再次进入 ProcessSpawnReqMsg |
| MSG_UPDATE_MOUNT_POINTS | ProcessSpawnRemountMsg:2083-2087 | 当前版本记录为不处理 |
| MSG_RESTART_SPAWNER | ProcessSpawnRestartMsg:2089-2093 | 回复重启结果 |
| MSG_DEVICE_DEBUG | ProcessAppSpawnDeviceDebugMsg | 调试设置 |
| MSG_UNINSTALL_DEBUG_HAP | ProcessUninstallDebugHap | 卸载调试 HAP |
| MSG_LOCK_STATUS | ProcessAppSpawnLockStatusMsg | 同步或异步更新锁状态 |
| MSG_OBSERVE_PROCESS_SIGNAL_STATUS | ProcessObserveProcessSignalMsg | 获取/使用信号 FD |

### 6.5 后续预埋候选

可在不同 Socket 或消息分支平均分配以下类别：

1. TLV 长度/计数整数溢出和流式拼包；
2. SCM_RIGHTS FD 计数、关闭、所有权和跨消息残留；
3. processName/bundleName/domain 字段到 Hook、沙箱和文件路径；
4. SO_PEERCRED UID 白名单或开发者模式条件；
5. fork/clone、异步 watcher 和重复请求资源；
6. debug、mount、unload/load web library 等状态转换。

预埋时必须确保目标函数仍然能由对应 Socket 的生产客户端或等价 IPC 入口到达，
不能把只由测试宏启用的分支当作可达样本。

## 7. startup_init

### 7.1 Socket 角色区分

startup_init 中有一个通用 Socket/loop-event 传输层，和多个具体服务。需要区分：

- paramservice：参数服务的生产命名 Unix Socket；
- init_control_fd：仅 root 使用的控制 FD Socket；
- fd_holder：init 内部保存服务 FD 的 Datagram Socket；
- init_service_socket.c、le_socket.c、le_streamtask.c：通用基础设施，不是一个
  单独的业务端点，但决定上述服务怎样创建、监听和接收。

通用证据：

- services/init/init_service_socket.c:39-123 形成 /dev/unix/socket/<name>、
  bind、lchown、fchmod 和 SO_PASSCRED；
- CreateSocketForService:199-226 为按配置的服务创建 Socket，按需服务可能
  listen 并注册 watcher；
- services/loopevent/socket/le_socket.c:45-80 创建 UDS 服务端，82-109 创建
  客户端，127-168 是 TCP 服务端/客户端，192-228 根据 flags 选择；
- services/loopevent/task/le_streamtask.c 的 HandleRecvMsg_ 负责 recv 循环和
  recvMessage 回调。

仓库映射：预期为 https://gitee.com/openharmony/startup_init；
本地研究版本为 7fb17f19。

### 7.2 paramservice：参数设置、等待和监听链

路径和宏：

- services/param/include/param_utils.h:79-81；
- 客户端路径 CLIENT_PIPE_NAME 为 /dev/unix/socket/paramservice；
- 服务端 PIPE_NAME 在目标构建中拼接启动数据根目录和同名 Socket。

初始化与监听：

- InitParamService：services/param/linux/param_service.c:412-455；
- info.server = PIPE_NAME、info.incomingConnect = OnIncomingConnect；
- ParamServerCreate：services/param/linux/param_msgadp.c:47-57；
- OnIncomingConnect：services/param/linux/param_service.c:377-399；
- ParamStreamCreate：services/param/linux/param_msgadp.c:59-79；
- OnReceiveRequest：同文件:29-45，按 msgSize 从原始流中切分消息；
- ProcessMessage：services/param/linux/param_service.c:349-375。

公共完整链：

~~~text
拥有参数服务访问能力的本地进程
  → param_request.c:GetClientSocket:129-145
  → socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)
  → ConnectServer("/dev/unix/socket/paramservice")
  → ParamServerCreate
  → LE_CreateStreamServer
  → OnIncomingConnect
  → ParamStreamCreate/LE_AcceptStreamClient
  → le_streamtask 接收流
  → param_msgadp::OnReceiveRequest
  → 检查 nread-curr、msgSize 和 ParamMessage 头
  → ProcessMessage
  → 按 msg->type 分派
~~~

主要命令链：

1. 设置参数：

~~~text
SystemSetParameter_/StartRequest
  → MSG_SET_PARAM
  → ProcessMessage
  → HandleParamSet:177-198
  → GetNextContent 取得 value
  → getsockopt(SO_PEERCRED) 构造 ParamSecurityLabel
  → SystemSetParam:139-159
  → CheckParameterSet
  → WriteParam
  → WritePersistParam
  → CheckAndSendTrigger
  → SendResponseMsg
~~~

2. 等待参数：

~~~text
客户端发送 MSG_WAIT_PARAM
  → HandleParamWaitAdd:250-300
  → 读取 valueContent 和可选 timeoutContent
  → SystemCheckMatchParamWait
  → 未匹配时拼接 name=value 条件
  → AddWatcherTrigger
  → 创建并启动 ParamTimer
  → 参数变化后 ExecuteWatchTrigger_/SendWatcherNotifyMessage
~~~

3. 增加/删除监听：

~~~text
MSG_ADD_WATCHER
  → HandleParamWatcherAdd:303-321
  → 校验 watcherTask 所属连接
  → AddWatcherTrigger
  → 记录 watcherId 和连接

MSG_DEL_WATCHER
  → HandleParamWatcherDel:323-329
  → DelWatchTrigger
  → SendResponseMsg
~~~

4. 保存持久化参数：

~~~text
MSG_SAVE_PARAM
  → HandleParamSave:331-347
  → getsockopt(SO_PEERCRED)
  → CheckIfUidInGroup(cr.uid, "servicectrl")
  → CheckAndSavePersistParam
  → SendResponseMsg
~~~

这里的关键输入有 msgSize、msg->type、key、contentSize、content、timeout 和
watcherId。未来可以覆盖消息分帧、长度算术、参数名/值边界、触发器数量、异步
生命周期和服务组授权，但应保留 CheckParameterSet 与 servicectrl 检查作为基线
对照。

### 7.3 init_control_fd：root-only 的控制命令链

路径定义：interfaces/innerkits/control_fd/control_fd.h:32。

服务端：

- CmdServiceInit：interfaces/innerkits/control_fd/control_fd_service.c:143-164；
- CmdOnIncommingConnect：同文件:117-140；
- CmdOnRecvMessage：同文件:55-96；
- CheckSocketPermission：同文件:39-53，仅允许 SO_PEERCRED uid 0；
- InitControlFd：services/init/standard/init_control_fd_service.c:291-294；
- ProcessControlFd：同文件:269-289。

客户端：

- CmdAgentCreate：interfaces/innerkits/control_fd/control_fd_client.c:105-127；
- SendCmdMessage：同文件:129-153；
- InitPtyInterface：同文件:155-200；
- CmdClientInit：同文件:203-220；
- 生产调用点包括 services/begetctl/dump_service.c、modulectl.c 和 sandbox.cpp。

完整链路：

~~~text
root begetctl 或其他 root 诊断进程
  → CmdClientInit("/dev/unix/socket/init_control_fd", type, cmd, callback)
  → CmdAgentCreate
  → LE_CreateStreamClient
  → CmdOnIncommingConnect
  → 发送固定 CmdMessage（type、cmd、ptyName）
  → CmdOnRecvMessage
  → 检查 buffer 长度、type < ACTION_MAX、cmd/ptyName 非空
  → CheckSocketPermission，SO_PEERCRED uid 必须为 0
  → fork
  → 子进程 GetRealPath(ptyName)，只允许 /dev/pts/
  → 打开 PTY 并 dup2 到标准输入输出错误
  → g_controlFdFunc(type, cmd, NULL)
  → ProcessControlFd
  → ACTION_SANDBOX → ProcessSandboxControlFd
  → ACTION_DUMP → ProcessDumpServiceControlFd
  → ACTION_MODULEMGR → ProcessModuleMgrControlFd
~~~

这是一个受 root 限制的命令/PTY 边界。后续若要预埋漏洞，应研究命令长度、PTY
路径规范化、fork/FD 错误路径、ACTION 分派和控制服务状态；不能把普通三方应用
作为默认攻击者。

### 7.4 fd_holder：init 内部的 Datagram FD 保存链

fd_holder 路径定义：interfaces/innerkits/fd_holder/fd_holder_internal.h:29，
为 /dev/unix/socket/fd_holder。它在 services/init/standard/init.c:188-230 中
由 FdHolderSockInit 创建为 AF_UNIX/SOCK_DGRAM|SOCK_NONBLOCK，设置 SO_PASSCRED，
属主 root:root 和用户/组可读写权限；SystemInit:233-247 注册
RegisterFdHoldWatcher。

客户端和服务端链：

~~~text
服务进程调用 ServiceSaveFd/ServiceSaveFdWithPoll
  → fd_holder/fd_holder.c:25-44 BuildClientSocket
  → connect("/dev/unix/socket/fd_holder")
  → BuildSendData:47-71 形成 "service|hold|get/poll" 文本
  → BuildControlMessage 携带 SCM_RIGHTS 和 ucred
  → sendmsg
  → init.c 注册的 ProcessFdHoldEvent
  → HandlerFdHolder:118-164
  → ReceiveFds 取得 FD 和 requestPid
  → SplitStringExt 按 | 切成三个字段
  → GetServiceByName(serviceName)
  → CheckFdHolderPermission:91-105，requestPid 必须等于 service->pid
  → HandlerHoldFds:35-55，检查 fdCount <= MAX_HOLD_FDS
  → UpdaterServiceFds 更新服务环境/FD
  → 出错时关闭已经接收的 FD
~~~

ServiceGetFd 并不是 Socket 服务端，它从环境变量中读取 init 注入的 FD 列表：
interfaces/innerkits/fd_holder/fd_holder.c:147-190。后续预埋可以研究
SCM_RIGHTS 计数、文本字段分隔、requestPid 与服务生命周期竞态以及错误路径 FD
关闭，但应将它标记为 init 内部边界，不要与普通应用可访问的公共 Socket 混淆。

### 7.5 startup_init 的后续研究分组

建议在该仓库中把样本分成三个真实入口族：

| 入口族 | 可覆盖类别 | 适合的下游函数 |
|---|---|---|
| paramservice | 长度/分帧、参数注入、触发器资源、异步生命周期、授权 | OnReceiveRequest、ProcessMessage、HandleParamSet、HandleParamWaitAdd、SystemSetParam |
| init_control_fd | root 身份、命令/PTY、路径、fork/FD 生命周期 | CmdOnRecvMessage、ProcessControlFd、ProcessDumpServiceControlFd |
| fd_holder | SCM_RIGHTS、PID/服务映射、计数和 FD 关闭 | HandlerFdHolder、HandlerHoldFds、ReceiveFds、UpdaterServiceFds |

通用 loop-event 代码只在控制版本证明某个变异能由生产 Socket 到达时使用，不要
单独把 transport helper 当作一个与业务无关的“漏洞函数”。

## 8. 后续预埋前的建议分配

用户的最终目标是 50 个样本，已有历史漏洞样本为 24 个，本次还需要规划 26 个。
在真正修改源码前，建议先按下表做候选配额；数量只是平衡建议，不是本文件的
实施授权：

| 仓库 | 建议候选数 | 入口分布（必须属于暴露面评测集） |
|---|---:|---|
| communication_netmanager_base | 6 | fwmarkd 2、dnsproxyd 2、tunfd 1、multivpnfd 1 |
| hiviewdfx_faultloggerd | 5 | server 2、crash 2、sdkdump 1 |
| hiviewdfx_hilog | 5 | input 2、output 1、control 2 |
| startup_appspawn | 5 | AppSpawn、CJAppSpawn、NativeSpawn、HybridSpawn、NWebSpawn 各 1 |
| startup_init | 5 | paramservice 3、control_fd 1、fd_holder 1 |
| **合计** | **26** | 之后再与安全规则库和可动态验证性复核 |

建议覆盖的 OpenHarmony 通用类别：

- IPC/Socket 输入验证和协议分帧；
- 长度、数量、索引和整数算术；
- 空指针、越界、Use-after-free、泄漏和 FD 所有权；
- 身份、UID/PID、Socket 路由和权限绕过；
- 文件名/路径、资源耗尽和并发状态；
- 网络控制、DNS 控制请求和代理相关类别（仅限已有暴露面 Socket 对应的代码链）；
- 信号、fork/exec、Hook 和进程生命周期；
- 日志/诊断数据的信息泄露和跨主体隔离。

同一漏洞类别可以在不同入口重复出现，但每一个样本必须有独立的输入、独立的
下游汇点和独立的真值说明，避免仅通过改名制造“不同漏洞”。

## 9. 预埋实施前的验收清单

每个候选点在下一阶段进入源码修改前，都应完成以下核验：

1. 入口是生产 Socket，而不是 test、fuzz、mock 或仅在测试宏下编译的代码；
2. 能从 Socket 名称/地址追踪到 accept、recv、recvmsg 或 recvfrom；
3. 明确外部输入字段以及它如何逐层传播到目标函数；
4. 记录当前版本的权限、SELinux、SO_PEERCRED、UID/PID 和命令路由；
5. 确认控制基线没有已经存在同类缺陷；若已有，标记为 pre-existing，不重复计入；
6. 只删除或改变一个安全条件，保留其它逻辑不变；
7. 预埋后仍能编译，静态解析器能建立目标函数和调用边；
8. processing_level=reachable 时，目标函数能由入口提示或语义种子进入；
9. 为每个样本设计最小的 Stage 1/Stage 2 输入和可选动态验证输入；
10. 记录修复前函数、修复后函数、攻击链、预期类别和判定证据；
11. 运行干净基线、预埋版本和修复版本三次对照扫描；
12. 不把模型的推测、Socket 名称或客户端自校验当作服务端证据。

## 10. 当前阶段交付边界

本文件交付的是五个仓库的 Socket 入口、生产监听器、消息解析和业务下游的
研究结果。它已经足够支持下一步挑选 26 个可达预埋位置，但还没有：

- 修改任何源码；
- 生成任何新的漏洞变体；
- 运行新的扫描；
- 承诺某个候选点一定能触发漏洞；
- 将候选链直接写入漏洞金标准。

下一步应先从本文件的候选链中选定具体函数，逐项确认基线防护和真实调用图，
再另行编写“预埋变异清单”和“修复对照清单”，经确认后才修改源码。
