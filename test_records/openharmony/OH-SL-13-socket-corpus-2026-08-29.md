# OH-SL-13：socket.txt 真实源码 corpus 回归记录

日期：2026-08-29  
执行目录：`OpenAnt`  
目标清单：`/Users/shiyu/学习/hyl/new/socket.txt`（实际读取 22 项）  
源码根目录：`OpenAnt/source_code_base`

## 1. 实际执行方法

本次使用新增的 `LocalCorpusClient.scan_targets()` 对整个本地源码目录做一次
有界单遍扫描，而不是把任意字符串命中直接当作服务归属：

1. 检查完整 socket 路径的精确字面量；
2. 检查 basename 的大小写敏感命中；
3. 检查 basename 的大小写折叠命中，发现 `CJAppSpawn -> cjappspawn` 这类别名；
4. 保存最多 8 个带仓库映射路径、行号和原文的样本；
5. 跳过 `.git`、`build`、`out`、`node_modules` 等目录、符号链接和超过 2 MiB
   的单文件，避免把构建产物或二进制当源码证据。

本次实际遍历 67,825 个文件，读取 53,478 个文本文件，约 497,231,351 字节。
`source_code_base` 是项目当前已有的部分仓库，不是完整 OpenHarmony 源码树；
所以“未命中”只能说明当前本地 corpus 没有证据，不能证明官方全量源码不存在。

## 2. 22 个目标的实测结果

| 目标 | 完整路径 | basename | 大小写别名 | 当前结论 |
| --- | ---: | ---: | ---: | --- |
| `/dev/unix/socket/fd_holder` | 0 | 0 | 0 | 当前部分仓库未命中，需 OpenGrok/补仓复核 |
| `/dev/unix/socket/init_control_fd` | 0 | 0 | 0 | 当前部分仓库未命中，需 OpenGrok/补仓复核 |
| `/dev/unix/socket/paramservice` | 0 | 0 | 0 | `startup_init` 不在当前 corpus，不能猜仓 |
| `/dev/unix/socket/CJAppSpawn` | 0 | 0 | 11 | 找到 `cjappspawn` 客户端别名，服务端仓库未证实 |
| `/dev/unix/socket/NativeSpawn` | 0 | 79 | 95 | 命中 AppManager 客户端/管理器，混有标识符噪声 |
| `/dev/unix/socket/HybridSpawn` | 0 | 71 | 82 | 命中 AppManager 客户端/管理器，混有标识符噪声 |
| `/dev/unix/socket/AppSpawn` | 0 | 1,739 | 2,462 | 过于泛化，不能用 basename 直接归属 |
| `/dev/unix/socket/faultloggerd.server` | 0 | 0 | 0 | 当前未拉取 faultloggerd 服务仓库 |
| `/dev/unix/socket/faultloggerd.sdkdump.server` | 0 | 0 | 0 | 当前未拉取 faultloggerd 服务仓库 |
| `/dev/unix/socket/faultloggerd.crash.server` | 0 | 0 | 0 | 当前未拉取 faultloggerd 服务仓库 |
| `/dev/unix/socket/hilogControl` | 0 | 0 | 0 | 当前部分仓库未命中，需 OpenGrok/补仓复核 |
| `/dev/unix/socket/hilogOutput` | 0 | 0 | 0 | 当前部分仓库未命中，需 OpenGrok/补仓复核 |
| `/dev/unix/socket/hisysevent` | 0 | 2,919 | 0 | 主要是 DFX 事件定义/文档，不足以证明 socket |
| `/dev/unix/socket/hisysevent_fast` | 0 | 0 | 0 | 当前部分仓库未命中，需 OpenGrok/补仓复核 |
| `/dev/unix/socket/native` | 0 | 56,512 | 0 | 通用词，噪声极高，必须要求路径/宏/通信证据 |
| `/dev/unix/socket/fusioncall` | 0 | 0 | 0 | 当前部分仓库未命中，需 OpenGrok/补仓复核 |
| `/dev/unix/socket/dnsproxyd` | 1 | 5 | 0 | 已找到同仓客户端、服务端和 init 配置线索 |
| `/dev/unix/socket/multivpnfd` | 0 | 3 | 0 | 已找到同仓服务端控制 socket 线索 |
| `/dev/unix/socket/tunfd` | 0 | 19 | 0 | 已找到同仓服务端控制 socket 线索 |
| `/dev/unix/socket/fwmarkd` | 1 | 3 | 0 | 已找到同仓完整路径、服务端和 init 配置线索 |
| `/dev/unix/socket/hdcd` | 0 | 5 | 0 | 仅有属性/进程名线索，不足以证明 socket |
| `/dev/unix/socket/NWebSpawn` | 1 | 119 | 174 | 已找到 AppManager 客户端；服务端需补 startup_appspawn |

## 3. 已找到服务的源码人工核验

### `dnsproxyd`

- `communication_netmanager_base/services/netmanagernative/include/netsys/dns_config_client.h:32`
  定义 `DNS_SOCKET_PATH` 为完整路径，`:33` 定义 `DNS_SOCKET_NAME`。
- `services/netmanagernative/src/netsys/netsys_client.c:125-148` 创建 Unix socket，
  把 `DNS_SOCKET_PATH` 写入 `sun_path` 并执行连接。
- `services/netmanagernative/src/netsys/dnsresolv/dns_resolv_listen.cpp:394-419`
  通过 `GetControlSocket(DNS_SOCKET_NAME)` 获取服务 fd，调用 `listen`，创建
  `EpollServer` 并运行；这是服务端证据，但需要语义追踪
  `DNS_SOCKET_NAME -> dnsproxyd`。
- `services/etc/init/netsysnative.cfg:23` 登记 `dnsproxyd`，说明 init 配置与
  服务代码属于同一仓库。

结论：本地 corpus 已证明仓库和服务端/客户端边界，但当前首轮字面量查询还不能
自动把 `DNS_SOCKET_NAME` 传播到监听实现；这是后续受限语义检索需要覆盖的场景。

### `fwmarkd`

- `interfaces/innerkits/netmanagernative/include/fwmark.h:43` 直接定义完整
  `FWMARK_SERVER_PATH`。
- `services/netmanagernative/src/netsys/fwmark_network.cpp:178-195` 执行
  `GetControlSocket("fwmarkd")`、`listen` 和 `FwmarkEpollServer.Run()`。
- `services/etc/init/netsysnative.cfg:33-41` 登记 Unix `SOCK_STREAM` 服务。

结论：服务端证据完整；客户端上层协议仍应由 OpenGrok 继续定位，不能把监听函数
误当作所有业务 caller。

### `tunfd` 与 `multivpnfd`

- `services/etc/init/netsysnative.cfg:43-51` 和 `:53-61` 分别登记两个 Unix
  `SOCK_STREAM` 控制 socket。
- `vpn_manager.cpp:308-335` 对 `tunfd` 获取控制 fd、`listen`、`accept`，并通过
  `SendVpnInterfaceFdToClient` 传递 fd。
- `multi_vpn_manager.cpp:492-525` 对 `multivpnfd` 获取控制 fd、`listen`、`accept`，
  并发送对应 VPN fd。

结论：这是“init 预创建 + 服务获取 fd”的典型情况，源码不一定出现完整
`/dev/unix/socket/...` 字符串；路径、配置名和 `GetControlSocket` 关系必须进入
证据图。

### AppSpawn 系列与 `NWebSpawn`

- `ability_ability_runtime/services/appmgr/src/remote_client_manager.cpp:25-30`
  创建 `cjappspawn`、`nativespawn`、`hybridspawn` 客户端对象。
- `app_spawn_client.cpp:63-80` 依据受限服务名选择对应常量；服务端常量定义在
  当前 AppManager 仓库之外的 appspawn 依赖中。
- `app_spawn_socket.cpp:25-29` 使用 `"AppSpawn"` 或完整
  `/dev/unix/socket/NWebSpawn`；`:35-48` 连接，`:62-98` 写入/读取消息。

结论：当前 corpus 能确认 AppManager 是通信客户端，不足以确认 appspawn 服务端
实现所在仓库。大量 basename 命中来自类名、文档和测试，必须继续使用协议、配置
和 Manifest 证据过滤。

## 4. 结果边界

本次结果确认：

1. 22 个目标全部被实际遍历，没有因清单解析错误漏掉目标；
2. `dnsproxyd`、`fwmarkd`、`tunfd`、`multivpnfd` 和 `NWebSpawn` 的关键样本
   已逐一回到真实源码行核验；
3. 未命中和高噪声目标均被保守标记，没有自动猜测仓库或把文档命中当服务端。

当前目录缺少完整 OpenHarmony manifest 及若干服务仓库。因此 `paramservice`、
faultloggerd、hilog、fusioncall 等在“本地 corpus 单遍扫描”阶段只能安全停在待
复核状态。这不是扫描器漏报的证据，而是输入 corpus 不完整的诊断；后续远程
OpenGrok worker 的补充回归见第 6 节。

## 5. 测试记录

```text
pytest tests/source_locator -q
该命令在早期基线运行时为 231 passed；加入生成物过滤和带点服务名回归后，
最新专项结果见第 7 节（240 passed）。

ruff check core/source_locator tests/source_locator openant/cli.py
All checks passed
```

当前环境没有 Go 编译器/gofmt，Go Web API 已完成源码静态检查和测试桩设计，未
声称 `go test` 已通过。部署前需在带 Go 1.25+ 的环境补跑：

```bash
cd apps/openant-cli
go test ./internal/python ./internal/server
```

## 6. 2026-08-29 远程 OpenGrok worker 补充回归

上一节记录的是本地 `source_code_base` 单遍扫描基线；本节记录随后使用真实
OpenGrok 实例（`https://u375886-9ad1-ba9448df.westc.seetacloud.com:8443/source`）
按 `socket.txt` 逐项执行的结果。远端实例的主页、健康检查和搜索接口可用，源码
REST `api/v1/file/content` 返回 401，客户端按设计回退到只读 `raw` 路由。所有
session 均使用 `OpenHarmony-6.1-LTS` Manifest，未写入凭据，也未在本轮自动 clone。

生成物目录：

```text
/private/tmp/openant-live-source-locator/all-targets-20260829-r7-a/
/private/tmp/openant-live-source-locator/all-targets-20260829-r7-b/
/private/tmp/openant-live-source-locator/fd-holder-r8/loc_fdholderr8/
```

| 目标 | 服务端结果 | 当前仓库/证据摘要 |
| --- | --- | --- |
| `fd_holder` | PARTIAL | `startup_init`；真实 `init.c` 有 `FdHolderSockInit`/`bind`，但 `fd_holder_service.c` 的 `ReceiveFds` 消费实现尚未由当前受限检索召回 |
| `init_control_fd` | PARTIAL | `startup_init` 线索不足，未确认消费路径 |
| `paramservice` | PARTIAL | 有 `startup_init`/参数服务线索，但跨仓噪声较大，未确认服务端消费者 |
| `CJAppSpawn` | PARTIAL | `startup_appspawn`、`ability_ability_runtime` 客户端别名，未确认服务端 |
| `NativeSpawn` | PARTIAL | `startup_appspawn`、`ability_ability_runtime` 客户端/管理器线索 |
| `HybridSpawn` | PARTIAL | `startup_appspawn`、`bundlemanager_bundle_framework` 等混合线索 |
| `AppSpawn` | PARTIAL | 名称过泛，候选多且包含测试/构建文件，拒绝直接归属 |
| `faultloggerd.server` | HIGH（等待用户确认） | `hiviewdfx_faultloggerd`；`fault_logger_server.cpp:110` read、`fault_logger_service.cpp:242` switch、`faultloggerd_socket.cpp:86/96` 获取 fd/listen |
| `faultloggerd.sdkdump.server` | HIGH（等待用户确认） | 同一 faultloggerd 服务仓；SDK dump 常量、公共 listener 和请求分派证据 |
| `faultloggerd.crash.server` | HIGH（等待用户确认） | 同一 faultloggerd 服务仓；crash 常量、公共 listener 和请求分派证据 |
| `hilogControl` | PARTIAL | `hiviewdfx_hilog` 有常量/客户端线索，未形成 listener + consumer 完整链 |
| `hilogOutput` | PARTIAL | `hiviewdfx_hilog` 有常量线索，服务端消费证据不足 |
| `hisysevent` | PARTIAL | 命中大量事件定义和文档，不能把 basename 命中当 socket 服务 |
| `hisysevent_fast` | PARTIAL | `hiviewdfx_hisysevent`/`hiviewdfx_hiview` 有事件 server 线索，但缺少明确 bind/listen |
| `native` | PARTIAL | 通用词噪声极高，命中内核/媒体等无关仓库，未确认 socket 服务 |
| `fusioncall` | PARTIAL | 当前索引未返回可验证候选，保持待复核 |
| `dnsproxyd` | HIGH（等待用户确认） | `communication_netmanager_base`；`DNS_SOCKET_PATH/NAME`、`GetControlSocket`、`listen`、switch 分派、客户端 connect/send |
| `multivpnfd` | PARTIAL | `communication_netmanager_base/ext` 有控制 socket 线索，但本轮服务端证据未满足全部谓词 |
| `tunfd` | PARTIAL | `communication_netmanager_base/ext` 有 VPN 控制 socket 线索，混有多个 helper/client |
| `fwmarkd` | HIGH（等待用户确认） | `communication_netmanager_base`；`fwmark_network.cpp:179/181` 获取 fd/listen，`fwmark_client.cpp:62/86` connect/sendmsg |
| `hdcd` | PARTIAL | `developtools_hdc` 等进程/属性命中，未证明目标 Unix socket 服务端 |
| `NWebSpawn` | PARTIAL | `ability_ability_runtime` 客户端和 `startup_appspawn` 线索，服务端需补仓复核 |

结果汇总：22 个目标均创建了独立 session；5 个服务端达到 HIGH 并停在人工确认
门，17 个保持 PARTIAL/待复核；没有未经确认的 Git 拉取，也没有把错误页面、构建
依赖或通用 basename 命中直接升级为服务端确认。

本轮发现并修复的可靠性问题：

1. `faultloggerd.server` 等带点号的合法服务名现在可标准化；
2. `AppSpawn`/`native` 等高噪声目标的事件和 attribution 摘要有界，完整证据仍在
   `evidence.json`；
3. 生成物、依赖清单、测试和第三方路径继续显示在路径分类中，但不能贡献服务端
   `bind/read/dispatch` 强制谓词；`check_deps_handler` 等文件名不再被识别为
   协议分派；
4. `fd_holder` 修复后从错误 HIGH 降为 PARTIAL。回到真实源码可见其服务端确实在
   `init.c` 创建并绑定 datagram socket，消费逻辑在 `fd_holder_service.c`；这说明
   当前受限检索存在跨文件召回缺口，下一步应由启用的 LLM 语义 planner 根据头文件
   和注册符号继续调用 OpenGrok，而不是放宽谓词制造 HIGH。

## 7. 修复后的自动测试

```text
pytest -q tests/source_locator
240 passed in 22.43s

ruff check core/source_locator tests/source_locator openant/cli.py
All checks passed
```

对整个 Python 套件的长时间回归在本机完成了 9072 个通过、39 个跳过和 31 个失败
后被中断；失败首要原因为本机没有 `go`，另有既有 Python fixture/文件规则和动态
工具链目录扫描问题。它不改变上面 237 个 source-locator 专项测试的通过结果。
