# 开发板 Socket 暴露面手工盘点（2026-09-12）

## 盘点结论

- **设备序列号**：`150100424a5444345209d945be14b900`
- **盘点时间**：2026-09-12 00:45（Asia/Shanghai，主机记录时间）
- **文件系统命名 Unix socket**：23 个
- **抽象 Unix socket**：1 个（`@ohjpid-control`）
- **Unix socket 端点总数**：24 个（同一名字的已连接客户端行已按 inode/状态去重）
- **严格显示为 `LISTENING` 的端点**：15 个（14 个文件系统路径 + 1 个抽象 socket）
- **已绑定但 netstat 未显示 `LISTENING` 的命名端点**：9 个。它们包括 DGRAM、SEQPACKET 和已绑定的 STREAM；这类端点仍可能接收本地消息，因此作为资产保留，状态单独记为 `BOUND`。
- **TCP 监听项**：0 个（`/proc/net/tcp`、`/proc/net/tcp6` 只有表头）
- **UDP 绑定/监听项**：0 个（`/proc/net/udp`、`/proc/net/udp6` 只有表头）
- **SP_daemon 的 `127.0.0.1:8283/8284/8285`**：本次快照未运行，未在 TCP/UDP 表中出现，因此不应写入本次设备资产清单。

> 说明：`netstat` 对 Unix DGRAM、部分 SEQPACKET 和只绑定未监听的 STREAM 行可能不输出 `LISTENING`，不能据此把它们当作“不存在”。本清单严格区分 `LISTENING` 与 `BOUND`，后续自动化应保留这两个状态。
>
> HDC 在主机端偶尔打印 `FreeChannelContinue handle->data is nullptr` 警告；设备命令仍返回了完整内容。该传输层警告未被当作设备资产字段或事实证据。

## 资产清单

| # | Socket 名称/路径 | 类型 | 状态 | inode | 关联进程（持有监听/绑定 fd） | 服务角色（按名称/属主推断） | UID | 进程 SELinux 域 | DAC 权限（设备输出） | Socket SELinux 标签 |
|---:|---|---|---|---:|---|---|---:|---|---|---|
| 1 | `/dev/unix/socket/AppSpawn` | STREAM | LISTENING | 10465 | `appspawn` (PID 209) | AppSpawn | 0 | `u:r:appspawn:s0` | `0666` `root:appspawn` | `u:object_r:appspawn_socket:s0` |
| 2 | `/dev/unix/socket/CJAppSpawn` | STREAM | LISTENING | 10418 | `init` (PID 1，fd 由 init 持有) | appspawn/CJAppSpawn | 0 | `u:r:init:s0` | `0660` `root:appspawn` | `u:object_r:appspawn_socket:s0` |
| 3 | `/dev/unix/socket/HybridSpawn` | STREAM | LISTENING | 10433 | `init` (PID 1，fd 由 init 持有) | appspawn/HybridSpawn | 0 | `u:r:init:s0` | `0660` `root:appspawn` | `u:object_r:appspawn_socket:s0` |
| 4 | `/dev/unix/socket/NWebSpawn` | STREAM | LISTENING | 16145 | `nwebspawn` (PID 1815) | NWebSpawn | 3081 | `u:r:nwebspawn:s0` | `0666` `nwebspawn:nwebspawn` | `u:object_r:nwebspawn_socket:s0` |
| 5 | `/dev/unix/socket/NativeSpawn` | STREAM | LISTENING | 10431 | `init` (PID 1，fd 由 init 持有) | appspawn/NativeSpawn | 0 | `u:r:init:s0` | `0660` `root:appspawn` | `u:object_r:appspawn_socket:s0` |
| 6 | `/dev/unix/socket/dnsproxyd` | STREAM | LISTENING | 11719 | `netsysnative` (PID 559) | DNS proxy | 1098 | `u:r:netsysnative:s0` | `0660` `netsysnative:netsys_socket` | `u:object_r:dnsproxy_service:s0` |
| 7 | `/dev/unix/socket/faultloggerd.crash.server` | STREAM | LISTENING | 575 | `faultloggerd` (PID 189) | faultloggerd crash | 1202 | `u:r:faultloggerd:s0` | `0666` `faultloggerd:system` | `u:object_r:faultloggerd_socket_crash:s0` |
| 8 | `/dev/unix/socket/faultloggerd.sdkdump.server` | STREAM | LISTENING | 573 | `faultloggerd` (PID 189) | faultloggerd sdkdump | 1202 | `u:r:faultloggerd:s0` | `0666` `faultloggerd:system` | `u:object_r:faultloggerd_socket_sdkdump:s0` |
| 9 | `/dev/unix/socket/faultloggerd.server` | STREAM | LISTENING | 570 | `faultloggerd` (PID 189) | faultloggerd | 1202 | `u:r:faultloggerd:s0` | `0666` `faultloggerd:system` | `u:object_r:faultloggerd_socket:s0` |
| 10 | `/dev/unix/socket/fd_holder` | DGRAM | BOUND | 2598 | `init` (PID 1) | fd_holder | 0 | `u:r:init:s0` | `0660` `root:root` | `u:object_r:fd_holder_socket:s0` |
| 11 | `/dev/unix/socket/fusioncall` | STREAM | BOUND | 672 | `telephony` (PID 374) | fusioncall | 1001 | `u:r:telephony_sa:s0` | `0660` `radio:radio` | `u:object_r:dev_unix_file:s0` |
| 12 | `/dev/unix/socket/fwmarkd` | STREAM | LISTENING | 11742 | `netsysnative` (PID 559) | fwmarkd | 1098 | `u:r:netsysnative:s0` | `0660` `netsysnative:netsys_socket` | `u:object_r:fwmark_service:s0` |
| 13 | `/dev/unix/socket/hdcd` | SEQPACKET | BOUND | 12575 | `hdcd` (PID 733) | hdcd | 0 | `u:r:su:s0` | `0660` `root:shell` | `u:object_r:hdcd_socket:s0` |
| 14 | `/dev/unix/socket/hilogControl` | SEQPACKET | LISTENING | 586 | `hilogd` (PID 190) | hilog 控制 | 1036 | `u:r:hilogd:s0` | `0660` `logd:log` | `u:object_r:hilog_control_socket:s0` |
| 15 | `/dev/unix/socket/hilogInput` | DGRAM | BOUND | 583 | `hilogd` (PID 190) | hilog 输入 | 1036 | `u:r:hilogd:s0` | `0222` `logd:log` | `u:object_r:hilog_input_socket:s0` |
| 16 | `/dev/unix/socket/hilogOutput` | SEQPACKET | LISTENING | 588 | `hilogd` (PID 190) | hilog 输出 | 1036 | `u:r:hilogd:s0` | `0666` `logd:log` | `u:object_r:hilog_output_socket:s0` |
| 17 | `/dev/unix/socket/hisysevent` | DGRAM | BOUND | 13368 | `hiview` (PID 602) | hisysevent | 1201 | `u:r:hiview:s0` | `0662` `hiview:system` | `u:object_r:hisysevent_socket:s0` |
| 18 | `/dev/unix/socket/hisysevent_fast` | DGRAM | BOUND | 13372 | `hiview` (PID 602) | hisysevent_fast | 1201 | `u:r:hiview:s0` | `0662` `hiview:system` | `u:object_r:hisysevent_socket:s0` |
| 19 | `/dev/unix/socket/init_control_fd` | STREAM | LISTENING | 2601 | `init` (PID 1) | init 控制 | 0 | `u:r:init:s0` | `0660` `root:root` | `u:object_r:dev_unix_file:s0` |
| 20 | `/dev/unix/socket/multivpnfd` | STREAM | BOUND | 11729 | `netsysnative` (PID 559) | multivpnfd | 1098 | `u:r:netsysnative:s0` | `0660` `netsysnative:netsys_socket` | `u:object_r:dev_unix_file:s0` |
| 21 | `/dev/unix/socket/native` | STREAM | BOUND | 10534 | `audio_server` (PID 286) | audio native | 1041 | `u:r:audio_server:s0` | `0660` `audio:system` | `u:object_r:native_socket:s0` |
| 22 | `/dev/unix/socket/paramservice` | STREAM | LISTENING | 10375 | `init` (PID 1) | paramservice | 0 | `u:r:init:s0` | `0666` `root:root` | `u:object_r:paramservice_socket:s0` |
| 23 | `/dev/unix/socket/tunfd` | STREAM | BOUND | 11731 | `netsysnative` (PID 559) | tunfd | 1098 | `u:r:netsysnative:s0` | `0660` `netsysnative:netsys_socket` | `u:object_r:dev_unix_file:s0` |
| 24 | `@ohjpid-control`（抽象命名空间） | STREAM | LISTENING | 12614 | `hdcd` (PID 733) | ohjpid-control | 0 | `u:r:su:s0` | 不适用（无文件系统 inode） | 不适用；需以进程域/策略核对 |

### 进程归属说明

`CJAppSpawn`、`NativeSpawn` 和 `HybridSpawn` 的监听 inode 分别由 PID 1 的 fd 13、15、16 持有；因此表中“关联进程”按实际 fd 持有者写为 `init`，并在服务角色列保留 `appspawn` 语义。`AppSpawn` 的监听 inode 10465 由 `appspawn` PID 209 的 fd 11 持有。其他进程归属均由对应 inode 与 `/proc/<pid>/fd` 的 `socket:[inode]` 交叉确认。

## 原始设备证据（节选）

### 1. 传输层状态

执行：

```text
hdc -t 150100424a5444345209d945be14b900 shell "cat /proc/net/tcp; cat /proc/net/tcp6; cat /proc/net/udp; cat /proc/net/udp6"
```

输出只有四个表头，没有数据行：

```text
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops
sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops
```

因此本次快照没有可登记的 TCP/UDP 端点。空表只代表采样时未观测到端点，不代表设备在其他状态或时刻永远没有网络 socket。

### 2. Unix socket 状态与 inode

执行：

```text
hdc -t 150100424a5444345209d945be14b900 shell "netstat -an"
```

从输出中保留所有带路径或抽象名的非 `CONNECTED` 端点：

```text
unix  2  [ ACC ]  STREAM    LISTENING  2601  /dev/unix/socket/init_control_fd
unix  2  [ ACC ]  STREAM    LISTENING 10375  /dev/unix/socket/paramservice
unix  2  [ ACC ]  STREAM    LISTENING 10418  /dev/unix/socket/CJAppSpawn
unix  2  [ ACC ]  STREAM    LISTENING 10431  /dev/unix/socket/NativeSpawn
unix  2  [ ACC ]  STREAM    LISTENING 10433  /dev/unix/socket/HybridSpawn
unix  2  [ ACC ]  STREAM    LISTENING   570  /dev/unix/socket/faultloggerd.server
unix  2  [ ACC ]  STREAM    LISTENING   573  /dev/unix/socket/faultloggerd.sdkdump.server
unix  2  [ ACC ]  STREAM    LISTENING   575  /dev/unix/socket/faultloggerd.crash.server
unix  2  [ ACC ]  SEQPACKET LISTENING   586  /dev/unix/socket/hilogControl
unix  2  [ ACC ]  SEQPACKET LISTENING   588  /dev/unix/socket/hilogOutput
unix  2  [ ACC ]  STREAM    LISTENING 10465  /dev/unix/socket/AppSpawn
unix  2  [ ACC ]  STREAM    LISTENING 11719  /dev/unix/socket/dnsproxyd
unix  2  [ ACC ]  STREAM    LISTENING 11742  /dev/unix/socket/fwmarkd
unix  2  [ ACC ]  STREAM    LISTENING 16145  /dev/unix/socket/NWebSpawn
unix  2  [ ACC ]  STREAM    LISTENING 12614  @ohjpid-control
unix  2  [ ]      DGRAM                 2598  /dev/unix/socket/fd_holder
unix  2  [ ]      STREAM                672   /dev/unix/socket/fusioncall
unix  2  [ ]      SEQPACKET             12575 /dev/unix/socket/hdcd
unix  160[ ]      DGRAM                 583   /dev/unix/socket/hilogInput
unix  2  [ ]      DGRAM                 13368 /dev/unix/socket/hisysevent
unix  2  [ ]      DGRAM                 13372 /dev/unix/socket/hisysevent_fast
unix  2  [ ]      STREAM                11729 /dev/unix/socket/multivpnfd
unix  2  [ ]      STREAM                10534 /dev/unix/socket/native
unix  2  [ ]      STREAM                11731 /dev/unix/socket/tunfd
```

> 上述节选按 endpoint 去重并只保留命名/抽象路径；`paramservice` 的大量 `CONNECTED` 客户端 inode 不计为新的资产。

### 3. DAC 与 socket SELinux 标签

执行：

```text
hdc -t 150100424a5444345209d945be14b900 shell "ls -lZ /dev/unix/socket"
```

该命令返回的 23 行文件模式、属主/属组和 `u:object_r:*:s0` 标签已经逐项写入上表。抽象 socket 没有文件系统路径，因此没有可由 `ls -lZ` 读取的独立 DAC/对象标签；其进程域由：

```text
hdc -t 150100424a5444345209d945be14b900 shell "cat /proc/733/attr/current"
```

确认是 `u:r:su:s0`。

### 4. 进程与 inode 交叉证据

使用 `/proc/<pid>/fd` 的 `socket:[inode]` 链接核对了表中归属。例如：

```text
1   0     init         /proc/1/fd/4   socket:[2598]
1   0     init         /proc/1/fd/6   socket:[2601]
1   0     init         /proc/1/fd/7   socket:[10375]
1   0     init         /proc/1/fd/13  socket:[10418]
1   0     init         /proc/1/fd/15  socket:[10431]
1   0     init         /proc/1/fd/16  socket:[10433]
189 1202  faultloggerd /proc/189/fd/11 socket:[570]
189 1202  faultloggerd /proc/189/fd/13 socket:[573]
189 1202  faultloggerd /proc/189/fd/15 socket:[575]
190 1036  hilogd       /proc/190/fd/12 socket:[583]
190 1036  hilogd       /proc/190/fd/13 socket:[586]
190 1036  hilogd       /proc/190/fd/15 socket:[588]
209 0     appspawn     /proc/209/fd/11 socket:[10465]
286 1041  audio_server /proc/286/fd/12 socket:[10534]
374 1001  telephony    /proc/374/fd/12 socket:[672]
559 1098  netsysnative  /proc/559/fd/12 socket:[11719]
559 1098  netsysnative  /proc/559/fd/13 socket:[11729]
559 1098  netsysnative  /proc/559/fd/15 socket:[11731]
559 1098  netsysnative  /proc/559/fd/16 socket:[11742]
602 1201  hiview       /proc/602/fd/12 socket:[13368]
602 1201  hiview       /proc/602/fd/13 socket:[13372]
733 0     hdcd         /proc/733/fd/12 socket:[12575]
733 0     hdcd         /proc/733/fd/11 socket:[12614]
1815 3081 nwebspawn    /proc/1815/fd/12 socket:[16145]
```

## 口径与后续自动化的约束

1. 资产主键建议使用 `device_serial + transport + normalized_endpoint + inode`；对于重启后 inode 变化的持久化比较，另保留路径/地址端点主键和 `observed_at`。
2. Unix socket 的 `LISTENING` 和 `BOUND` 必须是两个状态，不能把空状态的 DGRAM/SEQPACKET 行丢弃，也不能把 `CONNECTED` 客户端行重复计数为服务端资产。
3. TCP/UDP 需分别读取 IPv4/IPv6 表；TCP `0A` 对应监听，UDP 绑定通常只显示 `BOUND`/`UNCONN`，不能套用 TCP 状态。
4. 进程关联优先采用 `netstat -anp`/`ss -lntup` 的 PID 证据；设备缺少 PID 列时，再按 inode 交叉扫描 `/proc/<pid>/fd`，并记录不可访问或未匹配原因。
5. DAC/对象标签只适用于文件系统命名 Unix socket。网络端点和抽象 socket 应报告“无独立文件 DAC/对象标签”，同时保存进程 UID、进程域和可用安全策略证据。
6. 本文件是一次手工快照，不应被自动化当作永久事实。资产数据库每次扫描都应写入新的观测版本，保留原始命令、原始输出摘要、设备序列号和工具版本。
