# OH-DYN-10：真实设备 faultloggerd SDK 栈转储只读闭环

- 执行日期：2026-08-24（Asia/Shanghai）
- 设备：OpenHarmony 6.1.0.26，API 23，aarch64 内核 / 32 位用户态，串号 “150100424a5444345209d945be14b900”
- 工具：项目内 Command Line Tools 6.1.0.860，hdc 3.2.0c
- 目标仓库：[hiviewdfx_faultloggerd](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd)
- 源码快照：commit `08916c9e3230c77b492ef75e49d59d480eaf75d8`，bundle `@ohos/faultloggerd` 3.1
- 设备实际二进制：`/system/bin/faultloggerd`，32-bit ARM，BuildID `26f9708a5c9888418e3bf085a6b514e4`，SHA-256 `7d04a19b76b04b77df5e0fb66230b6a3b2ec7e818d95514860167e83cb526cde`
- 结果日志：[faultloggerd-sdkdump.log](artifacts/OH-DYN-10-faultloggerd-sdkdump-2026-08-24/faultloggerd-sdkdump.log)

## 1. 这次验证的对象

faultloggerd 是 OpenHarmony 的故障记录和栈转储服务。它不是通过 System Ability Manager 注册的 SA，而是由 init 启动的系统服务，使用本地 Unix socket 接收请求：

| 观察项 | 实际值 |
| --- | --- |
| 设备进程 | faultloggerd   191     1 ... faultloggerd |
| 普通请求 socket | /dev/unix/socket/faultloggerd.server |
| 崩溃/文件描述符 socket | /dev/unix/socket/faultloggerd.crash.server |
| SDK 栈转储 socket | /dev/unix/socket/faultloggerd.sdkdump.server |
| socket 标签 | faultloggerd_socket、faultloggerd_socket_crash、faultloggerd_socket_sdkdump |
| 服务 SELinux 域（源码配置） | u:r:faultloggerd:s0 |
| 设备服务身份 | UID 1202（faultloggerd），GID 1000（system），PID 191，PPID 1 |
| 设备安全状态 | SELinux Enforcing |

源码依据：

- [services/config/faultloggerd.cfg:24-76](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/services/config/faultloggerd.cfg#L24) 定义 init 服务路径、运行 UID/GID、三个 AF_UNIX SOCK_STREAM socket、SO_PASSCRED、能力和 SELinux 域。
- [interfaces/common/dfx_socket_request.h:27-36](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/interfaces/common/dfx_socket_request.h#L27) 定义实际 socket 名称。
- [interfaces/common/dfx_socket_request.h:97-120](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/interfaces/common/dfx_socket_request.h#L97) 定义 SDK_DUMP_CLIENT 请求类型。
- [services/fault_logger_server.cpp:58-85](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/services/fault_logger_server.cpp#L58) 将 SDK_DUMP_CLIENT 注册到 SdkDumpService，并监听 sdkdump socket。
- [tools/dump_catcher/main.cpp:36-46](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/tools/dump_catcher/main.cpp#L36) 说明 dumpcatcher -p pid 是用户态栈转储命令；[main.cpp:144-165](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/tools/dump_catcher/main.cpp#L144) 将用户栈选项交给 DumpCatcher。
- [interfaces/innerkits/dump_catcher/dfx_dump_catcher.cpp:682-719](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/interfaces/innerkits/dump_catcher/dfx_dump_catcher.cpp#L682) 显示远程用户栈路径调用 RequestSdkDump。
- [interfaces/innerkits/faultloggerd_client/faultloggerd_client.cpp:105-123](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/interfaces/innerkits/faultloggerd_client/faultloggerd_client.cpp#L105) 显示请求头、PID/TID、超时和 faultloggerd.sdkdump.server 的具体发送逻辑。
- [services/fault_logger_service.cpp:72-89](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/services/fault_logger_service.cpp#L72) 显示允许发起 SDK dump 的 UID 白名单；本次 HDC shell 为 root UID，符合该白名单。
- [services/fault_logger_service.cpp:298-329](../../../openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd/services/fault_logger_service.cpp#L298) 显示服务对 socket、PID、调用者 UID、崩溃记录和重复请求的过滤。

## 2. 安全边界

本次只验证已有的只读栈转储路径：

1. 在设备 shell 中启动临时 sleep 5 进程；
2. 通过设备自带的 /system/bin/dumpcatcher -p <pid> -T 3000 请求用户态栈；
3. 读取返回的栈文本和返回码；
4. 立即终止并等待临时进程；
5. 复核 faultloggerd 进程、三个 socket、故障记录和目标进程状态。

本次明确没有执行：

- dumpcatcher -c save/cancel 和任何 coredump；
- 主动发送 C/C++、JS 崩溃信号；
- crash socket 上的文件描述符/异常上报协议；
- 畸形、超长、批量或随机 socket 数据；
- 修改服务配置、权限、SELinux 状态或持久化数据。

## 3. 实际执行命令

~~~sh
HDC="/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/utilities/dynamic_tester/toolchains/commandline-tools-mac-arm64-6.1.0.860/command-line-tools/sdk/default/openharmony/toolchains/hdc"
SERIAL="150100424a5444345209d945be14b900"

"$HDC" -t "$SERIAL" shell '
  sleep 5 &
  target=$!
  echo target_pid=$target
  /system/bin/dumpcatcher -p "$target" -T 3000 2>&1
  rc=$?
  echo dumpcatcher_rc=$rc
  kill "$target" 2>/dev/null || true
  wait "$target" 2>/dev/null || true
  if ps -p "$target" >/dev/null 2>&1; then
    echo target_cleanup=FAIL
  else
    echo target_cleanup=PASS
  fi
  ps -ef | grep -E "(^|[ /])faultloggerd([ ]|$)" | grep -v grep || true
'
~~~

## 4. 结果

### 4.1 请求结果：通过

设备返回：

~~~text
target_pid=7469
Result:dump normal stack success.
Reason:success
Timestamp:2017-08-05 00:00:39.000
Pid:7469
Uid:0
Process name:/bin/sh
Tid:7469, Name:sh
state=S, utime=0, stime=0, priority=20, nice=0, clk=100
#00 pc 000da27c /system/lib/ld-musl-arm.so.1(__select_time64+388)(c72ecdf9b17099e337719de3451551df)
#01 pc 0001fd31 /system/bin/sh(c_sleep+280)(8b72a38be893283175d4ae7ce786a21e)
#02 pc 0001a667 /system/bin/sh(comexec+2218)(8b72a38be893283175d4ae7ce786a21e)
#03 pc 000191c9 /system/bin/sh(execute+1716)(8b72a38be893283175d4ae7ce786a21e)
#04 pc 00024365 /system/bin/sh(exchild+1116)(8b72a38be893283175d4ae7ce786a21e)
#05 pc 00019099 /system/bin/sh(execute+1412)(8b72a38be893283175d4ae7ce786a21e)
#06 pc 000193f9 /system/bin/sh(execute+2276)(8b72a38be893283175d4ae7ce786a21e)
#07 pc 000192b1 /system/bin/sh(execute+1948)(8b72a38be893283175d4ae7ce786a21e)
#08 pc 0002a79d /system/bin/sh(shell+604)(8b72a38be893283175d4ae7ce786a21e)
#09 pc 0002a323 /system/bin/sh(main+2118)(8b72a38be893283175d4ae7ce786a21e)
#10 pc 0007251c /system/lib/ld-musl-arm.so.1(libc_start_main_stage2+72)(c72ecdf9b17099e337719de3451551df)
#11 pc 000072a8 /system/bin/sh(_start_c+84)(8b72a38be893283175d4ae7ce786a21e)
#12 pc 0000724c /system/bin/sh(8b72a38be893283175d4ae7ce786a21e)

total cost:(113)ms
dumpcatcher_rc=0
target_cleanup=PASS
faultloggerd   191     1 0 17:00:24 ?     00:00:00 faultloggerd
~~~

这证明：

- 设备上的 faultloggerd 服务接受了真实的 SDK dump 请求；
- 请求返回成功，耗时 113ms；
- 返回内容包含目标进程 PID、TID、用户态 ELF/函数栈帧；
- 客户端返回码为 0；
- 临时目标进程已清理。

### 4.2 事后状态复核：通过

复核命令结果：

~~~text
uid=0(root) gid=0(root) groups=0(root),1006(file_manager),1007(log),2000(shell),3009(readproc) context=u:r:su:s0
faultloggerd   191     1 0 17:00:23 ?     00:00:00 faultloggerd
srw-rw-rw- 1 faultloggerd system u:object_r:faultloggerd_socket_crash:s0    0 2017-08-04 17:00 /dev/unix/socket/faultloggerd.crash.server
srw-rw-rw- 1 faultloggerd system u:object_r:faultloggerd_socket_sdkdump:s0  0 2017-08-04 17:00 /dev/unix/socket/faultloggerd.sdkdump.server
srw-rw-rw- 1 faultloggerd system u:object_r:faultloggerd_socket:s0          0 2017-08-04 17:00 /dev/unix/socket/faultloggerd.server
no records found.
target_7469=NOT_RUNNING
~~~

因此服务仍在运行，socket 仍存在，测试目标不存在，设备故障记录查询没有新增记录。

## 5. 结论与限制

**结论：OH-DYN-10 通过。** 已经在本机连接的真实开发板上跑通了 faultloggerd 的一个真实服务路径，而且是通过仓库源码可对应的 dumpcatcher → RequestSdkDump → faultloggerd.sdkdump.server → SdkDumpService 链路完成的。

但这个结果不能直接解释为“普通 HAP 可以无条件调用 faultloggerd”：

- 本次 HDC shell 身份是 root（uid=0），而不是普通第三方应用 UID；
- 源码中的 CheckCallerUID 明确限制 SDK dump 调用者；
- 临时目标进程也是 root shell 创建的 /bin/sh；
- 因而当前证据证明的是“服务存在、协议路径可用、root 调试身份可完成只读请求”，不是“任意应用身份的权限结论”；
- 设备报告的时间为 2017-08-05，后续自动化必须同时记录工作站时间和设备时间，不能仅按设备时间排序。
- 本地源码快照与设备二进制的源码提交对应关系尚未由构建产物证明；本记录保存了设备二进制 SHA-256/BuildID，后续应在构建系统中补充可验证 provenance。

这次实测为动态测试实现提供了一个明确的适配器类型：init_unix_socket / faultloggerd_sdkdump，而不是 ipc_sa。下一步若实现自动化，应先复用 dumpcatcher -p 的安全路径，再在明确授权和身份隔离后评估普通 HAP/受限 Native 身份；不要把 crash/coredump 路径默认纳入扫描。
