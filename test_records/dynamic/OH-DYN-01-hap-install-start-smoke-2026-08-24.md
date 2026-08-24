# OH-DYN-01：HAP 真机安装与受控启动冒烟测试记录

## 1. 测试结论

本次在真实 OpenHarmony 开发板上完成了一个 HAP 的重新安装、Ability 启动、窗口加载和受控停止，结果如下：

| 环节 | 结果 |
|---|---|
| 新版 HDC 连接指定设备 | PASS |
| HAP 重新安装 | PASS |
| `EntryAbility` 启动 | PASS |
| 窗口/页面加载 | PASS |
| 受控停止 | PASS |
| 停止后应用进程残留 | 未观察到 |
| `faultloggerd` fuzz 载荷发送 | NOT RUN（主动阻止） |
| 系统服务漏洞确认 | NOT RUN |

这是一轮安装和生命周期冒烟测试，不是漏洞验证结论。样例 HAP 会在页面出现约 2 秒后自动连接 `127.0.0.1:9999` 并发送 faultloggerd 测试载荷；为避免在未完成授权边界、服务发现和回滚保护前触发批量 fuzz，本轮在 0.6 秒左右主动停止应用。

构建/签名状态必须单独说明：本轮没有运行 Hvigor 构建，也没有运行 HAP 签名工具。输入是经验包中已经生成的 `entry-default-signed.hap`；我本轮亲手完成的是使用 HDC 重新安装、启动、观察和停止。

## 2. 测试输入

| 项目 | 实际值 |
|---|---|
| HAP | `/Users/shiyu/学习/hyl/harmony_exploit/02_hap_app/Entry/build/default/outputs/default/entry-default-signed.hap` |
| HAP SHA-256 | `907b9e7d9a6e47ce0c573139fab31aa491c093a64da96fbf069800be0f76d061` |
| HAP 大小 | `153551` bytes |
| bundle | `com.security.research.trigger` |
| 设备序列号 | `150100424a5444345209d945be14b900` |
| 设备系统 | `OpenHarmony 6.1.0.26` |
| 设备 API | `23` |
| 设备 release type | `Canary1` |
| 设备 ABI | `aarch64` |
| HDC | `/private/tmp/openant-hdc-6.1.1.280/hdc` |
| HDC 版本 | `3.2.0d` |
| 主机 | macOS Apple Silicon (`Darwin arm64`) |
| 本轮产物目录 | `/private/tmp/openant-hap-smoke-20260824_1342` |

测试开始前，设备中已经存在同名 bundle；本轮使用 `install -r` 覆盖安装，不卸载其他应用、不修改系统分区。该 HAP 和对应输出文件时间为 2026-06-30，早于本轮 2026-08-24 的设备测试。

## 3. HAP 静态安全边界检查

在启动前阅读了 HAP 对应源码 `02_hap_app/Entry/src/main/ets/pages/Index.ets`：

```ts
aboutToAppear(): void {
  setTimeout(() => {
    this.autoTest();
  }, 2000);
}
```

`autoTest()` 会连接 `127.0.0.1:9999`，之后调用 `batchSendAll()`；后者从 `PayloadGenerator` 生成多种 faultloggerd 协议的正常、边界、畸形、截断和 fuzz payload，并逐个发送。因此本轮没有等待 2 秒，也没有点击页面上的 Connect、Send 1 或 Batch All。

HAP 包内的 `module.json` 显示：

- `bundleName`: `com.security.research.trigger`；
- `compileSdkVersion`: `6.1.1.125`；
- `targetAPIVersion`: `60101024`（API 24 Release）；
- `minAPIVersion`: `50000012`（API 12）；
- 仅声明 `ohos.permission.INTERNET`；
- 应用是 debug、普通应用身份，不是系统特权应用。

## 4. 实际执行命令

### 4.1 HDC 客户端/服务端和设备确认

```bash
/private/tmp/openant-hdc-6.1.1.280/hdc kill
/private/tmp/openant-hdc-6.1.1.280/hdc start
/private/tmp/openant-hdc-6.1.1.280/hdc checkserver
/private/tmp/openant-hdc-6.1.1.280/hdc list targets -v
```

结果：客户端和服务端均为 `3.2.0d`，指定 USB 设备状态为 `Connected`。

### 4.2 重新安装 HAP

```bash
/private/tmp/openant-hdc-6.1.1.280/hdc \
  -t 150100424a5444345209d945be14b900 \
  install -r \
  /Users/shiyu/学习/hyl/harmony_exploit/02_hap_app/Entry/build/default/outputs/default/entry-default-signed.hap
```

设备返回：

```text
[Info]App install path: ... entry-default-signed.hap msg:install bundle successfully.
AppMod finish
```

结果：`PASS`。安装后通过设备 `bm dump` 复核 bundle 存在，应用 UID 为 `20010044`，应用身份为普通 debug 应用。

### 4.3 受控启动和停止

为避开源码中的 2 秒自动 fuzz 定时器，执行启动后约 0.6 秒立即停止：

```bash
/private/tmp/openant-hdc-6.1.1.280/hdc \
  -t 150100424a5444345209d945be14b900 \
  shell "aa start -b com.security.research.trigger -a EntryAbility; sleep 0.6; aa force-stop com.security.research.trigger"
```

设备返回：

```text
start ability successfully.
force stop process successfully.
```

结果：`PASS`。

## 5. 观察到的设备证据

本轮保存了以下文件：

```text
/private/tmp/openant-hap-smoke-20260824_1342/run.log
/private/tmp/openant-hap-smoke-20260824_1342/start_stop.txt
/private/tmp/openant-hap-smoke-20260824_1342/process_after.txt
/private/tmp/openant-hap-smoke-20260824_1342/app_logs.txt
/private/tmp/openant-hap-smoke-20260824_1342/port_before.txt
/private/tmp/openant-hap-smoke-20260824_1342/port_after.txt
```

相关 HiLog 记录显示：

```text
A00001/TriggerApp: EntryAbility onCreate
A00001/TriggerApp: onWindowStageCreate
A00001/TriggerApp: loadContent success
A00001/Index: Index aboutToAppear - auto testing
```

这证明 HAP 已经进入应用生命周期并加载页面。与此同时：

- `process_after.txt` 没有留下 `com.security.research.trigger` 应用进程；
- `port_before.txt` 和 `port_after.txt` 均没有发现本地 TCP 9999 监听；
- 匹配日志中没有观察到 `IpcClient` 连接、发送 payload、Batch 结果或 faultloggerd payload 日志。

因此可以确认本轮只完成了 HAP 生命周期冒烟，没有进入桥接连接和 fuzz 发送阶段。

## 6. 兼容性注意事项

设备是 OpenHarmony API 23 Canary1，而这个现成 HAP 按 API 24 Release SDK 构建。它本次能够安装并启动，但这不能证明正式动态测试已经满足版本兼容要求。后续正式构建应使用与设备一致的 OpenHarmony API 23 Canary1 SDK，并在构建配置中使用 `runtimeOS: OpenHarmony`、整数 API 版本和对应的 Canary stage。

本次安装成功只能说明当前设备接受该 debug HAP，不能把它解释为 API 兼容性或系统服务权限兼容性已经验证。

## 7. 对 OpenAnt 动态阶段的影响

已经验证的底座：

1. 主机可以使用新版 HDC 绑定真实设备；
2. HAP 可以通过 HDC 安装；
3. 可以启动/停止指定 Ability；
4. 可以采集应用日志、进程和端口观察结果；
5. 可以用 run 目录保存可审阅的证据。

尚未验证的部分：

1. API 23 Canary1 对齐的 HAP 构建和签名；
2. 受控的无害系统服务交互；
3. Native helper 的交叉编译、部署和回收；
4. faultloggerd 或其他系统服务的协议测试；
5. 日志时间窗口、PID 关联、服务健康检查和失败回滚的自动化；
6. 漏洞确认和报告生成。

下一步应先制作一个不含 fuzz payload 的最小 HAP 或 Native helper，验证单个只读系统接口/IPC 交互和完整清理，再考虑接入动态验证工作流。
