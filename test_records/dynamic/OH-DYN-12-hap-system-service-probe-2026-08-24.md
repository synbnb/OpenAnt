# OH-DYN-12：清理旧入口并在 HAP 内验证 Bundle Manager/FaultLogger

## 1. 测试目标

本轮将 HAP 从“TCP bridge + faultloggerd 原始载荷”改为“公开 HAP 系统服务 API”路径：启动后依次查询 Bundle Manager 和 FaultLogger 自身记录。

本轮不打开 Unix socket、不启动 TCP bridge、不生成崩溃、不执行 coredump、不发送 fuzz 数据。

| 项目 | 值 |
| --- | --- |
| 测试日期 | 2026-08-24 |
| HAP 包名 | `com.security.research.trigger` |
| Ability | `EntryAbility` |
| 设备序列号 | `150100424a5444345209d945be14b900` |
| API | OpenHarmony API 23 |
| 测试进程 UID | `20010044` |

## 2. 原逻辑和新逻辑

### 2.1 原逻辑

原 fixture 页面依赖：

```text
HAP -> TCP 127.0.0.1:9999 -> tcp_unix_bridge -> faultloggerd Unix socket
```

页面包含自动测试、Connect、Send 1、Batch All、Disconnect 等入口，并通过 `PayloadGenerator` 生成 faultloggerd 二进制请求。

### 2.2 新逻辑

页面现在只有两个只读系统服务调用：

```text
HAP 启动
  -> bundleManager.getBundleInfoForSelf()
  -> faultLogger.querySelfFaultLog(FaultType.NO_SPECIFIC)
  -> 页面和 HiLog 展示结果
```

具体修改：

* `Entry/src/main/ets/pages/Index.ets` 重写为系统服务探针页面；
* 删除 `Entry/src/main/ets/client/IpcClient.ets`；
* 删除 `Entry/src/main/ets/payload/PayloadGenerator.ets`；
* 删除 `autoTest()`、`batchSendAll()`、Connect/Send/Batch/Disconnect 按钮及其状态；
* `Entry/src/main/module.json5` 的 `requestPermissions` 改为空数组，移除 `ohos.permission.INTERNET`。

静态检查结果：fixture 中已找不到 `IpcClient`、`PayloadGenerator`、`autoTest`、`batchSendAll`、`127.0.0.1:9999`、`INTERNET` 等旧入口标记。

## 3. HAP 内使用的 FaultLogger API

本机 API 23 SDK 提供：

```text
@ohos.faultLogger
faultLogger.querySelfFaultLog(faultLogger.FaultType.NO_SPECIFIC)
```

它是公开 HAP API，由系统侧完成 fault log 查询；它不是 HAP 直接向 `/dev/unix/socket/faultloggerd.*` 写入私有二进制协议，也不会主动制造故障。

SDK 将该模块标记为 deprecated，但 API 23 仍能编译，设备实际调用也成功。本轮保留它是为了先验证真实系统服务链路；后续可以再评估迁移到新版 `hiAppEvent` 观察接口。

## 4. 构建、签名和校验

构建在 ASCII 临时目录 `/private/tmp/openant-hap-faultlogger-probe.uMMdwz` 完成，`local.properties` 指向 OpenAnt 内置 API 23 SDK 和 Node。

ArkTS 编译、资源处理、HAP 打包均成功。Hvigor 自动 `SignHap` 仍因 fixture 的旧配置引用不存在的 `signing/material` 目录而失败；这发生在 `PackageHap` 之后，不是源码编译错误。本轮使用已经验证过的开发版 OpenHarmony Release 授权材料手动签名。

`hap-sign-tool.jar` 输出：

```text
sign-app success
Digest verify result: true, DigestAlgorithm: SHA-256
verify: Verify success
verify-app success
```

产物目录：

```text
test_records/dynamic/artifacts/OH-DYN-12-hap-system-service-probe-2026-08-24/
```

| 文件 | SHA-256 |
| --- | --- |
| `entry-default-unsigned.hap` | `09cd2b3a21ab142682791ece7630b6d825439f2ca937ba7e9c8b985de8f5ad5f` |
| `entry-default-signed.hap` | `13424a2a8b9af5bae9693a85bf4642d8d339b77553123e3234895aff002cd4f3` |

Hvigor 原始日志在 `artifacts/.../hvigor-build.log`，签名摘要在 `artifacts/.../verify-app-summary.log`。

## 5. 真机执行

### 5.1 安装和启动

HDC 安装返回：

```text
msg:install bundle successfully.
AppMod finish
```

启动命令返回：

```text
start ability successfully.
```

设备 `bm dump` 复核：

```text
reqPermissions: []
uid: 20010044
versionName: 1.0.0
```

这证明本轮安装包不再请求 INTERNET 权限，并且仍以普通 HAP UID 运行。

### 5.2 HAP HiLog 结果

设备 HiLog 中出现了本轮唯一的探针序列：

```text
I A00001/Index: Index aboutToAppear - system-service probes
I A00001/Index: BundleManager probe started
I A00001/Index: BundleManager probe success: bundle=com.security.research.trigger; version=1.0.0(1000000)
I A00001/Index: FaultLogger probe started
I A00001/Index: FaultLogger probe success: faultRecords=10
```

### 5.3 服务侧证据

同一时间窗口内，设备出现 FaultLogger NAPI 回调：

```text
C02d11/Faultlogger-napi: FaultLogCompleteCallback: add element when resovled pid = ..., uid = 20010044, ts = ...
```

该回调连续添加 10 条当前 HAP UID 的 fault log 记录，随后 HAP 输出 `FaultLogger probe success: faultRecords=10`。这证明调用不是本地伪造字符串，而是经过系统 FaultLogger 服务返回了记录。

这些记录来自设备已有 fault log；本轮没有产生新的 crash 或 coredump。

### 5.4 清理

测试结束执行 `aa force-stop com.security.research.trigger`，设备返回：

```text
force stop process successfully.
```

随后进程表中已没有该 HAP 进程。

## 6. 结果判定

| 检查项 | 结果 |
| --- | --- |
| 删除 TCP 客户端和载荷生成器 | PASS |
| 删除自动/手动 fuzz 入口 | PASS |
| 移除 INTERNET 权限 | PASS |
| ArkTS 编译 | PASS（仅 deprecated 警告） |
| HAP 打包 | PASS |
| HAP 签名与校验 | PASS |
| Bundle Manager 真实调用 | PASS |
| FaultLogger 真实调用 | PASS |
| 服务侧 Faultlogger-napi 回调 | PASS |
| 设备进程清理 | PASS |
| faultloggerd 原始崩溃/coredump/fuzz 载荷 | NOT RUN |

## 7. TCP bridge 的结论

对当前目标而言，TCP bridge 已经没有保留必要：

* HAP 可以通过公开 `@ohos.faultLogger` API 与系统 FaultLogger 服务交互；
* bridge 会额外引入 TCP 监听端口和一层权限转发；
* 原始 faultloggerd Unix socket 协议仍属于私有底层接口，不应由普通 HAP 页面直接拼包调用。

因此当前架构采用“公开系统 API 在 HAP 内验证 + 后续必要时用 HDC/Native 工具验证私有协议”的分层方式。HAP 内的旧 bridge 和 fuzz 入口已全部清理。

