# OH-DYN-11：HAP 只读 Bundle Manager 真实交互

## 1. 测试目的

本轮只验证一个最小、可审计的 HAP→OpenHarmony 系统服务调用：HAP 启动后通过官方 ArkTS API `@ohos.bundle.bundleManager` 调用 `getBundleInfoForSelf()`，读取当前 HAP 自身的包名和版本号。

本轮不启动旧的 TCP bridge，不连接 `faultloggerd.server`，不发送崩溃、coredump、边界或 fuzz 载荷，也不修改设备上的系统服务数据。

| 项目 | 值 |
| --- | --- |
| 测试日期 | 2026-08-24 |
| HAP 包名 | `com.security.research.trigger` |
| Ability | `EntryAbility` |
| 目标设备 | `150100424a5444345209d945be14b900` |
| HDC | Command Line Tools 6.1.0.860 内置 HDC |
| SDK/API | OpenHarmony API 23 |
| 测试类型 | 只读系统服务 API 烟囱测试 |

## 2. 原逻辑与本轮逻辑

### 2.1 原逻辑

原页面 `Entry/src/main/ets/pages/Index.ets` 在 `aboutToAppear()` 中自动启动批量流程：连接本机 `127.0.0.1:9999` 的 TCP bridge，再由 bridge 转发到设备上的 `faultloggerd.server` Unix socket。批量流程会生成多种 faultloggerd 请求，包括正常请求、边界请求、格式错误请求和 fuzz 请求。

该 bridge 当前并未随 HAP 构建或部署；因此原流程要么连接失败，要么依赖外部 bridge，无法作为安全、可复现的第一条真机验证路径。

### 2.2 本轮逻辑

本轮将 `aboutToAppear()` 改为只调用 `probeBundleManager()`：

```text
EntryAbility 加载页面
  -> Index.aboutToAppear()
  -> bundleManager.getBundleInfoForSelf(GET_BUNDLE_INFO_DEFAULT)
  -> 更新页面状态和 HiLog
  -> 正常返回
```

修改位置：

* `Index.ets:21-24`：页面出现时不再启动自动 bridge/fuzz 流程；
* `Index.ets:26-50`：新增一次只读 Bundle Manager 查询；
* 原 `autoTest()`、`batchSendAll()` 等旧方法仍保留在文件中，但本轮入口没有调用它们，便于后续阶段逐步替换并保留历史对照。

静态检查显示 `aboutToAppear()` 中没有 `setTimeout()`、`autoTest()` 或 `batchSendAll()` 调用。旧的手动按钮和 `ohos.permission.INTERNET` 声明仍存在，后续应在安全载荷阶段开始前单独清理或改成显式测试开关；本轮没有点击这些按钮。

## 3. 构建

### 3.1 构建环境

* Hvigor：VulnFounder 内置 Command Line Tools 6.1.0.860；
* SDK：`.../sdk`，产品的 compile/target/compatible API 均为 23；
* 构建在 ASCII 临时目录 `/private/tmp/openant-hap-bundle-probe.IqT8dc` 中进行，避免工具链处理中文路径时产生额外变量；
* `local.properties` 显式指向 VulnFounder 内置 SDK 和 Node，不依赖机器全局 SDK。

### 3.2 构建结果

ArkTS 编译、资源处理和 HAP 打包成功，生成：

```text
Entry/build/default/outputs/default/entry-default-unsigned.hap
```

Hvigor 随后的自动 `SignHap` 失败，原因是样例旧式签名配置会查找不存在的目录：

```text
ENOENT: no such file or directory, stat
'/private/tmp/openant-hap-bundle-probe.IqT8dc/signing/material'
```

该错误发生在 `PackageHap` 完成以后，不是 ArkTS 编译或本轮源码逻辑错误。与此前 HAP 阶段相同，本轮改用同一 SDK 中的 `hap-sign-tool.jar` 手动签名。

### 3.3 手动签名和完整性校验

开发版对应的 OpenHarmony Release 授权材料来自先前已经验证的临时签名目录；私钥材料没有复制进 VulnFounder 产物，也没有把密码写入本记录。签名参数为 `localSign`、`SHA256withECDSA`、compatibleVersion `23`、signCode `0`。

产物目录：

```text
test_records/dynamic/artifacts/OH-DYN-11-hap-bundle-manager-2026-08-24/
```

关键产物：

| 文件 | SHA-256 |
| --- | --- |
| `entry-default-unsigned.hap` | `558f2829f6c344e0b47960b237043fa92dcc4ec52a4b10156909f7963ffa179c` |
| `entry-default-signed.hap` | `56173ea57baeb39c534074c75524573ad5caf7dc7a1d4184e4669d92d708b832` |

`hap-sign-tool.jar verify-app` 结果：

```text
Digest verify result: true, DigestAlgorithm: SHA-256
verify: Verify success
verify-app success
```

完整工具输出保存在 `artifacts/OH-DYN-11-hap-bundle-manager-2026-08-24/verify-app.log`，Hvigor 原始日志保存在同目录的 `hvigor-build.log`。

## 4. 设备执行

### 4.1 设备在线和安装

HDC 设备发现结果：

```text
150100424a5444345209d945be14b900
```

安装命令使用已校验签名的 HAP：

```text
hdc -t 150100424a5444345209d945be14b900 install -r entry-default-signed.hap
```

设备返回：

```text
[Info]App install path:.../entry-default-signed.hap msg:install bundle successfully.
AppMod finish
```

安装前 `bm dump -n com.security.research.trigger` 已确认设备上存在同名测试包，包名、版本 `1.0.0(1000000)`、API 23 和入口 `EntryAbility` 与本轮产物一致。

### 4.2 启动和系统服务调用

启动命令：

```text
hdc -t 150100424a5444345209d945be14b900 shell \
  aa start -b com.security.research.trigger -a EntryAbility
```

设备返回：

```text
start ability successfully.
```

随后从设备 HiLog 中读取到本轮新增的唯一探针标记：

```text
I A00001/Index: Index aboutToAppear - BundleManager probe
I A00001/Index: BundleManager probe started
I A00001/Index: BundleManager probe success: bundle=com.security.research.trigger; version=1.0.0(1000000)
```

这三条日志证明：页面实际加载、ArkTS API 调用实际返回，并且返回值与安装包身份一致。它不是仅凭静态编译结果推断。

### 4.3 进程权限和清理

启动期间设备进程表显示：

```text
UID            PID  PPID ... CMD
20010044       4994 210  ... com.security.research.trigger
```

`20010044` 是该 HAP 的普通应用 UID，不是 root。测试结束执行：

```text
hdc -t 150100424a5444345209d945be14b900 shell \
  aa force-stop com.security.research.trigger
```

设备返回 `force stop process successfully.`；随后再次查询进程表，没有匹配到 `com.security.research.trigger`，说明测试进程已退出。

## 5. 结果判定

| 检查项 | 结果 | 证据 |
| --- | --- | --- |
| ArkTS 源码编译 | PASS | `hvigor-build.log` 的 `CompileArkTS` 完成 |
| HAP 打包 | PASS | `entry-default-unsigned.hap` 存在 |
| HAP 签名 | PASS | `hap-sign-tool` 输出 `sign-app success` |
| HAP 签名校验 | PASS | `Digest verify result: true`、`verify-app success` |
| HDC 设备连接 | PASS | 目标序列号可发现 |
| HAP 安装 | PASS | `install bundle successfully` |
| Ability 启动 | PASS | `start ability successfully` |
| Bundle Manager 调用 | PASS | HiLog 返回正确包名和版本 |
| 普通 UID 运行 | PASS | UID `20010044` |
| 测试后清理 | PASS | force-stop 成功且进程消失 |
| faultloggerd 载荷发送 | NOT RUN | 本轮明确没有启动 bridge 或点击旧发送按钮 |

## 6. 局限和下一阶段入口

1. 本轮验证的是 HAP 通过官方系统 API 访问 Bundle Manager，证明了真实 HAP→系统服务交互链路和工具链可用；它还不是 faultloggerd 的 IPC/SA 业务验证。
2. 旧 `IpcClient`、载荷生成器、手动 Connect/Send/Batch UI 仍在 fixture 中，本轮只保证自动入口不再调用它们。正式加入任何 faultloggerd 载荷前，应先删除这些隐式入口，或增加明确的设备、权限、载荷白名单和 dry-run 开关。
3. 样例目录中的 `signing/debug-profile.p7b` 当前无法通过 API 23 工具校验；本轮使用了与开发版设备 ID 匹配的已验证授权材料。交付给其他设备时必须重新配置合法的签名和 profile，不能复用本次临时材料。
4. 本轮没有验证 TCP bridge、Unix socket、faultloggerd 命令协议，也没有尝试触发崩溃或生成 coredump。后续阶段应先实现无害的协议探测/错误码验证，再讨论受控载荷。

