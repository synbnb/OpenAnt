# OH-DYN-02：API 23 HAP 构建、签名、真机部署与受控启动记录

## 1. 结论

本轮第一次在 OpenAnt 项目目录内使用刚解压的 Command Line Tools 6.1.0.860，完成了从 ArkTS 源码编译、HAP 打包、手动签名、签名校验到真实 OpenHarmony 开发版安装和 Ability 生命周期冒烟的完整闭环。

| 环节 | 结果 |
|---|---|
| 工具链解压到 OpenAnt 动态验证目录 | PASS |
| 压缩包完整性和 SHA-256 校验 | PASS |
| API 23 SDK / HDC 版本识别 | PASS |
| Hvigor 任务发现 | PASS |
| ArkTS、资源和 HAP 打包 | PASS（产出未签名 HAP） |
| Hvigor 自动签名任务 | NOT USED；旧式签名配置与新 Hvigor 材料目录格式不兼容 |
| `hap-sign-tool.jar` 手动签名 | PASS |
| `hap-sign-tool.jar` `verify-app` | PASS，Digest verify result: true |
| HDC 连接真实开发版 | PASS |
| HAP `install -r` | PASS |
| `EntryAbility` 启动、窗口页面加载 | PASS |
| 受控停止及进程清理 | PASS |
| faultloggerd / 系统服务载荷测试 | NOT RUN（安全边界） |

这证明动态验证的“构建—签名—部署—生命周期观测”底座可用，不代表已经确认任何系统服务漏洞。

## 2. 工具、源码和设备

| 项目 | 实际值 |
|---|---|
| OpenAnt | `/Users/shiyu/学习/hyl/new/OpenAnt` |
| 工具链目录 | `libs/openant-core/utilities/dynamic_tester/toolchains/commandline-tools-mac-arm64-6.1.0.860` |
| HDC | `.../sdk/default/openharmony/toolchains/hdc` |
| HDC 版本 | `3.2.0c` |
| HAP fixture | `libs/openant-core/utilities/dynamic_tester/fixtures/hap_smoke_app` |
| fixture 来源 | `/Users/shiyu/学习/hyl/harmony_exploit/02_hap_app`（复制后作为本地构建样例） |
| 设备序列号 | `150100424a5444345209d945be14b900` |
| 设备系统 | `OpenHarmony 6.1.0.26` |
| 设备 API | `23` |
| 设备 release type | `Canary1` |
| 设备 ABI | `aarch64` |
| bundle | `com.security.research.trigger` |

原始压缩包 SHA-256、工具链目录和 HDC 路径见 [TOOLCHAIN-6.1.0.860.md](../../libs/openant-core/utilities/dynamic_tester/TOOLCHAIN-6.1.0.860.md)。

## 3. 构建过程

### 3.1 为什么使用 ASCII 临时构建目录

Hvigor 6.23.7 会拒绝包含中文目录名的工程路径，报错为：

```text
Invalid project path ... path must only letters/digits ...
```

因此本轮把 fixture 暂时复制到 `/private/tmp/openant-hap-build-20260824` 构建，SDK 本体仍然使用 OpenAnt 目录内的 6.1.0.860 工具链。构建完成后，HAP 和公开校验证书链已复制回 OpenAnt 的测试产物目录；这只是工具链兼容性 workaround，不改变源码和运行产物的归属。

### 3.2 构建配置

fixture 根目录 `build-profile.json5` 使用：

- `compileSdkVersion: 23`；
- `compatibleSdkVersion: 23`；
- `targetSdkVersion: 23`；
- `runtimeOS: OpenHarmony`。

`local.properties` 在临时构建目录中使用 OpenAnt 内置 SDK 的绝对路径，避免构建过程误读主机上其他 SDK。

### 3.3 Hvigor 和打包结果

`hvigorw tasks --no-daemon --stacktrace` 成功列出 `assembleApp`、`PackageApp`、`SignApp` 等任务。执行打包时，ArkTS、资源和模块编译成功，产出：

```text
/private/tmp/openant-hap-build-20260824/Entry/build/default/outputs/default/entry-default-unsigned.hap
```

大小为 `116092` bytes，SHA-256：

```text
3369b7b2e90afd79a0ea803cdec5670dd4a66ed12db8d77527e4ccb6fabf32a2
```

Hvigor 后续自动 `SignHap` 没有采用，因为当前 fixture 中的旧式签名配置会让新 Hvigor 查找不存在的 `signing/material` 目录并失败：

```text
ENOENT: no such file or directory, stat '/private/tmp/openant-hap-build-20260824/signing/material'
```

这不是源码或 ArkTS 编译失败，而是签名配置格式问题；本轮明确改为调用同一工具链内的 `hap-sign-tool.jar` 手动签名。

## 4. 手动签名和校验

手动签名使用 OpenHarmony Release 证书链、profile 和授权 keystore，签名工具来自 OpenAnt 内置 SDK：

```text
libs/openant-core/utilities/dynamic_tester/toolchains/
  commandline-tools-mac-arm64-6.1.0.860/command-line-tools/sdk/
  default/openharmony/toolchains/lib/hap-sign-tool.jar
```

使用 `sign-app -mode localSign`、`SHA256withECDSA`、`compatibleVersion 23` 和 `signCode 0` 完成签名。私钥密码和 keystore 没有写入本记录，也没有复制到 OpenAnt 产物目录。

签名 HAP：

```text
test_records/dynamic/artifacts/OH-DYN-02-hap-build-sign-deploy-2026-08-24/entry-default-signed.hap
```

大小为 `137169` bytes，SHA-256：

```text
28cff16372e57a0274a190d536605d936eff24e34c21db80ea1c27cc71a097b9
```

`verify-app` 输出的关键结果：

```text
Digest verify result: true, DigestAlgorithm: SHA-256
verify: Verify success
verify-app success
```

签名链中识别到 `OpenHarmony Application Release`。工具提示缺少可选的 `outproof`，但不影响本轮摘要校验和 `verify-app success`。

包内 `module.json` 复核结果：

- `bundleName`: `com.security.research.trigger`；
- `compileSdkVersion`: `6.1.0.105`；
- `minAPIVersion`: `23`；
- `targetAPIVersion`: `23`；
- `apiReleaseType`: `Release`；
- 仅请求 `ohos.permission.INTERNET`。

## 5. 真机部署和生命周期测试

### 5.1 HDC 连接

使用 OpenAnt 内置 HDC 3.2.0c 执行：

```bash
hdc kill
hdc start
hdc checkserver
hdc list targets -v
```

结果为：

```text
150100424a5444345209d945be14b900  USB  Connected  localhost
OpenHarmony 6.1.0.26
23
```

### 5.2 安装

```bash
hdc -t 150100424a5444345209d945be14b900 install -r \
  test_records/dynamic/artifacts/OH-DYN-02-hap-build-sign-deploy-2026-08-24/entry-default-signed.hap
```

设备返回：

```text
[Info]App install path: ... entry-default-signed.hap msg:install bundle successfully.
AppMod finish
```

安装后使用 `bm dump -n com.security.research.trigger` 复核 bundle 存在，目标 API 显示为 23。

### 5.3 受控启动和停止

fixture 页面 `Index.ets` 在 `aboutToAppear` 后约 2 秒才会调用 `autoTest()`；`autoTest()` 会连接 `127.0.0.1:9999` 并进入 faultloggerd 批量载荷逻辑。为避免未经本轮授权的系统服务交互，实际执行启动后仅等待约 0.6 秒：

```bash
hdc -t 150100424a5444345209d945be14b900 shell \
  'aa start -b com.security.research.trigger -a EntryAbility; \
   sleep 0.6; \
   aa force-stop com.security.research.trigger'
```

设备返回：

```text
start ability successfully.
force stop process successfully.
```

观察到的 HiLog：

```text
A00001/TriggerApp: EntryAbility onCreate
A00001/TriggerApp: onWindowStageCreate
A00001/TriggerApp: loadContent success
```

启动中能看到 `com.security.research.trigger` 进程，停止后进程检查为空。启动前后均未发现 TCP 9999 监听，过滤日志中没有 `IpcClient`、`Auto-test`、`Auto-connect`、`Batch` 或 payload 发送记录。原始冒烟日志保存在：

```text
test_records/dynamic/artifacts/OH-DYN-02-hap-build-sign-deploy-2026-08-24/lifecycle-smoke.log
```

## 6. 安全边界和未完成事项

本轮没有执行以下动作：

1. 不等待 2 秒自动测试定时器；
2. 不点击 Connect、Send 1 或 Batch All；
3. 不启动 `tcp_unix_bridge`；
4. 不向 `faultloggerd` 或其他系统服务发送协议载荷；
5. 不执行 fuzz、崩溃触发、权限绕过或持久化操作。

因此本记录的“PASS”只覆盖构建、签名、安装和生命周期，不是漏洞存在性结论。下一轮要进入系统服务动态验证前，仍需先完成设备服务发现、无害请求、权限边界、超时/回滚和证据采集的自动化。

## 7. 产物清单

```text
test_records/dynamic/artifacts/OH-DYN-02-hap-build-sign-deploy-2026-08-24/
├── entry-default-unsigned.hap
├── entry-default-signed.hap
├── verify_chain.cer
└── lifecycle-smoke.log
```

私钥 keystore 没有进入该目录。若要在另一台机器复现签名，需要由授权方安全地提供对应签名材料，并按照组织的密钥管理流程配置，而不是把私钥提交到仓库。
