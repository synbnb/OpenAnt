# OpenHarmony 动态验证公开工具库

此目录位于 Claude Code 任务目录的上一级，目的是让任务在不依赖主机 PATH 的情况下找到 OpenHarmony 动态验证工具。`bin/` 中的文件是项目内工具链的相对链接；大型 SDK 不会被重复复制。

## 工具清单

| 路径 | 用途 | 运行位置 |
|---|---|---|
| `bin/hdc` | 连接开发板、执行 shell、安装 HAP、采集日志 | 主机调用，命令作用于设备 |
| `bin/hvigorw` | 构建 ArkTS/HAP 工程 | 主机调用 |
| `bin/node` | Hvigor/ArkTS 构建运行时 | 主机调用 |
| `bin/hap-sign-tool.jar` | HAP 独立签名和 `verify-app` | 通过主机 Java 调用 |
| `bin/java` | 执行 HAP 签名校验工具（若主机可发现） | 主机调用 |
| `toolchain-manifest.json` | 工具链版本、来源和缺失项 | 只读元数据 |

设备侧命令（`aa`、`bm`、`hilog`、`ps`、`getprop`、`dumpcatcher` 等）不复制到本目录，它们由开发板系统提供，必须通过 `bin/hdc -t <serial> shell ...` 调用。

## 常用预检

```bash
TOOLS="../openharmony-public-tools"
"$TOOLS/bin/hdc" list targets -v
"$TOOLS/bin/hdc" -t <serial> shell 'uname -m; getconf LONG_BIT; getprop ro.build.version.sdk'
"$TOOLS/bin/hdc" -t <serial> shell 'bm dump -n <bundle-name>'
```

## HAP 构建和签名原则

1. Hvigor 工程使用 ASCII 临时目录；中文路径可能被当前 Hvigor 拒绝。
2. 先执行 `assembleApp` 产出 unsigned HAP，再用独立的 `hap-sign-tool.jar` 签名。
3. 签名材料、密码和私钥由运行环境安全注入，不放入本任务目录或公开工具库。
4. 始终保存 unsigned/signed SHA-256 和 `verify-app` 摘要。

参考命令（路径和签名参数必须按当前工程实际值替换，密码不要写入 shell 历史或任务文件）：

```bash
TOOLS="../openharmony-public-tools"
ASCII_WORKSPACE="/private/tmp/vulnfounder-hap-<run-id>"

# 构建 unsigned HAP
PATH="$TOOLS/bin:$PATH" \
  "$TOOLS/bin/hvigorw" assembleApp --no-daemon --stacktrace

# 独立签名；下面的 keystore/profile/certificate 只应来自安全的运行时配置
"$TOOLS/bin/java" -jar "$TOOLS/bin/hap-sign-tool.jar" sign-app \
  -mode localSign -inFile <unsigned.hap> -outFile <signed.hap> \
  -keyAlias <alias> -keyPwd '<runtime-secret>' \
  -keystoreFile <runtime-keystore.p12> -keystorePwd '<runtime-secret>' \
  -appCertFile <app-cert.pem> -profileFile <profile.p7b> \
  -signAlg SHA256withECDSA -compatibleVersion 23 -signCode 0

"$TOOLS/bin/java" -jar "$TOOLS/bin/hap-sign-tool.jar" verify-app \
  -inFile <signed.hap>
```

## HDC、安装和观察

```bash
TOOLS="../openharmony-public-tools"
SERIAL="<device-serial>"
"$TOOLS/bin/hdc" list targets -v
"$TOOLS/bin/hdc" -t "$SERIAL" install -r <signed.hap>
"$TOOLS/bin/hdc" -t "$SERIAL" shell "aa start -b <bundle> -a EntryAbility"
"$TOOLS/bin/hdc" -t "$SERIAL" shell "hilog -x | grep -E 'VulnFounder|Index|Trigger'"
"$TOOLS/bin/hdc" -t "$SERIAL" shell "bm dump -n <bundle>"
"$TOOLS/bin/hdc" -t "$SERIAL" shell "aa force-stop <bundle>"
```

## 设备交互原则

- 任何命令都带明确的设备序列号，不使用设备自动选择。
- `hilog -x` 可能返回历史内容，必须结合采集前基线、设备时间、PID 和运行标记。
- 任务只清理本次创建的进程和远端临时目录，不清空历史日志，不修改系统分区。
- 普通 HAP 公开 API 调用不需要 TCP bridge；私有 Unix socket 不能通过 TCP 端口暴露给 HAP。

## 版本事实

工具链版本、SDK API、HDC client 版本和路径以 `toolchain-manifest.json` 为准；如果工具缺失或版本与设备不兼容，停止并在候选结果中写 `BLOCKED`，不要静默使用主机上的另一个版本。
