# 项目内 OpenHarmony 运行时

本目录是 OpenHarmony 工具链的项目内导入点。当前目标版本为
OpenHarmony 7.0-Release，正式交付目标是 Linux x86_64；本目录已经导入一份
官方 7.0 macOS arm64 L2 SDK（`macos-arm64-7.0/`），用于本机 HDC、HAP 签名、
Native/ETS/JS SDK 和 C/C++ PoC 验证。正式 Linux 交付不下载、不内置 Linux
二进制，仅保留清单和导入说明。部署方应将匹配版本的 Linux 工具包放在例如
`linux-x64-7.0/`，目录内应包含 `hvigor/`、`tool/`、`sdk/` 等标准子目录，也
可以通过 `VULNFOUNDER_DYNAMIC_TOOLCHAIN` 指向外部安装目录。

macOS 这份 L2 SDK 不包含 command-line-tools 中的 Hvigor/Node。需要构建 HAP
工程时，必须另行取得与 7.0/API 26 匹配的 macOS command-line-tools；不能把
`macos-arm64-6.1/` 中的 Hvigor/Node 与 7.0 SDK 混用。当前本机包已经具备
`sdk/default/openharmony/toolchains/hdc`、`hap-sign-tool.jar`、
`OpenHarmony.p12` 以及 Native SDK，因此可以运行设备资产发现、源码定位依赖的
HDC 操作、原生 PoC 构建和签名验证。

工作区中可能存在 `macos-arm64-6.1/` 历史本机验证运行包，但它只适用于 macOS
arm64，且不是当前 7.0 运行时，不能复制到 Linux 主机，也不应被自动选择。若只有
6.1 工具链，动态测试必须先报告版本不匹配，不能静默使用。

运行时解析优先级为：

1. `VULNFOUNDER_DYNAMIC_TOOLCHAIN` 明确指定的目录；
2. 本目录下与 `VULNFOUNDER_OPENHARMONY_VERSION`（默认 7.0）匹配的
   `manifest.json`/标准子目录；
3. `assets/toolchains` 中与目标版本匹配的兼容目录；
4. 系统 `PATH` 中的 HDC（仅用于设备发现的最低能力，不代表 HAP 工具链完整）。

工具包中的二进制文件不能跨操作系统或 CPU 架构直接复用。Linux 部署方负责获取
并导入 Linux 工具包；发布包不会假装已经包含该工具链。安装或导入后，
请通过设置页的“运行环境诊断”检查 HDC、Hvigor、Node、HAP 签名工具和 SDK
是否来自同一版本。运行时目录不包含任何 API Key；HAP 私钥独立放在
`config/hap_cert`，不应提交到版本库。

版本切换后必须重新执行设备版本探测、Socket 资产发现、协议描述符自证和动态
冒烟测试。旧版本的设备事实、契约、调用图和扫描缓存不能直接复用到 7.0。

主机上的 Python、Java 和 Go 仍由操作系统提供：Python 用于运行分析引擎，
Java 用于调用 HAP 签名工具，Go 只在从源码编译 Web/CLI 时需要。设置页会
显示它们是否可用，不会把平台相关的解释器或系统库伪装成项目内工具。
