# 项目内 OpenHarmony 运行时

本目录是 OpenHarmony command-line-tools 的项目内导入点。正式交付目标是 Linux
x86_64；本次交付不下载、不内置 Linux 二进制，仅保留清单和导入说明。部署方应将
匹配版本的 Linux 工具包放在例如 `linux-x64-6.1/`，目录内应包含 `hvigor/`、
`tool/`、`sdk/` 等标准子目录，也可以通过 `VULNFOUNDER_DYNAMIC_TOOLCHAIN` 指向
外部安装目录。

工作区中可能存在 `macos-arm64-6.1/` 本机验证运行包，但它只适用于 macOS arm64，
不是 Linux 交付物，不能复制到 Linux 主机，也不应由部署脚本自动选择。

运行时解析优先级为：

1. `VULNFOUNDER_DYNAMIC_TOOLCHAIN` 明确指定的目录；
2. 本目录下能被 `manifest.json`/标准子目录识别的版本；
3. `assets/toolchains` 兼容目录；
4. 系统 `PATH` 中的 HDC（仅用于设备发现的最低能力）。

工具包中的二进制文件不能跨操作系统或 CPU 架构直接复用。Linux 部署方负责获取
并导入 Linux 工具包；发布包不会假装已经包含该工具链。安装或导入后，
请通过设置页的“运行环境诊断”检查 HDC、Hvigor、Node、HAP 签名工具和 SDK
是否来自同一版本。运行时目录不包含任何 API Key；HAP 私钥独立放在
`config/hap_cert`，不应提交到版本库。

主机上的 Python、Java 和 Go 仍由操作系统提供：Python 用于运行分析引擎，
Java 用于调用 HAP 签名工具，Go 只在从源码编译 Web/CLI 时需要。设置页会
显示它们是否可用，不会把平台相关的解释器或系统库伪装成项目内工具。
