# VulnFounder

VulnFounder 是面向 OpenHarmony 及其他软件项目的证据驱动安全分析平台。它把设备
暴露面发现、源码定位、静态分析、调用图与可达性分析、Stage 1/Stage 2 复核、动态
验证和报告生成组织成可追踪的阶段流水线。每个阶段保存结构化产物、日志和证据，结论
可以回溯到源码、设备观测或模型决策，而不是只保留一段不可复查的自然语言。

## 能做什么

* 从已连接的 OpenHarmony 开发板发现 Unix socket、TCP/UDP 端点、进程、权限和
  SELinux 信息；
* 根据 socket 或端点在 OpenGrok 中定位服务端实现、入口函数、客户端边界和源码仓库；
* 对 C/C++、Go、Python、JavaScript/TypeScript、PHP、Ruby、Rust、Swift、Zig 等代码
  建立函数索引和调用关系；
* 用严格入口准入、有效调用图、LLM 可达性和上下文增强缩小静态分析范围；
* 生成包含漏洞说明、触发行、入口到触发点调用链、根因、修复建议和完整源码上下文的
  中英文报告；
* 对指定 finding 独立运行动态验证，生成 PoC/Exp、发送帧、设备日志和预言机结论。

## 快速开始

```bash
cd /path/to/VulnFounder
cp config/vulnfounder/config.example.json config/vulnfounder/config.json
chmod 600 config/vulnfounder/config.json

cd apps/vulnfounder-cli
make build
./bin/vulnfounder serve --addr 127.0.0.1:18099
```

然后访问 <http://127.0.0.1:18099/>，在“设置”中选择模型配置、填写 OpenGrok 地址，
并检查“运行环境诊断”。完整部署步骤见
[部署与交接指南](docs/DEPLOYMENT_GUIDE.zh-CN.md)。

## Linux 交付与项目内运行时

正式交付目标为 Linux x86_64。本次交付包不下载、不内置 Linux 版 OpenHarmony
command-line-tools，只包含运行时清单和导入说明。Linux 部署方应准备匹配版本的
工具包并放入：

```text
runtime/openharmony/linux-x64-6.1/
```

该目录应包含 HDC、Hvigor、Node、SDK 和 HAP 签名工具。也可以设置
`VULNFOUNDER_DYNAMIC_TOOLCHAIN` 指向外部 Linux 工具目录。工作区中可能保留一份
macOS arm64 验证包，但它不属于 Linux 交付物，不能跨平台复用。没有正式 HAP 证书时，系统会使用
SDK 公开测试根材料，按当前 HDC serial 临时生成设备绑定的研究用 debug profile，
无需用户手工寻找 p7b。它不等同于生产证书。

Python、Java、Go 和系统库仍由 Linux 主机提供，设置页会诊断这些依赖。不要把本机
API Key、正式 P12、`config.json` 或
`result/` 放入公开仓库。

## Web 工作台流程

```mermaid
flowchart LR
    A[设置] --> B[设备暴露面发现]
    B --> C[暴露面识别与源码定位]
    C --> D[静态扫描]
    D --> E[漏洞报告]
    E --> F[独立动态测试]
```

各阶段可以单独运行。设备资产历史、源码定位历史、扫描历史和动态测试历史都保存
在项目数据目录，页面支持查看中间证据和最终产物。

## CLI 常用命令

```bash
# 解析仓库
./apps/vulnfounder-cli/bin/vulnfounder parse source_code_base/<repo>

# 完整静态流程，先跳过动态测试
./apps/vulnfounder-cli/bin/vulnfounder scan source_code_base/<repo> \
  --level reachable --skip-dynamic-test

# 分阶段执行
./apps/vulnfounder-cli/bin/vulnfounder enhance
./apps/vulnfounder-cli/bin/vulnfounder analyze
./apps/vulnfounder-cli/bin/vulnfounder verify
./apps/vulnfounder-cli/bin/vulnfounder report -f summary

# 独立动态测试（需要已有 pipeline_output.json）
./apps/vulnfounder-cli/bin/vulnfounder dynamic-test \
  path/to/pipeline_output.json --mode openharmony-device --device <serial>
```

动态测试的设备状态变更、载体执行和安装操作必须显式授权；默认使用受限命令和
canary 路径。

## 配置与安全

配置文件：

* `config/vulnfounder/config.example.json`：可提交的安全模板；
* `config/vulnfounder/config.json`：本机配置，建议权限 `0600`；
* `config/hap_cert/`：正式证书导入目录，私钥建议权限 `0600`。

重要环境变量：

| 变量 | 作用 |
|---|---|
| `VULNFOUNDER_PROJECT_ROOT` | 项目根目录 |
| `VULNFOUNDER_DATA_DIR` | 运行产物根目录 |
| `VULNFOUNDER_CONFIG_FILE` | 受保护配置文件 |
| `VULNFOUNDER_PYTHON` | Python 可执行文件 |
| `VULNFOUNDER_HDC` | HDC 可执行文件 |
| `VULNFOUNDER_DYNAMIC_TOOLCHAIN` | OpenHarmony 工具链根目录 |
| `VULNFOUNDER_HAP_CERT_DIR` | HAP 证书目录 |

OpenGrok 地址必须是 HTTPS，页面只保存令牌环境变量名；模型和签名私钥不会在日志、
报告或页面中回显。源码仓库、扫描结果和设备数据应按使用方权限单独保护。

## 开发与测试

```bash
# Go Web/CLI
cd apps/vulnfounder-cli
go test ./...
make build

# Python 核心
cd ../..
PYTHONPATH=libs/vulnfounder-core \
  result/venv/bin/python -m pytest -q libs/vulnfounder-core/tests
```

大型 OpenHarmony 源码仓库可能包含自己的测试依赖；测试 VulnFounder 时应使用上面
指定的项目测试路径，不要把被扫描仓库的测试错误当作产品测试失败。

## 文档索引

* [部署与交接指南](docs/DEPLOYMENT_GUIDE.zh-CN.md)
* [项目全流程说明](docs/VULNFOUNDER_PROJECT_WORKFLOW.zh-CN.md)
* [开发者架构说明](docs/VULNFOUNDER_DEVELOPER_ARCHITECTURE.zh-CN.md)
* [运行时与设置说明](docs/VULNFOUNDER_RUNTIME_BUNDLE_AND_SETTINGS_PLAN.zh-CN.md)
* [OpenHarmony 工具包说明](runtime/openharmony/README.md)
* [HAP 签名材料说明](config/hap_cert/README.md)

## 许可证

本项目沿用仓库中的许可证和第三方依赖许可说明。
