# VulnFounder 部署与交接指南

本文用于把 VulnFounder 交给新的使用者。默认工作目录为项目根目录，文中的命令
均可在该目录执行。

## 1. 交付内容与 Linux 目标

本项目的正式交付目标为 **Linux x86_64**。本次不会下载或内置 Linux 版
OpenHarmony command-line-tools；当前工作区中的 macOS arm64 工具仅用于本机验证，
不作为 Linux 交付运行时。Linux 使用者需要从与目标 OpenHarmony 版本匹配的官方渠道
取得 Linux 工具包，或由部署方提供经过审计的内部工具包，然后放入项目目录或在设置中
指定路径。源码分析、报告查看和不依赖开发板的页面功能可以先运行；设备资产发现、
HAP 构建/安装和动态验证必须在 Linux 工具链准备完成后启用。

项目目录应保持以下结构：

```text
VulnFounder/
├── apps/vulnfounder-cli/       # Go Web/CLI
├── libs/vulnfounder-core/      # Python 分析引擎
├── assets/                    # HAP 模板、规则和知识库
├── runtime/openharmony/       # Linux 工具包导入位置（本次不内置 Linux 二进制）
├── config/vulnfounder/         # 配置模板和本机配置
├── config/hap_cert/           # 本机受保护的签名材料目录
├── source_code_base/          # 用户待分析的源码仓库
└── result/                    # 运行产物（可重新生成）
```

本机验证目录曾准备过 macOS arm64 的旧版 OpenHarmony command-line-tools，包含 HDC、
Hvigor、Node、SDK 和 HAP 签名工具；该目录不应复制到 Linux 主机，也不会进入本次
Linux 交付包。Linux 交付包只包含运行时清单、导入说明和程序源码，部署方应将匹配
版本的 Linux 工具包放到例如
`runtime/openharmony/linux-x64-7.0/`，或在设置页/环境变量中指定外部目录。默认目标为
`OpenHarmony-7.0-Release`；6.1 仅作为显式兼容版本，不会被自动回退使用。

## 2. 主机要求

必须具备：

* Linux x86_64；
* Python 3.11 或更高版本；
* Git；
* Go 1.25 或更高版本（只有从源码重新编译 Web/CLI 时需要）；
* 能访问所选模型服务的网络和凭据。

设备暴露面发现、源码定位中的设备协作和动态 HAP 验证还需要一块已连接的
OpenHarmony 开发板。Java 是 HAP 签名工具的宿主运行时。Python、Java、Go 属于
主机运行时，项目不捆绑平台解释器，但 Web 设置页会显示缺失项。

## 3. 首次启动

```bash
cd /path/to/VulnFounder
cp config/vulnfounder/config.example.json config/vulnfounder/config.json
chmod 600 config/vulnfounder/config.json
```

如果 Go 可用，构建本地 CLI：

```bash
cd apps/vulnfounder-cli
make build
cd ../..
```

启动 Web：

```bash
./apps/vulnfounder-cli/bin/vulnfounder serve --addr 127.0.0.1:18099
```

浏览器打开 `http://127.0.0.1:18099/`。如果尚未构建，也可以先执行
`go run ./apps/vulnfounder-cli serve --addr 127.0.0.1:18099`。

Python 包首次运行时会在 `result/venv` 创建受管虚拟环境并安装
`libs/vulnfounder-core`。也可以手动准备：

```bash
python3.11 -m venv result/venv
source result/venv/bin/activate       # Windows 使用 result\\venv\\Scripts\\activate
python -m pip install -e libs/vulnfounder-core
```

依赖版本参考 `libs/vulnfounder-core/requirements.txt`。生产环境建议使用固定的
Python 虚拟环境并提前缓存依赖。

如果部署环境无法访问 Python 包源，可以单独使用随交付提供的 Linux x86_64
Python 3.11 虚拟环境包：

```bash
unzip vulnfounder-python-venv-linux-x86_64-py311.zip -d /path/to/
```

该包会解压到 `VulnFounder/result/venv/`，其中已经安装当前版本的 Python 依赖和
分析引擎。它由 Linux x86_64、Python 3.11 构建，只适用于相同架构和兼容的 Python
运行时；不能在 macOS、ARM Linux 或其他 Python 主版本上直接复用。若部署主机的
Python 安装路径不同，建议按上面的手动步骤重新创建虚拟环境，而不是修改包内的
解释器链接。虚拟环境包不包含 OpenHarmony/HDC 工具链、模型凭据或项目扫描数据。

## 4. Web 设置

左侧菜单进入“设置”：

1. 在“模型管理”中新增或选择模型配置。API Key 只保存在本机配置或环境变量中，
   页面不会回显密钥。
2. 在“OpenHarmony 源码定位设置”中填写 OpenGrok HTTPS 地址、项目名、目标版本、
   超时、重试和认证环境变量名。页面不接受 URL 中的用户名、密码或令牌。

项目名填写 `*` 时表示查询 OpenGrok 索引中的全部项目；如果索引按多个顶层目录
（例如 `base`、`foundation`、`developtools`）组织，建议使用 `*`，不要填写
`openharmony` 这类并不存在于索引中的根目录名。也可以填写单个项目名或逗号分隔的
项目名来缩小检索范围。
3. 在“运行环境诊断”中确认 HDC、Hvigor、Node、HAP 签名工具和主机依赖均为可用。

OpenGrok 配置保存在 `config/vulnfounder/config.json` 的 `source_locator` 中；
本地配置文件必须保持 `0600` 权限，不应提交到版本库。

## 5. HAP 签名与开发板

动态测试默认优先使用 `config/hap_cert/` 中的正式材料：

```text
oh_release_chain.cer
oh_profile8.p7b
oh_release.p12
```

没有正式证书时，系统会从项目内 SDK 的公开测试根材料出发，根据当前 HDC serial
在每次 HAP 构建的临时目录生成设备绑定的 debug profile，完成签名校验后才继续。
用户不需要手工寻找 p7b。该材料只适用于受控研究设备，不代表生产证书；临时私钥
不会写入扫描报告，构建结束后会清理。

Linux 工具包导入后可用以下命令确认 HDC（路径以实际导入目录为准）：

```bash
runtime/openharmony/linux-x64-7.0/sdk/default/openharmony/toolchains/hdc list targets
```

也可以在设置页的“运行环境诊断”中确认工具来源。若部署方使用外部目录，设置
`VULNFOUNDER_DYNAMIC_TOOLCHAIN=/opt/openharmony-command-line-tools/linux-x64-7.0`；
若只需要设备枚举，也可以单独设置 `VULNFOUNDER_HDC`。工具包必须与 Linux 架构、
OpenHarmony 版本和 HAP 签名工具版本匹配，不能把 macOS 可执行文件重命名后使用。

如果存在多块设备，应在 Web 或 CLI 中明确选择 serial。HDC 路径解析顺序为：显式
环境变量 `VULNFOUNDER_HDC` → 项目内运行包 → 兼容目录 → 系统 PATH。

## 6. 三类常用操作

### 6.1 设备暴露面发现

在“设备暴露面发现”页面选择设备并开始扫描。系统通过 HDC 读取 Unix socket、
TCP/UDP 端点、进程、权限和 SELinux 信息，Agentic Loop 会记录命令、输出、任务树
和证据。结果写入 `result/exposure-surface/`，可在资产历史中查看。

阶段只负责资产发现，不会自动拉取源码或改变设备状态。

### 6.2 暴露面识别与源码定位

在“暴露面识别与源码定位”页面从设备资产中选择目标，或输入自定义 socket/端点。
阶段 1 识别设备事实；阶段 2 使用 OpenGrok 检索服务端实现、入口和仓库映射。用户
确认候选仓库后才会拉取源码，结果写入 `result/source-locator/`。

### 6.3 静态扫描

将源码仓库放入 `source_code_base/`，在“静态扫描”中选择仓库、处理级别和执行选项。
建议先用 `reachable` 验证入口召回，再按需开启 LLM 可达性、调用图恢复、Clang
语义辅助和 Stage 2。静态扫描的动态测试已独立到“动态测试”页面。

CLI 最小示例：

```bash
./apps/vulnfounder-cli/bin/vulnfounder scan source_code_base/<repo> \
  --level reachable --skip-dynamic-test --no-report
```

### 6.4 动态测试

动态测试从漏洞报告或 `pipeline_output.json` 进入，选择开发板、协议契约和安全授权。
系统会生成 HAP/其他载体、安装、发送协议帧、收集日志和设备产物，并按预言机给出
`CONFIRMED`、`NOT_REPRODUCED`、`BLOCKED` 或 `INCONCLUSIVE`。设备状态变更和载体
执行必须由用户显式授权。

## 7. 运行产物与备份

`result/` 保存扫描会话、阶段日志、证据、报告和动态测试交付物。它可整体备份或
清空重建，不应放入版本库。`source_code_base/` 是用户源码，也默认不提交。

可通过环境变量迁移运行数据：

```bash
export VULNFOUNDER_PROJECT_ROOT=/path/to/VulnFounder
export VULNFOUNDER_DATA_DIR=/path/to/vulnfounder-result
export VULNFOUNDER_CONFIG_FILE=/path/to/protected/config.json
```

## 8. 常见故障

| 现象 | 处理 |
|---|---|
| 找不到 Python | 安装 Python 3.11+，或设置 `VULNFOUNDER_PYTHON` |
| HDC 无设备 | 检查 USB/网络连接，执行 `hdc list targets`，并选择正确 serial |
| HAP 签名失败 | 查看设置页运行环境诊断；确认 Java、SDK 版本和设备 serial；正式证书需匹配目标设备 |
| OpenGrok 请求失败 | 在设置页检查 HTTPS 地址、项目名、目标版本、TLS 和令牌环境变量 |
| 模型认证失败 | 在模型管理中选择正确配置，检查 API Key 环境变量或本地配置权限 |
| Web 端口被占用 | 使用 `--addr 127.0.0.1:<port>` 更换端口 |

安全边界：不要把 API Key、P12 私钥、设备凭据、`config.json` 或 `result/` 产物加入
交付包。交付前执行敏感信息扫描，并只保留 `config.example.json`。
