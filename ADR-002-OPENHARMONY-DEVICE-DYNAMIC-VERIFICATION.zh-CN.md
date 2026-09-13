# ADR-002：OpenHarmony 开发板动态验证完整实施方案

## 状态

提议中（Proposed）

本文只记录设计和实施顺序。尚未开始 OpenHarmony 开发板动态验证功能的代码实现，也尚未在开发板上执行任何漏洞触发。

## 日期

2026-08-24

## 1. 文档目的

VulnFounder 当前已经能够对 OpenHarmony 源码执行解析、入口识别、调用图构建、上下文增强、漏洞分析、二次验证和报告生成，但现有动态测试功能面向 Docker 内的通用软件漏洞复现，不能直接验证真实 OpenHarmony 开发板上的 HAP、SA、IPC、HDF/HDI 或 Native socket 行为。

本文定义一套新的 OpenHarmony 开发板动态验证方案，目标是把静态扫描结果安全地转换为可以审计、可以分阶段执行、可以重复、可以回滚的真实设备验证流程。

本方案同时参考以下内容：

- 当前 VulnFounder 动态测试实现；
- VulnFounder 已生成的 OpenHarmony 静态扫描产物；
- 本地 OpenHarmony 源码仓库；
- `/Users/shiyu/学习/hyl/new/openharmony-dynamic-verify.zip` 经验交付包；
- 当前连接开发板所使用的 HDC 工具。

经验包只作为候选经验来源。文档、脚本或结论均需要通过源码、工具行为和真实设备结果重新验证。

## 2. 给初学者的术语说明

### 2.1 HDC

HDC 是 OpenHarmony 的设备连接工具，可以理解为 OpenHarmony 环境中的设备调试桥。它负责列出设备、执行设备端命令、发送文件、接收文件、安装 HAP 和采集日志。

### 2.2 HAP

HAP 是 OpenHarmony 应用安装包。普通应用通常通过 HAP 运行在应用沙箱中。HAP 的权限和 SELinux 身份与通过 HDC shell 执行的 Native 程序不同。

### 2.3 SA

SA 是 System Ability，即系统能力。许多 OpenHarmony 系统服务通过数字 SA ID 注册。例如 `sensors_medical_sensor` 的 SA profile 声明了 SA 3605。

### 2.4 IPC

IPC 是进程间通信。OpenHarmony 的 Stub、Proxy、`OnRemoteRequest` 和 `MessageParcel` 都与 IPC 有关。调用 IPC 时，不仅要知道函数名称，还要知道接口 token、transaction code 和 MessageParcel 字段顺序。

### 2.5 NAPI

NAPI 是 ArkTS/JavaScript 调用 Native C/C++ 能力的一种桥梁。如果 OpenHarmony 组件导出了 NAPI 函数，HAP 可以通过公开模块调用这些函数，再进入系统服务或 Native 逻辑。

### 2.6 HDF/HDI

HDF 是 OpenHarmony 驱动框架，HDI 是硬件设备接口。HDF/HDI 入口通常不能简单地用随机 socket 数据测试，需要使用生成的接口代码、设备节点协议或已有测试 client。

## 3. 当前 VulnFounder 动态测试的原始逻辑

当前实现位于：

- `libs/vulnfounder-core/core/dynamic_tester.py`
- `libs/vulnfounder-core/utilities/dynamic_tester/`
- `libs/vulnfounder-core/core/scanner.py`
- `apps/vulnfounder-cli/cmd/dynamictest.go`

现有流程如下：

```text
pipeline_output.json
    ↓
筛选 stage2_verdict 为 confirmed、agreed 或 vulnerable 的 finding
    ↓
LLM 根据 finding 生成 Dockerfile、测试脚本和依赖文件
    ↓
在隔离的 Docker 容器中 build 和 run
    ↓
解析容器 stdout 中的 JSON
    ↓
输出 CONFIRMED / NOT_REPRODUCED / BLOCKED / INCONCLUSIVE / ERROR
```

现有 Docker 执行器实现了只读文件系统、能力丢弃、资源限制、隔离网络、超时和 Docker Compose allowlist，这些设计适合通用 Web 服务、Python、JavaScript 和 Go 漏洞复现。

但是，它没有以下 OpenHarmony 开发板能力：

- HDC 设备选择；
- HDC server 状态检查；
- 设备 UID、SELinux domain 和调用者身份记录；
- HAP 构建、签名、安装、启动和卸载；
- OpenHarmony Native ELF 交叉编译和 ABI 校验；
- SA ID、IPC transaction code、接口 token 和 MessageParcel 协议构造；
- HDF/HDI client；
- 目标进程 PID、进程重启和 faultlog 关联；
- HiLog、dmesg、SELinux AVC、socket 和资源的前后快照；
- 静态 `finding_id` 与 `unit_id`、进程、SA、socket、NAPI API 的关联。

因此，不能直接把现有 `docker_executor.py` 改成通过 HDC 访问开发板。两个后端的权限模型、运行环境、风险等级和证据含义不同。

## 4. 经验交付包审计结论

### 4.1 经验包基本信息

文件：

```text
/Users/shiyu/学习/hyl/new/openharmony-dynamic-verify.zip
```

SHA-256：

```text
56acf5a4678a8a3808b26e6ad984b095a70b2f7914aa9ff09c2d9de7a30f4575
```

经验包实际包含以下主要内容：

- 设备信息采集脚本；
- Native UNIX socket client；
- 日志采集脚本；
- 正则形式的结果解析器；
- artifact manifest 示例；
- macOS、Docker 和 OpenHarmony 开发板操作说明。

### 4.2 可以采纳的原则

- 只在明确授权的开发板上执行；
- 先采集基线，再执行触发；
- macOS 主机负责 USB/HDC；
- Docker 负责构建、签名和离线分析；
- HDC shell/root、debug HAP、normal HAP 的结果必须分开；
- SELinux Enforcing 状态下的结果不能与 Permissive 混写；
- artifact 必须记录来源、架构和 SHA-256；
- 不关闭 SELinux；
- 不修改 `/system`；
- 不执行无限 fuzz；
- 不主动 kill `foundation`、`init`、`appspawn`、`samgr` 等关键系统进程；
- 动态日志自动解析只能作为初筛，不能替代人工证据审查。

### 4.3 不能直接采纳的问题

| 问题 | 实际影响 | VulnFounder 中的处理方式 |
|---|---|---|
| 文档声称存在 `02_hap_app`、`04_automation`、`project/`，压缩包实际缺少这些内容 | 不能直接完成 HAP 构建和自动化部署 | 在 VulnFounder 内重新实现最小 HAP harness 和自动化状态机 |
| 部分脚本调用未带 `-t <设备序列号>` 的 `hdc` | 多设备时可能误操作 | 统一 HDC client 强制指定设备 |
| 脚本使用 GNU `timeout` | macOS 默认不可用 | 使用 Python `subprocess` 超时和进程组回收 |
| 多处使用 `|| true` | 命令失败被吞掉 | 每条命令记录 stdout、stderr、exit code、timeout |
| `hilog -r` 会清空日志 | 破坏历史基线和现场证据 | 默认不清理日志，使用时间窗口和 run marker |
| socket client 使用固定临时文件 | 多次运行或并发时冲突 | 为每个 run 和 attempt 创建唯一远端目录 |
| fuzz 数据是通用随机、全 0、全 FF、格式字符串 | 不符合目标协议，也可能造成不必要风险 | 只使用协议感知、固定种子、有限次数的 payload |
| C client 未完整处理 partial send、超时和 errno | 可能把客户端失败误写成服务失败 | 重写传输循环并记录原始系统调用结果 |
| 正则将 SIGKILL、OOM、Process exited 等直接视为 crash | 容易混入历史日志或无关事件 | 使用 PID、时间窗口、faultlog 增量和服务健康联合判断 |
| 没有静态 unit/finding 关联 | 无法证明动态结果验证的是哪段源码 | 所有 attempt 同时记录 candidate、finding 和 unit |
| Native/root 结果与普通 HAP 结果未形成统一协议 | 容易把高权限可达误写成普通应用可利用 | caller identity 成为必填字段和结论组成部分 |

### 4.4 经验包的最终定位

经验包适合作为：

- 安全边界检查清单；
- macOS 与 Docker 分工参考；
- HDC、日志、artifact 操作示例；
- 初学者培训材料。

经验包不适合作为：

- VulnFounder 可直接调用的完整动态后端；
- 普通 HAP 可达性的证明；
- 自动漏洞确认器；
- OpenHarmony IPC 通用 fuzz 引擎。

## 5. 当前本机 HDC 实际状态

本机检测到 HDC：

```text
/Users/shiyu/harmonyos-sdk/openharmony/9/toolchains/hdc
Ver: 1.2.0a
```

但只读检查时：

```text
hdc list targets
Connect server failed
```

同时观察到本地 HDC server 的 PID 文件较旧，PID 51750 仍监听 `127.0.0.1:8710`，状态疑似异常或陈旧。

因此，当前只能确认 HDC 客户端存在，尚不能确认设备序列号、设备 API、CPU 架构、SELinux 状态或 shell 身份。真实设备阶段前需要先恢复 HDC server：

```bash
hdc kill
hdc start
hdc list targets -v
hdc -t <设备序列号> shell id
```

如果仍然失败，应先诊断 HDC server 和 USB 连接。VulnFounder 不应自动删除 PID 文件，也不应自动重启开发板。

## 6. 核心架构决策

### 6.1 决策一：新增独立的 OpenHarmony 动态后端

保留现有模块：

```text
utilities/dynamic_tester/
```

新增模块：

```text
utilities/openharmony_dynamic/
```

职责划分：

| 后端 | 用途 |
|---|---|
| `dynamic_tester` | Docker 内的通用软件漏洞复现 |
| `openharmony_dynamic` | 通过 HDC 对真实 OpenHarmony 开发板进行验证 |

两个后端可以共享 finding 筛选、LLM registry、step report 和最终报告接口，但不能共享执行器和证据判定规则。

### 6.2 决策二：开发板验证不会由普通 scan 自动触发

当前 `vulnfounder scan` 可以运行通用 Docker 动态测试。开发板动态验证具有安装 HAP、推送 ELF、调用系统服务和改变设备运行状态等副作用，因此必须显式选择设备、身份、候选和风险等级。

开发板动态验证默认关闭，不能因为 `--platform openharmony` 就自动启用。

### 6.3 决策三：HDC 只在 macOS 主机执行

推荐分工：

```text
macOS 主机
    ├── HDC server
    ├── 设备选择和串行锁
    ├── file send / recv
    ├── shell / install / uninstall
    └── 实时日志采集

Docker
    ├── Linux OpenHarmony SDK
    ├── HAP 构建和签名
    ├── Native 交叉编译
    ├── ELF 分析
    └── 日志离线分析
```

不要求 Docker Desktop 直接透传 USB，也不通过 `--privileged` 扩大容器权限。

### 6.4 决策四：静态候选先编译为安全计划，再允许执行

LLM 或静态分析结果不能直接变成 HDC 命令。必须先生成 `candidate_plan.json`，经过 schema、源码证据、adapter 能力和风险策略校验后，才能进入设备执行阶段。

### 6.5 决策五：身份是结论的一部分

以下身份分别记录：

- `native_privileged`：HDC shell/root 或高权限 Native 程序；
- `native_unprivileged`：低权限 Native 测试进程；
- `debug_hap`：调试签名 HAP；
- `normal_hap`：普通或 release-like HAP；
- `system_hap`：具有系统签名或系统权限的 HAP；
- `system_service`：系统服务内部触发。

高权限身份能够触发不代表普通应用可利用。

## 7. 新动态验证完整流程

```text
pipeline_output.json
dataset_enhanced.json
call_graph.json
platform_profile.json
    ↓
OpenHarmony Candidate Compiler
    ↓
candidate_plan.json
    ↓
设备和工具链预检
    ↓
只读基线
    ↓
构建并校验 HAP / Native artifact
    ↓
安装或推送
    ↓
合法 baseline 触发
    ↓
有限边界触发
    ↓
响应、PID、HiLog、faultlog、SELinux、资源前后对比
    ↓
证据关联和结论分级
    ↓
清理和恢复确认
    ↓
JSON / Markdown / HTML / Web 展示
```

运行状态机：

```text
PLANNED
  → PREFLIGHTED
  → BASELINED
  → ARTIFACT_READY
  → DEPLOYED
  → BASELINE_TRIGGERED
  → TARGET_TRIGGERED
  → OBSERVED
  → ANALYZED
  → CLEANED
  → COMPLETED
```

任何阶段都可以进入：

```text
ABORTED
BLOCKED
INFRA_ERROR
SAFETY_STOPPED
```

## 8. 动态候选数据模型

### 8.1 DynamicCandidate

```json
{
  "schema_version": "1.0",
  "candidate_id": "OH-CAND-001",
  "finding_ids": ["VULN-001"],
  "unit_id": "path/file.cpp:Class::Function",
  "source": {
    "file": "path/file.cpp",
    "function": "Class::Function",
    "start_line": 32,
    "end_line": 53,
    "commit_sha": null
  },
  "entry": {
    "kind": "binder_ipc_stub",
    "entry_point_reason": "platform:openharmony:binder_ipc",
    "boundary": ["binder_ipc"],
    "guards": ["interface_token"]
  },
  "target": {
    "component": "samgr",
    "build_target": "samgr_proxy",
    "process": null,
    "library": "libsamgr_proxy.z.so",
    "sa_id": null,
    "socket": null
  },
  "adapter": "ipc_proxy",
  "allowed_identities": ["native_system", "debug_hap", "normal_hap"],
  "input_contract": {
    "transaction_code": null,
    "interface_token": null,
    "parcel_fields": []
  },
  "risk_tier": "benign",
  "confidence": 0.0,
  "limitations": []
}
```

### 8.2 候选入口类型

- `napi_entry`：ArkTS/JavaScript 可调用的 Native API；
- `binder_ipc_stub`：`OnRemoteRequest`、Proxy/Stub；
- `sa_lifecycle`：System Ability 生命周期和注册入口；
- `unix_socket`：UNIX domain socket 服务；
- `hdf_hdi`：驱动和硬件接口；
- `cli_dump`：dump、hidumper 或命令入口；
- `fuzz_target`：源码自带的 fuzz target；
- `unsupported_internal`：内部函数，当前没有可靠外部触发路径。

### 8.3 候选可执行性状态

- `ELIGIBLE`：协议、入口、身份和目标均已确认；
- `REQUIRES_HAP`：需要构建或提供 HAP；
- `REQUIRES_NATIVE_ARTIFACT`：需要 Native client；
- `REQUIRES_PROTOCOL_REVIEW`：字段或 transaction code 不完整；
- `PERMISSION_EXPECTED`：预计会被权限阻断，但可以验证边界；
- `SOURCE_FIRMWARE_MISMATCH`：源码与设备固件不能对应；
- `UNSUPPORTED`：当前没有安全、可靠的触发方式；
- `NEEDS_HUMAN_APPROVAL`：高风险，需要人工确认。

## 9. HDC 执行层设计

### 9.1 统一调用方式

所有设备操作必须通过统一客户端：

```python
run_hdc(
    device_id=device_id,
    args=["shell", "id"],
    timeout_seconds=10,
)
```

禁止拼接任意 shell 字符串：

```python
os.system("hdc shell " + user_input)
```

### 9.2 必须具备的能力

- 强制指定设备序列号；
- 不允许空设备 ID；
- 使用参数数组启动进程；
- Python 层实现超时；
- 超时后回收 HDC 子进程组；
- 记录命令开始、结束、耗时和退出状态；
- 记录 stdout 和 stderr 文件路径；
- 对每台设备加独占锁；
- 设备断开后停止当前运行；
- 对可重试和不可重试错误进行区分；
- 命令输出进行敏感字段脱敏；
- 所有命令写入 `commands.jsonl`；
- 禁止用户通过 Web 传入任意远端命令。

### 9.3 禁止自动执行的命令

- `hdc smode`；
- 关闭 SELinux；
- `target mount`；
- 修改 `/system` 或 `/vendor`；
- 重启开发板；
- kill 关键系统服务；
- 删除 `/data/local/tmp` 整个目录；
- 安装来源和 hash 未确认的 HAP 或 ELF。

## 10. 设备预检和基线

### 10.1 预检字段

- HDC 版本；
- 设备序列号；
- 设备连接状态；
- shell UID/GID；
- shell SELinux domain；
- SELinux Enforcing/Permissive；
- OpenHarmony API 版本；
- 产品型号；
- build fingerprint；
- CPU 架构；
- 内核版本；
- 设备时间；
- 剩余磁盘；
- 目标进程；
- 目标 socket；
- 可用的 `hilog`、`hidumper`、`ss`、`dmesg`、`bm` 和 `aa` 命令。

### 10.2 预检停止条件

- 没有唯一设备且用户未明确指定序列号；
- HDC server 异常；
- 设备处于 offline/unauthorized；
- SELinux 状态未知；
- 设备空间不足；
- 目标服务在测试前已经反复崩溃；
- 源码版本无法与固件建立对应关系；
- payload 含义未知；
- 无法完成清理或恢复；
- 用户没有确认当前开发板属于授权范围。

## 11. Artifact 构建与管理

### 11.1 Native ELF

Native artifact 必须记录：

- 源码路径；
- 编译器版本；
- OpenHarmony SDK 版本；
- target triple；
- sysroot；
- CPU 架构；
- ELF interpreter；
- 依赖库；
- 文件大小；
- SHA-256；
- 构建日志；
- 预期设备路径。

推送后需要校验远端大小和 hash，不能只看 `hdc file send` 的返回码。

### 11.2 HAP

HAP artifact 必须记录：

- bundle name；
- ability name；
- target API；
- compatible API；
- 请求权限；
- debug/release 类型；
- 签名证书摘要；
- HAP SHA-256；
- 构建日志；
- 签名验证结果。

私钥、密码和完整签名材料不写入 Git，不写入 Docker 镜像，也不复制到动态测试结果中。配置只保存路径或证书公开摘要。

### 11.3 远端目录

每次运行使用唯一目录：

```text
/data/local/tmp/vulnfounder/<run_id>/<attempt_id>/
```

清理时只删除本轮明确创建的文件，不使用通配符删除其他文件。

## 12. 动态触发适配器

### 12.1 HAP NAPI Adapter

适用于源码包含以下信号的组件：

- `DECLARE_NAPI_FUNCTION`；
- `napi_module`；
- ArkTS/JS module 注册；
- NAPI 函数继续调用 Native client 或 system ability。

执行流程：

```text
确认导出 API
  → 生成最小 HAP harness
  → 构建和签名
  → 安装
  → 启动 Ability
  → 执行合法 baseline
  → 执行有限边界参数
  → 采集应用与服务证据
  → force-stop 和卸载
```

### 12.2 IPC/SA Adapter

适用于：

- `OnRemoteRequest`；
- `IRemoteBroker`；
- `IPCObjectStub`；
- Stub/Proxy；
- IDL 生成接口；
- SA profile。

构造请求必须优先使用：

1. 源码已有 Proxy；
2. IDL 生成的 client；
3. 源码测试中的 client；
4. 根据 Stub/Proxy 共同确认的手工 MessageParcel schema。

不能仅凭 `OnRemoteRequest` 的参数名称就随机写入 MessageParcel。

### 12.3 Native UNIX Socket Adapter

只有在以下条件满足时才执行：

- 设备 socket 确实存在；
- 源码确认 socket 的服务端；
- 目标进程和 PID 已确认；
- 协议 framing 已确认；
- 有合法最小请求；
- 调用者身份已确认；
- SELinux 和 DAC 信息已记录。

第一版不提供默认随机 fuzz。

### 12.4 HDF/HDI Adapter

优先使用生成的 HDI client 或源码已有测试程序。设备节点权限、socket 权限或 HDF 注册信息只能作为候选证据，不能单独证明外部输入可达。

### 12.5 SA 生命周期和 Dump Adapter

用于验证 SA 是否存在、进程是否加载、dump 命令是否可达。该适配器默认只读，不把 `OnStart`、`OnStop` 或 `OnDump` 自动当作漏洞触发入口。

## 13. 真实源码试点设计

### 13.1 sensors_medical_sensor

`source_code_base/sensors_medical_sensor/sa_profile/3605.xml` 声明：

```text
process: sensors
system ability: 3605
library: libmedical_service.z.so
```

`interfaces/plugin/src/medical_js.cpp` 导出：

```text
on
setOpt
off
```

它适合作为第一个 HAP 链路试点，因为公开 NAPI、目标 SA 和服务进程都相对明确。

建议测试顺序：

1. 安装并启动不调用任何系统 API 的最小 HAP；
2. 确认 HAP 的 UID、PID 和 SELinux domain；
3. 使用合法传感器类型调用一次 `on`；
4. 调用 `off` 清理；
5. 记录 `sensors` 服务 PID 前后状态；
6. 再测试少量明确边界值；
7. 分别记录 debug HAP 与 normal HAP 结果。

该仓库最近一次静态扫描没有产生 finding，因此这个试点验证的是动态基础设施和可达性，不是漏洞复现。

### 13.2 systemabilitymgr_samgr

当前实际静态扫描产生过两个 finding：

- `SystemAbilityLoadCallbackStub::OnRemoteRequest`；
- `SystemAbilityLoadCallbackStub::OnLoadSACompleteForRemoteInner`。

当前调用图中，`OnRemoteRequest` 已解析到四个 handler 和 `EnforceInterceToken`。

但 `system_ability_load_callback_stub.cpp` 被编译进 `samgr_proxy` library target。它可能在持有 callback stub 的调用方进程执行，不能直接把仓库名 `samgr` 当作运行进程。

`OnLoadSACompleteForRemoteInner` 按源码读取：

```text
string deviceId
int32 systemAbilityId
bool result
IRemoteObject remoteObject
```

因此动态验证需要先回答：

- callback object 由谁创建；
- 哪个 Proxy 持有它；
- transaction code 的真实数字值；
- interface token；
- 普通 HAP 是否能够获取该对象；
- 实际执行函数的目标进程。

第一轮只做只读和权限边界验证，不对 samgr 关键控制面执行随机 fuzz。

## 14. Payload 策略

### 14.1 默认测试顺序

```text
合法最小请求
  → 合法重复请求
  → 缺少一个可选字段
  → 类型允许范围的边界值
  → 长度边界附近的小规模样本
  → 明确授权后的安全变异
```

### 14.2 第一版禁止的 payload 行为

- 无限随机；
- 无固定种子；
- 无总时长限制；
- 无速率限制；
- 未知协议上的 `%n` 或任意格式字符串；
- 大尺寸内存/磁盘消耗；
- 对 `init`、`appspawn`、`foundation`、`samgr` 的广泛 fuzz；
- 可能导致设备重启或持久化修改的 payload。

### 14.3 可重复性

每个 payload 记录：

- 语义说明；
- 原始 bytes 的 SHA-256；
- 长度；
- 生成规则；
- seed；
- 目标 adapter；
- 发送时间；
- 是否属于 baseline；
- 预期响应或安全控制。

## 15. 日志和证据采集

### 15.1 默认不清空 HiLog

VulnFounder 不默认执行 `hilog -r`。运行前先探测当前设备支持的 `hilog` 参数，再选择时间窗口或流式采集方式。

### 15.2 Run Marker

每次运行生成唯一 `run_id`，HAP 和 Native harness 尽量在自己的日志中打印该标识。设备不支持 marker 的日志源必须使用前后快照和时间窗口关联。

### 15.3 需要采集的证据

- HAP/Native 测试程序 stdout 和 stderr；
- 请求结果和响应长度；
- target process PID；
- `/proc/<pid>` 可用信息；
- `ps -A` 和必要时的 `ps -Z`；
- HiLog；
- dmesg；
- faultlog 文件列表和新增文件；
- SELinux AVC；
- socket 列表；
- 服务健康检查；
- 磁盘和资源状态；
- HDC 连接状态。

### 15.4 崩溃关联条件

不能因为日志里出现 `SIGSEGV` 就写成确认。至少需要：

- 日志时间位于本轮触发窗口；
- 进程名或 PID 与目标一致；
- faultlog 是本轮新增；
- 触发前服务正常；
- 触发后出现 PID 消失、重启或明确异常；
- 同一条件可以重复；
- 排除测试客户端自身崩溃。

## 16. 动态结论和证据等级

### 16.1 结论状态

- `REPRODUCED_NORMAL_APP`：普通 HAP 可以到达并产生安全影响；
- `REPRODUCED_DEBUG_HAP`：只有调试 HAP 能复现；
- `REPRODUCED_NATIVE_PRIVILEGED`：只有 HDC shell/root Native 能复现；
- `SERVICE_FAULT_CORRELATED`：目标服务发生与本轮请求关联的异常；
- `PERMISSION_BLOCKED`：DAC、SELinux 或业务权限阻断；
- `NOT_REPRODUCED`：正确执行测试但没有出现预期安全影响；
- `INCONCLUSIVE`：执行完成但证据不足；
- `INFRA_ERROR`：HDC、构建、安装或测试工具失败；
- `SOURCE_FIRMWARE_MISMATCH`：源码和设备固件不匹配；
- `UNSUPPORTED_TRANSPORT`：没有可靠触发通道。

### 16.2 证据等级

| 等级 | 含义 |
|---|---|
| A | normal/release-like HAP 可达，安全影响明确，可重复 |
| B | debug HAP 可达，安全影响明确，可重复 |
| C | Native 高权限身份可达，安全影响明确，但不代表普通应用 |
| D | 只有服务异常或权限日志，因果证据不足 |
| E | 仅静态推断或未关联日志 |

### 16.3 `NOT_REPRODUCED` 的约束

只有测试 adapter、artifact、权限、目标版本和合法 baseline 均正常时，才可以写 `NOT_REPRODUCED`。

以下情况不能写成 `NOT_REPRODUCED`：

- HDC 断开；
- HAP 没有安装成功；
- 调用被权限阻断；
- 目标组件不在设备上；
- 源码与固件版本不匹配；
- 客户端协议不确定；
- 测试超时且不知道请求是否送达。

## 17. 输出目录和 JSON 协议

每次动态运行保存到扫描目录下：

```text
<scan_dir>/openharmony_dynamic/<run_id>/
├── run.json
├── candidate_plan.json
├── device_preflight.json
├── commands.jsonl
├── baseline/
│   ├── processes.json
│   ├── sockets.json
│   ├── selinux.json
│   └── faultlog_index.json
├── artifacts/
│   └── manifest.json
├── attempts/
│   └── <candidate_id>/<attempt_id>/
│       ├── request.json
│       ├── response.json
│       ├── before.json
│       ├── after.json
│       ├── hilog.txt
│       ├── dmesg.txt
│       ├── faultlog/
│       └── observation.json
├── dynamic_test_results.json
├── DYNAMIC_TEST_RESULTS.zh-CN.md
└── DYNAMIC_TEST_RESULTS.en.md
```

### 17.1 run.json

```json
{
  "schema_version": "1.0",
  "run_id": "OH-RUN-20260824-001",
  "repository": {
    "name": "sensors_medical_sensor",
    "path": "source_code_base/sensors_medical_sensor",
    "commit_sha": null
  },
  "device": {
    "serial_hash": "...",
    "model": "...",
    "api_version": "...",
    "build_fingerprint": "...",
    "arch": "...",
    "selinux": "Enforcing",
    "shell_identity": "..."
  },
  "caller_identity": "normal_hap",
  "risk_tier": "benign",
  "hdc_version": "1.2.0a",
  "candidate_plan_sha256": "...",
  "artifacts": [],
  "attempts": [],
  "started_at": "...",
  "ended_at": null,
  "final_status": "RUNNING"
}
```

### 17.2 observation.json

```json
{
  "attempt_id": "ATTEMPT-001",
  "candidate_id": "OH-CAND-001",
  "finding_ids": ["VULN-001"],
  "unit_id": "path/file.cpp:Class::Function",
  "caller_identity": "normal_hap",
  "payload_sha256": "...",
  "request_result": {},
  "response_result": {},
  "target_process_before": {},
  "target_process_after": {},
  "new_faultlogs": [],
  "correlated_events": [],
  "status": "INCONCLUSIVE",
  "evidence_grade": "D",
  "limitations": []
}
```

## 18. LLM 在动态验证中的角色

### 18.1 可以使用 LLM 的位置

LLM 可以作为协议和测试计划顾问，输入包括：

- 目标 unit 源码；
- Stub 和 Proxy；
- transaction code 定义；
- IDL；
- 调用图；
- `platform_context`；
- guard signals；
- 相关 BUILD.gn 和 SA profile。

LLM 输出包括：

- 可能的入口类型；
- 字段读取顺序；
- 参数语义；
- 合法 baseline；
- 安全边界测试建议；
- 预期返回值；
- 预期 guard；
- 代码文件和行号证据；
- 置信度和未知项。

### 18.2 LLM 不能直接控制的内容

- 任意 HDC shell；
- 任意远端文件路径；
- 设备 root 或 SELinux 状态；
- HAP 签名和安装授权；
- 任意二进制 payload；
- 无限 fuzz；
- 动态结论最终等级。

### 18.3 LLM 输出校验

所有输出必须经过：

1. JSON schema 校验；
2. 文件和函数索引校验；
3. transaction code 来源校验；
4. MessageParcel 字段与源码校验；
5. adapter 能力校验；
6. 风险等级校验；
7. 高风险人工批准。

LLM 输出无法被源码验证时，候选状态为 `REQUIRES_PROTOCOL_REVIEW`，不能直接运行。

## 19. 建议模块结构

```text
libs/vulnfounder-core/
├── core/
│   └── openharmony_dynamic_tester.py
└── utilities/
    └── openharmony_dynamic/
        ├── __init__.py
        ├── models.py
        ├── candidate_compiler.py
        ├── hdc_client.py
        ├── device_lock.py
        ├── preflight.py
        ├── baseline.py
        ├── artifacts.py
        ├── observation.py
        ├── correlation.py
        ├── verdict.py
        ├── runner.py
        ├── reporter.py
        └── adapters/
            ├── base.py
            ├── hap_napi.py
            ├── ipc_proxy.py
            ├── native_socket.py
            ├── hdf_hdi.py
            └── sa_lifecycle.py

apps/vulnfounder-cli/
├── cmd/
│   └── ohosdynamic.go
└── internal/server/
    └── OpenHarmony dynamic endpoints and stage integration
```

新增 `OpenHarmonyDynamicStepResult`，不要强行把设备字段塞入现有 Docker `DynamicTestResult`。

## 20. CLI 设计

建议提供分阶段命令：

```bash
vulnfounder ohos-dynamic preflight \
  --device <serial> \
  --output <run-dir>

vulnfounder ohos-dynamic plan \
  <pipeline_output.json> \
  --repo <repo-path> \
  --output <run-dir>

vulnfounder ohos-dynamic build \
  --plan <candidate_plan.json> \
  --candidate OH-CAND-001

vulnfounder ohos-dynamic baseline \
  --device <serial> \
  --run <run-dir>

vulnfounder ohos-dynamic run \
  --device <serial> \
  --run <run-dir> \
  --candidate OH-CAND-001 \
  --identity normal_hap \
  --risk benign

vulnfounder ohos-dynamic analyze \
  --run <run-dir>

vulnfounder ohos-dynamic cleanup \
  --device <serial> \
  --run <run-dir>
```

允许用户单独执行阶段，避免一次性走到底。

## 21. Web 设计

Web 中增加独立的“开发板动态验证”阶段，而不是复用通用 Docker 动态测试页面。

### 21.1 页面区域

- 设备连接状态；
- HDC server 状态；
- 设备型号、API、架构、SELinux；
- 候选列表；
- 每个候选对应的静态函数和调用图；
- 入口类型和目标进程；
- 所需 artifact；
- 调用者身份选择；
- 风险等级；
- 执行时间线；
- 原始请求和响应；
- 前后进程状态；
- HiLog、faultlog 和 SELinux AVC；
- 结论、证据等级和限制；
- 原始 JSON 和原始日志下载。

### 21.2 Web 安全边界

- 不允许提交任意 shell 字符串；
- 设备序列号来自 HDC 枚举结果；
- 每台设备一次只运行一个任务；
- 安装、触发、边界测试分别确认；
- 高风险测试需要二次确认；
- 取消任务时进入安全停止和 cleanup；
- 私钥和密码不显示、不写日志；
- artifact 必须位于允许目录且 hash 已校验；
- 历史运行保留，不覆盖上一轮证据。

## 22. 分阶段实施计划

所有阶段遵循既定协作方式：修改前说明原逻辑和修改后逻辑，得到用户同意后执行；每阶段只改一个小范围；阶段完成后单独测试并产生测试记录。

### OH-DYN-01：数据模型和 HDC 客户端

范围：

- 新增候选、设备、运行、尝试和证据模型；
- 新增统一 HDC client；
- 新增设备独占锁；
- 新增 fake HDC；
- 不连接真实设备；
- 不发送文件；
- 不安装 HAP。

测试：

- 强制 device ID；
- 参数数组和 shell 注入测试；
- stdout/stderr/exit code；
- 超时；
- 进程组回收；
- 单设备串行；
- 多设备隔离；
- HDC 不存在和 server 连接失败；
- 输出脱敏。

验收：HDC 基础层可以可靠失败，不会误操作其他设备。

### OH-DYN-02：设备只读预检和基线

范围：

- 实现 preflight；
- 实现 baseline；
- 记录设备指纹；
- 能力探测；
- 停止条件；
- 真实开发板只读测试。

验收：不改变设备配置，可以重复生成相同结构的基线产物。

### OH-DYN-03：观察和证据关联

范围：

- HiLog 采集；
- dmesg 可用性探测；
- faultlog 前后索引；
- PID 和进程重启检测；
- run marker；
- 日志时间窗口；
- 历史日志排除；
- fixture 日志测试。

验收：历史 crash 不会被判定为本轮 crash；客户端错误不会被判定为服务错误。

### OH-DYN-04：Native Artifact Adapter

范围：

- OpenHarmony Native 交叉编译接口；
- ELF 架构和 interpreter 检查；
- artifact manifest；
- 唯一远端目录；
- 远端 hash；
- 精确 cleanup。

真实设备测试：只推送并运行一个无害的 `--version`/退出码 0 工具。

### OH-DYN-05：最小 HAP Adapter

范围：

- 最小 HAP 工程模板；
- 外置签名配置；
- 构建、验证、安装、启动、force-stop、卸载；
- normal/debug identity 记录；
- 无操作 HAP 测试；
- `sensors_medical_sensor` NAPI 合法 baseline。

验收：能够证明普通 HAP 是否真正到达公开 API，并完整清理。

### OH-DYN-06：IPC/SA Adapter

范围：

- Proxy/Stub/IDL 协议发现；
- transaction code 解析；
- interface token；
- MessageParcel 字段 schema；
- SA 获取；
- 权限阻断分类；
- `systemabilitymgr_samgr` 只读/权限试点。

验收：不会把未知 transaction code 或未知 Parcel 协议直接发送到设备。

### OH-DYN-07：静态结果到动态候选编译

范围：

- 联合 `pipeline_output.json`；
- 联合 `dataset_enhanced.json`；
- 联合 `call_graph.json`；
- 联合 `platform_profile.json`；
- 联合 bundle、BUILD.gn、IDL 和 SA profile；
- 生成 `candidate_plan.json`；
- 支持人工修正和重新校验。

真实源码测试：

- `sensors_medical_sensor`；
- `systemabilitymgr_samgr`；
- 后续从其他 OpenHarmony 仓库选择 NAPI、IPC、socket 和 HDF 各一个样本。

### OH-DYN-08：结论、报告和 Web

范围：

- 证据分级引擎；
- 动态结果 JSON；
- 中英文 Markdown 报告；
- 报告数据合并；
- Web 设备状态；
- 候选列表；
- 执行时间线；
- 原始日志与友好视图；
- 历史动态运行。

验收：用户可以从 finding 一直追踪到 unit、入口、artifact、设备身份、每次请求和最终结论。

### OH-DYN-09：有限边界测试

范围：

- 固定种子；
- 固定 payload 集；
- 请求次数上限；
- 速率上限；
- 总时长上限；
- 服务健康检查；
- 日志/磁盘/内存阈值；
- 自动 safety stop。

该阶段不包含无限 fuzz，也不默认测试关键系统控制面。

### OH-DYN-10：全流程集成和交付

范围：

- CLI 和 Web 完整串联；
- 项目内相对路径；
- 配置模板；
- SDK/签名材料外置说明；
- 安装说明；
- 故障排查；
- 脱敏和打包检查；
- 回归测试；
- 最终交付文档。

## 23. 阶段依赖关系

```text
OH-DYN-01 数据模型/HDC
    ├── OH-DYN-02 设备预检
    ├── OH-DYN-03 观察系统
    ├── OH-DYN-04 Native artifact
    └── OH-DYN-07 候选编译

OH-DYN-02 + OH-DYN-03 + OH-DYN-04
    ├── OH-DYN-05 HAP adapter
    └── OH-DYN-06 IPC/SA adapter

OH-DYN-05 + OH-DYN-06 + OH-DYN-07
    └── OH-DYN-08 结论/报告/Web

OH-DYN-08
    ├── OH-DYN-09 有限边界测试
    └── OH-DYN-10 全流程交付
```

## 24. 每阶段测试记录协议

每阶段创建：

```text
test_records/ohos-dynamic/
├── OH-DYN-01-hdc-client-YYYY-MM-DD.md
├── OH-DYN-02-device-preflight-YYYY-MM-DD.md
├── OH-DYN-03-observation-YYYY-MM-DD.md
├── OH-DYN-04-native-artifact-YYYY-MM-DD.md
├── OH-DYN-05-hap-adapter-YYYY-MM-DD.md
├── OH-DYN-06-ipc-sa-adapter-YYYY-MM-DD.md
├── OH-DYN-07-candidate-compiler-YYYY-MM-DD.md
├── OH-DYN-08-report-web-YYYY-MM-DD.md
├── OH-DYN-09-boundary-tests-YYYY-MM-DD.md
└── OH-DYN-10-end-to-end-YYYY-MM-DD.md
```

每份记录必须包括：

- 阶段目标；
- 修改前逻辑；
- 修改后逻辑；
- 修改文件；
- 测试环境；
- 测试命令；
- 设备指纹哈希；
- artifact SHA-256；
- 测试输入；
- 原始产物路径；
- 预期结果；
- 实际结果；
- 通过/失败；
- 已知限制；
- 清理结果；
- 是否允许进入下一阶段。

## 25. 测试策略

### 25.1 单元测试

- JSON schema；
- HDC 参数构造；
- 设备锁；
- 超时和进程回收；
- 输出脱敏；
- candidate mapping；
- transaction code 解析；
- MessageParcel 字段提取；
- PID/faultlog 时间关联；
- verdict 状态机；
- cleanup allowlist。

### 25.2 Fake HDC 集成测试

使用本地 fake `hdc` 可执行程序模拟：

- 单设备；
- 多设备；
- offline；
- unauthorized；
- shell 成功；
- shell 失败；
- 命令超时；
- file send 中断；
- install 失败；
- 设备中途断开；
- stdout/stderr 含非法编码；
- HDC server 无法连接。

### 25.3 日志 fixture 测试

- 历史 SIGSEGV；
- 目标服务本轮崩溃；
- 测试 client 自身崩溃；
- unrelated OOM；
- SELinux AVC；
- permission denied；
- 服务 PID 重启；
- 无 faultlog；
- 日志时间戳不完整；
- dmesg 不可读。

### 25.4 真实设备递进测试

```text
只读预检
  → 无害 Native 工具
  → 空操作 HAP
  → sensors 合法 NAPI
  → sensors 有限边界参数
  → samgr IPC 只读/权限边界
  → 经过审批的具体漏洞候选
```

## 26. 运行安全和停止条件

出现以下任意条件立即停止当前 candidate：

- HDC 断开；
- 设备重启；
- 目标关键服务 PID 消失或反复重启；
- 新增关联的 SIGSEGV、SIGABRT、panic 或 watchdog；
- 未知 faultlog 快速增长；
- 日志或磁盘空间快速下降；
- 测试客户端无响应且无法确认请求状态；
- payload 与批准计划不一致；
- 调用者身份发生变化；
- SELinux 状态发生变化；
- 无法完成 cleanup；
- 用户主动取消。

停止后只执行安全、精确的清理，不自动重启系统服务或开发板。

## 27. 隐私和敏感信息

默认不采集：

- 私钥和签名密码；
- 完整用户数据；
- 与候选无关的应用日志；
- 设备唯一序列号明文进入报告；
- `/etc/app/install_list_capability.json` 等敏感全量配置；
- 与本轮无关的历史 faultlog 内容。

设备序列号在报告中保存 hash；如现场需要明文，仅写入不进入 Git 的本地运行元数据。

## 28. 与报告流水线的关系

动态结果必须同时关联：

- `finding_id`；
- `unit_id`；
- source file/function/line；
- entry type；
- caller identity；
- adapter；
- target process/SA/socket；
- artifact；
- payload；
- attempt；
- evidence；
- verdict；
- limitations。

最终漏洞报告不能只显示“动态确认”，而应显示类似：

```text
动态结果：REPRODUCED_NATIVE_PRIVILEGED
证据等级：C
调用身份：HDC shell/native
普通 HAP 可达性：未验证
目标进程：xxx
复现次数：3/3
限制：该结果不能证明普通第三方应用可利用
```

## 29. 第一版最小可用闭环

第一版应聚焦以下闭环：

```text
静态 finding/unit
  → candidate plan
  → 指定设备
  → 只读预检
  → 合法 baseline
  → 单次触发
  → 日志/PID/faultlog 前后关联
  → 分级结论
  → cleanup
  → Web/JSON/Markdown 查看
```

第一版暂不承诺：

- 覆盖所有 OpenHarmony IPC 变体；
- 覆盖所有 HDF 驱动；
- 自动生成可利用 exploit；
- 自动 fuzz 关键系统服务；
- 从高权限 Native 结果推断普通 HAP 可利用；
- 在源码与设备固件不匹配时给出强结论。

## 30. 建议的下一步

从 OH-DYN-01 开始：只实现数据模型、统一 HDC 客户端、设备锁和 fake HDC 单元测试。

该阶段不连接设备、不推送文件、不安装 HAP、不触发系统服务。开始修改前，需要先向用户说明：

- 原项目动态测试只支持 Docker；
- 新增 HDC 层不会替换或影响原 Docker 动态测试；
- HDC client 的安全边界；
- 本阶段具体文件和测试范围。

得到用户同意后再执行 OH-DYN-01。

## 31. 决策总结

本 ADR 选择：

- 保留原 Docker 动态测试；
- 新增独立 OpenHarmony 开发板动态后端；
- HDC 在 macOS 主机执行；
- Docker 只负责构建和离线分析；
- 开发板动态测试默认关闭且显式授权；
- 所有测试按调用者身份分级；
- 静态结果先生成受约束的 candidate plan；
- 协议感知 payload 优先于通用随机 fuzz；
- 日志必须通过 PID、时间窗口和前后快照关联；
- LLM 只作为受约束的计划顾问；
- 每个阶段单独修改、单独测试、单独记录；
- 先完成可运行的低风险闭环，再考虑高风险优化。
