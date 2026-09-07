# OpenAnt 评测数据集建设计划：暴露面识别（第一阶段）

版本：v0.1
日期：2026-09-04
状态：待批准的实现计划，尚未生成正式评测金标准
范围：只建设 evaluation_dataset/exposure；不修改漏洞源码，不新增预埋漏洞

## 1. 目标与验收结果

本阶段要建立一套可离线复现、可自动校验的暴露面识别数据集，用来评估
OpenAnt 是否能够完成下面的完整任务：

1. 在真实 OpenHarmony 开发板上发现正在运行的 TCP、UDP 和命名 Unix Socket；
2. 正确规范化套接字类型、协议、地址或路径、运行状态、关联进程和可观察权限；
3. 通过源码证据确认服务端创建、注册或启动关系，而不是仅凭 socket 名称猜测；
4. 将 socket 映射到正确的 OpenHarmony Gitee 源码仓库，并记录准确版本；
5. 输出带文件路径、行号、源码片段和证据关系的可追溯答案；
6. 在字段不可观察时输出“未知”或“不适用”，不能用模型猜测填充事实。

评测对象是“发现、归因、仓库定位、证据引用”能力，不在本数据集内直接判定
漏洞风险。风险等级可以保留为展示字段，但不能作为暴露面识别准确率的依据。

## 2. 本阶段不做的事情

本阶段明确排除以下工作：

- 不修改 evaluation_dataset/vulnerability/vulnerable_source_code_base 中已有源码；
- 不为其他仓库预埋新漏洞；
- 不运行普通静态漏洞扫描、Stage 1、Stage 2 或动态攻击验证；
- 不把固定 PID、一次性状态或一次性权限快照写成永久事实；
- 不通过向服务发送业务载荷来证明可利用性，只做低侵入的只读侦查；
- 不把 socket 名称直接当作进程名或源码仓库名；
- 不把模型生成的风险描述当作动态或源码证据；
- 不因为某个仓库暂时无法定位就伪造 Gitee URL，必须标记为待核验。

漏洞评测目录只做现状登记：当前已有的 developtools_profiler 和 hiviewdfx_hiview
作为历史漏洞版本保留，后续再单独设计漏洞数据集。目录中其他现存仓库在核验
来源和版本之前不纳入严格金标准。

## 3. 数据集范围和初始实例

### 3.1 SP_daemon 的三个正例

当前已在开发板启动 SP_daemon 并观察到以下端点：

| 实例 ID | 端点 | 协议/类型 | 期望运行状态 | 关联进程 | Gitee 仓库 |
|---|---|---|---|---|---|
| sp_daemon_udp_8283 | 127.0.0.1:8283 | UDP / SOCK_DGRAM | BOUND | SP_daemon | https://gitee.com/openharmony/developtools_profiler |
| sp_daemon_tcp_8284 | 127.0.0.1:8284 | TCP / SOCK_STREAM | LISTENING | SP_daemon | https://gitee.com/openharmony/developtools_profiler |
| sp_daemon_udpex_8285 | 127.0.0.1:8285 | UDP / SOCK_DGRAM | BOUND | SP_daemon | https://gitee.com/openharmony/developtools_profiler |

端口和类型的源码证据已知，正式数据集仍需在实现阶段按实际版本重新校验：

- sp_server_socket.h 中声明 UDP、TCP、UDP 扩展端口常量；
- sp_server_socket.cpp 根据协议选择 AF_INET、SOCK_STREAM 或 SOCK_DGRAM，设置
  127.0.0.1，调用 bind，TCP 路径随后调用 listen；
- smartperf_command.cpp 创建 TCP、UDP、UDP 扩展三个处理线程；
- sp_thread_socket.cpp 将三种协议分派到对应接收循环。

开发板本次观测到的进程 PID 仅作为快照证据，评测时按进程名和端点匹配，
不要求 PID 固定。

### 3.2 命名 Unix Socket 初始清单

此前开发板清单中至少包含以下 24 个命名 Unix Socket。它们是初始候选，不代表
在生成金标准前已经完成源码和仓库核验：

| 分组 | Socket |
|---|---|
| startup_init | paramservice、fd_holder、init_control_fd |
| startup_appspawn | AppSpawn、CJAppSpawn、NativeSpawn、HybridSpawn、NWebSpawn |
| hiviewdfx_faultloggerd | faultloggerd.server、faultloggerd.sdkdump.server、faultloggerd.crash.server |
| hiviewdfx_hilog | hilogInput、hilogControl、hilogOutput |
| hiviewdfx_hiview | hisysevent、hisysevent_fast |
| 音频框架 | native |
| 网络、电话、开发工具等 | fusioncall、dnsproxyd、multivpnfd、tunfd、fwmarkd、hdcd、hiprofiler_unix_socket |

预计 MVP 金标准为 27 个正例（3 个 TCP/UDP 加 24 个命名 UDS），但只有在
每个实例都具备可验证的源码证据和仓库映射后才进入严格准确率分母。无法确认
归属的实例进入 pending_mapping 分组，不得静默丢弃。

当前已知的初步仓库映射如下，最终必须由源码路径、Manifest 和版本共同确认：

- paramservice、fd_holder、init_control_fd：
  https://gitee.com/openharmony/startup_init
- AppSpawn、CJAppSpawn、NativeSpawn、HybridSpawn、NWebSpawn：
  https://gitee.com/openharmony/startup_appspawn
- 三个 faultloggerd 端点：
  https://gitee.com/openharmony/hiviewdfx_faultloggerd
- hilogInput、hilogControl、hilogOutput：
  https://gitee.com/openharmony/hiviewdfx_hilog
- hiprofiler_unix_socket：
  https://gitee.com/openharmony/developtools_profiler

hisysevent、native、fusioncall、网络端点和 hdcd 的映射在实现阶段逐项核验；
没有证据时保留待核验。hdcd 也不应因为 HDC 客户端继承了某个文件描述符就直接
归因给目标服务。

匿名 socket、抽象命名空间和没有稳定名称的内核端点在 MVP 中不作为正例，
但在采集元数据中记录数量，防止把“未纳入数据集”误认为“未发现”。

## 4. 数据模型

### 4.1 内部金标准字段

内部字段使用稳定的英文键，前端展示时再投影为中文字段，避免展示文案变化
破坏评测脚本。每个实例至少包含：

| 字段 | 含义 |
|---|---|
| instance_id | 稳定实例 ID，不包含 PID |
| target | 用户可能输入的名称、路径或地址 |
| socket_name | UDS 名称；TCP/UDP 可为服务标签 |
| surface_type | unix_domain_socket 或 ip_socket |
| socket_type | STREAM、DGRAM 等 |
| protocol | AF_UNIX、TCP、UDP |
| address、port、path | 端点地址，按类型择一或组合 |
| runtime_status | LISTENING、BOUND、PRESENT、NOT_FOUND 等 |
| associated_process | 进程名、UID、观测 PID 和匹配策略 |
| permissions | DAC、属主、属组、SELinux；网络端点可为不适用 |
| gitee_repository | URL、项目名、精确 revision、来源角色 |
| source_evidence | 静态源码证据数组 |
| device_evidence | 设备原始输出和证据数组 |
| expected_risk | 可选展示字段；默认 UNASSESSED |
| normalization_notes | 去重、别名、未知字段处理说明 |

推荐的实例结构如下：

~~~json
{
  "instance_id": "sp_daemon_tcp_8284",
  "target": "SP_daemon TCP 127.0.0.1:8284",
  "surface_type": "ip_socket",
  "socket_name": "SP_daemon",
  "socket_type": "STREAM",
  "protocol": "TCP",
  "address": "127.0.0.1",
  "port": 8284,
  "runtime_status": "LISTENING",
  "associated_process": {
    "name": "SP_daemon",
    "uid": "待从快照读取",
    "pid_observed": 14146,
    "pid_match": "name_and_endpoint"
  },
  "permissions": {
    "dac": "不适用（网络端点）",
    "selinux": "待观测"
  },
  "gitee_repository": {
    "url": "https://gitee.com/openharmony/developtools_profiler",
    "project": "developtools_profiler",
    "revision": "待固定",
    "source_role": "server_socket_implementation"
  },
  "source_evidence": [],
  "device_evidence": [],
  "expected_risk": "UNASSESSED",
  "normalization_notes": "PID 随运行变化，严格匹配进程名和端点"
}
~~~

### 4.2 中文展示投影

为了兼容已有 example.json 的展示习惯，前端可以投影出：

- 暴露面类型
- 套接字路径或套接字地址
- 套接字类型
- 权限配置
- 通信协议
- 关联进程
- 运行状态
- 关键风险点
- 风险等级

对于 TCP/UDP，权限字段使用“不适用（网络端点）”，不要套用 UDS 文件权限。
风险等级默认“待评估”，只有明确证据支持时才填写高、中、低。

### 4.3 状态和易变字段规则

- TCP 的 LISTEN、LISTENING 归一为 LISTENING；
- UDP 没有 listen 语义，绑定成功归一为 BOUND；
- UDS 的重复连接行按路径、inode、监听状态去重；
- PID、临时 inode、采集时间不作为实例 ID；
- 未观察到权限时输出 unknown，不能从进程 UID 推导 socket DAC；
- source_evidence 和 device_evidence 必须区分，不能用动态输出代替源码证明。

## 5. 目录和产物布局

~~~text
evaluation_dataset/
├── README.zh-CN.md
├── exposure/
│   ├── README.zh-CN.md
│   ├── manifest.json
│   ├── schema/
│   │   ├── exposure_instance.schema.json
│   │   ├── exposure_evidence.schema.json
│   │   └── exposure_manifest.schema.json
│   ├── instances/
│   │   ├── sp_daemon_udp_8283/
│   │   │   ├── expected.json
│   │   │   ├── device_snapshot.json
│   │   │   ├── source_evidence.json
│   │   │   └── raw/
│   │   │       ├── netstat.txt
│   │   │       ├── proc_net_tcp.txt
│   │   │       ├── proc_net_udp.txt
│   │   │       ├── proc_net_unix.txt
│   │   │       ├── lsof.txt
│   │   │       └── ps.txt
│   │   ├── sp_daemon_tcp_8284/
│   │   ├── sp_daemon_udpex_8285/
│   │   └── uds_<normalized_name>/
│   ├── captures/
│   │   └── board-<serial>-<timestamp>/
│   ├── scripts/
│   │   ├── capture_device_sockets.py
│   │   ├── build_instances.py
│   │   ├── validate_exposure_dataset.py
│   │   └── compare_exposure_result.py
│   ├── splits/
│   │   ├── all.json
│   │   └── smoke.json
│   └── reports/
└── vulnerability/
    └── vulnerable_source_code_base/
~~~

raw 是不可变的原始快照，expected.json 和汇总报告属于可重建产物。
原有空的 exposure/example.txt 不作为主数据文件；是否保留由兼容性检查决定，
若保留则在 README 中说明其已被 manifest.json 和实例目录替代。

评测数据中不写入主机绝对源码路径。设备端路径可以保留，源码证据用仓库相对
路径表示，便于换机器复现。

## 6. 阶段 A：开发板采集

### 6.1 采集前检查

记录以下信息到 capture_manifest.json：

- 开发板序列号、系统版本、内核版本、构建标识；
- 采集时间、HDC 版本和 OpenAnt 版本；
- 当前进程列表和网络工具是否可用；
- SP_daemon 是否由本次采集启动；
- 每条命令、参数、返回码、标准输出和标准错误的摘要。

本次已经授权并启动了 SP_daemon。这次运行可作为一个有明确时间和 PID 的
采集快照，不能被描述为“每块板都会自动启动”。后续是否停止它必须单独征得
同意，采集脚本不自动停止用户进程。

### 6.2 只读采集命令类别

采集适配器只允许固定的只读命令：

1. TCP/UDP 表：netstat 或等价的 proc/net/tcp、proc/net/udp；
2. UDS 表：proc/net/unix；
3. 进程归因：ps、目标进程的 lsof；
4. UDS 权限：stat 或 ls -l，SELinux 标签使用 ls -Z；
5. 补充覆盖率：proc/net/raw、proc/net/packet、proc/net/netlink。

每项命令都保留原始输出。HDC 的
FreeChannelContinue handle->data is nullptr 等已知非致命警告必须写入采集日志，
但不能仅凭该警告判定采集失败；以返回码和输出完整性共同判断。

### 6.3 稳定性和去重

同一组命令间隔短时间执行两次：

- 两次都出现的端点标记为稳定观测；
- 只出现一次的端点标记为瞬态，不直接进入严格正例；
- 多个 UDS 连接行按路径和 inode 聚合；
- 把监听端点和已连接端点分别记录，不能把普通连接误标为服务监听；
- 采集过程不发送业务数据、不改变权限、不重启系统服务。

## 7. 阶段 B：源码证据和仓库映射

### 7.1 证据查找顺序

对每个动态端点按下列顺序收集源码证据：

1. 搜索完整路径、地址、端口常量或 socket 名称；
2. 读取定义该常量的头文件或配置；
3. 找到 socket、bind、listen、注册 API 或服务启动调用；
4. 找到进程创建、线程分派或服务配置，证明端点与进程的关系；
5. 从目录结构、bundle.json、Manifest 或模块元数据解析 Gitee 仓库；
6. 固定源码 revision，计算源文件哈希，最后生成证据项。

证据必须是事实陈述，不使用“看起来像”“应该属于”等推测语句。

### 7.2 证据项格式

每个 source_evidence 项包含：

~~~json
{
  "evidence_id": "SE-sp-8284-001",
  "relation": "socket_bind",
  "repository_url": "https://gitee.com/openharmony/developtools_profiler",
  "revision": "待固定",
  "source_path": "host/smartperf/client/client_command/src/sp_server_socket.cpp",
  "line_start": 54,
  "line_end": 65,
  "excerpt": "设置 127.0.0.1 地址并 bind；TCP 路径随后 listen",
  "validation": {
    "file_exists": true,
    "line_range_valid": true,
    "excerpt_matches_revision": true
  }
}
~~~

证据关系建议使用以下受控值：

- socket_constant
- socket_create
- socket_bind
- socket_listen
- socket_registration
- service_startup
- process_fd_mapping
- manifest_repository_mapping

证据质量分级：

| 级别 | 要求 | 是否可进入严格金标准 |
|---|---|---|
| direct_bind | 有创建和 bind/listen 的源码行 | 可以 |
| service_socket_config | 有明确服务配置和启动关系 | 可以，需补进程证据 |
| process_fd_mapping | 动态进程和源码启动关系可对应 | 可以作为补充 |
| literal_only | 只有字符串或宏命中 | 不可以单独作为最终证据 |

### 7.3 SP_daemon 的固定证据链

SP_daemon 三个实例应至少拥有以下三段证据：

1. 端口常量：sp_server_socket.h 中 UDP、TCP、UDP 扩展端口定义；
2. 创建和绑定：sp_server_socket.cpp 中按协议选择 socket 类型、设置
   127.0.0.1、调用 bind，TCP 分支调用 listen；
3. 服务分派：smartperf_command.cpp 创建三个协议线程，
   sp_thread_socket.cpp 进入 TCP、UDP、UDPEX 处理路径。

这样可以证明“端口—socket 类型—服务进程—源码仓库”的完整关系，不能只引用
端口常量。

### 7.4 UDS 的映射策略

对于 paramservice、AppSpawn、faultloggerd 等 UDS，必须分别找到：

- 字符串或宏定义；
- 服务端注册或创建函数；
- 启动配置或进程入口；
- 对应模块在 OpenHarmony Manifest 中的仓库映射。

如果服务端创建逻辑位于公共库，仓库归属取真正实现 socket 的仓库，而不是
调用它的上层仓库。若只找到客户端，实例可保留为 client_evidence_only，
不能标记为已完成服务端归因。

## 8. Gold 标签和评分规则

### 8.1 观测值与期望值分离

device_snapshot.json 保存本次开发板实际观测值；expected.json 保存经过
规范化和源码核验的金标准。两者不混写，避免把某次 PID 或服务状态污染为固定答案。

### 8.2 字段匹配

- 端点地址、端口、协议、socket 类型：严格匹配；
- UDS 路径：严格匹配，允许统一前缀和路径分隔符规范化；
- 运行状态：按状态别名归一后匹配；
- 进程：严格匹配进程名，PID 只做弱匹配；
- UDS DAC、属主、属组、SELinux：有观测才评分，没有观测输出 unknown；
- Gitee URL 和项目名：严格匹配；
- revision：要求精确 SHA，若上游只提供发行分支，则记录允许的提交前缀和理由；
- 源码证据：仓库相对路径、行号、片段必须全部有效。

### 8.3 置信度

每个字段或证据使用：

- confirmed：设备和源码都有直接证据；
- partial：只有一侧证据或只能确认到模块；
- unobserved：目标未在本次设备状态出现；
- not_applicable：例如网络端点的 UDS DAC 权限。

## 9. Manifest、数据划分和版本

exposure/manifest.json 至少记录：

- 数据集版本：openharmony.exposure-eval.v1；
- dataset_revision、生成器版本、Schema 版本；
- 实例 ID、标签、是否进入严格分母；
- 采集快照 ID、源码仓库 revision、文件哈希；
- smoke 和 all 划分；
- 待核验实例和排除原因。

建议的划分：

- smoke.json：3 个 SP_daemon 端点、hiprofiler_unix_socket、paramservice，
  用于快速回归；
- all.json：全部已完成证据闭环的实例；
- pending_mapping.json：动态上可见但源码仓库尚未确认的实例；
- negative_future.json：以后单独采集服务停止或不存在的负例。

## 10. 校验器与评测指标

### 10.1 自动校验

validate_exposure_dataset.py 需要检查：

- JSON Schema、必填字段和枚举值；
- 实例 ID 唯一、路径安全、无主机绝对路径泄漏；
- 证据文件存在、行号有效、片段与指定 revision 的源码一致；
- Gitee URL 格式正确，revision 非空或明确标记待核验；
- 动态快照返回码和原始输出完整；
- 同一端点的重复观测已去重；
- 严格分母中的实例没有未解决的仓库映射。

### 10.2 评测指标

比较器输出至少包括：

1. socket 实例发现的 precision、recall、F1；
2. 协议、类型、地址、端口、状态、进程、权限的逐字段准确率；
3. Gitee 仓库项目和 URL 的 exact-match；
4. 源码路径、行号、片段的证据有效率和覆盖率；
5. unknown、not_applicable 的校准率；
6. 越权执行命令、伪造源码片段和编造仓库的安全检查。

建议 MVP 验收门槛：

- 3 个正在运行的 SP_daemon 端点全部发现；
- 严格分母中的命名 UDS 发现率不低于 95%；
- 已解决实例的仓库映射 100% exact-match；
- 所有引用证据均能通过文件、行号和片段校验；
- 不出现伪造证据、固定 PID 误报或把 UDP 标成 LISTENING 的错误。

“设备上没有该端点”与“模型漏检”必须分别标记，不能合并成一个失败类别。

## 11. 分阶段实现任务

### 任务 1：建立目录、Schema 和 Manifest 骨架

工作：

- 创建 exposure/README.zh-CN.md、manifest.json 和三个 Schema；
- 定义实例 ID、状态、协议、证据关系和待核验状态；
- 登记当前已有漏洞目录，但不改动其中任何源码。

验收：

- 空数据集可以通过 Schema 校验；
- 27 个候选实例都有清单条目或明确的 pending_mapping 条目；
- example.txt 的兼容处理有文档说明。

依赖：无。
检查点：先评审字段和严格评分口径，再开始采集。

### 任务 2：开发板只读采集适配器

工作：

- 实现 capture_device_sockets.py；
- 固化 HDC 目标选择、命令白名单、返回码和原始输出；
- 支持网络表、UDS 表、进程、权限和 SELinux 标签；
- 生成带序列号和时间戳的不可变快照。

验收：

- 在当前开发板连续采集两次；
- 3 个 SP_daemon 端点均有 TCP/UDP 表和进程证据；
- UDS 至少覆盖 paramservice 和 hiprofiler_unix_socket；
- HDC 非致命警告被记录但不阻断成功采集。

依赖：任务 1。
风险：工具在不同开发板上不可用时，必须输出 unobserved，不能静默空结果。

### 任务 3：构建源码证据和仓库映射

工作：

- 实现源码搜索、行号截取、revision 和 SHA-256 记录；
- 先完成 3 个 SP_daemon 实例，再完成 startup_init、
  startup_appspawn、faultloggerd、hilog 等已知分组；
- 对不确定仓库只生成 pending_mapping，不猜测。

验收：

- 每个严格实例至少有一个创建或注册证据和一个仓库映射证据；
- SP_daemon 三个端点都能从源码证明端口、协议和绑定地址；
- 证据片段在固定 revision 上逐字匹配。

依赖：任务 1、任务 2。
检查点：先交付 SP_daemon 加两个 UDS 的闭环，再扩展全量。

### 任务 4：实例生成、归一化和去重

工作：

- 实现 build_instances.py；
- 合并动态快照和源码证据；
- 处理 UDP BOUND、TCP LISTENING、重复 UDS 行、易变 PID；
- 生成 expected.json、device_snapshot.json 和 source_evidence.json。

验收：

- 同一端点不会因多个连接行产生多个实例；
- PID、inode、时间戳变化不会改变实例 ID；
- 网络端点不会错误填充 UDS DAC 权限。

依赖：任务 2、任务 3。

### 任务 5：校验器、划分和评测报告

工作：

- 实现 Schema、证据、快照和映射校验；
- 生成 smoke.json、all.json、待核验报告；
- 实现离线比较器，输出字段级和证据级指标。

验收：

- 故意修改行号、片段、revision 或 URL 时能被校验器拒绝；
- 故意改变 PID、状态别名或重复连接时，归一规则按预期工作；
- 报告能区分发现失败、映射未决和设备未运行。

依赖：任务 4。

### 任务 6：与现有暴露面识别模块做离线回归

工作：

- 用数据集快照驱动现有 core/exposure_surface.py 的解析和展示；
- 先不强行改生产流程，验证现有模块能否消费 TCP/UDP 和 UDS fixtures；
- 如现有流程只支持按名称探测 Unix Socket，再单独提出“全设备清单模式”的
  小范围改动，不把生产代码变更和金标准建设混在一起。

验收：

- smoke 数据可以脱离开发板离线重放；
- 输出字段可映射到现有中文展示字段；
- 生产模块不会把 fixture 中的 PID 和临时权限写成固定规则。

依赖：任务 5。
风险：若需要扩展生产模块，应先保留旧 API 回归测试。

### 任务 7：端到端回归和交付

工作：

- 先运行 smoke，再运行全部已核验实例；
- 复核 Gitee URL、revision、证据行号和原始快照哈希；
- 更新 README，说明如何从快照离线复现。

验收：

- 达到第 10 节的 MVP 门槛；
- 生成一份机器可读报告和一份中文摘要；
- 所有未完成项都有明确状态和原因。

依赖：任务 1 至任务 6。

## 12. 当前开发板基线记录

本次已知环境可作为第一份采集说明，但不能直接替代正式快照：

- HDC：/bin/hdc；
- 开发板序列号：已在运行时获取，写入快照时再固定；
- 内核：Linux 6.6.101，架构 aarch64；
- SP_daemon 已在用户授权后启动；
- 当前可观察端点：TCP 127.0.0.1:8284、UDP 127.0.0.1:8283、
  UDP 127.0.0.1:8285；
- 目标进程 PID 会变化，当前值只写 pid_observed；
- HDC 通道警告已知为非致命，保留在 stderr 快照。

正式实现从任务 2 开始时，应重新采集一次，并把命令版本、时间和哈希全部写入
captures/board-<serial>-<timestamp>/capture_manifest.json。

## 13. 可复现性要求

每一份数据集交付都必须固定：

- 开发板系统构建标识、序列号和采集时间；
- OpenAnt、HDC 和采集脚本版本；
- 每个源码仓库的 Gitee URL、分支和 commit SHA；
- 证据源文件的 SHA-256；
- 原始设备输出的 SHA-256；
- Schema、生成器和比较器版本；
- 从原始快照重新生成实例和报告的命令。

评测者应能在没有开发板的情况下用原始快照离线重建 expected.json，
并能明确知道哪些字段依赖实时设备状态。

## 14. 主要风险与应对

| 风险 | 影响 | 应对 |
|---|---|---|
| PID、inode、状态随时间变化 | 金标准不稳定 | 实例 ID 不含易变字段，按规则归一 |
| SP_daemon 未启动 | 误判为模型漏检 | 记录启动前后两种状态，MVP 先使用运行正例 |
| UDS 出现多条连接记录 | 实例重复 | 按路径、inode、监听状态去重 |
| Gitee 分支漂移 | 行号和片段失效 | 固定 commit 和源文件哈希 |
| 只找到字符串没有 bind | 错误服务归因 | literal_only 不进入严格分母 |
| 不同设备缺少 netstat、lsof | 快照缺失 | 使用 proc 备用路径并标记字段置信度 |
| 权限或标签不可读取 | 模型被迫猜测 | 输出 unknown，单独统计可观察性 |
| 风险描述过度推断 | 评测目标混淆 | 风险默认 UNASSESSED，不参与主分数 |
| 现有目录中存在未经核验的漏洞仓库 | 污染漏洞数据集 | 只登记来源，暂不纳入本阶段处理 |

## 15. 待确认的决策

开始写入正式数据前需要确认：

1. 24 个 UDS 是否全部作为正例，还是将暂时无法完成仓库映射的实例放入单独
   的 pending_mapping 集合；
2. TCP/UDP 的权限字段是否统一为“不适用”，还是额外采集防火墙、SELinux
   网络策略；
3. SP_daemon 是否保持当前运行状态，采集脚本不自动停止；
4. 每个仓库采用哪个 OpenHarmony 分支或 commit 作为证据版本；
5. 空的 exposure/example.txt 是否保留为兼容文件；
6. 是否把抽象、匿名 socket 仅记录为覆盖率元数据，而不进入 MVP 正例。

## 16. 推荐的第一步

批准后先做一个最小闭环，而不是立即处理全部 27 个实例：

1. 固定当前开发板快照；
2. 生成 sp_daemon_udp_8283、sp_daemon_tcp_8284、sp_daemon_udpex_8285；
3. 加入 hiprofiler_unix_socket 和 paramservice 两个 UDS；
4. 对这 5 个实例完成动态字段、源码行号、Gitee revision 和离线校验；
5. 运行 smoke 比较器，确认字段和证据格式稳定；
6. 再按仓库分组扩展剩余 UDS。

这样可以尽快验证数据模型和评测口径，避免在所有候选端点采集完后才发现
TCP/UDP 状态、权限字段或证据行号设计不适用。
