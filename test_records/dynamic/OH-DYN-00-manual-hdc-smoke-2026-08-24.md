# OH-DYN-00：OpenHarmony 手动 HDC 交互冒烟测试记录

## 1. 测试目的

在不安装 HAP、不运行 Native payload、不执行 fuzz、不修改系统分区的前提下，手动跑通一次动态验证的基础闭环，确认：

1. 宿主机可以通过 HDC 选择指定开发板；
2. 可以采集设备只读基线；
3. 可以读取日志和进程/Socket 信息；
4. 可以完成一个无害测试工件的发送、哈希校验、回读和清理；
5. 经验包中的日志解析器可以被调用，并评估其误报风险。

本记录不代表漏洞已经触发，也不代表普通 HAP 身份具备相同能力。

## 2. 测试输入和环境

| 项目 | 实际值 |
|---|---|
| 经验包 | `/Users/shiyu/学习/hyl/new/openharmony-dynamic-verify.zip` |
| 经验包 SHA-256 | `56acf5a4678a8a3808b26e6ad984b095a70b2f7914aa9ff09c2d9de7a30f4575` |
| 设备序列号 | `150100424a5444345209d945be14b900` |
| 连接方式 | USB |
| HDC 状态 | Connected |
| HDC 路径 | `/Users/shiyu/harmonyos-sdk/openharmony/9/toolchains/hdc` |
| 运行目录 | `/private/tmp/openant-manual-hdc-20260824_131756` |

HDC 命令在宿主机环境执行。Codex 受限环境无法访问宿主机 HDC/USB 通道，直接执行会返回 `Connect server failed`；在宿主机环境执行成功。

## 3. 经验包工具审计

经验包明确建议采用：

```text
macOS：USB、HDC、设备 shell、文件传输
Docker Linux：HAP 构建、签名、Native 交叉编译、ELF 分析、日志解析
```

包内实际提供了：

- 设备信息和基线脚本；
- Native socket client 示例；
- 日志采集脚本；
- 日志分类脚本；
- Dockerfile 和 Compose；
- artifact manifest 模板。

但包内实际没有 README 中提到的完整 `02_hap_app`、`04_automation` 工程，也没有可直接使用的 HAP、Native ELF 或 payload。因此这次没有执行 HAP 安装、Native 执行或漏洞触发。

包内脚本存在几个需要适配的问题：

1. 部分脚本使用未带 `-t <设备序列号>` 的 `hdc`；本次全部显式指定设备；
2. `collect_logs.sh start` 会执行 `hilog -r` 清空旧日志并改变日志设置；本次没有运行它，改为只读 `hilog -x | tail`；
3. 文档依赖 GNU `timeout`，macOS 主机没有该命令；本次未使用它；
4. `ss -lxp` 在目标设备上不可用，需要以 Socket 文件清单作为降级信息源。

## 4. 宿主机工具检查

| 工具 | 结果 |
|---|---|
| HDC | 可用 |
| Python 3 | 可用 |
| jq | 可用 |
| ripgrep | 可用 |
| Docker client/server | `29.4.1 / 29.4.1`，可用 |
| Docker Compose | `v5.1.3`，可用 |
| Java | 可用 |
| Node/npm | 可用 |
| `readelf` | macOS PATH 中缺失 |
| `llvm-readelf` / `llvm-objdump` | macOS PATH 中缺失 |
| GNU `timeout` / `gtimeout` | 缺失 |
| `hvigor` / `hvigorw` | 主机 PATH 中缺失 |

本地 OpenHarmony SDK API 9 目录约 21 MB，包含 HDC、IDL、restool、Ark 工具和 `hap-sign-tool.jar`，但没有发现可用于 Linux 容器交叉编译的 clang 和 LLVM ELF 工具。因此 Docker/HAP/Native 构建阶段还不能仅依赖当前本地 SDK 完成。

## 5. 只读设备基线

执行的核心命令：

```bash
hdc list targets -v
hdc -t <serial> shell id
hdc -t <serial> shell getenforce
hdc -t <serial> shell uname -a
hdc -t <serial> shell param get const.ohos.apiversion
hdc -t <serial> shell param get const.product.model
hdc -t <serial> shell param get const.product.devicetype
hdc -t <serial> shell param get const.product.brand
hdc -t <serial> shell df -h /data
hdc -t <serial> shell 'ps -A | head -n 40'
hdc -t <serial> shell 'ss -lxp'
hdc -t <serial> shell 'ls -laZ /dev/unix/socket'
hdc -t <serial> shell 'hilog -x | tail -n 80'
hdc -t <serial> shell 'dmesg | tail -n 60'
```

实测结果：

| 项目 | 结果 |
|---|---|
| API | `23` |
| Model | `ohos` |
| Device type | `default` |
| Brand | `default` |
| Kernel/ABI | Linux `6.6.101`，`aarch64` |
| HDC shell 身份 | `uid=0(root)`，`context=u:r:su:s0` |
| SELinux | `Enforcing` |
| 设备空间 | 观察到 20G 分区，已用约 1.1G，可用约 18G |
| `ss -lxp` | 命令不存在，不能作为本设备 Socket 查询依据 |
| Socket 文件清单 | 成功读取 `/dev/unix/socket` |

Socket 清单中观察到 `AppSpawn`、`CJAppSpawn`、`HybridSpawn`、`NWebSpawn`、`NativeSpawn`、`dnsproxyd` 和 faultloggerd 相关 Socket。它们只是设备入口事实，不代表本次测试访问了这些服务。

## 6. 无害工件往返测试

为验证 HDC 文件传输闭环，使用 VulnFounder 自带的 477 字节 fixture：

```text
本地文件：libs/vulnfounder-core/tests/fixtures/openharmony/ipc_service/bundle.json
本地 SHA-256：79bf4005fb7696914eb98f0f2cd3f6bac52bbb39455f2cd0a8bd0fd05a4de2e6
远端目录：/data/local/tmp/openant-manual-20260824_131756/
```

操作顺序：

1. 创建本轮唯一远端临时目录；
2. `hdc file send` 发送 `bundle.json`；
3. 在设备端执行 `sha256sum`；
4. 比较本地和远端 hash；
5. 执行 `wc -c` 和 `head` 回读；
6. 只删除本轮创建的远端目录；
7. 再次检查目录已不存在。

结果：

```text
FileTransfer finish, Size:477, File count = 1
远端 SHA-256 与本地一致
回读成功，大小 477 字节
cleanup_verify=REMOVED
```

结论：HDC 的设备选择、shell、文件发送、远端 hash、回读和定向清理闭环通过。

## 7. 经验包日志解析器测试

使用经验包中的 `06_analysis/parse_results.py` 对本次基线目录执行：

```bash
python3 parse_results.py \
  --logs-dir /private/tmp/openant-manual-hdc-20260824_131756/baseline \
  -o /private/tmp/openant-manual-hdc-20260824_131756/analysis/report.json
```

解析结果：

```text
分析文件数：13
总发现数：41
崩溃：0
权限：41
服务异常：0
综合评级：INFERRED
```

41 条权限发现全部来自 `dmesg_tail.txt`。这些 AVC 是设备历史 dmesg 中的记录，没有本轮 run marker、目标 PID 关联或触发前后时间窗口。因此不能把 `INFERRED` 解读为本次测试造成了权限异常。

这次结果验证了经验包解析器的定位：

- 可以作为日志初筛工具；
- 不能单独作为动态漏洞确认器；
- 必须增加 run marker、时间窗口、目标 PID、服务健康状态和历史日志隔离；
- `CRASH`、`PERMISSION`、`SERVICE_ERROR` 只能作为观察标签，不能直接映射到漏洞结论。

## 8. HDC 非致命警告

每次 HDC 操作后偶尔出现：

```text
[W] FreeChannelContinue handle->data is nullptr
```

本次命令退出码、文件传输、哈希校验和回读均成功，因此暂时记录为 HDC 非致命警告。后续 HDC 客户端实现应同时保存 stdout、stderr 和退出码，不能只依据 stderr 是否为空判断失败。

## 9. 本次闭环结论

| 环节 | 结果 |
|---|---|
| 设备枚举 | PASS |
| 指定设备 shell | PASS |
| 设备只读基线 | PASS |
| 只读日志采集 | PASS |
| 临时工件发送 | PASS |
| 远端 hash 校验 | PASS |
| 工件回读 | PASS |
| 定向清理 | PASS |
| 经验包日志解析调用 | PASS |
| 日志解析是否可直接定案 | FAIL（存在历史日志误报） |
| HAP/Native 漏洞触发 | NOT RUN |

本次实践证明，动态验证的最小设备交互底座已经可以手动跑通；尚未证明 VulnFounder 的动态测试代码已经实现，也尚未证明任何漏洞存在。

## 10. 对后续实现的直接影响

1. HDC client 必须在宿主机执行，并强制绑定设备序列号；
2. VulnFounder 的首次动态阶段应先实现 preflight、baseline、artifact round trip 和 cleanup；
3. 默认不能调用 `hilog -r`，应使用时间窗口和 run marker；
4. `ss` 不可用时要有设备能力探测和降级路径；
5. 日志结论必须关联 PID、时间窗口和目标候选；
6. root/native 结果必须与普通 HAP 结果分开；
7. 当前本地 SDK 缺少交叉编译和 ELF 分析工具，Native/HAP 阶段需要另行准备匹配的 Linux SDK 容器；
8. 下一步实现应从 OH-DYN-01 的 Fake HDC + 真实设备 preflight 开始，而不是直接触发漏洞。

## 11. 原始产物位置

本次完整的主机侧临时产物位于：

```text
/private/tmp/openant-manual-hdc-20260824_131756/
```

其中包含：

- `targets.txt`：设备枚举结果；
- `baseline/`：各只读基线输出；
- `artifact/`：发送、hash、回读和清理输出；
- `analysis/report.json`：经验包解析器输出；
- `run.log`：本次运行摘要。

