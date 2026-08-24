# OH-DYN-03：手动 IPC/SA 只读请求与 Native ELF 冒烟记录

## 1. 测试结论

本轮没有执行 fuzz、崩溃触发或会改变系统状态的服务操作，只验证真实设备上的两条动态执行底座：

| 项目 | 结果 |
|---|---|
| HDC 3.2.0c 连接设备 | PASS |
| SA 列表枚举 | PASS |
| BundleMgr 只读 dump | PASS |
| 设备 SensorService SA 3601 只读请求 | PASS |
| 源码医疗传感器 SA 3605 设备存在性检查 | BLOCKED：设备不存在该 SA |
| AArch64 Native ELF 直接运行 | BLOCKED：设备用户态没有对应 loader |
| ARMv7 Native ELF 运行 | PASS |
| 远端 hash 校验 | PASS |
| Native 临时目录清理 | PASS |
| 传感器启用/停用、IPC 畸形载荷、系统服务 fuzz | NOT RUN |

这轮的价值是确认：动态测试必须同时验证“源码中的 SA 是否真的部署在目标设备”和“设备内核架构是否等于用户态 ABI”，不能只根据主机工具链或源码注册宏推断可执行性。

## 2. 设备和工具

| 项目 | 实际值 |
|---|---|
| 设备序列号 | `150100424a5444345209d945be14b900` |
| 系统 | `OpenHarmony 6.1.0.26` |
| 内核架构 | `aarch64`（`uname -m`） |
| 用户态位数 | `32`（`getconf LONG_BIT`） |
| HDC | OpenAnt 内置 Command Line Tools 6.1.0.860 / HDC 3.2.0c |
| SELinux | `Enforcing` |
| HDC shell 身份 | `uid=0(root) ... context=u:r:su:s0` |
| 设备 SensorService | SA `3601`，进程 `sensors`，PID `588` |
| 源码医疗传感器服务 | SA `3605`（源码定义），设备上不存在 |

## 3. IPC/SA 手动只读验证

### 3.1 源码事实

本地源码仓库为：

```text
source_code_base/sensors_medical_sensor
```

源码证据：

- `system_ability_definition.h:241-244` 定义 `SENSOR_SERVICE_ABILITY_ID = 3601` 和 `MEDICAL_SENSOR_SERVICE_ABILITY_ID = 3605`；
- `medical_service.cpp:51` 使用 `REGISTER_SYSTEM_ABILITY_BY_ID(MedicalSensorService, MEDICAL_SENSOR_SERVICE_ABILITY_ID, true)` 注册；
- `i_medical_sensor_service.h:35` 定义 descriptor `IMedicalSensorService`；
- `i_medical_sensor_service.h:55-64` 定义 transaction code：`ENABLE_SENSOR=0`、`DISABLE_SENSOR=1`、`GET_SENSOR_STATE=2`、`RUN_COMMAND=3`、`GET_SENSOR_LIST=4`、`TRANSFER_DATA_CHANNEL=5`、`DESTROY_SENSOR_CHANNEL=6`、`SET_OPTION=7`；
- `medical_service_stub.cpp:54-72` 的 `OnRemoteRequest` 先读取 interface token，再按 code 分派；`medical_service_stub.cpp:75-143` 中多个入口会执行 `CheckSensorPermission`，`medical_service_stub.cpp:146-160` 的 `GetAllSensorsInner` 返回列表。

### 3.2 设备事实

执行：

```bash
hdc -t 150100424a5444345209d945be14b900 shell \
  'hidumper -s SystemAbilityManager -a "-sa 3605"'
```

设备返回：

```text
said is not exist
```

对 `hidumper -s 3605 -a "-h"` 和 `hidumper -s 3605` 也没有得到服务 dump。结论是：当前开发版没有部署 `sensors_medical_sensor` 对应的 SA，不能把 3605 的 IPC 请求发送到目标服务；如果强行构造 transaction，只能得到“目标不存在”，不能评价源码 handler 的安全性。

### 3.3 实际可达的 SensorService SA 3601

系统能力定义中 `SENSOR_SERVICE_ABILITY_ID = 3601`。设备状态查询返回：

```text
said: 3601
sa_state: LOADED
process_name: sensors
process_state: STARTED
pid: 588
```

使用设备实际支持的 dump 命令执行只读请求：

```bash
hdc -t 150100424a5444345209d945be14b900 shell \
  'hidumper -s 3601 -a "-l"'
hdc -t 150100424a5444345209d945be14b900 shell \
  'hidumper -s 3601 -a "-c"'
hdc -t 150100424a5444345209d945be14b900 shell \
  'hidumper -s 3601 -a "-d"'
hdc -t 150100424a5444345209d945be14b900 shell \
  'hidumper -s 3601 -a "-o"'
```

实际结果：

- `-l` 返回 6 个传感器，包括加速度、颜色、SAR、头部姿态和接近传感器；
- `-c` 返回 `Sensor channel info`，当前无通道条目；
- `-d` 返回 `Last 10 packages sensor data`，当前无数据条目；
- `-o` 返回 `Opening sensors`，前后均为空。

这属于 root HDC shell 通过系统 dump 入口发起的只读 SA 请求，证明了“SA 已加载、命令入口存在、服务可返回数据”。它不等价于普通 HAP UID 调用，也不等价于医疗传感器服务的 `IMedicalSensorService` transaction 测试。

### 3.4 BundleMgr 只读请求

执行：

```bash
hdc -t 150100424a5444345209d945be14b900 shell \
  'hidumper -s BundleMgr -a "-bundle com.security.research.trigger"'
```

设备返回了 bundle、`EntryAbility`、`compatibleVersion: 23`、HAP 路径、UID 和权限等信息，证明 HAP 的安装状态可以通过 SA dump 进行复核。

## 4. Native ELF 手动验证

### 4.1 测试程序

源码位于：

```text
libs/openant-core/utilities/dynamic_tester/fixtures/native_smoke/native_smoke.c
```

程序只调用 `uname`、`getpid`、`getuid`、`geteuid` 并输出结果，不访问文件、网络或系统服务。

### 4.2 第一次失败：AArch64 ELF 与用户态不匹配

使用 `aarch64-unknown-linux-ohos-clang` 编译得到 AArch64 ELF，解释器为：

```text
/lib/ld-musl-aarch64.so.1
```

主机侧 ELF 检查通过，但设备执行返回：

```text
/bin/sh: .../native_smoke: No such file or directory
native_smoke_rc=126
```

设备只读检查显示：

```text
uname -m              => aarch64
getconf LONG_BIT      => 32
/system/lib/ld-musl-arm.so.1  => 存在
/lib/ld-musl-aarch64.so.1     => 不存在
```

这里的“找不到文件”实际是动态解释器找不到，不是 HDC 传输失败。该失败应在 Native adapter 中分类为 `ABI_OR_LOADER_MISMATCH`，不能简单报告为目标程序不存在。

### 4.3 修正后的 ARMv7 ELF

改用工具链中的 `armv7-unknown-linux-ohos-clang`，并显式设置：

```text
-Wl,--dynamic-linker=/system/lib/ld-musl-arm.so.1
```

产物：

```text
test_records/dynamic/artifacts/OH-DYN-03-manual-ipc-native-readonly-2026-08-24/native_smoke_armv7_system_loader
```

SHA-256：

```text
bf14fa8d54180d1777d6ea5175fd59064d2143b362dd7eb02a4d177d20dfd306
```

ELF 检查：

```text
ELF 32-bit LSB pie executable, ARM, EABI5
interpreter /system/lib/ld-musl-arm.so.1
```

### 4.4 推送、运行和清理

远端目录：

```text
/data/local/tmp/openant/manual-native-smoke-20260824/
```

传输后远端 SHA-256 与主机一致。运行输出：

```text
openant_native_smoke pid=6460 uid=0 euid=0 machine=aarch64 sysname=Linux release=6.6.101
native_smoke_rc=0
```

运行后删除远端目录，检查结果：

```text
cleanup=PASS
```

这里的 `uid=0/euid=0` 是因为该开发版的 HDC shell 处于 root/su 上下文；它不能代表普通 HAP 或第三方 Native helper 的权限身份。后续 Native adapter 必须把执行身份作为结果字段，而不能只保存退出码。

## 5. 对动态测试实现的修正

这次手工运行得到以下实现要求：

1. **先确认部署事实**：源码注册的 SA ID、设备 SA 列表、进程 PID 和服务状态必须同时存在，缺少任一项就标记 `SERVICE_NOT_DEPLOYED`，不生成 IPC 漏洞结论。
2. **区分 dump IPC 与业务 transaction**：`hidumper -s 3601 -a -l` 是 root dump 请求，只能验证只读管理入口；要验证 `IMedicalSensorService`，仍需构建与设备对应的真正 proxy/client，并记录 descriptor、code 和 parcel 字段顺序。
3. **Native 先做用户态 ABI 预检**：不能只比较 `uname -m`。还要检查 `getconf LONG_BIT`、ELF `Class/Machine`、解释器路径和设备 loader；aarch64 kernel 不等于 64 位用户态。
4. **执行身份必须进入证据模型**：HDC shell root、系统服务 UID、HAP UID 和普通 Native helper 的可达性不能合并。
5. **系统服务载荷分级**：先做 `hidumper`/状态/列表等只读请求，再做明确源码支持的合法最小请求，最后才考虑边界值；本轮没有进入会启用传感器、创建数据通道或触发 faultloggerd 的阶段。
6. **失败需要保留原始证据**：AArch64 loader 失败本身是适配器必须识别的环境问题，不能被重试或改写成“漏洞未复现”。

## 6. 未完成事项

- 没有在设备上部署 `sensors_medical_sensor` 服务，因此没有执行其 `IMedicalSensorService` 的真实 transaction；
- 没有构建带 OpenHarmony IPC/SA NDK 的普通 HAP/Native proxy；
- 没有执行 `EnableSensor`、`DisableSensor`、`RunCommand`、数据通道创建等会改变状态的请求；
- 没有向 faultloggerd、foundation、samgr 等关键服务发送畸形或高频载荷；
- 还没有把本轮 HDC、hidumper、ELF 检查和清理流程封装成 OpenAnt 自动适配器。

因此本记录只证明只读 IPC/SA 探索和 Native 工件生命周期可行，不包含任何漏洞确认结论。

## 7. 产物

```text
test_records/dynamic/artifacts/OH-DYN-03-manual-ipc-native-readonly-2026-08-24/
├── native_smoke.c
├── native_smoke_armv7_system_loader
└── ipc-readonly.log
```
