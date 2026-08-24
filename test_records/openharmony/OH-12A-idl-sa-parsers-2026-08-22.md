# OH-12A：IDL 与 SA profile 静态解析器测试记录

- 执行日期：2026-08-22
- 阶段：OH-12A（IDL/SA 解析器）
- 状态：通过，可进入 OH-12B 评审
- IDL 解析器：`libs/openant-core/core/platforms/openharmony/idl.py`
- SA 解析器：`libs/openant-core/core/platforms/openharmony/sa_profile.py`
- 测试：`libs/openant-core/tests/platforms/test_openharmony_idl.py`、`test_openharmony_sa_profile.py`

## 1. 原逻辑与本阶段目标

原逻辑只把 `.idl` 作为接口元数据路径进行分类和计数，没有提取 IPC interface、方法、参数方向/类型、sequenceable，也没有解析 OpenHarmony 的 SA profile。生成的 Proxy/Stub 或仓库脚本不能作为默认扫描依赖。

本阶段只新增独立的安全静态解析器，不接入平台画像主流程：

1. IDL：提取 package、import、sequenceable、interface（含前向声明）、方法、返回类型、参数 `[in]`/`[out]`/`[inout]`、enum 和 struct。
2. SA profile：支持真实源码中使用的 JSON 和 XML 两种格式，提取 process、SA ID、libpath、run-on-create、distributed、auto-restart、dump-level、extension 和权限字段。
3. 所有输入均限大小、拒绝符号链接、保持仓库相对路径；XML 明确拒绝 DTD/ENTITY；不执行生成器、脚本或子进程。
4. 语法不完整、超大文件、恶意 XML 和不可读文件均转换为结构化 `parse_failures`。

## 2. TDD 记录

### RED

先新增 IDL/SA 契约测试，再运行：

```text
../../.venv/bin/python -m pytest -q \\
  tests/platforms/test_openharmony_idl.py \\
  tests/platforms/test_openharmony_sa_profile.py
```

结果：测试收集失败，两个新模块尚不存在：

```text
ModuleNotFoundError: core.platforms.openharmony.idl
ModuleNotFoundError: core.platforms.openharmony.sa_profile
```

### GREEN

实现两个解析器后，未配置外部源码时：

```text
7 passed, 2 skipped
```

配置真实源码路径后：

```text
9 passed
```

## 3. 合成安全测试覆盖

### IDL

- 完整 interface、前向声明和重复 interface 合并；
- `[in]`、`[out]`、`[inout]` 参数方向；
- 基本类型、数组、`List<T>`、复杂泛型类型；
- sequenceable、enum、struct、import、package；
- 不平衡 interface 块；
- 超大文件和符号链接逃逸；
- 注释中的伪 interface 不被解析或执行。

### SA profile

- JSON `systemability` 对象/数组；
- XML `<systemability>` 与连字符字段名；
- 布尔值、整数、extension、permission 归一化；
- DTD/ENTITY 拒绝，避免外部实体读取；
- 只收集 `sa_profile`/`sa_profiles` 目录，忽略无关 XML；
- 相对路径、文件大小和解析失败记录。

## 4. 真实 OpenHarmony 源码验证

使用：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

### 4.1 六个真实 IDL

测试覆盖：

- `communication_netmanager_base/interfaces/innerkits/netstatsclient/INetStatsService.idl`
- `communication_wifi/wifi/frameworks/native/HotspotTypes.idl`
- `communication_wifi/wifi/frameworks/native/IWifiHotspot.idl`
- `communication_wifi/wifi/frameworks/native/IWifiHotspotMgr.idl`
- `communication_wifi/wifi/frameworks/native/IWifiScan.idl`
- `communication_wifi/wifi/frameworks/native/IWifiScanMgr.idl`

`collect()` 最终结果：

- IDL 文件：6
- interface：8（含前向声明）
- 方法：71
- enum：4
- struct：1
- 解析失败：0

### 4.2 真实 SA profile

`collect()` 最终结果：

- SA profile 文件：13
- SA 条目：13
- 解析失败：0
- 同时验证了 JSON profile（如 `1123.json`）和 XML profile（`sensors_medical_sensor/sa_profile/3605.xml`）。

IDL 与 SA 序列化结果均不包含本机绝对路径。

## 5. 相关回归测试

| 测试组 | 结果 |
|---|---|
| IDL/SA 真实测试 | 9 passed |
| 平台、GN、manifest、profile、base | 31 passed, 2 skipped |
| scanner 与 scanner profile | 18 passed |
| OpenHarmony C/scope/fixture | 13 passed, 2 skipped |
| parser adapter 与 CLI 平台参数 | 13 passed |
| Ruff、py_compile、git diff 检查 | 全部通过 |

## 6. 阶段结论与边界

OH-12A 已完成：OpenHarmony IPC 契约和 SA 部署元数据现在可以在无构建环境、无生成代码条件下被安全静态读取。当前结果尚未写入 `RepositoryProfile.build_metadata`，也尚未把 IDL 方法和 SA 条目连接到 C/C++ Proxy/Stub 或语义图；这些属于下一小阶段 OH-12B。
