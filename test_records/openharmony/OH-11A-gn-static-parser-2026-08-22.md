# OH-11A：GN 静态提取测试记录

- 执行日期：2026-08-22
- 阶段：OH-11A（OH-11 GN 静态提取）
- 状态：通过，可进入 OH-11B 评审
- 代码：`libs/openant-core/core/platforms/openharmony/gn.py`
- 测试：`libs/openant-core/tests/platforms/test_openharmony_gn.py`

## 1. 本阶段范围

原项目的 `core/platforms/openharmony/scope.py` 只用正则提取 GN 文件中的 target 名称和 `sources`，无法表达 target 类型、依赖、宏、头文件目录、测试/Fuzz 角色，也不能报告 GN 条件表达式的静态解析缺口。

本阶段先不接入扫描主流程，新增一个隔离的、只读的 GN 静态解析器。计划逻辑是：

1. 仅读取 `.gn`/`.gni`，提取常见 target 的 `kind`、`name`、`sources`、`deps`、`external_deps`、`defines` 和 `include_dirs`。
2. 不求值 GN 条件；保存条件表达式并统计 `unknown_condition_count`。
3. 根据 target 类型、名称和相对路径保守标记 `production`、`test` 或 `fuzz`。
4. 将仓库内容视为不可信输入：限制文件大小、target/条件数量和递归深度；拒绝符号链接；不执行脚本、导入文件或启动 `gn`。
5. 对超大文件、不可读文件和不平衡 target 块返回结构化 `parse_failures`，不让单个文件中止整个 inventory。

## 2. 实现摘要

- 新增 `OpenHarmonyGNParser`，并提供 `GNParser` 别名。
- 新增 `GNTarget` 与 `GNParseResult` 数据模型及 `to_dict()`，便于后续 profile、构建图和报告复用。
- 使用注释清理、字符串掩码、括号/花括号平衡扫描和安全的引号读取；没有 `eval`、`exec` 或子进程调用。
- 默认边界：单文件 1 MiB、target 2048、条件 4096、递归深度 64。
- 支持普通 GN target 及常见 OpenHarmony target（包括 `ohos_unittest`、`ohos_fuzztest`、`ohos_shared_library`、`ohos_prebuilt_*`、host/test target 等）。
- `collect()` 只遍历仓库内真实文件，不跟随文件或目录符号链接，并输出确定性排序结果。

## 3. TDD 记录

### RED

先新增测试，再运行：

```text
../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_gn.py
```

结果：测试收集失败，`ModuleNotFoundError: No module named 'core.platforms.openharmony.gn'`。这确认测试确实针对尚不存在的实现。

### GREEN

实现解析器后运行同一命令：

```text
.....s                                                                   [100%]
5 passed, 1 skipped
```

覆盖项包括：常见字段提取和未知条件、测试/Fuzz 分类、脚本字符串不执行、不平衡 target 块、超大文件、符号链接逃逸。

## 4. 真实 OpenHarmony 源码验证

使用本地参考源码目录：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

命令：

```text
OPENHARMONY_CORPUS_ROOT=../../../openharmony_reference/openharmony_source_code \\
  ../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_gn.py
```

结果：

```text
......                                                                   [100%]
6 passed
```

实际检查的文件及 target：

| 文件 | 检查的 target |
|---|---|
| `sensors_medical_sensor/services/medical_sensor/BUILD.gn` | `libmedical_service` |
| `communication_netmanager_base/services/netconnmanager/BUILD.gn` | `net_conn_manager` |
| `drivers_peripheral/pin_auth/test/unittest/pin_auth/BUILD.gn` | `PinAuthHdiUtTest` |
| `drivers_peripheral/pin_auth/test/fuzztest/pin_auth/pinauthexecutorstub_fuzzer/BUILD.gn` | `PinAuthExecutorStubFuzzTest` |

另外对五个本地参考仓执行了 `collect()` inventory：

| 仓库 | GN 文件 | targets | 未知条件 | 解析失败 |
|---|---:|---:|---:|---:|
| `arkweb_arkweb_cangjie_wrapper` | 4 | 3 | 2 | 0 |
| `communication_netmanager_base` | 86 | 198 | 212 | 0 |
| `communication_wifi` | 90 | 142 | 323 | 0 |
| `drivers_peripheral` | 706 | 1299 | 1080 | 0 |
| `sensors_medical_sensor` | 12 | 22 | 1 | 0 |

这些数字证明解析器已经在用户提供的真实 OpenHarmony 代码上运行，而不是只在合成字符串上通过。

## 5. 相关回归测试

以下测试按模块隔离运行，避免项目中已知的顶层 `repository_scanner` 模块名冲突：

| 测试组 | 结果 |
|---|---|
| `tests/platforms/`（GN、scope、manifest、profile、base） | 28 passed, 2 skipped |
| `tests/test_scanner.py tests/test_scanner_platform_profile.py` | 18 passed |
| OpenHarmony C/scope/fixture 测试组 | 13 passed, 2 skipped |
| parser adapter 与 Python/Go CLI 平台参数测试组 | 13 passed |
| `ruff`、`py_compile`、`git diff --check` | 全部通过 |

## 6. 全量测试说明

曾运行 `../../.venv/bin/python -m pytest -q`，得到 `3026 passed, 38 skipped, 23 failed`。失败不由 OH-11A 引入：

- 1 个 Go conformance 测试因当前环境没有 `go` 可执行文件失败；
- 其余失败集中在全量测试顺序下既有的 Python 顶层模块缓存/样例路径问题（例如 `sample_python_repo` 被扫描为 0 个文件），与本阶段新增 GN 文件无调用关系；
- 本阶段及相关回归均使用上节隔离命令通过。

## 7. 阶段结论与边界

OH-11A 已完成：GN 元数据现在可以安全、可审计地被静态读取，并能区分生产、单元测试和 Fuzz target；未知条件不会被假装求值。当前解析结果尚未接入 `OpenHarmonyProfileBuilder` 的 build metadata，也尚未用于 scanner 的 component/target 分区，这些属于下一小阶段 OH-11B，需单独说明原逻辑和拟修改逻辑后再执行。
