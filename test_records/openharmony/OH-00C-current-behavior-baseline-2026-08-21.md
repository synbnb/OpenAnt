# OH-00C VulnFounder 当前行为基线测试记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-00C：OpenHarmony 适配前的发现、C 解析与入口行为基线 |
| 日期 | 2026-08-21 |
| VulnFounder 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 开发分支 | `feature/openharmony-adaptation` |
| Python | 3.11.15，项目 `.venv` |
| pytest | 9.1.1 |

## 2. 原逻辑与本阶段目标

当前 VulnFounder 没有 OpenHarmony 平台画像，主要沿用三类通用逻辑：

1. `core/parser_adapter.detect_languages()` 只统计语言注册表中已经注册的扩展名。
2. C/C++ 流水线只扫描 C/C++ 扩展名，通过 tree-sitter 抽取函数，再以名称匹配方式构建调用边。
3. 通用入口检测器识别 Web、CLI、`main` 等入口，但不理解 OpenHarmony Binder IPC 的 `OnRemoteRequest`、transaction code 和 Proxy/Stub 语义。

OH-00C 不修复上述行为，只把实际结果固化为机器可读、可重复运行的基线。后续 OH-01 及之后的改动必须明确说明基线中的哪一项行为发生了预期变化，避免把现有缺陷误当成新回归，也避免无意改变未授权范围。

本阶段没有修改生产代码、语言注册表、解析器、调用图或入口检测器。

## 3. 修改内容

新增：

```text
tests/openharmony/test_current_behavior_baseline.py
tests/fixtures/openharmony/current_behavior_baseline.json
```

基线 JSON 具有以下属性：

- `schema_version: 1`，便于后续显式演进契约。
- `mode: observed_current_behavior`，表明它是现状记录，不是目标行为规范。
- 固定 VulnFounder 基线提交，但不包含用户绝对路径。
- 保存五个外部语料仓的当前语言发现结果。
- 保存合成 IPC fixture 的扫描文件、函数、unit 类型、调用边和入口结果。
- 显式列出已知缺口，防止当前限制被误解为正确的 OpenHarmony 语义。

测试支持两种模式：不设置 `OPENHARMONY_CORPUS_ROOT` 时仍可使用仓内 fixture 和固定清单执行；设置后会对本地五仓执行实时发现，并与固定基线逐仓比较。

## 4. 修改前的实测行为

对 OH-00B 合成 IPC fixture 运行现有 C 流水线：

```bash
../../.venv/bin/python parsers/c/test_pipeline.py \
  tests/fixtures/openharmony/ipc_service \
  --output /private/tmp/openant-oh00c.hl6RiX \
  --processing-level reachable \
  --name openharmony-ipc-baseline
```

结果：

- 扫描 3 个 C/C++ 文件，共 2820 bytes。
- 抽取 8 个 function，生成 8 个 unit。
- unit 类型为 constructor 1、function 3、method 3、static_function 1。
- 生成 1 条名称匹配调用边，平均出度 0.12，6 个孤立函数。
- 检测到 0 个入口。
- 因入口集合为空触发安全兜底，保留全部 8 个 unit，裁剪率 0%。
- 全程未调用 LLM。

现有抽取器还把接口头文件中的 3 个 namespace/class 节点记录成 function unit。这是本次固定下来的现状之一，不代表期望语义。

唯一调用边为：

```text
HealthSensorServiceStub::EnableSensorInner
  -> HealthSensorServiceProxy::EnableSensor
```

该边来自同名匹配，不是从 `SendRequest`、transaction code 和 `OnRemoteRequest` 分派关系恢复出的 IPC 语义边。`HealthSensorServiceStub::OnRemoteRequest` 当前不是入口，且没有到 handler 的出边。

## 5. 外部五仓发现基线

基于 OH-00A 固定的外部语料快照，当前 `detect_languages()` 实测结果如下：

| 仓库 | 当前发现结果 | 当前未注册源码 | 忽略的构建元数据 |
|---|---|---|---|
| `arkweb_arkweb_cangjie_wrapper` | javascript 6、python 2 | Cangjie 25 | BUILD.gn 4、bundle.json 1 |
| `communication_netmanager_base` | c 1085、javascript 5、rust 68 | ArkTS 4、IDL 1 | BUILD.gn 85、gni 1、bundle.json 1 |
| `communication_wifi` | c 1168、javascript 19 | ArkTS 209、IDL 5 | BUILD.gn 87、gni 3、bundle.json 1 |
| `drivers_peripheral` | c 3029、python 3 | 无 | BUILD.gn 678、gni 28、bundle.json 39 |
| `sensors_medical_sensor` | c 71、javascript 1 | 无 | BUILD.gn 11、gni 1、bundle.json 1 |

其中 `.ts` 目前按 javascript 计数；`.ets`、`.cj`、`.idl`、`BUILD.gn`、`.gni` 和 `bundle.json` 不属于当前语言发现范围。

## 6. 已知缺口

基线显式记录以下缺口：

```text
no_platform_profile
build_metadata_not_discovered
arkts_not_registered
cangjie_not_registered
idl_not_registered
on_remote_request_not_an_entry_point
no_ipc_semantic_edge
namespace_nodes_misclassified
name_only_call_graph_edge
dataset_language_missing
```

这些条目是后续实施的对照项，不是允许永久保留的预期结果。

## 7. TDD RED

先新增契约测试，不创建基线 JSON，执行：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest \
  tests/openharmony/test_current_behavior_baseline.py -v
```

结果：退出码 `1`，收集 4 项，4 项均因缺少以下文件而报错：

```text
tests/fixtures/openharmony/current_behavior_baseline.json
```

结论：RED 有效。测试确实要求显式提供当前行为基线，没有在实现缺失时误通过。

## 8. OH-00C 独立 GREEN 测试

创建基线 JSON 后，以相同命令复测。

结果：退出码 `0`。

```text
4 passed in 0.10s
```

通过的契约：

1. 基线格式可移植、有版本且明确标记为当前行为观测。
2. 外部仓语言发现统计与 OH-00A 固定清单一致。
3. 合成 IPC fixture 的发现、解析、调用图和入口结果与实测基线一致。
4. 注入真实外部语料路径时，五仓实时语言发现结果与基线一致。

## 9. OpenHarmony 联合测试

命令：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest tests/openharmony -v
```

结果：退出码 `0`。

```text
9 passed in 0.17s
```

其中包括 OH-00A 的外部五仓快照实测、OH-00B 的合成 IPC fixture 契约和 OH-00C 的当前行为基线，不是便携模式 skip。

## 10. 相关回归

命令：

```bash
../../.venv/bin/python -m pytest \
  tests/test_language_registry.py \
  tests/test_language_registry_resolution.py \
  tests/test_parser_adapter.py \
  tests/test_parser_adapter_timeout.py \
  tests/test_entry_point_detector.py \
  tests/test_entry_point_detector_native_seeds.py \
  tests/parsers/test_entry_point_detector_init_root.py \
  tests/parsers/test_entry_point_detector_u12.py \
  tests/parsers/c/test_empty_seed_keep_all.py -v
```

结果：退出码 `0`。

```text
92 passed in 1.77s
```

确认新增基线没有改变现有语言注册与解析器配置解析、语言自动发现、子进程超时、通用入口检测、native `main`/`init` 种子和 C 空入口保留全部 unit 的行为。

## 11. 静态与差异检查

命令：

```bash
../../.venv/bin/ruff check tests/openharmony/test_current_behavior_baseline.py
../../.venv/bin/python -m py_compile tests/openharmony/test_current_behavior_baseline.py
git diff --check
```

结果：三项退出码均为 `0`；Ruff 输出 `All checks passed!`，Python 语法检查和 Git 空白错误检查通过。

基线 JSON 在测试中通过 `json.loads` 解析，并被逐字段用于契约比较。

## 12. 测试范围说明

本阶段没有修改生产代码或依赖，因此没有重复运行 2969 项完整 Python 套件。直接影响范围由 9 项 OpenHarmony 专项测试、92 项语言/解析/入口回归和静态检查覆盖；环境阶段完整套件结果仍为 `2969 passed, 34 skipped`。

外部语料实时检查依赖本机环境变量注入；基线文件本身不保存 `/Users/shiyu/...` 等绝对路径。`/private/tmp/openant-oh00c.hl6RiX` 仅用于本阶段流水线观察，不属于项目交付物。

## 13. 阶段结论

OH-00C 已完成。VulnFounder 适配前对 OpenHarmony 语料的“能发现什么、会忽略什么、C parser 会生成什么、入口和调用边如何退化”已经形成可执行基线。

OH-00 至此完成。下一小阶段是 OH-01：建立 OpenHarmony 平台协议与 schema；在用户批准前不修改生产代码。
