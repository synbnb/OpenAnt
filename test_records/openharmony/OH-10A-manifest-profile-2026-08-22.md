# OH-10A OpenHarmony 平台识别与 bundle.json 清单测试记录

- 日期：2026-08-22
- 阶段：OH-10A（OH-10 的第一切片）
- 目标：新增安全的 `bundle.json` 清单解析和基于仓库本地证据的 OpenHarmony profile 自动构建。
- 范围：`manifest.py`、`profile.py` 及单元/fixture/corpus 验证。
- 不包含：GN 深度解析、IDL/SA 语义提取、IPC 图、入口点、规则和 CLI `auto` 模式接入；这些保留到后续切片。

## 原逻辑与修改后逻辑

原逻辑：`OpenHarmonyProfileBuilder` 只能接收调用方预先提供的 signals，不能自己读取仓库；C scope 层虽然会读取少量 `BUILD.gn`/`bundle.json` 元数据，但没有可复用的组件清单模型，也不能从五个参考仓自动生成统一 profile。畸形清单的处理没有独立的 fail-safe 契约。

修改后逻辑：

1. `BundleManifestReader` 只读仓库内的 `bundle.json`，限制单文件大小和文件数量，拒绝 symlink 越界，所有结果路径保持相对路径。
2. 每个清单被归一化为组件记录：`name`、`subsystem`、`syscaps`、`system_types`、构建目标、测试目标、inner kits、组件依赖和第三方依赖。
3. 支持 OpenHarmony 实际使用的 `build.sub_component`、`build.group_type` 嵌套结构；不会执行 GN 或仓库脚本。
4. `OpenHarmonyProfileBuilder.inspect_repository()` 汇总 bundle、GN target、`namespace OHOS`、IDL、System Ability、Binder 和 HDF 等相对路径证据，并返回置信度，即使置信度不足也保留 signals。
5. `build_from_repository()` 只有在已有平台协议的阈值（0.75）上构建 `RepositoryProfile`；低置信度返回 `None`，调用方可安全回退 generic。成功 profile 保存组件、语言、边界和 provenance，包含 manifest parse failures。

## 修改文件

- [manifest.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/platforms/openharmony/manifest.py)：安全发现、解析和归一化 `bundle.json`。
- [profile.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/platforms/openharmony/profile.py)：仓库证据扫描、置信度计算和 profile 构建。
- [test_openharmony_manifest.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/tests/platforms/test_openharmony_manifest.py)：清单字段、畸形 JSON、嵌套 group_type、自动识别和五仓检查。

## TDD 结果

### RED

先加入 OH-10A 测试并运行：

```text
../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_manifest.py
```

结果：收集阶段失败，`core.platforms.openharmony.manifest` 尚不存在；这是预期的 RED。

### GREEN

实现最小清单解析器和 profile builder 后：

```text
../../.venv/bin/python -m pytest -q \
  tests/platforms/test_openharmony_manifest.py \
  tests/platforms/test_openharmony_profile.py
```

结果：`8 passed, 1 skipped`。

## 合成 OpenHarmony fixture 验收

在 `tests/fixtures/openharmony/ipc_service` 上自动识别结果：

- `platform=openharmony`，置信度 `1.0`。
- 证据包含 `bundle_manifest`、`gn_target`、`namespace_ohos`。
- 组件为 `openant_ipc_fixture`，subsystem 为 `security`。
- 解析出 syscap `SystemCapability.Security.OpenAntFixture`、`standard` 系统类型、1 个构建 target 和 `access_token`/`ipc` 依赖。
- 仅有 `namespace OHOS` 的临时仓库置信度为 `0.25`，profile 返回 `None`，但 signals 中仍保留相对路径 `service.cpp`。
- malformed JSON 和非 object JSON 均进入相对路径 `parse_failures`，不会阻断其他 manifest，也不会将绝对用户路径写入结果。

## 五个本地 OpenHarmony 参考仓验收

使用：

```text
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
  ../../.venv/bin/python -m pytest -q \
  tests/platforms/test_openharmony_manifest.py::test_external_reference_repositories_are_auto_detected_when_configured
```

结果：`1 passed in 2.17s`。五个仓均自动生成 OpenHarmony profile：

| 仓库 | 结果 | 置信度 | 组件 | 首个组件 subsystem |
|---|---:|---:|---:|---|
| `arkweb_arkweb_cangjie_wrapper` | 通过 | 0.75 | 1 | web |
| `communication_netmanager_base` | 通过 | 1.00 | 1 | communication |
| `communication_wifi` | 通过 | 1.00 | 1 | communication |
| `drivers_peripheral` | 通过 | 1.00 | 39 | hdf |
| `sensors_medical_sensor` | 通过 | 1.00 | 1 | sensors |

期间发现 `communication_netmanager_base/bundle.json` 使用 `build.group_type` 而非 `build.sub_component`；已补充递归目标提取并增加单元测试，重新验收通过。

## 相关回归

平台、OpenHarmony fixture、C scanner 回归（拆分运行以保持 Python/C parser 的测试导入隔离）：

```text
../../.venv/bin/python -m pytest -q \
  tests/platforms tests/openharmony \
  tests/parsers/c/test_repository_scanner_is_test_file.py
```

结果：`37 passed, 3 skipped`。

parser adapter 回归：

```text
../../.venv/bin/python -m pytest -q tests/test_parser_adapter.py
```

结果：`11 passed`。

扫描器/多语言回归：

```text
PYTHONPATH=tests:. ../../.venv/bin/python -m pytest -q \
  tests/test_scanner_contract.py tests/test_scanner_multilang.py \
  tests/test_scanner_refilter_metadata.py tests/test_scanner_refilter_library_mode.py \
  tests/test_scanner_refilter_loop.py tests/test_scanner_refilter_loop_executes.py \
  tests/test_scanner_refilter_multilang.py tests/test_scanner_threat_model_integration.py \
  tests/test_schemas_multilang.py
```

结果：`80 passed in 1.95s`。

## 已知测试隔离注意事项

把 `tests/platforms`、`tests/openharmony` 和 `tests/test_parser_adapter.py` 放在同一个 pytest 进程时，已有的 C pipeline 测试会把顶层模块名 `repository_scanner` 缓存在 `sys.modules`；随后 Python parser 的旧式无包名导入会解析到 C scanner，造成 5 个 Python parser 测试失败。单独运行 parser adapter（上面的规范命令）为 `11 passed`。本切片未修改这一项无关的历史测试导入污染，避免把 OH-10A 与测试隔离重构混在一起；后续可单列兼容性修复。

## 质量检查

```text
ruff check core/platforms/openharmony/manifest.py \
  core/platforms/openharmony/profile.py \
  tests/platforms/test_openharmony_manifest.py \
  tests/platforms/test_openharmony_profile.py
python -m py_compile core/platforms/openharmony/manifest.py \
  core/platforms/openharmony/profile.py \
  tests/platforms/test_openharmony_manifest.py
git diff --check
```

结果：`All checks passed!`，退出码为 `0`。

## 阶段结论

OH-10A 已完成。OpenHarmony profile 现在可以独立从五个本地参考仓自动识别并提取组件核心边界，畸形输入安全降级；下一切片再把 profile 接入 `--platform auto` 的扫描产物，并补充平台 profile JSON 输出。进入下一切片前仍按约定先说明原逻辑、计划逻辑并等待确认。
