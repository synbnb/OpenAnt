# OH-11B：GN 结果接入平台画像测试记录

- 执行日期：2026-08-22
- 阶段：OH-11B（GN 静态结果接入 `RepositoryProfile`）
- 状态：通过，可进入下一阶段评审
- 解析器：`libs/openant-core/core/platforms/openharmony/gn.py`
- 画像：`libs/openant-core/core/platforms/openharmony/profile.py`
- 公共契约：`libs/openant-core/core/platforms/base.py`
- 测试：`libs/openant-core/tests/platforms/test_openharmony_manifest.py`、`test_base.py`

## 1. 原逻辑与目标逻辑

原逻辑中，`OpenHarmonyProfileBuilder.inspect_repository()` 使用旧的轻量 GN 正则结果，仅能得到 `build_files[].targets` 和 `sources`。这些信息只停留在 inspection 返回值中，`RepositoryProfile` 没有稳定的构建元数据字段，后续模块无法直接复用完整的 GN 依赖和条件信息。

本阶段目标逻辑：

1. 复用 OH-11A 的安全 `OpenHarmonyGNParser.collect()`，不再执行 GN 或仓库脚本。
2. 在画像顶层新增可选 `build_metadata` 字段；空值时从 JSON 中省略，保持 generic 和旧画像序列化形状不变。
3. 保留旧 `build_files` 结构，避免 C scanner 现有契约变化；新增 `build_metadata.gn`，包含文件、详细 targets、sources、deps、external_deps、defines、include_dirs、test/fuzz role、未知条件和解析失败。
4. GN 解析失败只进入 `build_metadata.gn.parse_failures`，不阻断 bundle/namespace 证据驱动的平台画像。
5. 平台检测的 `gn_target` 信号改为来自详细 GN target 结果；如果 GN 解析不足，仍可依靠 bundle 和 OpenHarmony namespace 进行低置信度/阈值判断。

## 2. TDD 记录

### RED

先增加两个契约测试：

- fixture 画像必须暴露详细 GN metadata；
- 不平衡 GN target 块必须保留平台检测并记录解析失败。

运行：

```text
../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_manifest.py \\
  -k 'detailed_gn_metadata or unbalanced_target'
```

结果：2 个测试均失败，分别为 `KeyError: 'gn'` 和 `AttributeError: RepositoryProfile has no attribute build_metadata`。

### GREEN

实现以下最小改动后，同一命令结果：

```text
..                                                                       [100%]
2 passed
```

## 3. 功能验证

fixture `ipc_service` 的画像现在包含：

- `build_metadata.gn.files == ["BUILD.gn"]`；
- `openant_ipc_service` / `ohos_shared_library`；
- `external_deps == ["access_token:libaccesstoken_sdk", "ipc:ipc_core"]`；
- `unknown_condition_count == 0`；
- `parse_failures == []`。

畸形 GN fixture 验证：

- profile 仍成功生成；
- `build_metadata.gn.targets == []`；
- `build_metadata.gn.parse_failures` 保存相对路径和 `unbalanced target block` 原因。

公共 `RepositoryProfile` 的 `build_metadata` 也完成 JSON round-trip，空 metadata 仍不出现在旧 profile JSON 中。

## 4. 真实 OpenHarmony 五仓验证

使用：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

命令同时执行既有外部仓画像测试：

```text
OPENHARMONY_CORPUS_ROOT=../../../openharmony_reference/openharmony_source_code \\
  ../../.venv/bin/python -m pytest -q \\
  tests/platforms/test_openharmony_manifest.py \\
  tests/platforms/test_openharmony_profile.py
```

结果：`11 passed`。

直接构建五个 profile 的最终 inventory：

| 仓库 | GN 文件 | target | 未知条件 | 解析失败 | metadata 含绝对路径 |
|---|---:|---:|---:|---:|---|
| `arkweb_arkweb_cangjie_wrapper` | 4 | 3 | 2 | 0 | 否 |
| `communication_netmanager_base` | 86 | 198 | 212 | 0 | 否 |
| `communication_wifi` | 90 | 144 | 323 | 0 | 否 |
| `drivers_peripheral` | 706 | 1346 | 1080 | 0 | 否 |
| `sensors_medical_sensor` | 12 | 22 | 1 | 0 | 否 |

## 5. 相关回归测试

| 测试组 | 结果 |
|---|---|
| `tests/platforms` | 31 passed, 2 skipped |
| scanner 与 scanner profile | 18 passed |
| OpenHarmony C/scope/fixture | 13 passed, 2 skipped |
| parser adapter 与 CLI 平台参数 | 13 passed，1 个 pytest 临时目录清理 warning |
| Ruff、py_compile、git diff 检查 | 全部通过 |

## 6. 兼容性与边界

- generic profile 的 JSON 结构未增加空 `build_metadata` 字段。
- 旧 C scanner 继续读取旧 `build_files`，本阶段没有改变其 scope 行为。
- 详细 GN target 结果现在有稳定画像入口，后续可供 component/target 分区和语义图使用。
- GN 条件仍是未知表达式，不代表已经完成 GN 求值；它们只用于覆盖和风险提示。
