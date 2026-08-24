# OH-12B：IDL/SA 结果接入平台画像测试记录

- 执行日期：2026-08-22
- 阶段：OH-12B（IDL/SA 元数据接入 `RepositoryProfile`）
- 状态：通过，可进入下一阶段评审
- 画像实现：`libs/openant-core/core/platforms/openharmony/profile.py`
- 契约实现：`libs/openant-core/core/platforms/base.py`（OH-11B 已新增可选 `build_metadata`）
- 测试：`libs/openant-core/tests/platforms/test_openharmony_manifest.py`

## 1. 原逻辑与目标逻辑

原逻辑中，`RepositoryProfile.build_metadata` 只包含 GN 和旧版 build metadata；IDL 仅作为源码类型信号，SA profile 完全没有进入画像。

本阶段将两个已验证的静态解析器接入画像：

- `build_metadata.idl`：保存 IDL 文件、interface、方法、参数方向/类型、enum、struct 和解析失败；
- `build_metadata.sa_profiles`：保存 JSON/XML SA profile、process、SA ID、libpath、启动/分布式属性和解析失败；
- `provenance.idl_paths` 与 `provenance.sa_profile_paths` 保存相对路径；
- malformed IDL/SA 只产生 metadata failure，不降低已有 bundle/GN/namespace 画像构建的 fail-safe 行为；
- generic scanner 和旧 `build_files` 结构不改变。

## 2. TDD 记录

### RED

先增加两个画像契约测试：有效 IDL/SA 应进入 profile，畸形 IDL/SA 应保留画像并记录失败。运行：

```text
../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_manifest.py \\
  -k 'idl_and_sa_metadata or idl_or_sa_metadata'
```

结果：2 个测试均失败，原因是 `profile.build_metadata` 尚未包含 `idl` / `sa_profiles`。

### GREEN

接入两个 parser 后同一命令结果：

```text
..                                                                       [100%]
2 passed
```

有效 fixture 验证了 interface、method、SA ID 和 provenance 路径；畸形 fixture 验证 profile 仍成功生成并保存相对解析失败。

## 3. 真实五仓验证

使用本地参考源码：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

最终画像 inventory：

| 仓库 | IDL 文件 | IDL interface | SA profile | SA 条目 | IDL/SA 解析失败 |
|---|---:|---:|---:|---:|---:|
| `arkweb_arkweb_cangjie_wrapper` | 0 | 0 | 0 | 0 | 0 |
| `communication_netmanager_base` | 1 | 2 | 8 | 8 | 0 |
| `communication_wifi` | 5 | 6 | 4 | 4 | 0 |
| `drivers_peripheral` | 0 | 0 | 0 | 0 | 0 |
| `sensors_medical_sensor` | 0 | 0 | 1 | 1 | 0 |

真实 profile 测试命令：

```text
OPENHARMONY_CORPUS_ROOT=../../../openharmony_reference/openharmony_source_code \\
  ../../.venv/bin/python -m pytest -q \\
  tests/platforms/test_openharmony_manifest.py \\
  tests/platforms/test_openharmony_profile.py
```

结果：`13 passed`。

检查了 `communication_wifi` 的 5 个 IDL、`communication_netmanager_base` 的 1 个 IDL，以及 `sensors_medical_sensor/sa_profile/3605.xml`；画像 metadata 不含本机绝对路径。

## 4. 相关回归测试

| 测试组 | 结果 |
|---|---|
| profile/manifest/base 契约 | 26 passed |
| IDL/SA parser 真实测试 | 9 passed |
| 平台/GN/scope 回归 | 33 passed, 2 skipped |
| scanner 与 scanner profile | 18 passed |
| OpenHarmony C/scope/fixture | 13 passed, 2 skipped |
| parser adapter 与 CLI 平台参数 | 13 passed |
| Ruff、py_compile、git diff 检查 | 全部通过 |

## 5. 阶段边界

OH-12B 完成后，`RepositoryProfile` 已能统一携带 bundle、GN、IDL 和 SA profile 元数据。当前还没有把 IDL interface 与 C/C++ Proxy/Stub 方法自动连边，也没有执行权限校验或生成代码解析；这些属于后续 OH-13/OH-14 入口与语义覆盖图阶段。
