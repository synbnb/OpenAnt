# OH-01B OpenHarmony Profile Builder 测试记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-01B：最小 OpenHarmony 静态信号 Profile Builder |
| 日期 | 2026-08-21 |
| OpenAnt 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 开发分支 | `feature/openharmony-adaptation` |
| Python | 3.11.15，项目 `.venv` |
| pytest | 9.1.1 |

## 2. 原逻辑与本阶段目标

OH-01A 已提供平台无关的 `RepositoryProfile`、`CoverageReport` 和语义图契约，但没有任意平台 adapter 能构造该 profile。OpenAnt 仍不能从平台线索获得可版本化的 OpenHarmony 描述。

OH-01B 新增 `OpenHarmonyProfileBuilder`，但范围严格限制为：将调用方**已经收集**的静态信号归一化为 `RepositoryProfile`。它不遍历仓库、不读取源码、不解析 `bundle.json`、不解析 GN/IDL、不运行 shell、也不接入 scanner 或 CLI。

## 3. 修改内容

新增：

```text
core/platforms/openharmony/__init__.py
core/platforms/openharmony/profile.py
tests/platforms/test_openharmony_profile.py
```

并将 `PlatformProfileBuilder` 的协议方法签名扩展为允许 adapter 接收平台专属的显式关键字参数。

`OpenHarmonyProfileBuilder` 认可的信号与确定性权重：

| 信号键 | 权重 | 说明 |
|---|---:|---|
| `bundle_manifest` | 0.50 | 调用方已定位到 bundle manifest 的信号 |
| `gn_target` | 0.25 | 调用方已定位到 OpenHarmony GN target 的信号 |
| `namespace_ohos` | 0.25 | 调用方已定位到 OHOS namespace 的信号 |

最低识别阈值为 `0.75`。例如 `bundle_manifest + gn_target` 可识别；仅 `namespace_ohos + binder_stub` 只有 0.25，返回 `None`。未在白名单中的信号完全忽略，不影响分数或 detection evidence。

## 4. TDD RED

先新增测试、不创建 OpenHarmony adapter 包，执行：

```bash
../../.venv/bin/python -m pytest \
  tests/platforms/test_openharmony_profile.py -v
```

结果：退出码 `2`，收集阶段失败：

```text
ModuleNotFoundError: No module named 'core.platforms.openharmony'
```

结论：RED 有效。测试在 adapter 尚未实现时无法导入。

## 5. GREEN 实现与独立测试

创建 builder 后，以相同命令复测。

结果：退出码 `0`。

```text
3 passed in 0.01s
```

通过的契约：

1. 读取 OH-00B 合成 IPC fixture manifest 中的显式静态信号，可以构造 schema version 为 1 的 OpenHarmony profile；其信号得分为 1.0。
2. 证据不足时返回 `None`，不会把含少量 OHOS/Binder 文本的 C++ 目录误判成 OpenHarmony。
3. 未知信号不会被作为证据、配置或命令处理；`bundle_manifest + gn_target` 的结果固定为 confidence 0.75、两项证据。

## 6. 联合回归

命令：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest \
  tests/platforms \
  tests/openharmony \
  tests/test_schemas_multilang.py \
  tests/test_parse_repository_analyzer_schema.py \
  tests/test_json_corrector_verify_schema.py \
  tests/test_llm_config_schema.py -v
```

结果：退出码 `0`。

```text
49 passed in 0.32s
```

覆盖 OH-01A 平台基础契约、OH-01B builder、OH-00 五仓清单与当前行为基线、合成 IPC fixture，以及既有 schema/多语言/验证/LLM 配置兼容性。

## 7. 静态与差异检查

命令：

```bash
../../.venv/bin/ruff check core/platforms tests/platforms
../../.venv/bin/python -m py_compile \
  core/platforms/base.py \
  core/platforms/openharmony/profile.py \
  tests/platforms/test_base.py \
  tests/platforms/test_openharmony_profile.py
git diff --check
```

结果：三项退出码均为 `0`；Ruff 输出 `All checks passed!`，Python 语法检查和 Git 空白错误检查通过。

## 8. 测试范围说明

测试只读取仓内的合成 fixture manifest，未对用户提供的五个外部 OpenHarmony 仓进行文件遍历或 profile 构建。外部语料路径仅用于联合回归中的 OH-00 snapshot 验证。

本阶段不修改 generic scanner、语言检测、tree-sitter、入口规则、CLI 或结果报告流程，因此未重复运行完整 Python 套件。直接受影响范围由 49 项联合回归与静态检查覆盖；环境阶段完整套件基线仍为 `2969 passed, 34 skipped`。

## 9. 阶段结论

OH-01B 已完成。OpenAnt 现在可以在不执行或信任目标仓文本的前提下，将明确的 OpenHarmony 静态信号构造成版本化 profile，并对证据不足情形保持 fail-safe。

下一小阶段建议为 OH-01C：增加 profile 输入/输出的严格 schema 验证和 coverage 一致性检查；仍不接入 scanner，用户批准前不修改代码。
