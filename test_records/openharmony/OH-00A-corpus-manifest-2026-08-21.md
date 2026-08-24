# OH-00A OpenHarmony Corpus Manifest 测试记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-00A：外部 OpenHarmony corpus manifest 契约 |
| 日期 | 2026-08-21 |
| OpenAnt 基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 平台 | macOS（Darwin） |
| Python | 3.13.13，`/Users/shiyu/miniconda3/bin/python` |
| pytest | 9.0.3 |
| 外部语料根目录 | 通过 `OPENHARMONY_CORPUS_ROOT` 注入；未写入 manifest |

## 2. 本阶段范围

本阶段只建立外部五仓的版本、Git 跟踪文件数量和关键文件特征基线，不修改 OpenAnt 生产代码、语言配置、parser 或 CLI。

新增文件：

- `libs/openant-core/tests/openharmony/test_corpus_manifest.py`
- `libs/openant-core/tests/fixtures/openharmony/corpus_manifest.json`
- `test_records/openharmony/OH-00A-corpus-manifest-2026-08-21.md`

## 3. TDD RED 记录

先新增测试，不创建 manifest，然后执行：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
python -m pytest tests/openharmony/test_corpus_manifest.py -v
```

结果：退出码 `1`，收集 2 个测试，2 个均在 fixture setup 阶段报错。

预期失败原因：

```text
AssertionError: OpenHarmony corpus manifest is missing:
tests/fixtures/openharmony/corpus_manifest.json
```

结论：RED 有效，测试确实约束了待实现的 manifest，而不是在没有实现时直接通过。

## 4. GREEN 实现与测试

创建最小 `corpus_manifest.json` 后，使用外部五仓执行：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
python -m pytest tests/openharmony/test_corpus_manifest.py -v
```

结果：退出码 `0`，`2 passed in 0.11s`。

通过的行为：

- manifest schema version 为 1。
- 五个仓名称完整且无重复。
- manifest 不包含 `/Users/...` 绝对路径。
- 每个 commit 是 40 位小写 Git SHA。
- source count 字段完整且均为非负整数。
- expected signal 使用相对 glob，禁止绝对路径和 `..`。
- 外部五仓目录存在，HEAD 与固定 commit 一致。
- 使用 `git ls-files` 统计的源码数量与 manifest 一致。
- 每仓的 `bundle.json`、`BUILD.gn`、IDL、ArkTS、仓颉等阶段相关文件特征存在。

## 5. 固定语料快照

| 仓库 | Commit | 关键计数 |
|---|---|---|
| `arkweb_arkweb_cangjie_wrapper` | `534acd4c3089d07c25e0638b9356553d4c80f127` | TS=4，JS=2，CJ=25，BUILD.gn=4 |
| `communication_netmanager_base` | `2401a2287eb7e99fc400ea9801b9ebdcba9f8e3d` | CPP=628，H=450，C=7，Rust=68，ETS=4，TS=5，IDL=1，BUILD.gn=85 |
| `communication_wifi` | `ac0e5205675ca17403f92107a8e0d89685c8dd51` | CPP=595，H=551，C=22，ETS=209，TS=19，IDL=5，BUILD.gn=87 |
| `drivers_peripheral` | `9aef209a5bd8e9dca05c2c736a5459ce44c5173a` | CPP=1282，H=1500，C=247，BUILD.gn=678，bundle.json=39 |
| `sensors_medical_sensor` | `6f87daec8f0a91057336b0b243eee702bd8731e7` | CPP=33，H=38，TS=1，BUILD.gn=11 |

计数口径是 Git 跟踪文件，不包含未跟踪文件和编辑器/构建产物。该口径下 `communication_wifi` 的 TS 数为 19；此前使用 `rg --files` 得到的工作树可见文件数为 17，因此 manifest 统一以可复现的 Git index 为准。

## 6. 便携模式测试

不设置外部语料路径：

```bash
python -m pytest tests/openharmony/test_corpus_manifest.py -v
```

结果：退出码 `0`，`1 passed, 1 skipped in 0.01s`。

- manifest 契约测试正常执行并通过。
- 外部五仓测试因未设置 `OPENHARMONY_CORPUS_ROOT` 而明确跳过。
- 该 skip 是外部大语料未配置时的预期行为，不是为了规避测试失败；本次本地完整模式已实际执行并通过该测试。

## 7. 相关回归测试

命令：

```bash
python -m pytest tests/test_language_registry.py tests/test_parser_adapter.py -v
```

结果：退出码 `0`，`61 passed in 0.14s`。

说明：本阶段没有修改语言注册或 parser，但该回归确认新增测试目录和 fixture 未影响现有语言发现、fence、CLI choices 和 Python parser adapter。

## 8. 静态检查

| 检查 | 结果 |
|---|---|
| `python -m py_compile tests/openharmony/test_corpus_manifest.py` | 通过 |
| JSON 解析 `corpus_manifest.json` | 通过 |
| 新增测试和 JSON 尾随空白检查 | 通过 |
| `python -m ruff check tests/openharmony/test_corpus_manifest.py` | 未执行：当前环境未安装 `ruff`，报错 `No module named ruff` |

没有为通过测试而安装或修改环境依赖。Ruff 检查需在安装 OpenAnt dev dependencies 的环境或现有 CI 中补跑。

## 9. 结论

OH-00A 的功能与相关回归均通过。当前已具备：

- 可移植、带版本的五仓基线。
- 本地完整语料校验。
- 不依赖用户绝对路径的 CI 契约测试。
- 后续各阶段可以复用的 commit 和文件数量比较基准。

本阶段没有改变 OpenAnt 的实际扫描行为。下一小阶段开始前，需要重新说明原有测试/fixture 逻辑和拟新增的最小 OpenHarmony IPC fixture，并获得用户批准。
