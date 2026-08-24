# OH-03B-1 OpenHarmony 文件角色与构建元数据分类测试记录

- 日期：2026-08-22
- 阶段：OH-03B-1（OH-03B 的第一切片）
- 目标：为 OpenHarmony C/C++ 文件发现增加可移植的角色分类、source scope、coverage 缺口记录和受限构建元数据读取。
- 本切片不包含：parser adapter/CLI 参数传递、IDL 语义图、IPC 入口点、确定性漏洞规则和 LLM Prompt 修改。

## 原逻辑与修改后逻辑

原逻辑：C 扫描器仅按扩展名收集文件，并在遍历阶段硬排除 `test/tests/fuzz/vendor` 等目录；文件记录没有角色，`BUILD.gn`、`bundle.json`、`.ets`、`.idl` 等文件没有结构化 coverage 记录。

修改后逻辑：只有显式传入 `platform=openharmony` 才启用 OpenHarmony scope 层。安全遍历仍保留，测试/Fuzz 目录会被遍历后按角色过滤，第三方目录继续默认裁剪但记录在 `coverage.excluded_directories`。C/C++ 文件记录增加 `role`，扫描结果增加 `scope.coverage` 与 `scope.build_metadata`。generic/auto 模式保持旧输出和目录策略。

## 新增实现

- [scope.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/platforms/openharmony/scope.py)
  - 角色：`production`、`test`、`fuzz`、`generated`、`third_party`、`build_metadata`、`interface_metadata`、`unsupported_source`、`unknown`。
  - scope：`production`、`security-tests`、`all`。
  - 静态读取 `bundle.json` 与 GN 文件中的 target/source 字符串，不执行 GN 或仓库代码。
  - 限制元数据文件大小，并拒绝绝对路径、`..` 路径和 symlink fallback 越界读取。
- [repository_scanner.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/parsers/c/repository_scanner.py)
  - OpenHarmony 模式下生成文件角色、每类角色计数、unsupported 文件、跳过原因和构建元数据。
  - `skip_tests=True` 映射到 `production`，`skip_tests=False` 映射到 `all`，保留旧参数兼容性。

## TDD 结果

1. RED：在实现分类器前执行目标测试，收集阶段因缺少 `core.platforms.openharmony.scope` 导入失败。
2. GREEN：

   ```text
   python -m pytest -q \
     tests/platforms/test_openharmony_scope_classifier.py \
     tests/openharmony/test_c_scope_classification.py
   ```

   结果：`5 passed`。

## 夹具观测

在 `scope_roles` 合成夹具上：

- `platform=openharmony, skip_tests=False`：发现 6 个 C/C++ 文件，其中 production 3、test 2、fuzz 1；`.ets` 作为 unsupported source 记录；`BUILD.gn` 和 `bundle.json` 解析出 1 个 target 和 1 个 source。
- `platform=openharmony, skip_tests=True`：保留 production 3 个文件，记录 test 2 个和 fuzz 1 个被 scope 过滤。
- `vendor/` 未被默认遍历，但记录为 `coverage.excluded_directories: {"vendor": 1}`。
- generic 模式仍不增加 `role`/`scope` 输出，保持 OH-03A 既有基线。

## 相关回归

```text
python -m pytest -q \
  tests/platforms/test_openharmony_scope_classifier.py \
  tests/openharmony/test_c_scope_classification.py \
  tests/openharmony/test_c_scope_baseline.py \
  tests/openharmony/test_current_behavior_baseline.py \
  tests/openharmony/test_ipc_fixture.py \
  tests/openharmony/test_corpus_manifest.py \
  tests/parsers/c/test_repository_scanner_is_test_file.py \
  tests/test_scanner_contract.py
```

结果：`46 passed, 2 skipped`。

```text
PYTHONPATH=tests:. python -m pytest -q \
  tests/test_scanner_contract.py tests/test_scanner_multilang.py \
  tests/test_scanner_refilter_metadata.py tests/test_scanner_refilter_library_mode.py \
  tests/test_scanner_refilter_loop.py tests/test_scanner_refilter_loop_executes.py \
  tests/test_scanner_refilter_multilang.py tests/test_scanner_threat_model_integration.py \
  tests/test_schemas_multilang.py
```

结果：`80 passed`。

```text
python -m pytest -q tests/test_parser_adapter.py \
  tests/parsers/c/test_repository_scanner_is_test_file.py
```

结果：`13 passed`。

## 质量检查

```text
ruff check core/platforms/openharmony/scope.py parsers/c/repository_scanner.py \
  tests/platforms/test_openharmony_scope_classifier.py \
  tests/openharmony/test_c_scope_classification.py
python -m py_compile core/platforms/openharmony/scope.py \
  parsers/c/repository_scanner.py \
  tests/platforms/test_openharmony_scope_classifier.py \
  tests/openharmony/test_c_scope_classification.py
git diff --check
```

结果：全部通过，退出码为 `0`。

## 阶段结论

OH-03B-1 已完成。分类器和扫描器接口已经可独立测试；由于当前 `--platform` 仍只记录显式选择，下一切片需要把 platform 从 Python/Go parse/scan 命令传入 C 子进程，才能让用户命令真正触发上述 OpenHarmony 逻辑。
