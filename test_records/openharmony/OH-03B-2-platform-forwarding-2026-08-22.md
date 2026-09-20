# OH-03B-2 OpenHarmony 平台参数转发与 C 管线接入测试记录

- 日期：2026-08-22
- 阶段：OH-03B-2（OH-03B 的第二切片）
- 目标：把显式 `--platform` 从 Python/Go CLI 入口传到 parser adapter 和 C 子进程，使 `--platform openharmony` 真正启用 OH-03B-1 的 scope/coverage/build metadata，并保留 generic/auto 的兼容行为。
- 本切片不包含：OpenHarmony profile/IDL/IPC 语义图、确定性漏洞规则、LLM Prompt、Fuzz 质量规则和安全知识导入。

## 原逻辑与修改后逻辑

原逻辑：平台值可以出现在 CLI/扫描结果的选择字段中，但 parser adapter 调用仍使用旧的固定参数；C 子进程不会收到 `--platform`，因此用户显式选择 OpenHarmony 时并不会触发 C 扫描器的角色分类和构建元数据读取。解析结果也没有把 C 管线产生的 `scan_results.json.scope` 暴露给上层。

修改后逻辑：

1. `openant/cli.py` 和 `core/scanner.py` 校验 `auto|generic|openharmony`。只有显式值才形成 parser kwargs，`auto` 不改变旧 parser 调用形状。
2. `core/parser_adapter.py` 将显式平台值传给 C parser；非 C parser 不添加平台参数。C 子进程命令行只在显式平台模式下追加 `--platform <value>`。
3. C 子进程完成后，parser adapter 读取同一输出目录的 `scan_results.json.scope`，写入 `ParseResult.platform_coverage`，并记录 `platform_selection`。
4. `parsers/c/test_pipeline.py` 接收并校验平台值，将其传入 `RepositoryScanner`；OpenHarmony 运行时把 scope 同步到 `dataset.json.metadata.openharmony_scope`。
5. `ParseResult`/`ScanResult` 对新增字段采用可选序列化：generic/auto 且没有平台数据时省略新字段，避免改变旧 JSON 形状。

## 修改文件

- [core/parser_adapter.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/core/parser_adapter.py)：新增平台参数、C 子进程 argv 转发和 scope 读取。
- [core/scanner.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/core/scanner.py)：把显式平台传入单语言/多语言解析入口，并回填扫描结果覆盖数据。
- [core/schemas.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/core/schemas.py)：新增可选 `platform_coverage`/`platform_selection` 字段并保持 generic 序列化兼容。
- [openant/cli.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/openant/cli.py)：parse/scan 命令校验和转发平台值，更新帮助文本。
- [parsers/c/test_pipeline.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/parsers/c/test_pipeline.py)：C 管线平台参数和 dataset scope 元数据。
- 测试：[test_parser_adapter_platform.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/tests/test_parser_adapter_platform.py)、[test_parse_platform_flags.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/tests/test_parse_platform_flags.py)、[test_scanner.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/tests/test_scanner.py)、[test_c_pipeline_platform.py](/Users/shiyu/学习/hyl/new/VulnFounder/libs/vulnfounder-core/tests/openharmony/test_c_pipeline_platform.py)。

## TDD 结果

### RED

先加入平台转发契约测试，再运行目标测试。实现前得到 6 个预期失败，原因包括 parser callable 尚未接受 `platform`、C 管线构造函数尚无该参数，以及扫描器没有把平台传入解析阶段。

### GREEN

平台转发与 CLI/C 管线目标测试：

```text
../../.venv/bin/python -m pytest -q \
  tests/test_parser_adapter_platform.py \
  tests/test_parse_platform_flags.py \
  tests/test_cli_platform_flags.py \
  tests/test_scanner.py \
  tests/openharmony/test_c_pipeline_platform.py \
  tests/platforms/test_base.py \
  tests/platforms/test_openharmony_profile.py
```

结果：`41 passed in 0.46s`。

OH-03B 相关 C/fixture 回归：

```text
../../.venv/bin/python -m pytest -q \
  tests/openharmony/test_c_scope_classification.py \
  tests/openharmony/test_c_scope_baseline.py \
  tests/openharmony/test_current_behavior_baseline.py \
  tests/openharmony/test_ipc_fixture.py \
  tests/openharmony/test_corpus_manifest.py \
  tests/parsers/c/test_repository_scanner_is_test_file.py \
  tests/test_parser_adapter.py
```

结果：`25 passed, 2 skipped in 0.07s`。

## 真实 C 管线验收

命令使用脱敏 fixture `tests/fixtures/openharmony/scope_roles`，不调用 LLM：

```text
OPENANT_RUN_DIR=<temporary-dir> python -c \
  'parse_repository(<fixture>, <run>/c, language="c", processing_level="all", skip_tests=False, platform="openharmony")'
```

结果：C parser 成功扫描 6 个 C/C++ 文件，提取 5 个函数并生成 5 个 units；返回 `platform_selection="openharmony"`，并从 `scan_results.json` 读回完整 `platform_coverage`。

scope 关键观测：

- `source_scope=all`，`discovered_files=11`、`eligible_files=6`、`parsed_files=6`。
- 角色计数：production 3、test 2、fuzz 1、build_metadata 2、interface_metadata 1、unknown 1、unsupported_source 1。
- `vendor` 被排除但计入 `excluded_directories`；`.ets` 被记录为 unsupported source。
- `BUILD.gn` 解析出 target `health_sensor_service` 和 source `services/health_sensor_service.cpp`。
- `bundle.json` 解析出 component `openant_scope_roles_fixture`。
- `dataset.json.metadata.openharmony_scope` 与 `scan_results.json.scope` 完全一致。

这证明参数不是只停留在 ScanResult 字段，而是已经经过 CLI/扫描器 → parser adapter → C subprocess → C scanner → dataset/coverage 产物的完整链路。

## 相关回归

扫描器/多语言/威胁模型回归：

```text
PYTHONPATH=tests:. ../../.venv/bin/python -m pytest -q \
  tests/test_scanner_contract.py tests/test_scanner_multilang.py \
  tests/test_scanner_refilter_metadata.py tests/test_scanner_refilter_library_mode.py \
  tests/test_scanner_refilter_loop.py tests/test_scanner_refilter_loop_executes.py \
  tests/test_scanner_refilter_multilang.py tests/test_scanner_threat_model_integration.py \
  tests/test_schemas_multilang.py
```

结果：`80 passed in 1.92s`。

Go CLI 回归（模块目录为 `apps/vulnfounder-cli`）：

```text
GOCACHE=/private/tmp/openant-go-build-cache GOPATH=/private/tmp/openant-go \
  ../../.devtools/go1.25.7/go/bin/go test ./cmd -v
```

结果：`PASS`，`ok github.com/synbnb/vulnfounder/apps/vulnfounder-cli/cmd`。其中探测失败用例的失败子调用是测试设计的预期负例，外层测试整体通过。

## 质量检查

```text
ruff check <本切片修改的 Python 文件>
python -m py_compile <本切片修改的 Python 文件>
git diff --check
```

结果：`All checks passed!`，退出码为 `0`。

## 阶段结论

OH-03B-2 已完成。显式 OpenHarmony 平台选择现在会真实触发 C scope 分类，并把 coverage/build metadata 传回 Python 解析结果和 dataset；默认 `auto`、显式 `generic` 以及非 C parser 的旧调用行为保持兼容。OH-03B（文件范围契约及其参数链路）可以标记完成，下一阶段开始前仍需按约定先说明原逻辑、目标逻辑并征得确认。
