# OH-10B Scanner 自动平台画像接入测试记录

- 日期：2026-08-22
- 阶段：OH-10B（OH-10 的第二切片）
- 目标：把 OH-10A 的 profile builder 接入 `scan_repository`，让 `platform=auto` 在达到置信度阈值时自动启用 OpenHarmony C parser，并生成 `platform_profile.json`。
- 本切片不包含：GN 深度归属、IDL/SA 解析、IPC 图、规则和 LLM 行为变化。

## 原逻辑与修改后逻辑

原逻辑：`scan_repository(platform="auto")` 不读取 OpenHarmony profile，也不改变 C parser 的平台模式；即使仓库包含有效 `bundle.json`、GN target 和 OpenHarmony 源码特征，C 子进程仍按 generic/auto 方式运行，扫描结果没有独立的 `platform_profile.json`。

修改后逻辑：

1. `platform=auto` 或显式 `platform=openharmony` 时，扫描开始阶段调用 `OpenHarmonyProfileBuilder.build_from_repository()`。
2. `auto` 只有在 profile 达到现有阈值时才将有效平台提升为 `openharmony`；低置信度返回 generic 兼容路径。
3. 成功识别后写入 `<output_dir>/platform_profile.json`，同时填充 `ScanResult.platform_profile` 和 aggregate `scan.report.json` 的 profile/路径字段。
4. 有效平台通过已有 parser adapter 链路传给 C parser；非 C parser仍不会收到平台 argv。
5. profile 检测异常被记录到 stderr 并安全回退，不阻断扫描；显式 `generic` 不触发 OpenHarmony profile 检测。

## 修改文件

- [core/scanner.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/scanner.py)：自动 profile 检测、有效平台选择、profile 产物和 scan report 记录。
- [test_scanner_platform_profile.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/tests/test_scanner_platform_profile.py)：自动识别、低置信度回退、异常回退、显式 generic 隔离和真实 C parser 链路测试。

## TDD 结果

### RED

先写入 scanner profile 集成测试。在修正一个测试断言（显式 generic 应保留原有 `platform="generic"` 转发）后，未实现代码的目标结果为：`1 failed, 2 passed`；失败点是未生成 `platform_profile.json`。

### GREEN

```text
../../.venv/bin/python -m pytest -q tests/test_scanner_platform_profile.py
```

结果：`6 passed in 0.47s`。

覆盖内容：

- auto profile 成功时切换到 OpenHarmony、写出 JSON 并填充 `ScanResult`；
- 真实 `ipc_service` fixture 的 auto 识别；
- auto 识别结果驱动真实 C 子进程，`scan_results.json.scope.platform == "openharmony"`；
- 低置信度和 profile 异常均不改变 generic parser 合同；
- 显式 generic 不调用 profile builder。

## 真实 C 管线验收

真实 fixture 测试使用实际 `parse_repository`/C subprocess，仅将后续 LLM 分析和报告阶段替换为离线 stub：

- 自动 profile 识别成功，C parser 收到 `--platform openharmony`；
- `scan_results.json` 中 `scope.platform` 为 `openharmony`；
- `ScanResult.platform_coverage` 回填 C scope 数据；
- 输出目录存在 `platform_profile.json`，`scan.report.json` 同时记录 `platform_profile` 和 `platform_profile_path`。

## 相关回归

scanner 既有测试：

```text
../../.venv/bin/python -m pytest -q tests/test_scanner.py
```

结果：`12 passed in 0.63s`。

扫描器、多语言和 schema 回归：

```text
PYTHONPATH=tests:. ../../.venv/bin/python -m pytest -q \
  tests/test_scanner_contract.py tests/test_scanner_multilang.py \
  tests/test_scanner_refilter_metadata.py tests/test_scanner_refilter_library_mode.py \
  tests/test_scanner_refilter_loop.py tests/test_scanner_refilter_loop_executes.py \
  tests/test_scanner_refilter_multilang.py tests/test_scanner_threat_model_integration.py \
  tests/test_schemas_multilang.py
```

结果：`80 passed in 1.99s`。

OpenHarmony/profile/C 回归：

```text
../../.venv/bin/python -m pytest -q \
  tests/platforms/test_openharmony_manifest.py \
  tests/platforms/test_openharmony_profile.py \
  tests/platforms/test_base.py
```

结果：`20 passed, 1 skipped`。

```text
../../.venv/bin/python -m pytest -q \
  tests/openharmony tests/parsers/c/test_repository_scanner_is_test_file.py
```

结果：`15 passed, 2 skipped`。

parser adapter 与 CLI 平台契约回归：`24 passed`。

本切片未修改 Go 代码；OH-03B-2 已验证的 Go CLI `go test ./cmd -v` 结果仍为 `PASS`。

## 质量检查

```text
ruff check core/scanner.py tests/test_scanner_platform_profile.py
python -m py_compile core/scanner.py tests/test_scanner_platform_profile.py
git diff --check
```

结果：`All checks passed!`，退出码为 `0`。

## 阶段结论

OH-10B 已完成。`platform=auto` 现在可以从本地仓库画像自动选择 OpenHarmony C parser，并把画像及其来源路径写入扫描产物；低置信度或检测异常保持 generic 安全回退。下一阶段可进入 OH-11 GN 静态提取，但开始前仍需先说明原逻辑、计划逻辑并等待确认。
