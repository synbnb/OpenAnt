# OH-03A C/C++ 文件范围与 coverage 基线测试记录

- 日期：2026-08-22
- 阶段：OH-03A
- 目标：在不改变生产扫描逻辑的前提下，冻结 C/C++ 扫描器对 OpenHarmony 风格目录的当前文件范围、测试跳过行为和可见 coverage 缺口。
- 生产代码变更：无

## 夹具

新增合成夹具：

`libs/openant-core/tests/fixtures/openharmony/scope_roles/`

夹具覆盖以下角色：

- production：`.h`、`.cpp`、`.c`
- test：根目录 `test_*.cpp` 与 `tests/` 目录文件
- fuzz：`fuzz/` 目录文件
- build metadata：`BUILD.gn`、`bundle.json`
- unsupported source：`.ets`、`.idl`
- vendor：`vendor/` 目录文件

角色与文件清单记录在夹具内的 `scope_manifest.json`，扫描结果基线记录在：

`libs/openant-core/tests/fixtures/openharmony/c_scope_baseline.json`

## RED 阶段

在创建基线 JSON 之前执行：

```text
pytest -q tests/openharmony/test_c_scope_baseline.py
```

结果：`1 passed, 2 failed`。失败原因是断言明确要求基线记录存在，符合先写测试再冻结观测结果的预期。

## 基线观测

直接调用 `RepositoryScanner` 得到的当前行为如下：

| 配置 | 发现的 C/C++ 文件数 | 排除目录数 | test_files_skipped |
| --- | ---: | ---: | ---: |
| `skip_tests=False` | 4 | 3 | 0 |
| `skip_tests=True` | 3 | 3 | 1 |

`tests/`、`fuzz/`、`vendor/` 在目录遍历阶段直接被裁剪；根目录的 `test_health_sensor.cpp` 在默认配置下仍会被发现，只有 `skip_tests=True` 才按文件名规则跳过。`BUILD.gn`、`bundle.json`、`.ets`、`.idl` 不会出现在 C/C++ 文件记录中。当前记录项只有 `path`、`size`、`extension`，没有文件角色字段。

## GREEN 阶段

```text
pytest -q tests/openharmony/test_c_scope_baseline.py
```

结果：`3 passed`。

## 相关回归

1. OpenHarmony 夹具、平台测试和 C 扫描器测试：

   ```text
   pytest -q tests/openharmony tests/parsers/c/test_repository_scanner_is_test_file.py
   ```

   结果：`12 passed, 2 skipped`。

2. 扫描编排与多语言回归（通过 `PYTHONPATH=tests:.` 使现有 pytest 插件可加载）：

   ```text
   PYTHONPATH=tests:. python -m pytest -q \
     tests/test_scanner_contract.py tests/test_scanner_multilang.py \
     tests/test_scanner_refilter_metadata.py tests/test_scanner_refilter_library_mode.py \
     tests/test_scanner_refilter_loop.py tests/test_scanner_refilter_loop_executes.py \
     tests/test_scanner_refilter_multilang.py tests/test_scanner_threat_model_integration.py \
     tests/test_schemas_multilang.py
   ```

   结果：`80 passed`。

3. 解析器适配与 C 扫描器回归：

   ```text
   python -m pytest -q tests/test_parser_adapter.py \
     tests/parsers/c/test_repository_scanner_is_test_file.py
   ```

   结果：`13 passed`。

## 质量检查

```text
ruff check tests/openharmony/test_c_scope_baseline.py
python -m py_compile tests/openharmony/test_c_scope_baseline.py
git diff --check
```

结果：全部通过，退出码为 `0`。

## 阶段结论

OH-03A 已完成。当前 C/C++ 扫描器的覆盖边界已由可移植合成夹具和 JSON 基线锁定；后续 OH-03B 才引入文件角色与 OpenHarmony 构建元数据分类，避免把“当前未扫描”误认为“已分类”。
