# OH-10B-2：平台画像文件统计同步测试记录

## 变更范围

平台画像在解析前生成，原先使用默认的 `0/0/0` 覆盖统计；OpenHarmony C/C++ 解析完成后虽然已经得到真实的 `scope.coverage`，但没有回写 `platform_profile.json`。

本阶段只同步以下三个字段：

- `coverage.discovered_files`
- `coverage.eligible_files`
- `coverage.parsed_files`

平台识别证据、组件、边界、构建元数据、调用图和漏洞分析逻辑均未修改。

## 实现

- 在 `core/scanner.py` 增加 `_sync_platform_profile_file_counts()`。
- 解析结果包含合法的 `platform_coverage.coverage` 时，更新内存中的平台画像并重新写入 `platform_profile.json`。
- 如果解析器没有提供覆盖统计或字段格式不合法，则保持原有画像，不阻断扫描。
- 已将三次历史扫描的画像文件按对应 `scan_results.json` 校正，避免用户必须重新调用模型。

## 测试结果

| 检查项 | 结果 |
| --- | --- |
| `python3 -m py_compile` | 通过 |
| `pytest tests/test_scanner_platform_profile.py` | 9 passed |
| 平台画像、解析器转发和基础 profile 回归测试 | 27 passed |
| `ruff check core/scanner.py tests/test_scanner_platform_profile.py` | 通过 |
| 历史 `platform_profile.json` 与对应 `scan_results.json` 统计值比对 | 通过 |

## 实际校正值

| 扫描仓库 | 发现文件 | 符合解析条件 | 已解析 |
| --- | ---: | ---: | ---: |
| `sensors_medical_sensor`（LLM 可达性复核） | 92 | 67 | 67 |
| `sensors_medical_sensor`（普通扫描） | 92 | 67 | 67 |
| `systemabilitymgr_samgr` | 543 | 97 | 97 |
