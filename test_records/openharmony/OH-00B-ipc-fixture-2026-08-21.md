# OH-00B OpenHarmony IPC Fixture 测试记录

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 阶段 | OH-00B：小型脱敏 OpenHarmony Binder IPC fixture |
| 日期 | 2026-08-21 |
| OpenAnt 实施基线 | `2476527b9d6f929a5c987bd3d5df414da04f1eaf` |
| 开发分支 | `feature/openharmony-adaptation` |
| Python | 3.11.15，项目 `.venv` |
| pytest | 9.1.1 |

## 2. 原逻辑与本阶段目标

OH-00A 只固定了外部五仓的版本、文件计数和关键文件 glob。完整语料需要通过 `OPENHARMONY_CORPUS_ROOT` 注入，仓库内没有一个可供后续平台识别、GN、IPC 图、入口和权限规则稳定复用的小型 OpenHarmony 源码样例。

OH-00B 新增完全合成、可随测试提交的最小 Binder IPC fixture，固定以下路径：

```text
bundle.json
BUILD.gn
IHealthSensorService transaction/descriptor
HealthSensorServiceProxy::EnableSensor
SendRequest(ENABLE_SENSOR)
HealthSensorServiceStub::OnRemoteRequest
transaction -> handler 映射
MessageParcel 字段读取
GetCallingTokenID
VerifyAccessToken permission guard
guarded EnableSensor sink
```

本阶段不修改 OpenAnt 生产代码、CLI、语言注册或扫描结果。

## 3. TDD RED

先新增：

```text
tests/openharmony/test_ipc_fixture.py
```

此时不创建 fixture，执行：

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony/test_ipc_fixture.py -v
```

结果：退出码 `1`，收集 3 项，3 项均在 fixture setup 阶段报错。

```text
AssertionError: OpenHarmony IPC fixture manifest is missing:
tests/fixtures/openharmony/ipc_service/fixture_manifest.json
```

结论：RED 有效。测试确实依赖待实现的 IPC fixture，没有在实现缺失时误通过。

## 4. GREEN 实现

新增目录：

```text
tests/fixtures/openharmony/ipc_service/
├── BUILD.gn
├── bundle.json
├── fixture_manifest.json
├── frameworks/health_sensor_service_proxy.cpp
├── interfaces/i_health_sensor_service.h
└── services/health_sensor_service_stub.cpp
```

所有名称、组件、权限和代码均为 OpenAnt 测试专用合成内容，没有复制外部真实仓源码。fixture 保留了真实 OpenHarmony 常见语义结构，但不代表实际产品组件，也不是漏洞样本。

`fixture_manifest.json` 包含：

- schema version 和 synthetic 标记。
- 精确文件清单。
- 平台识别信号。
- Proxy 到受权限保护 handler 的最小 IPC 流。
- 18 个稳定源码锚点，记录相对文件、行号和期望文本。
- 不包含用户绝对路径或外部语料目录。

## 5. OH-00B 独立 GREEN 测试

命令：

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony/test_ipc_fixture.py -v
```

结果：退出码 `0`。

```text
3 passed in 0.01s
```

通过的契约：

1. fixture 是合成、便携且文件清单完整。
2. 所有源码锚点与固定行号一致。
3. manifest 描述了 `EnableSensor` Proxy → transaction → Stub → handler → permission guard 的最小路径。

## 6. OpenHarmony 联合测试

命令：

```bash
OPENHARMONY_CORPUS_ROOT=/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
../../.venv/bin/python -m pytest tests/openharmony -v
```

结果：退出码 `0`。

```text
5 passed in 0.14s
```

其中包括 OH-00A 的外部五仓快照实测，不是便携模式 skip。

## 7. 相关回归

命令：

```bash
../../.venv/bin/python -m pytest \
  tests/test_language_registry.py \
  tests/test_parser_adapter.py -v
```

结果：退出码 `0`。

```text
61 passed in 0.08s
```

确认新增 C++ fixture 和测试目录没有改变现有语言注册、语言检测、fence、CLI language choices 或 Python parser adapter 行为。

## 8. 静态检查

命令：

```bash
../../.venv/bin/python -m ruff check tests/openharmony/test_ipc_fixture.py
../../.venv/bin/python -m py_compile tests/openharmony/test_ipc_fixture.py
```

结果：退出码 `0`，Ruff 输出 `All checks passed!`，Python 语法检查通过。

fixture JSON 已在测试中使用 `json.loads` 解析；相对路径、目录逃逸和用户绝对路径均由契约测试检查。

## 9. 测试范围说明

本阶段没有运行 2969 项完整 Python 套件，原因是没有修改任何生产代码或依赖；直接影响范围已经由 5 项 OpenHarmony 测试、61 项语言/解析回归及静态检查覆盖。环境阶段的完整套件结果仍为 `2969 passed, 34 skipped`。

合成 C++ fixture 用于静态解析和语义测试，不连接真实 OpenHarmony SDK，也不在本阶段尝试链接或运行。后续 parser/graph 测试应读取该 fixture，而不是把“无法独立编译”解释成测试失败。

## 10. 阶段结论

OH-00B 已完成。OpenAnt 仓库现在具备一个不依赖用户本地路径、语义锚点稳定、同时覆盖平台清单与 Binder 权限边界的最小测试素材。

下一小阶段应记录现有 OpenAnt 对该 fixture 和外部语料的发现、解析与入口识别基线，明确哪些 OpenHarmony 信号当前会被忽略；在用户批准前不修改生产扫描逻辑。
