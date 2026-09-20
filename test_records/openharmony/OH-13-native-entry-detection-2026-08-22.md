# OH-13 OpenHarmony 原生入口检测测试记录

日期：2026-08-22

## 1. 阶段目标

在不改变 generic 默认入口检测行为的前提下，增加 OpenHarmony 原生入口识别，覆盖：

- Binder IPC：`OnRemoteRequest`；
- System Ability：`OnStart`、`OnStop`、`OnDump`、`OnAddSystemAbility`、`OnRemoveSystemAbility`；
- HDF/HDI：带 HDF/HDI 签名或驱动路径证据的 `*Dispatch`。

本阶段不实现 transaction code 到 handler 的语义边、IDL/Proxy/Stub 对齐或 HDF 数据流分析，这些属于后续 OH-14/OH-21 范围。

## 2. 修改前后逻辑

### 修改前

通用 `EntryPointDetector` 主要根据 `unit_type`、`main`、Web/CLI 装饰器和通用输入读取模式识别入口。OpenHarmony 的 `OnRemoteRequest`、SA 生命周期和 HDF Dispatch 不在这些模式内，因此 reachable 过滤可能把服务实现误判为不可达。

### 修改后

- 新增 `OpenHarmonyEntryPointDetector`，仅在 `platform="openharmony"` 时启用；
- `OnRemoteRequest` 按方法名精确匹配；
- SA 生命周期按稳定回调名匹配，`OnDump` 额外要求 SA/service 上下文；
- HDF Dispatch 要求函数名以 `Dispatch` 结尾，并同时具备 HDF/HDI 类型签名或驱动/HDF 路径信号；
- 每个命中项保存 `category`、`matched`、`confidence`、`reason`、文件路径和起止行号；
- 单独出现 `ReadInterfaceToken`、`MessageParcel` 读取或普通内部 handler 名称不会被当作入口；
- generic/auto（未显式解析成 OpenHarmony 时）继续使用旧逻辑。

## 3. 修改文件

- `libs/vulnfounder-core/utilities/agentic_enhancer/openharmony_entry_point_detector.py`
- `libs/vulnfounder-core/utilities/agentic_enhancer/entry_point_detector.py`
- `libs/vulnfounder-core/utilities/agentic_enhancer/__init__.py`
- `libs/vulnfounder-core/parsers/c/test_pipeline.py`
- `libs/vulnfounder-core/core/parser_adapter.py`
- `libs/vulnfounder-core/core/scanner.py`
- `libs/vulnfounder-core/tests/platforms/test_openharmony_entry_points.py`

## 4. TDD 定向测试

### RED

在生产实现前运行：

```text
../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_entry_points.py
```

结果：测试收集阶段失败，原因是预期的新模块尚不存在：

```text
ModuleNotFoundError: No module named 'utilities.agentic_enhancer.openharmony_entry_point_detector'
```

### GREEN

实现后运行同一命令：

```text
../../.venv/bin/python -m pytest -q tests/platforms/test_openharmony_entry_points.py
```

结果：`8 passed`。

覆盖内容：Binder、SA、HDF Dispatch、接口令牌反例、generic 兼容、证据位置、真实 IPC fixture 以及 C pipeline 的 platform 透传。

## 5. 回归测试

以下命令均在 `libs/vulnfounder-core` 下执行：

| 测试组 | 结果 |
|---|---:|
| 入口检测器历史回归（33 项） | `33 passed` |
| reachability/黑屏保护（27 项） | `27 passed` |
| profile 契约回归 | `26 passed` |
| IDL/SA 解析器回归 | `9 passed` |
| 平台 profile/GN/scope/base/入口回归 | `43 passed` |
| OpenHarmony C scope/fixture/baseline 回归 | `13 passed` |
| CLI/parser platform 回归 | `19 passed` |
| scanner 回归 | `18 passed` |

默认 generic 模式的 OpenHarmony 基线测试仍确认：`OnRemoteRequest` 在未启用 OpenHarmony 平台模式时不会被误报为入口。

## 6. 真实源码验证

使用 `openharmony_reference/openharmony_source_code` 的真实源码抽样：

| 仓库/样本 | 函数数 | 平台入口数 | 命中类别 |
|---|---:|---:|---|
| `sensors_medical_sensor` 的 SA/Stub 文件 | 33 | 4 | SA 生命周期 3、Binder 1 |
| `communication_netmanager_base` 的 SA/Stub 文件 | 332 | 5 | SA 生命周期 4、Binder 1 |
| `drivers_peripheral` 电池 HDF driver | 4 | 1 | HDF Dispatch 1 |

完整 C/C++ pipeline 验证：

```text
仓库：sensors_medical_sensor
平台：openharmony
扫描文件：67
提取函数：408
入口点：5
可达单元：9
```

结果：pipeline 和 reachability 阶段均成功，入口检测没有依赖 LLM。

## 7. 质量检查

```text
ruff check：All checks passed
python -m py_compile：通过
git diff --check：通过
parser_adapter 动态加载 OpenHarmony detector：通过
```

## 8. 未纳入本阶段的已知事项

- `HDF_INIT` 通常是文件级注册宏，不是函数定义；本阶段以 `Dispatch` 作为 reachability 入口，宏到 driver 生命周期的映射留给后续语义图阶段。
- 当前只记录入口证据，不连接 transaction code、IDL 方法、Proxy、Stub 和 handler。
- 一次回归中 `tests/test_parser_adapter.py` 的 5 个 Python 测试仍因既有空 `sample_python_repo` fixture 导致 `standalone_functions` KeyError；失败位置不涉及本阶段修改文件，已与 OH-13 结果分开记录。

