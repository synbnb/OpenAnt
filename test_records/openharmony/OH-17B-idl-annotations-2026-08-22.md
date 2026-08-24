# OH-17B：IDL 方法注解与 IPC code 元数据测试记录

日期：2026-08-22  
范围：仅补全 OpenHarmony IDL 方法前缀注解的解析，并把 `ipccode`/注解保留到 IPC transaction 节点。未修改 native 调用图算法、入口检测、SA 关联或 LLM prompt。

## 1. 原逻辑与本阶段目标

原来的 IDL 方法识别只接受如下形态：

```text
返回类型 方法名(参数...);
```

OpenHarmony 生成的 IDL 经常在返回类型前增加方括号注解，例如：

```text
[ipccode 7] void GetDefaultDisplayInfo();
[oneway] void NotifyChange([in] int state);
```

旧正则把 `[ipccode 7]` 当成返回类型的一部分，因而整个方法声明无法匹配；这会导致接口仍被识别，但方法、transaction 节点以及后续 native IPC 关系都缺失。

本阶段目标：

1. 解析一个或多个方法级方括号注解，保留其规范化后的文本顺序；
2. 对严格匹配的非负十进制 `[ipccode N]` 提取 `ipc_code: N`；
3. 将 `annotations` 与 `ipc_code` 写入 `IDLMethod.to_dict()` 以及 IPC transaction 节点和 IDL 证据；
4. 对未知注解保持兼容，不把未知注解误当成 IPC code；
5. 不改变既有 handler/proxy 匹配和 orphan 规则。

## 2. 测试驱动过程

### 2.1 先写失败测试（RED）

新增测试：

```text
libs/openant-core/tests/platforms/test_openharmony_idl.py::test_parser_extracts_method_annotations_and_ipccode_metadata
```

执行：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_idl.py \
  -k 'annotations_and_ipccode'
```

结果：按预期失败。旧解析器返回的方法列表为空，核心失败为：

```text
assert [] == ['GetSession', 'NotifyChange']
```

同时新增 transaction 元数据测试：

```text
libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py::test_resolver_preserves_ipccode_metadata_on_transaction
```

它在解析器缺少方法时无法得到对应 transaction，作为端到端的失败约束。

## 3. 实现内容

### 3.1 `IDLMethod` 增加元数据

文件：`libs/openant-core/core/platforms/openharmony/idl.py`

新增字段：

```text
annotations: list[str] = []
ipc_code: int | None = None
```

字段放在原有字段之后，避免破坏旧代码可能使用的前置位置参数构造方式。`to_dict()` 同步输出这两个字段。

### 3.2 解析连续的方括号注解

方法声明开始处现在会循环读取形如 `[ ... ]` 的注解：

- `[ ipccode 42 ]` 规范化为 `"ipccode 42"`；
- `[oneway]` 保留为 `"oneway"`；
- 多个注解按源码顺序保存；
- 只有完整匹配 `ipccode` 加非负十进制数字时才设置 `ipc_code`。

因此未知注解可以被审计，但不会被强行解释成数值协议编号。

### 3.3 IPC semantic graph 传递元数据

文件：`libs/openant-core/core/platforms/openharmony/ipc_graph.py`

`_method_records()` 读取 dataclass 或字典形式的 `annotations`、`ipc_code`。创建 `ipc_transaction` 节点时，只有字段存在时才写入对应属性，避免改变没有注解的旧节点结构；`interface_to_transaction` 的 IDL evidence 也同步保留这些字段。

## 4. 定向测试结果（GREEN）

执行：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_idl.py \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py
```

结果：

```text
15 passed, 1 skipped in 0.02s
```

覆盖点包括：

- 单个 `[ipccode 0]`；
- 带空格的 `[ ipccode 42 ]`；
- 连续 `[ipccode 42] [oneway]`；
- transaction 节点和 IDL evidence 的元数据保留；
- 原有 proxy、stub、handler、重载、注释/字符串屏蔽和 orphan 行为。

语法检查：

```text
OpenAnt/.venv/bin/python -m py_compile \
  OpenAnt/libs/openant-core/core/platforms/openharmony/idl.py \
  OpenAnt/libs/openant-core/core/platforms/openharmony/ipc_graph.py \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_idl.py \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_ipc_graph.py
```

结果：通过。

## 5. OpenHarmony 真实仓库回归

使用解析器只读扫描：

```text
OpenAnt/.venv/bin/python - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, 'OpenAnt/libs/openant-core')
from core.platforms.openharmony.idl import OpenHarmonyIDLParser
...
PY
```

仓库根目录：`openharmony_reference/openharmony_source_code`。结果如下：

| 仓库 | IDL 文件 | 接口 | 方法 | 含注解方法 | 含 `ipccode` 方法 | 解析失败 |
|---|---:|---:|---:|---:|---:|---:|
| `window_window_manager` | 3 | 6 | 87 | 2 | 1 | 0 |
| `multimedia_camera_framework` | 39 | 46 | 258 | 258 | 197 | 0 |
| `multimedia_audio_framework` | 30 | 28 | 697 | 95 | 15 | 0 |
| `ability_ability_runtime` | 8 | 9 | 63 | 4 | 0 | 0 |
| `filemanagement_storage_service` | 4 | 4 | 157 | 156 | 149 | 0 |

代表性解析结果：

```text
multimedia_camera_framework:
  Open -> ["ipccode 0"] -> ipc_code=0
  Close -> ["ipccode 1"] -> ipc_code=1
  Release -> ["ipccode 2"] -> ipc_code=2

window_window_manager:
  GetSessionManagerService -> ["ipccode 0"] -> ipc_code=0
  NotifySceneBoardAvailable -> ["oneway"] -> ipc_code=None
```

这说明此前因注解导致的方法漏解析已经在真实仓库中恢复；尤其是 `multimedia_camera_framework`，本阶段首次得到 258 个 IDL 方法，其中 197 个携带数值 IPC code。

## 6. 相关回归结果

执行：

```text
OpenAnt/.venv/bin/python -m pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony \
  OpenAnt/libs/openant-core/tests/platforms/test_openharmony_*.py \
  OpenAnt/libs/openant-core/tests/test_c_pipeline.py \
  OpenAnt/libs/openant-core/tests/report/test_build_pipeline_output_return_contract.py
```

结果：

```text
104 passed, 6 skipped in 0.45s
```

## 7. 边界与下一阶段建议

- 当前只识别方法声明开头的方括号注解；其他位置的生成器语法仍保持原解析边界。
- `ipc_code` 目前是可审计的数字元数据，不参与 transaction 与 native 函数的自动强匹配；这样可以避免仅凭编号制造错误关系。
- 只接受非负十进制数字；未知或非十进制注解会保留原文，但 `ipc_code` 为 `None`。
- 本阶段没有把 `oneway` 进一步解释为线程/权限语义，也没有改变 SA、入口检测和 prompt；这些应作为独立的小阶段设计和测试。

