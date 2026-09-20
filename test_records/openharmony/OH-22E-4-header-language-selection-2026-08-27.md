# OH-22E-4：共享 `.h` 头文件的 C/C++ 解析器选择回归记录

**日期**：2026-08-27  
**范围**：C/C++ `FunctionExtractor`，OpenHarmony 原生 socket 入口归属  
**目标**：修复 C++ 风格 `.h` 被 C grammar 解析导致的类内联方法和 `accept()` 调用无法归属问题。

## 1. 根因证据

OpenHarmony 的 `.h` 同时用于 C 和 C++。修复前的选择逻辑只根据扩展名判断：

- `.cpp/.hpp/.cc/.cxx/.hxx/.hh` 使用 tree-sitter C++ parser；
- `.c/.h` 使用 tree-sitter C parser。

因此下面两个真实 C++ 头文件被送入了 C parser：

```text
communication_netmanager_base/utils/common_utils/include/epoller.h:242
communication_netmanager_base/utils/common_utils/include/fwmark_epoller.h:150
```

这两个位置分别是 `EpollServer::RunForEvents` 和
`FwmarkEpollServer::RunForReceivers` 方法中的 `accept()`。用 C++ grammar
直接解析时，tree-sitter 能得到完整的 `function_definition`；用原逻辑的 C
grammar 时，只产生错误的外层/部分函数单元。

## 2. 修改后的逻辑

明确的 C++ 扩展名和明确的 C 扩展名保持原行为。对于有源代码可读的 `.h`：

1. 先用 C++ grammar 构建临时语法树；
2. 只依据结构节点判断是否存在 C++ 语法，例如命名空间、类、模板、访问说明符、
   C++ 限定名、引用声明、运算符重载等；
3. 如果 C++ 记录体内出现函数定义，也判定为 C++ 头文件，以覆盖
   `struct Foo { void Method() { ... } };` 形式；
4. 检测到 C++ 结构后使用 C++ parser，否则继续使用 C parser；
5. 函数提取器本身不增加仓库名、类名或函数名特例。

`process_file()` 将已完成的选择结果传给 parser，避免同一个 `.h` 被重复探测。

## 3. 自动化测试

### 3.1 新增回归测试

文件：

```text
libs/vulnfounder-core/tests/parsers/c/test_header_language_detection.py
```

覆盖：

- C++ `.h` 中的 `demo::EpollServer::RunForEvents` 被提取为
  `unit_type=method`，保留 `class_name`、起止行和 `accept()` 代码；
- 普通 C `.h` 中的顶层函数仍为 `unit_type=function`。

TDD 记录：

- RED：修复前 `1 failed, 1 passed`，C++ 内联方法缺失；
- GREEN：修复后 `2 passed`。

### 3.2 全量相关测试

执行：

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/pytest -q \
  libs/vulnfounder-core/tests/parsers/c \
  libs/vulnfounder-core/tests/openharmony
```

结果：

```text
230 passed, 2 skipped in 0.88s
```

### 3.3 代码质量检查

执行 `ruff check` 和 `git diff --check` 均通过。当前 Ruff formatter 对部分历史文件报告既有格式差异，本阶段没有对这些文件做无关的大规模格式化。

## 4. 真实 OpenHarmony 回归

### 4.1 communication_netmanager_base

仓库：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_netmanager_base
```

输出：

```text
/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-4-netmanager-20260827
```

执行 parser/reachability（无 LLM、无设备）：

```bash
.venv/bin/python libs/vulnfounder-core/parsers/c/test_pipeline.py \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_netmanager_base \
  --output debug_outputs/OH-22E-4-netmanager-20260827 \
  --processing-level reachable --platform openharmony --skip-tests
```

关键结果：

```text
730 files
6968 functions
0 parse errors
5448 native call-graph edges
17 residual call sites / 306 candidate edges
72 entry points
6967 units -> 718 reachable units
pipeline success
```

两个修复点的实际提取结果：

| 文件 | 函数单元 | 行号 | 入口证据 |
|---|---|---:|---|
| `utils/common_utils/include/epoller.h` | `OHOS::NetManagerStandard::EpollServer::RunForEvents` | 236–260 | `accept@242`，`native_socket`，`local_socket` |
| `utils/common_utils/include/fwmark_epoller.h` | `OHOS::NetManagerStandard::FwmarkTool::FwmarkEpollServer::RunForReceivers` | 144–174 | `accept@150`，`native_socket`，`local_socket` |

对该仓库扫描结果中的 socket 接收调用做函数范围归属和入口种子复核：

```text
source socket calls: 25
covered by extracted function + OpenHarmony detector: 25
missing: 0
```

### 4.2 sensors_medical_sensor

仓库：

```text
/Users/shiyu/学习/hyl/new/VulnFounder/source_code_base/sensors_medical_sensor
```

输出：

```text
/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-22E-4-sensors-20260827
```

关键结果：

```text
67 files
340 functions
0 parse errors
130 call-graph edges
3 residual call sites / 8 candidate edges
7 entry points
340 units -> 25 reachable units
pipeline success
```

该小仓库回归证明共享 `.h` 探测不会破坏普通 OpenHarmony C/C++ 混合仓库的完整流程。

## 5. 基线迁移

原有 IPC fixture 基线记录的是修复前 `.h` 被 C parser 误解析时的异常节点。修复后将
`current_behavior_baseline.json` 更新为实际的 5 个真实函数/方法单元，并同步更新
基线 ID 为 `openant-after-header-language-selection-v1`。这不是放宽测试，而是把
“当前行为”快照迁移到修复后的实际行为。

## 6. 限制与后续建议

- 当前探测是结构级启发式，不是完整的 C++ 编译语义分析；无法替代编译器对宏展开、
  条件编译和构建参数的判断。
- 无法解析 C++ 语法时会保守回退 C parser，并由现有 per-file error guard 保证单文件
  不阻断整个仓库。
- 本阶段没有调用 LLM。下一步仍可针对剩余的真实间接调用点做 LLM 辅助验证，但应以
  已恢复的函数索引为输入。
