# OH-22B-2H：结构化函数指针初始化列表恢复测试记录

日期：2026-08-27  
范围：OpenHarmony C/C++ 解析器、调用图残余诊断器、Native SemanticGraph 投影  
参考源码：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`

## 1. 阶段目标

本阶段处理一种在 OpenHarmony 实际源码中出现、但此前没有进入 Native 分派恢复流程的
C++ 写法：类成员表整体用初始化列表赋值，表项的函数引用没有显式写 `&`，例如：

```cpp
parseTable_ = {
    {SnapshotSection::TRANSACTION_START, KernelSnapshotParser::ParseTransStart},
    {SnapshotSection::THREAD_INFO, KernelSnapshotParser::ParseThreadInfo},
    {SnapshotSection::STACK_BACKTRACE, KernelSnapshotParser::ParseStackBacktrace},
    {SnapshotSection::PROCESS_STATISTICS, KernelSnapshotParser::ParseProcessRealName}
};
```

该表在另一个方法中通过 `find` 和 `it->second(...)` 调用：

```cpp
auto it = parseTable_.find(cell.sectionKey);
if (it != parseTable_.end() && it->second) {
    it->second(cell, output);
}
```

源码位置为：

```text
hiviewdfx_faultloggerd/services/snapshot/kernel_snapshot_parser.cpp:197-220
```

## 2. 修改前后的逻辑

### 修改前

1. 诊断器能识别 `table[key] = &Class::Handler` 和带元数据的函数指针赋值；
2. 对整体 `table = {{key, Class::Handler}, ...}`，Tree-sitter 能解析初始化列表，
   但诊断器没有把第二个字段当作函数引用；
3. `it->second(...)` 被归入通用 callable/Lambda 残余，找不到注册目标；
4. Native resolver 只接受 `OnRemoteRequest` 作为分派调用者，因此即使残余中有候选，
   普通解析器方法也不会形成语义边。

### 修改后

1. 仅在函数体内的简单 `assignment_expression` 初始化列表中观察表项；
2. 只接受二元表项的最后一个字段作为目标，并支持：
   - `Class::Method`（无显式 `&`）;
   - `&Class::Method`;
   - `{&Class::Method, metadata}` 这类嵌套值；
3. 要求目标类限定名与注册方法的 `class_name` 一致；
4. 目标函数必须能在函数索引中唯一解析，未知目标保留为 orphan，不生成语义边；
5. 对 `find`/`it->second` 的同类方法调用建立有界候选；
6. Native resolver 只对 `registration_form=initializer_member_function` 且调用者和注册类
   一致的非 `OnRemoteRequest` 调用投影语义边；原有 IPC `OnRemoteRequest` 规则保持不变；
7. 普通赋值路径仍不接受裸 `qualified_identifier`，因此
   `table[key] = Namespace::Enum` 不会被误报为函数指针注册；
8. 不做局部数组跨函数参数传播，不对 `Eval → Decode` 这类 callback 传递关系猜测。

## 3. 测试驱动过程

先加入以下回归测试，再实现代码：

1. 无 `&` 的 `Class::Method` 初始化列表必须产生两个注册和两个候选；
2. `SnapshotSection::X, CrashSection::Y` 这种枚举初始化不能被识别为函数注册；
3. 非 `OnRemoteRequest` 的同类表读取必须能够投影一条 Native 分派语义边。

实现前第一项测试结果：

```text
1 failed, 1 passed, 15 deselected
dispatch_assignments == 0  # 预期为 2
```

实现后定向测试结果：

```text
2 passed, 15 deselected
1 passed, 8 deselected
```

完整 OpenHarmony 单元测试和规范检查：

```text
.venv/bin/pytest -q libs/openant-core/tests/openharmony
109 passed, 2 skipped

.venv/bin/ruff check \
  libs/openant-core/core/platforms/openharmony/call_graph_diagnostics.py \
  libs/openant-core/core/platforms/openharmony/native_dispatch.py \
  libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py \
  libs/openant-core/tests/openharmony/test_native_dispatch.py
All checks passed!
```

## 4. 真实 OpenHarmony 仓库验证

### 4.1 执行方式

9 个参考仓库分别以 `all` 和 `reachable` 模式重新解析，均使用当前代码、独立输出目录和
`--fresh`：

```bash
PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output debug_outputs/OH-22B-2H-all-20260827/<repo> \
  --platform openharmony --language c --level all --fresh

PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output debug_outputs/OH-22B-2H-reachable-20260827/<repo> \
  --platform openharmony --language c --level reachable --fresh
```

### 4.2 结果汇总

“诊断”列为 `unresolved_call_sites / candidate_edges / dispatch_assignments`；其中
`dispatch_assignments` 是直接函数指针分派记录，不包含 Lambda 子树记录。

| 仓库 | All 单元 | Reachable 单元 | Native 边（All/Reachable） | Semantic 边（All/Reachable） | 诊断（残余/候选/注册） | 新初始化函数指针记录 |
|---|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 7563 | 1317 | 6394 / 6394 | 642 / 642 | 17 / 306 / 307 | 0 |
| developtools_hdc | 2052 | 164 | 2831 / 2831 | 0 / 0 | 0 / 0 / 0 | 0 |
| hiviewdfx_faultloggerd | 2994 | 79 | 3415 / 3415 | 4 / 4 | 2 / 4 / 4 | **4** |
| hiviewdfx_hilog | 857 | 79 | 851 / 851 | 2 / 2 | 0 / 0 / 0 | 0 |
| hiviewdfx_hiview | 7008 | 202 | 5687 / 5687 | 37 / 37 | 0 / 0 / 0 | 0 |
| multimedia_audio_framework | 23178 | 287 | 33816 / 33816 | 715 / 715 | 55 / 66 / 33 | 0 |
| startup_appspawn | 1204 | 81 | 2267 / 2267 | 0 / 0 | 1 / 0 / 0 | 0 |
| startup_init | 2708 | 628 | 4929 / 4929 | 9 / 9 | 0 / 0 / 0 | 0 |
| telephony_core_service | 6842 | 431 | 7196 / 7196 | 341 / 341 | 11 / 0 / 0 | 0 |
| **合计** | **54406** | **3268** | **67386 / 67386** | **1750 / 1750** | — | **4** |

9 个仓库的 all/reachable `parse.report.json.errors` 均为空。

### 4.3 faultloggerd 具体结果

新增的 4 条注册全部来自同一个真实初始化表，目标和 selector 如下：

| Selector | 目标函数 | 解析结果 |
|---|---|---|
| `SnapshotSection::PROCESS_STATISTICS` | `KernelSnapshotParser::ParseProcessRealName` | `exact_function_id` |
| `SnapshotSection::STACK_BACKTRACE` | `KernelSnapshotParser::ParseStackBacktrace` | `exact_function_id` |
| `SnapshotSection::THREAD_INFO` | `KernelSnapshotParser::ParseThreadInfo` | `exact_function_id` |
| `SnapshotSection::TRANSACTION_START` | `KernelSnapshotParser::ParseTransStart` | `exact_function_id` |

新增语义边为：

```text
KernelSnapshotParser::ProcessSnapshotSection
  -> KernelSnapshotParser::ParseProcessRealName
  -> KernelSnapshotParser::ParseStackBacktrace
  -> KernelSnapshotParser::ParseThreadInfo
  -> KernelSnapshotParser::ParseTransStart
```

四个注册表项的证据文本经过空白归一化后均能在真实源码中找到。语义边的证据同时保留
注册行（199）和调用行（218），`registration_form` 为
`initializer_member_function`，`value_kind` 为 `member_function_reference`。

### 4.4 残余变化解释

faultloggerd 的 2G 结果中，`parseTable_` 调用曾被错误归入 Lambda callable 残余；2H
将其转为 Native 分派残余并补上 4 个候选，因此顶层残余从 1 个变为 2 个，但候选从 0
变为 4 个，Lambda 调用点相应减少 1 个。这不是新增未知调用，而是同一真实调用点被
放入更准确的诊断类别。

当前仍保留的无候选残余是：

```text
interfaces/innerkits/unwinder/src/unwind_entry_parser/exidx_entry_parser.cpp:
ExidxEntryParser::Decode:407
ret = (this->*(decodeTable[i].decoder))();
```

它的注册数组在 `Eval()` 内，调用发生在另一个方法 `Decode()`，数组通过参数传递。没有
跨函数数据流证据时，本阶段不将它猜测成 18 个 decoder 目标；这留给后续 callback 参数
传播阶段。

## 5. 不变性和误报检查

1. 9 个仓库的 Native 调用图边集与 OH-22B-2G 逐仓库完全相同；本阶段只增加
   SemanticGraph overlay，不改写原始 `call_graph.json`。
2. 除 faultloggerd 的 4 条真实初始化注册外，其他 8 个仓库没有出现新的
   `initializer_member_function` 记录。
3. 除 faultloggerd 新增的 4 条初始化注册外，其他仓库的普通
   `dispatch_assignments` 数量与 OH-22B-2G 相同，说明收紧后的裸限定名规则没有把枚举
   赋值扩散进旧分派路径。
4. All 与 Reachable 的单元 ID 满足 `Reachable ⊆ All`，9 个仓库均为真；新增语义边没有
   裁剪原有可达集合。
5. 新增 4 条语义边的源、目标函数均存在于对应 `call_graph.json.functions`，且注册和
   调用证据路径均为真实源码路径。

## 6. 产物位置

- All 结果：[debug_outputs/OH-22B-2H-all-20260827](../../debug_outputs/OH-22B-2H-all-20260827)
- All 日志：[debug_outputs/OH-22B-2H-all-20260827-logs](../../debug_outputs/OH-22B-2H-all-20260827-logs)
- Reachable 结果：[debug_outputs/OH-22B-2H-reachable-20260827](../../debug_outputs/OH-22B-2H-reachable-20260827)
- Reachable 日志：[debug_outputs/OH-22B-2H-reachable-20260827-logs](../../debug_outputs/OH-22B-2H-reachable-20260827-logs)

每个仓库目录包含 `dataset.json`、`call_graph.json`、`call_graph_residuals.json`、
`semantic_graph.json`（存在语义边时）、`parse.report.json`、`pipeline_results.json` 和
`scan_results.json`。

## 7. 阶段结论

OH-22B-2H 已用 Tree-sitter 语法证据、函数索引唯一解析、同类约束和源码回溯验证，补上
faultloggerd `parseTable_` 的 4 条实际分派边；没有改变原生调用图，也没有在其余 8 个
仓库引入新的 initializer 函数指针误报。该阶段不声称已经解决 callback 参数跨函数传播，
也不声称已经解决所有成员函数指针形式。
