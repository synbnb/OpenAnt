# OH-22B-2I：跨函数成员函数数组参数流恢复测试记录

日期：2026-08-27  
范围：OpenHarmony C/C++ 调用图残余诊断、Native SemanticGraph 投影  
参考源码：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`

## 1. 阶段目标

处理上一阶段在真实 `hiviewdfx_faultloggerd` 中留下的调用图缺口：

```cpp
// Eval()
DecodeTable decodeTable[] = {
    {0xc0, 0x00, &ExidxEntryParser::Decode00xxxxxx},
    // ... 共 18 项
};
while (Decode(decodeTable, sizeof(decodeTable) / sizeof(decodeTable[0])));

// Decode()
ret = (this->*(decodeTable[i].decoder))();
```

数组在 `Eval()` 的局部作用域内创建，作为第一个参数传给同类的 `Decode()`，随后在
`Decode()` 内通过成员函数指针调用。普通语法调用图能够得到 `Eval → Decode`，但此前
无法把 `Decode()` 的参数与 `Eval()` 的数组注册表连接起来。

真实源码位置：

```text
interfaces/innerkits/unwinder/src/unwind_entry_parser/exidx_entry_parser.cpp:343-364
interfaces/innerkits/unwinder/src/unwind_entry_parser/exidx_entry_parser.cpp:396-412
```

## 2. 修改前后的逻辑

### 修改前

1. Tree-sitter 可以看到 `DecodeTable decodeTable[] = {{...}}` 的初始化树，但诊断器只
   处理成员表赋值，不能产生局部数组注册记录；
2. `Decode()` 中的 `(this->*(decodeTable[i].decoder))()` 只能成为无候选残余；
3. 即使手工把数组注册记录塞入诊断结果，Native resolver 也只允许 `OnRemoteRequest`
   或上一阶段的类成员整体初始化表，普通 `Decode()` 调用者不会投影语义边；
4. 直接按表名匹配会把不同函数的同名局部数组误合并，因此不能作为默认回退。

### 修改后

1. 诊断器识别函数体内的简单数组声明初始化 `init_declarator`，将每个
   `{selector..., &Class::Method}` 表项记录为
   `registration_form=declaration_member_function_array`；
2. 通过 Tree-sitter 的直接调用节点查找 `Eval → Decode(array, ...)`，要求：
   - 参数实参是简单标识符；
   - 被调函数在索引中唯一解析，并且参数位置存在明确的参数名；
   - 调用者和被调函数属于同一个 C++ 类；
   - 实参标识符必须是调用者自己声明的成员函数数组；
3. 在 `Decode()` 的成员指针表达式中识别 `parameter[index].member` 形式，利用唯一的
   参数流绑定回调用者的局部数组；
4. Native resolver 对这种有完整证据的非 IPC 调用投影
   `Decode → DecodeXX` 语义边，并在边属性中保留数组注册函数、参数流和证据位置；
5. 如果同名数组来自多个调用者、参数流有多个来源、调用跨类/跨文件、存在别名或
   传递链超过一跳，则不猜测，继续保留无候选残余；
6. 普通 `OnRemoteRequest` 分派和上一阶段 `initializer_member_function` 逻辑保持不变。

实现不调用 LLM；语法结构由 Tree-sitter 提供，参数名和局部作用域只作保守的确定性
连接。间接表达式的最后一步仍使用经过注释/字符串屏蔽的窄词法扫描，以覆盖当前
Tree-sitter 版本把 `this->*` 解析成 `ERROR` 子树的情况。

## 3. 修改文件

- `libs/openant-core/core/platforms/openharmony/call_graph_diagnostics.py`
  - 支持局部成员函数数组声明；
  - 新增数组声明名提取、参数名提取、直接参数流和唯一来源校验；
  - 残余站点记录 `parameter_flow`、注册作用域和注册形式；
  - 对无唯一参数流的局部数组禁止跨函数按表名兜底匹配。
- `libs/openant-core/core/platforms/openharmony/native_dispatch.py`
  - 接受 `declaration_member_function_array` 作为同类非 IPC 分派证据；
  - 按 `registration_owner_function_id` 选择注册记录；
  - 在 SemanticGraph 边属性中记录参数流和局部注册函数。
- `libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py`
  - 新增唯一参数流正例；
  - 新增两个调用者各自拥有同名局部数组时必须保持无候选的负例。
- `libs/openant-core/tests/openharmony/test_native_dispatch.py`
  - 新增跨函数数组到 `Decode` 的 Native 语义边投影测试。

## 4. 测试驱动过程

### 4.1 实现前红测

先加入诊断器正例，未实现参数流时结果为：

```text
1 failed, 17 deselected
dispatch_assignments == 2
candidate_edges == 0  # 预期为 2
```

再加入 Native resolver 正例，未允许新注册形式时结果为：

```text
1 failed, 9 deselected
graph is None  # 预期应产生 Decode → handler 语义边
```

### 4.2 实现后定向测试

```bash
source .venv/bin/activate
pytest -q libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py \
  -k 'ambiguous_local_member_array_sources or local_member_function_array_flows'
# 2 passed, 17 deselected

pytest -q libs/openant-core/tests/openharmony/test_native_dispatch.py \
  -k 'parameterized_decoder_projects_local_member_array or initializer_list_projects_same_class_non_remote_site'
# 2 passed, 8 deselected
```

### 4.3 OpenHarmony 专项回归和规范检查

```bash
source .venv/bin/activate
pytest -q libs/openant-core/tests/openharmony
# 112 passed, 2 skipped

ruff check \
  libs/openant-core/core/platforms/openharmony/call_graph_diagnostics.py \
  libs/openant-core/core/platforms/openharmony/native_dispatch.py \
  libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py \
  libs/openant-core/tests/openharmony/test_native_dispatch.py
# All checks passed!
```

## 5. 真实 faultloggerd 验证

### 5.1 命令

```bash
PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd \
  --output debug_outputs/OH-22B-2I-all-20260827/hiviewdfx_faultloggerd \
  --platform openharmony --language c --level all --fresh

PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/hiviewdfx_faultloggerd \
  --output debug_outputs/OH-22B-2I-reachable-20260827/hiviewdfx_faultloggerd \
  --platform openharmony --language c --level reachable --fresh
```

### 5.2 关键结果

all 和 reachable 的诊断结果一致：

```text
dispatch_assignments:       22
  declaration_member_function_array: 18
  initializer_member_function:        4
candidate_edges:            22
unresolved_call_sites:       2
unresolved_without_candidates: 0
parameter_flows:             1
orphan_assignments:          0
semantic native edges:      22
parse errors:                0
```

唯一参数流为：

```text
Eval(decodeTable, ...) → Decode(decodeTable, size)
```

`Decode` 的一个残余调用站点现在具有 18 个候选目标，Native SemanticGraph 中形成 18
条边：

```text
ExidxEntryParser::Decode
  → Decode00xxxxxx
  → Decode01xxxxxx
  → Decode1000iiiiiiiiiiii
  → ...（共 18 个真实表项）
```

上一阶段的 `KernelSnapshotParser::ProcessSnapshotSection → parseTable_` 4 条边仍然存在。
`Eval → Decode` 本身仍由原生直接调用图提供，本阶段只补充 `Decode → decoder` 的动态
分派候选边。

三字段数组表项当前将第一个字段作为 `selector`（例如 `0xc0`），完整的 mask/result 和
函数引用保留在 `evidence.text`（如 `{0xc0, 0x40, &ExidxEntryParser::Decode01xxxxxx}`）
中；本阶段不改变 selector 字段的既有表示约定。

## 6. 9 个真实仓库 all/reachable 回归

9 个仓库均使用当前代码完成 all 和 reachable CLI 解析，所有 `parse.report.json.errors`
均为空。表中“Native 边”只统计 `native_dispatch_to_handler` 和
`native_dispatch_to_service`；“语义图总边”还包括 IPC/interface resolver 产生的边；
“诊断”按 `残余 / 候选 / 直接注册` 记录。

| 仓库 | 单元 all/reachable | Native 边 all/reachable | 语义图总边 all/reachable | 诊断（残余/候选/注册） all/reachable | 参数流 all/reachable |
|---|---:|---:|---:|---:|---:|
| communication_netmanager_base | 7563 / 1317 | 586 / 586 | 642 / 642 | 17/306/307 / 17/306/307 | 0 / 0 |
| developtools_hdc | 2052 / 164 | 0 / 0 | 0 / 0 | 0/0/0 / 0/0/0 | 0 / 0 |
| hiviewdfx_faultloggerd | 2994 / 79 | 22 / 22 | 22 / 22 | 2/22/22 / 2/22/22 | 1 / 1 |
| hiviewdfx_hilog | 857 / 79 | 2 / 2 | 2 / 2 | 0/0/0 / 0/0/0 | 0 / 0 |
| hiviewdfx_hiview | 7008 / 202 | 7 / 7 | 37 / 37 | 0/0/0 / 0/0/0 | 0 / 0 |
| multimedia_audio_framework | 23178 / 287 | 12 / 12 | 715 / 715 | 55/66/33 / 55/66/33 | 0 / 0 |
| startup_appspawn | 1204 / 81 | 0 / 0 | 0 / 0 | 1/0/0 / 1/0/0 | 0 / 0 |
| startup_init | 2708 / 628 | 0 / 0 | 9 / 9 | 0/0/0 / 0/0/0 | 0 / 0 |
| telephony_core_service | 6842 / 431 | 320 / 320 | 341 / 341 | 11/0/0 / 11/0/0 | 0 / 0 |

全库初次 CLI 回归后又加入了“多来源不合并”的保护规则。保护规则加入后，使用这批
真实 `call_graph.json` 重新执行当前诊断器，9 个仓库的 all/reachable 诊断摘要均与持久化
结果一致；再用当前诊断结果重建 Native resolver，18 个仓库（9×2）的 Native 边集合均
完全一致。`faultloggerd` all/reachable 另外用最终代码重新跑过 CLI，结果与上表一致。

## 7. 误报和不变性检查

1. 多来源负例通过：两个同类调用者各自声明同名 `decodeTable` 时，`Decode` 保持
   `candidate_target_ids=[]`，不按表名把两个作用域合并；
2. 9 个仓库的原生 `call_graph.json` 未被修改；Native resolver 只向独立 SemanticGraph
   overlay 添加边；
3. 除 `faultloggerd` 的 18 个真实数组表项外，其余 8 个仓库没有新的
   `declaration_member_function_array` 记录；
4. `faultloggerd` 的 18 个目标函数、调用函数和参数流来源函数全部存在于函数索引，注册
   行和调用行均能回溯到真实源码；
5. all/reachable 的 Native 语义边集合一致，reachable 只改变最终单元集合，不裁剪本阶段
   生成的独立语义证据；
6. 本阶段没有把不确定的跨类、别名、容器传递、返回值传递或多跳 callback 传播提升为
   语义边。

## 8. 产物位置

- all 结果：[debug_outputs/OH-22B-2I-all-20260827](../../debug_outputs/OH-22B-2I-all-20260827)
- all 仓库日志：[debug_outputs/OH-22B-2I-all-20260827-*.log](../../debug_outputs)
- reachable 结果：[debug_outputs/OH-22B-2I-reachable-20260827](../../debug_outputs/OH-22B-2I-reachable-20260827)
- reachable 仓库日志：[debug_outputs/OH-22B-2I-reachable-20260827-*.log](../../debug_outputs)
- faultloggerd all 残余：[call_graph_residuals.json](../../debug_outputs/OH-22B-2I-all-20260827/hiviewdfx_faultloggerd/call_graph_residuals.json)
- faultloggerd all 语义图：[semantic_graph.json](../../debug_outputs/OH-22B-2I-all-20260827/hiviewdfx_faultloggerd/semantic_graph.json)
- faultloggerd reachable 残余：[call_graph_residuals.json](../../debug_outputs/OH-22B-2I-reachable-20260827/hiviewdfx_faultloggerd/call_graph_residuals.json)

## 9. 阶段结论

OH-22B-2I 已在真实 `hiviewdfx_faultloggerd` 中补上此前缺失的 18 条
`Decode → decoder` 成员函数指针边，同时保留 `Eval → Decode` 的原生直接调用关系；
其余 8 个仓库没有引入新的局部数组误报。该实现是有边界的确定性一跳参数流恢复，不声称
覆盖所有 callback 传递形式；后续若要处理别名、容器、返回值或多跳传播，应另设阶段并继续
以“唯一来源、可回溯证据、歧义保留残余”为准则。
