# OH-22B-2G：函数体内局部初始化列表 Lambda 分派恢复测试记录

- 日期：2026-08-27
- 阶段：OH-22B-2G
- 评估对象：`/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`
- 仓库数量：9
- 运行方式：真实源码离线解析；不调用大模型；不修改 OpenHarmony 源码

## 1. 本阶段目标

本阶段只补一个确定性缺口：OpenHarmony C++ 函数体内经常直接声明局部
`std::map`、`std::unordered_map` 或 `std::function` 表，例如：

```cpp
std::unordered_map<Code, Handler> handlers = {
    {CODE, [this](Args args) { Handle(args); }}
};
auto it = handlers.find(code);
it->second(args);
```

之前的诊断器只观察 `table[key] = lambda`、已有表的赋值初始化列表，以及文件级
初始化列表；函数体内的 `init_declarator.value = initializer_list` 没有注册记录，
后面的 `it->second(...)` 只能保留为无候选残余。本阶段不处理 callback 参数跨函数
传播、`std::bind`、模板实例参数推导，也不使用函数名相似性或 LLM 猜测。

## 2. 原项目逻辑与修改后逻辑

### 2.1 原项目逻辑

`_lambda_dispatch_assignments()` 只接受 Tree-sitter 节点
`assignment_expression`。而局部声明在 AST 中是 `init_declarator`；文件级扫描又
主动跳过位于 `function_definition` 内的初始化列表，造成“调用点存在、注册点没有”
的残余。

### 2.2 修改后逻辑

1. 遇到 `init_declarator` 时读取 `declarator` 和 `value` 字段；
2. 仅当 `value` 是 `initializer_list`，且其中存在 `{selector, lambda}` 条目时记录；
3. 复用既有 Lambda 调用目标提取、参数个数、函数索引唯一解析和源码证据格式；
4. 新增 `registration_form = "declaration_initializer_list"`，明确表示函数局部表；
5. 局部表只允许与同一 `owner_function_id` 的 `find()/second()` 调用点匹配，避免把
   不同函数中同名变量错误合并；
6. `native_dispatch` 语义投影层再次检查该作用域，防止旧版或手写残差绕过诊断器；
7. 没有命名函数调用目标的 Lambda 仍保留 `no_lambda_call_target` orphan，不生成猜测边；
8. 对未限定命名空间的自由函数调用，仅在同文件唯一且参数个数匹配时解析为命名空间
   全名；已限定的 `Class::Method` 不走叶子名回退。

代码位置：

- [局部 Lambda 诊断与作用域匹配](../../libs/vulnfounder-core/core/platforms/openharmony/call_graph_diagnostics.py)
- [语义投影作用域保护](../../libs/vulnfounder-core/core/platforms/openharmony/native_dispatch.py)

## 3. 先失败、后通过的测试过程

新增了以下单元测试：

1. 局部 `unordered_map = {{key, lambda}}` 能被发现并与同函数调用点闭合；
2. 同名局部表位于不同函数时不得跨函数匹配；
3. Lambda 只修改字段、没有命名调用时仍为显式 orphan；
4. `OHOS::HiviewDFX::TimeHandler` 这类命名空间函数可在同文件唯一叶子名下解析；
5. 语义投影层拒绝残差文件声称的跨函数局部注册。

实现前，局部初始化列表测试观察到 `dispatch_assignments == 0`，跨函数测试也观察到
错误候选边；修复后结果为：

```text
.venv/bin/pytest -q libs/vulnfounder-core/tests/openharmony
106 passed, 2 skipped

.venv/bin/ruff check …
All checks passed!
```

## 4. 真实仓库复现命令

### All 模式

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output debug_outputs/OH-22B-2G-all-20260827/<repo> \
  --platform openharmony --language c --level all --fresh
```

### Reachable 模式

```bash
PYTHONPATH=libs/vulnfounder-core .venv/bin/python -m openant.cli parse \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/<repo> \
  --output debug_outputs/OH-22B-2G-reachable-20260827/<repo> \
  --platform openharmony --language c --level reachable --fresh
```

9 个仓库的两种模式均返回成功，所有 `parse.report.json.errors` 均为空。

## 5. 9 个仓库结果

Lambda 列依次为“注册记录 / 调用点 / 候选边 / 无候选调用点 / orphan 注册”；局部注册
只统计 `declaration_initializer_list`。

| 仓库 | All Unit | Reachable Unit | Native 边 | Semantic 边 | Lambda | 局部注册 | Semantic 新增可达 |
|---|---:|---:|---:|---:|---:|---:|---:|
| communication_netmanager_base | 7563 | 1317 | 6394 | 642 | 0/2/0/2/0 | 0 | 1017 |
| developtools_hdc | 2052 | 164 | 2831 | 0 | 0/0/0/0/0 | 0 | 0 |
| hiviewdfx_faultloggerd | 2994 | 79 | 3415 | 0 | 0/2/0/2/0 | 0 | 0 |
| hiviewdfx_hilog | 857 | 79 | 851 | 2 | 11/1/2/0/5 | 11 | 0 |
| hiviewdfx_hiview | 7008 | 202 | 5687 | 37 | 136/22/7/19/120 | 94 | 0 |
| multimedia_audio_framework | 23178 | 287 | 33816 | 715 | 81/7/12/6/35 | 9 | 0 |
| startup_appspawn | 1204 | 81 | 2267 | 0 | 0/0/0/0/0 | 0 | 0 |
| startup_init | 2708 | 628 | 4929 | 9 | 0/0/0/0/0 | 0 | 0 |
| telephony_core_service | 6842 | 431 | 7196 | 341 | 347/16/320/0/17 | 0 | 318 |
| **合计** | **54406** | **3268** | **67386** | **1746** | **575/50/341/29/177** | **114** | **1335** |

相对 OH-22B-2F：

- Native 调用图边集在 9 个仓库均不变；
- SemanticGraph 从 1737 条边增加到 1746 条，新增 9 条闭合 Lambda 语义边；
- 诊断器新发现 114 条函数局部初始化列表注册；
- Reachable 最终 Unit 数未因本阶段减少，原生可达集合始终是最终集合的子集；
- 语义端点、源码证据文件和 Lambda 诊断证据均通过检查。

## 6. 真实源码抽查

### 6.1 `hiviewdfx_hilog`

`services/hilogtool/main.cpp:855-901` 的 `FormatHandler` 声明局部静态 `handlers` 表，
并在 `handler->second(context, 0)` 处调用。本阶段记录 11 个初始化条目：

- `TimeHandler` 和 `TimeAccuHandler` 的调用均通过同文件唯一叶子名解析；
- `color`、`colour`、`year`、`wrap` 只有字段更新或常量返回，保留为 orphan；
- `tzset` 没有对应的项目函数 Unit，保留为 `unknown_target_function`。

SemanticGraph 形成两条函数边：

```text
FormatHandler -> TimeHandler
FormatHandler -> TimeAccuHandler
```

### 6.2 `hiviewdfx_hiview`

真实局部表包括 `decoded_event.cpp` 的 `allFuncs`、`raw_data_builder.cpp` 的
`paramFuncs`、`raw_data_builder_json_parser.cpp` 的 `valueAppendFuncs`/`arrayValueAppendFuncs`，
以及内存采集器、事件导出和 fault formatter 中的局部表。共发现 94 条局部注册、22 个
调用点，形成 7 条有唯一目标的语义边。抽查显示 `DecodedEvent::AppendCustomizedArrayParam`
只闭合到自身局部表中真实存在的 `AsUint64Vec`，没有合并另一个函数的同名 `allFuncs`。

### 6.3 `multimedia_audio_framework`

新增识别到 9 条局部初始化列表注册，但没有新增语义边：这些条目主要是策略表，目标
函数未在当前索引中唯一解析，或 Lambda 没有命名调用。原来已经闭合的
`AudioSuiteCapabilities::loadCapabilityFuncs_` 12 条边保持不变。

## 7. 安全性和不变性检查

- 1746 条语义边的源、目标节点均存在；所有带文件证据的路径均存在于对应真实仓库；
- 625 条 Lambda 注册/调用证据经过空白归一化后全部能在源码中找到；
- 所有局部注册的 `owner_function_id` 都能对应函数 Unit；当前产物没有局部注册跨函数
  的 `registrations`；
- 9 个仓库的 `monotonicity_violation` 均为 `false`；SemanticGraph 只作为加法 overlay；
- 刚加入的投影作用域保护经过最终产物无写入重算，9 个仓库的 native semantic 边集合
  均与完整重跑产物一致，因此不需要重新覆盖已生成的历史结果目录。

## 8. 本阶段结论与边界

### 已验证

1. 函数体内局部 `map = {{selector, lambda}}` 已从“不可见”变为可审计诊断记录；
2. 真实 hilog/hiview 源码产生了闭合候选和语义边；
3. 局部变量作用域在诊断和语义投影两层均受到约束；
4. 命名空间自由函数的叶子名解析只在同文件唯一、参数个数匹配时生效；
5. 9 个仓库的原生调用图和 Reachable 安全不变量保持不变。

### 尚未处理

以下形式仍明确保留为残余，不能在本阶段靠名称猜测：

- callback 参数通过 `RegisterCallback`/`emplace` 跨函数传播；
- `std::bind`、`std::mem_fn` 和模板 `std::apply` 展开；
- 无 `&` 的成员函数指针初始化；
- `std::make_shared<ConcreteNode>()` 等工厂 Lambda 的构造函数目标；
- 一个目标函数对应多个 selector 时 SemanticGraph 的边属性聚合仍沿用现有合并机制，
  完整注册列表继续以 `call_graph_residuals.json` 为准。

这些形式需要单独的小阶段和独立回归测试，不在 OH-22B-2G 的修改范围内。

## 9. 产物目录

- [All 结果](../../debug_outputs/OH-22B-2G-all-20260827)
- [All 日志](../../debug_outputs/OH-22B-2G-all-20260827-logs)
- [Reachable 结果](../../debug_outputs/OH-22B-2G-reachable-20260827)
- [Reachable 日志](../../debug_outputs/OH-22B-2G-reachable-20260827-logs)
