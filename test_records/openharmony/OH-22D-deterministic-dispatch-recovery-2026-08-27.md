# OH-22D：确定性分派候选恢复测试记录

日期：2026-08-27  
范围：OpenHarmony C/C++ 间接调用诊断、注册辅助函数传播、Lambda/函数引用分派候选  
实现文件：

- `libs/openant-core/core/platforms/openharmony/call_graph_diagnostics.py`
- `libs/openant-core/core/platforms/openharmony/native_dispatch.py`
- `libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py`

## 1. 阶段目标

OH-22C-2 已经把残余调用点按源码位置去重并分类，但 `local_dispatch` 和
`template_dispatch` 仍只是分类结果，没有继续利用注册表、Lambda 和参数流恢复候选。
本阶段的目标是补充一组通用、可审计的确定性规则：

1. 迭代器声明与后续赋值都能追踪到同一个 `table`；
2. `emplace`、`try_emplace` 和 `insert({key, lambda})` 注册能形成 Lambda 证据；
3. 一个辅助函数把 callable 参数写入 `table[key]` 时，调用点传入的函数指针可以
   沿参数位置传播到注册表；
4. 初始化列表中的已索引自由函数引用可以形成候选；
5. 候选仍然只进入诊断和已有语义图 overlay，不修改原生 `call_graph.json`，也不调用
   LLM。

## 2. 修改前后的逻辑

### 修改前

- `_local_dispatch_flow` 只识别 `auto it = table.find(...)`，不识别
  `auto it = table.begin()` 或 `it = table.find(...)`；
- Lambda 只识别下标赋值和 `{key, lambda}` 初始化列表，不识别
  `handlers.emplace(key, lambda)` 等方法注册；
- 没有分析“注册辅助函数的参数如何写入表”，所以以下两段代码无法连接：

  ```cpp
  void RegisterHandler(Key key, Handler handler) { handlers_[key] = handler; }
  RegisterHandler(READY, &Factory::HandleReady);
  ```

- 初始化列表的值如果是未加 `&` 的自由函数名，会被当作普通标识符，不会进入函数索引
  解析；
- 因此真实源码中的 `HpaeManager::RegisterHandler`、`RawDataBuilder` 的后续迭代器赋值、
  `RawDataBuilderJsonParser::handlers.emplace` 和 faultlog formatter 函数表仍有残余。

### 修改后

- 新增 `_lookup_table_from_call` 和赋值表达式跟踪：`find`、`begin`、`cbegin`、
  `lower_bound`、`upper_bound` 产生的迭代器，以及之后的 `it = ...`，都保留表身份；
  只有表注册证据和已索引目标都存在时才生成候选。`begin` 没有具体 key，因此产生的是
  该表的可能目标集合，而不是唯一运行目标；
- 新增 `_lambda_method_registration_records`，仅在第二个参数确实是 Lambda 时识别
  `emplace/try_emplace`，并支持 `insert({key, lambda})`。Lambda 内部调用仍经过原有
  receiver 类型、调用参数个数和函数索引约束；
- 新增结构化 `_registration_helper_specs`：只有当函数体出现
  `table[key] = callable_parameter`，或 Lambda 捕获该 callable 参数并写入表时，才把它
  视为注册辅助函数。调用点必须传入 `&Class::Method`、`Class::Method` 或唯一的已索引
  自由函数名，不能按 helper 名称猜测目标；
- 新增初始化列表函数引用观察。`{key, FunctionName}` 只有在 `FunctionName` 能唯一
  解析到现有函数索引时才记录，未解析名字（例如常量或外部符号）不会被误当作函数；
- `native_dispatch.py` 允许新增的 `initializer_function_reference`、
  `declaration_function_reference` 和 `helper_parameter_registration` 证据进入现有
  SemanticGraph resolver。resolver 仍检查端点、同文件/同类或注册 helper 证据；
- 为避免大仓库的重复线性扫描，新增目标解析路径使用一次性 name/leaf 索引；诊断输出
  增加 `registration_helpers`，并把 helper ID、参数名和 helper 体证据保留在 registration
  记录中。

## 3. 测试驱动过程

### 3.1 RED：先证明旧逻辑缺失

先加入三个最小 fixture：

- `emplace` + `it = table.find(...)`；
- `RegisterHandler` 把参数写入表；
- `{key, FreeFunction}` 初始化列表。

未实现新逻辑时定向测试结果为：

```text
3 failed, 21 passed
```

失败点分别是 Lambda 注册数为 0、辅助函数没有 assignment、自由函数表没有 assignment，
说明失败来自旧解析能力而不是测试构造错误。

随后再加入 HPAE 风格的模板成员函数指针 wrapper fixture，以及 `insert({key, lambda})`
fixture，验证两个新增分支。

### 3.2 GREEN：定向与回归测试

```bash
source .venv/bin/activate
pytest -q \
  libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py \
  libs/openant-core/tests/openharmony/test_native_dispatch.py
# 34 passed

pytest -q libs/openant-core/tests/openharmony/test_c_pipeline_platform.py
# 2 passed

pytest -q libs/openant-core/tests/openharmony
# 122 passed, 2 skipped

ruff check \
  libs/openant-core/core/platforms/openharmony/call_graph_diagnostics.py \
  libs/openant-core/core/platforms/openharmony/native_dispatch.py \
  libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py
# All checks passed!
```

测试还验证了：

- 输入的 native call graph 不被修改；
- 未索引函数指针不会生成幽灵节点；
- 不同类的同名 helper 不会互相传播；
- SemanticGraph 的新增边包含 registration/helper 源码证据；
- Lambda wrapper 的定义不会与具体 helper 调用重复生成一个 orphan registration。

## 4. 真实 OpenHarmony 源码验证

以下结果直接使用真实仓库的 `FunctionExtractor` 和源码文件，不调用大模型。每个重点
文件单独重新解析，并调用现有 `build_native_dispatch_graph` 检查 overlay 投影。

### 4.1 HPAE 模板 helper：`multimedia_audio_framework`

源码：
`services/audio_engine/manager/src/hpae_manager.cpp`

实际源码中的逻辑是：

```cpp
RegisterHandler(UPDATE_STATUS, &HpaeManager::HandleUpdateStatus);
// ... 共 14 次注册

handlers_[cmdID] = [this, cmdID, func](...) {
    std::apply([this, func](...) { (this->*func)(...); }, *args);
};

auto it = handlers_.find(cmdID);
it->second(args);
```

OH-22D 结果：

- 识别 `RegisterHandler` 为结构化 helper，识别 selector 参数 `cmdID` 和 callable 参数
  `func`；
- 14 次构造函数注册全部解析到已索引的 `HpaeManager::Handle*` 函数；
- `Invoke` 和 `InvokeSync` 各形成 14 个候选，合计 28 条 overlay handler 边；
- `build_native_dispatch_graph` 输出 16 个函数节点、28 条
  `native_dispatch_to_handler` 边、0 个 orphan；
- 注册形式为 `helper_parameter_registration`，证据同时包含构造函数调用行和
  `RegisterHandler` helper 体，不是按 `Handle` 名称猜测。

### 4.2 后续迭代器赋值：`hiviewdfx_hiview`

源码：
`base/event_raw/encoded/raw_data_builder.cpp`

`paramFuncs` 的局部表先声明，随后通过 `iter = paramFuncs.find(...)` 更新迭代器，
最后调用 `iter->second(...)`。旧逻辑不能把后续 assignment 连接到表；新逻辑在真实文件中
得到：

- `RawDataBuilder::AppendValue` 候选 2 条（对应源码中的两处读取）；
- overlay 投影 2 条 handler 边；
- 其他未解析 Lambda 仍保留为 orphan/残余，不因表名相似而强行连接。

### 4.3 `emplace` Lambda 注册：`hiviewdfx_hiview`

源码：
`base/event_raw/encoded/raw_data_builder_json_parser.cpp`

真实代码通过 7 次 `handlers.emplace(STATUS_*, [this] { ... })` 注册状态处理器，
之后用 `iter->second()` 分派。新逻辑得到：

- 7 个 `method_emplace` registration；
- 该文件的三个 callable 表读取共 13 个候选，overlay 13 条 handler 边；
- `handlers` 表对应的读取点（源码约第 486 行）有 7 个候选状态 handler。

### 4.4 函数引用初始化列表：`hiviewdfx_hiview`

源码：
`plugins/faultlogger/service/bdfr_base/fault_file/faultlog_formatter.cpp`

`GetLogParseSections` 中的表形如：

```cpp
{FaultLogType::CPP_CRASH, GetCppCrashSectionLogs}
```

新逻辑在真实文件中识别 9 个 `declaration_function_reference`，读取点形成 9 个候选，
并成功投影 9 条 overlay 边。未索引的名字不会生成 registration。

### 4.5 有意保留的残余

- `communication_netmanager_base/services/netstatsmanager/src/net_stats_listener.cpp` 的
  两处 `callbackMap*->second(...)` 仍无候选：注册值来自文件级命名 Lambda
  `onUidRemove` 或外部 callback 参数，本阶段没有把文件级变量别名当作唯一函数目标；
- `hiviewdfx_faultloggerd/tools/process_dump/minidump_parser/minidump_factory.cpp` 的
  `RegisterCreator` helper 已识别，但 `MinidumpException::Instance` 等目标没有出现在
  当前函数索引，因此不生成幽灵节点；
- `hiviewdfx_hiview` 的 `DecodedEvent` Lambda 调用 `AppendValue` 仍可能因模板函数未被
  当前索引收录而无候选；
- Taihe/JS callback、RIL/HDI 接口、`dlsym` 动态符号和无法唯一解析的模板仍属于外部边界
  或 residual，不交给本阶段的确定性 resolver 猜测。

## 5. 9 个仓库重点文件 smoke 回归

为避免 `dataset.json` 中依赖内联代码造成数万次重复解析，本表用每个仓库
`call_graph_residuals.json` 出现的源码文件做重点重解析，同时保留完整 dataset 函数索引。
因此“候选数”包含函数单元重复/内联造成的观察记录，不能直接当作唯一运行边计数；唯一
源码位置仍应通过 OH-22C-2 的去重器统计。

| 仓库 | 重点文件数 | 解析单元数 | native 候选/无候选 | Lambda 候选/无候选 | helper 规格 |
|---|---:|---:|---:|---:|---:|
| communication_netmanager_base | 17 | 427 | 30662 / 0 | 0 / 2 | 2 |
| developtools_hdc | 0 | 0 | 0 / 0 | 0 / 0 | 0 |
| hiviewdfx_faultloggerd | 3 | 56 | 40 / 22 | 0 / 2 | 1 |
| hiviewdfx_hilog | 1 | 63 | 0 / 0 | 6 / 0 | 0 |
| hiviewdfx_hiview | 10 | 191 | 27 / 0 | 335 / 40 | 2 |
| multimedia_audio_framework | 46 | 1875 | 852 / 234 | 236 / 11 | 6 |
| startup_appspawn | 1 | 36 | 0 / 3 | 0 / 0 | 0 |
| startup_init | 0 | 0 | 0 / 0 | 0 / 0 | 0 |
| telephony_core_service | 21 | 897 | 0 / 36 | 18507 / 1 | 0 |

表中数值来自一次只读 smoke 脚本；`developtools_hdc` 和 `startup_init` 的残余文件集合
为空，所以没有重复解析文件。高候选数主要来自同一头文件被多个函数单元内联的观察记录，
不是声称存在同样数量的真实唯一边。

## 6. 安全边界与不变性

1. 本阶段没有 API/LLM 调用；目标解析只使用本地函数索引和 tree-sitter AST。
2. `call_graph.json` 不修改；新增候选仅进入 `call_graph_residuals.json` 的诊断通道和
   现有 `SemanticGraph` overlay。
3. 所有投影边的目标都存在于函数索引；函数名无法唯一解析、文件级变量别名和外部回调
   均保留为残余。
4. `begin` 等无具体 selector 的读取只能产生可能目标集合，报告不能把它描述为唯一
   实际运行路径。
5. helper 分析不依赖 `RegisterHandler`、`RegisterCreator` 等固定名称，依据是“参数写入
   下标表 + 调用点函数引用 + 同类/同文件证据”；因此可以覆盖更多仓库，但仍不覆盖
   `std::bind`、宏生成注册、跨文件全局别名和反射/动态加载。

## 7. 阶段结论

OH-22D 已把确定性恢复从“分类后等待”推进到“注册证据 → 函数索引 → 候选/overlay”阶段，
并在真实 OpenHarmony 源码中验证了后续 iterator assignment、`emplace` Lambda、模板
helper 和自由函数初始化列表四类写法。它没有把所有 73 个去重残余都消除，也没有
启用 LLM；外部 callback、未索引模板和动态符号仍被明确保留。下一步可以在此候选层之上
增加差异报告与增量 BFS，再单独把真正无确定性证据的残余交给 OH-22C 的严格 LLM 审核协议。
