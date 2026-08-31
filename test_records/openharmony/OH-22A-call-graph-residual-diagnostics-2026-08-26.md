# OH-22A：OpenHarmony 间接调用诊断与候选提取测试记录

日期：2026-08-26
阶段：ADR-001 阶段 1 第一切片
状态：通过

## 1. 原项目逻辑

原 C/C++ `CallGraphBuilder` 可以处理直接调用和部分静态类型成员调用，但调用目标为 `parenthesized_expression` 时返回未解析。以真实源码为例：

```cpp
return (this->*memberFunc)(data, reply);
```

tree-sitter 能产生 `call_expression`，但原流程不会：

- 保存这个未解析调用点；
- 保存未解析原因；
- 把 `baseFuncs_[KEY] = &Class::Handler` 与调用点关联；
- 输出可供确定性 resolver 或 LLM 审核的有限候选。

现有 `--llm-reachability` 只补充入口种子，不恢复 caller → callee 边。

## 2. 本阶段修改逻辑

新增只读诊断器，使用 tree-sitter AST 收集：

1. `parenthesized_expression` 形式的函数指针和成员函数指针调用；
2. `table[selector] = &Class::Handler` 形式的分发表赋值；
3. `table.find(...) → iterator->second → memberFunc` 的函数内取值链；
4. 能够精确映射到现有函数 ID 的有限候选；
5. 未知目标 orphan 和没有候选的 residual。

OpenHarmony C/C++ 流水线新增：

```text
call_graph_residuals.json
```

该阶段不修改：

- `call_graph.json` 中的函数和边；
- `semantic_graph.json`；
- reachable 图；
- Unit 的调用上下文。

诊断器失败时，解析流水线继续成功，并在产物中写入 `status: failed` 和结构化错误。

## 3. 修改文件

- `libs/openant-core/core/platforms/openharmony/call_graph_diagnostics.py`
- `libs/openant-core/parsers/c/test_pipeline.py`
- `libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py`
- `libs/openant-core/tests/openharmony/test_c_pipeline_platform.py`
- `ADR-001-OPENHARMONY-LLM-CALL-GRAPH-RECOVERY.zh-CN.md`

## 4. TDD 记录

### RED：纯诊断契约

先添加诊断器测试：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_call_graph_diagnostics.py \
  libs/openant-core/tests/openharmony/test_c_pipeline_platform.py
```

实现前结果：

```text
ModuleNotFoundError:
No module named 'core.platforms.openharmony.call_graph_diagnostics'
```

### GREEN：纯诊断器

实现最小诊断器后：

```text
3 passed in 0.02s
```

覆盖：

- 成员函数分发表产生有限候选；
- 输入原生图保持不变；
- 直接 switch 调用不作为间接残余；
- 未知目标只进入 orphan，不产生候选边。

### RED：流水线产物

在接入流水线前单独运行：

```text
./.venv/bin/python -m pytest -q \
  libs/openant-core/tests/openharmony/test_c_pipeline_platform.py
```

结果：

```text
FileNotFoundError: call_graph_residuals.json
1 failed
```

### GREEN：流水线接入

接入后运行诊断器和流水线测试：

```text
4 passed in 0.06s
```

之后增加安全降级覆盖，相关回归测试最终结果：

```text
55 passed, 1 skipped in 0.10s
```

跳过项属于原有环境条件测试，没有禁用本阶段测试。

## 5. 真实仓库验证 A：sensors_medical_sensor

源码提交：

```text
6f87daec8f0a91057336b0b243eee702bd8731e7
```

执行命令：

```text
./.venv/bin/python libs/openant-core/parsers/c/test_pipeline.py \
  source_code_base/sensors_medical_sensor \
  --output debug_outputs/OH-22A/sensors_medical_sensor \
  --platform openharmony \
  --processing-level all \
  --skip-tests
```

流水线结果：

```text
67 个源码文件
408 个函数
227 条原生调用边
2 个间接调用残余
8 个分发表赋值
8 个候选边
1 个无候选残余
0 个 orphan assignment
耗时 0.46 秒
```

目标调用点：

```text
services/medical_sensor/src/medical_service_stub.cpp:
MedicalSensorServiceStub::OnRemoteRequest
第 68 行：(this->*memberFunc)(data, reply)
```

得到 8/8 个候选：

```text
AfeEnableInner
AfeDisableInner
GetAfeStateInner
RunCommandInner
GetAllSensorsInner
CreateDataChannelInner
DestroyDataChannelInner
AfeSetOptionInner
```

每个候选都满足：

- 目标是当前函数索引中的精确函数 ID；
- 具有第 39～46 行分发表赋值证据；
- 表名为 `baseFuncs_`；
- selector 与目标函数分别保存；
- 没有幽灵目标。

原生行为核对：

```text
OnRemoteRequest 原生下游仍为 []
函数数仍为 408
边数仍为 227
```

与修改前历史产物比较时，forward/reverse adjacency 按集合归一化后完全相等。原始 JSON 中少量数组顺序不同，属于构建器已有的 set 迭代顺序，不是边集合变化。

### 额外发现

诊断器还发现真实残余：

```text
services/medical_sensor/hdi_connection/adapter/src/compatible_connection.cpp:
CompatibleConnection::SensorDataCallback
第 147 行：(reportDataCache_->*cacheData_)(&sensorEvent, reportDataCache_)
```

`cacheData_` 来自另一个函数参数的赋值，而不是当前支持的 `table[key] = &Handler` 形式。本阶段没有足够证据确定其最终目标，因此：

- 候选目标为空；
- `unresolved_without_candidates` 增加 1；
- 没有根据名称猜测函数边。

这条结果证明诊断器既能恢复确定性候选，也能保守保留尚需跨函数分析的残余。

完整产物：

```text
debug_outputs/OH-22A/sensors_medical_sensor/call_graph_residuals.json
```

## 6. 真实仓库验证 B：systemabilitymgr_samgr

源码提交：

```text
ab33181bdb13d9e2bd0ee4961dc8315f6ba618bc
```

执行命令：

```text
./.venv/bin/python libs/openant-core/parsers/c/test_pipeline.py \
  source_code_base/systemabilitymgr_samgr \
  --output debug_outputs/OH-22A/systemabilitymgr_samgr \
  --platform openharmony \
  --processing-level all \
  --skip-tests
```

结果：

```text
97 个源码文件
1136 个持久化调用图函数节点
989 条原生调用边
0 个间接调用残余
0 个候选边
耗时 3.77 秒
```

`SystemAbilityLoadCallbackStub::OnRemoteRequest` 原有 5 条直接边全部保留：

```text
EnforceInterceToken
OnLoadSystemAbilityFailInner
OnLoadSystemAbilityFailWithCodeInner
OnLoadSystemAbilitySuccessInner
OnLoadSACompleteForRemoteInner
```

诊断器没有把这些直接 switch 调用重复输出成间接候选。forward/reverse adjacency 与修改前历史产物按集合归一化后完全相等。

完整产物：

```text
debug_outputs/OH-22A/systemabilitymgr_samgr/call_graph_residuals.json
```

## 7. 结论

OH-22A 的目标已达到：

- 已证明 tree-sitter 能为目标案例提供足够的诊断事实；
- `OnRemoteRequest` 得到 8/8 个有证据候选；
- 未知目标不会变成调用边；
- 原生调用图未被修改；
- 没有调用 LLM，模型费用为 0；
- 诊断失败不会阻断主解析流程。

本阶段只能证明“缺口和候选可以可靠发现”，尚不能证明 Unit 上下文已经改善，因为调用边还没有进入 SemanticGraph/reachable。

下一阶段 OH-22B 应只处理这 8 条确定性关系：验证证据后生成 `native_dispatch_map` 语义边，接入现有 semantic reachability overlay，并分别测试调用图展示、reachable 单调性和 Unit `context_functions`。
