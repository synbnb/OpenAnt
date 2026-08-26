# OH-22B 原生分派语义图：sensors_medical_sensor 离线回归记录

日期：2026-08-26
仓库：`source_code_base/sensors_medical_sensor`
测试目的：验证新增的 OpenHarmony `baseFuncs_` 成员函数表解析，能否补上
`OnRemoteRequest → handler → MedicalSensorService` 的缺失关系，并确认它不会
修改原有的 C/C++ 原生调用图。

## 1. 本阶段实现范围

原项目的 tree-sitter 调用图可以识别普通的直接调用，但下面的调用目标隐藏在
成员函数指针表中：

```cpp
baseFuncs_[ENABLE_SENSOR] = &MedicalSensorServiceStub::AfeEnableInner;
return (this->*memberFunc)(data, reply);
```

本阶段新增了一个独立的语义解析器：

- 只接受有源码赋值证据的 `baseFuncs_`（及同类明确命名）表；
- 用诊断阶段给出的精确 `target_id` 建立
  `native_dispatch_to_handler` 边；
- 只有在源码类声明证明服务类继承 stub，且 handler 中存在直接方法调用时，
  才建立 `native_dispatch_to_service` 边；
- 目标不唯一、表名不支持或缺少证据时记录 orphan，不猜测目标；
- 语义边只写入 `semantic_graph.json`，原始 `call_graph.json` 保持不变；
- 可达性过滤与 Unit context 只把语义图作为附加边使用。

## 2. 执行命令

未启用 LLM、CodeQL 或动态测试，执行两次离线 C/C++ 流程：

```bash
PYTHONPATH=libs/openant-core .venv/bin/python \
  libs/openant-core/parsers/c/test_pipeline.py \
  source_code_base/sensors_medical_sensor \
  --output debug_outputs/OH-22B-native-dispatch-sensors-20260826-rerun \
  --platform openharmony --processing-level all --skip-tests

PYTHONPATH=libs/openant-core .venv/bin/python \
  libs/openant-core/parsers/c/test_pipeline.py \
  source_code_base/sensors_medical_sensor \
  --output debug_outputs/OH-22B-native-dispatch-sensors-20260826-reachable \
  --platform openharmony --processing-level reachable --skip-tests
```

## 3. 测试结果

### 3.1 定向单元测试

```text
35 passed in 0.09s
```

覆盖内容包括：

- 原有 IDL IPC resolver；
- 原有语义可达性 overlay；
- 原有 Unit context；
- OH-22A 间接调用诊断；
- 新增 native dispatch resolver 的夹具、继承解析、非 `baseFuncs_` 排除和
  Unit context 接入。

单独的新模块测试：

```text
4 passed in 0.04s
```

Ruff 静态检查：`All checks passed!`。

### 3.2 真实仓库解析结果

| 指标 | 结果 |
| --- | ---: |
| 扫描文件 | 67 |
| tree-sitter 函数 | 408 |
| 原生调用图边 | 227 |
| 诊断出的间接调用位置 | 2 |
| `baseFuncs_` 赋值 | 8 |
| 分派候选 | 8 |
| 语义图节点 | 17 |
| 语义图边 | 16 |
| 语义图 orphan | 0 |
| 生成 Unit | 408 |
| 带语义上下文的 Unit | 17 |
| 语义上下文函数总数 | 32 |

语义图的 16 条边为：

- 8 条 `native_dispatch_to_handler`：
  `MedicalSensorServiceStub::OnRemoteRequest` 到 8 个 `*Inner` handler；
- 8 条 `native_dispatch_to_service`：
  8 个 handler 到 `MedicalSensorService` 中对应的业务方法。

8 个 selector 与 handler 的映射均来自真实源码第 39--46 行，间接调用位置
来自第 68 行。例如：

```text
ENABLE_SENSOR              → AfeEnableInner
DISABLE_SENSOR             → AfeDisableInner
GET_SENSOR_STATE           → GetAfeStateInner
RUN_COMMAND                → RunCommandInner
GET_SENSOR_LIST            → GetAllSensorsInner
TRANSFER_DATA_CHANNEL      → CreateDataChannelInner
DESTROY_SENSOR_CHANNEL     → DestroyDataChannelInner
SET_OPTION                 → AfeSetOptionInner
```

服务实现边使用了真实类声明：
`MedicalSensorService : public SystemAbility, public MedicalSensorServiceStub`，
并核对 handler 中的直接调用及 `medical_service.cpp` 的唯一实现。例如：

```text
AfeEnableInner       → MedicalSensorService::EnableSensor
GetAllSensorsInner   → MedicalSensorService::GetSensorList
CreateDataChannelInner → MedicalSensorService::TransferDataChannel
```

### 3.3 原生调用图不变性

将 OH-22A 的基线 `call_graph.json` 与本阶段重新生成的文件进行比较：

- `functions`、文件索引、统计信息完全相同；
- `call_graph` 和 `reverse_call_graph` 的键集合及每个节点的目标集合完全相同；
- 仅有部分邻接列表的顺序变化，不存在拓扑新增或删除；
- 语义边只出现在 `semantic_graph.json`，没有回写 `call_graph.json`。

因此本阶段是 additive overlay，不会破坏原项目已有的普通调用关系。

### 3.4 可达性过滤结果

`reachable` 输出：

```text
Entry points: 7
Native reachable units: 11
Combined reachable units: 47
Units: 408 -> 47 (88.5% reduction)
Semantic overlay candidate edges: 16
Semantic overlay edges added: 16
Monotonicity violation: false
```

相对于原生 BFS，新增 36 个可达 Unit。新增内容包含 8 个 dispatch handler、8 个
`MedicalSensorService` 业务实现及其后续普通调用链；原生可达的 11 个 Unit 没有
被裁剪。

## 4. 结论与限制

本阶段已在真实 `sensors_medical_sensor` 源码上验证了目标缺口：原生图没有直接
表示的 8 条 Binder 分派边和 8 条 stub 到具体服务实现边，均能由源码证据稳定
恢复，并可以进入可达性与 Unit context。

仍然保留的未解析位置是
`CompatibleConnection::SensorDataCallback` 中的另一个成员函数指针调用；它没有
可确定的赋值候选，因此本阶段按“记录 residual、不猜测”处理。其他 dispatch 表、
跨仓库生成代码、复杂模板/宏和运行时注册关系不在本切片范围，后续需单独增加
解析器并用更多仓库回归。

## 5. 产物位置

- 全量解析：`debug_outputs/OH-22B-native-dispatch-sensors-20260826-rerun2/`
- 可达性解析：`debug_outputs/OH-22B-native-dispatch-sensors-20260826-reachable2/`
- 语义图：上述目录中的 `semantic_graph.json`
- 间接调用诊断：上述目录中的 `call_graph_residuals.json`
- 可达性元数据：上述目录中的 `dataset.json → metadata.reachability_filter`
