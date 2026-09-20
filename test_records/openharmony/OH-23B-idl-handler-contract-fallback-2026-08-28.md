# OH-23B：无生成 Stub 时的 IDL→handler 契约回退

日期：2026-08-28  
阶段：阶段 1（实现与独立验证）  
模型调用：0 次  
动态测试：未执行

## 1. 本阶段目标

解决部分 OpenHarmony 源码仓库只有 IDL、服务类和业务实现，而没有构建过程生成的
`*Stub::OnRemoteRequest` 源文件时，业务 handler 被 reachable 过滤裁掉的问题。

本阶段只恢复“外部 IPC 事务可以到达哪个已存在的业务函数”这一关系，不声称恢复了
缺失的生成代码，也不把一个不存在的 `AudioPolicyStub::OnRemoteRequest` 函数写入
调用图。

## 2. 修改前后的逻辑

### 修改前

1. IDL 解析出接口和事务节点。
2. 只有在原生函数体、原生调用图或显式分派表中看到 `OnRemoteRequest`、事务常量、
   `SendRequest` 或 handler 调用证据时，才建立 Stub/Proxy 与事务的关系。
3. 找不到生成 Stub 时记录 `unresolved_ipc_stub` orphan。
4. reachable 过滤只能从结构化入口或已有原生调用图开始，因此只有 IDL 和业务实现的
   源码快照会丢失该 handler。

### 修改后

1. 保留上述所有强原生证据路径，原生调用图仍是普通调用关系的主来源。
2. 从 `FunctionExtractor.export()` 读取已经解析的 `class_bases`，不执行 GN、不读取
   生成代码、不调用模型。
3. 当生成 Stub 不可见时，只查找：
   - 与 IDL 方法名完全相同的非静态成员函数；
   - 该函数所属类（或 `class_name`）存在继承链；
   - 继承链最终到达由 IDL 接口名推导出的 Stub 基类，例如
     `IAudioPolicy` → `AudioPolicyStub`；
   - C++ 参数个数一致，且可归一化为相同的参数形状（标量、序列、字符串、对象等）。
4. 返回类型不作为硬匹配条件：OpenHarmony 的 IDL 方法可能是 `void`，而服务端实现
   返回 `int32_t` IPC 状态码。
5. 满足唯一候选时建立带有
   `source=idl_handler_contract`、`signal=service_inherits_stub`、参数匹配信息和
   `dispatch_mode=generated_code_missing` 的 `transaction_to_handler` 语义边。
6. 该语义边没有 Stub 函数端点，因此可达性投影器会把事务直接指向的、已知的 native
   handler 加入外部 IPC 入口种子，再从该函数沿原生 reverse call graph 做 BFS。
7. 没有继承证据、参数冲突或多个同分候选时不猜测，继续保留 orphan 诊断。

## 3. 涉及代码

- `libs/vulnfounder-core/core/platforms/openharmony/ipc_graph.py`
  - 保存函数参数、返回类型、类名和静态属性；
  - 读取 `class_bases`；
  - 增加类型形状归一化、Stub 继承链检查和契约候选排序；
  - 增加缺失生成代码时的 `transaction_to_handler` 证据边。
- `libs/vulnfounder-core/core/platforms/openharmony/reachability.py`
  - 增加 `entry_points` 结果字段；
  - 从合法 `ipc_transaction → transaction_to_handler → function` 关系提取外部入口。
- `libs/vulnfounder-core/core/parser_adapter.py`
  - 在空入口保护判断前合并语义外部入口；
  - 保证语义入口只扩大 reachable 集合，不裁剪原生 reachable 集合；
  - 记录 `entry_points_added` 和语义入口明细。
- `libs/vulnfounder-core/parsers/c/test_pipeline.py`
  - 将同样的语义入口合并逻辑接入 C/C++ 流水线。
- 测试文件：
  - `libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py`
  - `libs/vulnfounder-core/tests/openharmony/test_semantic_reachability_overlay.py`

## 4. 单元和回归测试

使用项目独立虚拟环境：`.venv/bin/python`。

### 4.1 IPC resolver 与可达性测试

```text
.venv/bin/python -m pytest -q \
  libs/vulnfounder-core/tests/platforms/test_openharmony_ipc_graph.py \
  libs/vulnfounder-core/tests/openharmony/test_semantic_reachability_overlay.py
```

结果：`26 passed`。

新增断言包括：

- 缺少生成 Stub 时，`IAudioPolicy` 能连接到 `AudioPolicyServer::UnexcludeOutputDevices`；
- 证据中包含 `AudioPolicyStub` 和两项参数形状匹配；
- 没有 Stub 继承关系的同名 `Enable` 不会被误判；
- 只有事务到 handler 的语义边时，handler 可以作为外部 IPC 入口；
- C pipeline 和通用 parser adapter 都能使用该入口，并保持原生 reachable 单调性。

### 4.2 OpenHarmony 相关回归

```text
.venv/bin/python -m pytest -q libs/vulnfounder-core/tests/openharmony
```

结果：`171 passed, 2 skipped`。

```text
.venv/bin/python -m pytest -q \
  libs/vulnfounder-core/tests/openharmony/test_c_pipeline_platform.py \
  libs/vulnfounder-core/tests/parsers/c
```

结果：`103 passed`。

语法检查：

```text
.venv/bin/python -m compileall -q \
  libs/vulnfounder-core/core/platforms/openharmony/ipc_graph.py \
  libs/vulnfounder-core/core/platforms/openharmony/reachability.py \
  libs/vulnfounder-core/core/parser_adapter.py \
  libs/vulnfounder-core/parsers/c/test_pipeline.py
```

结果：`COMPILE_OK`。

## 5. 真实仓库定向验证

### 5.1 输入源码证据

仓库：`source_code_base/multimedia_audio_framework`

- `services/audio_policy/idl/IAudioPolicy.idl:244`：声明
  `UnexcludeOutputDevices`；
- `services/audio_policy/server/service/service_main/include/audio_policy_server.h:79-81`：
  `AudioPolicyServer` 继承 `AudioPolicyStub`；
- 同一头文件 `:213-214`：声明同名 `override`；
- `services/audio_policy/server/service/service_main/src/audio_policy_server.cpp:1984-1995`：
  存在业务实现，返回类型为 `int32_t`，参数为 `int32_t` 与设备描述符序列。

### 5.2 定向 resolver 结果

仅提取上述头文件和实现文件，并收集仓库 IDL 后运行 resolver：

```text
class_bases[AudioPolicyServer] =
['SystemAbility', 'AudioPolicyStub', 'AudioStreamRemovedCallback']

transaction_to_handler:
idl:transaction:IAudioPolicy:UnexcludeOutputDevices
  -> function:.../audio_policy_server.cpp:AudioPolicyServer::UnexcludeOutputDevices

confidence = 0.90
source = idl_handler_contract
signal = service_inherits_stub
base_class = AudioPolicyStub
parameter_match = scalar, sequence；matched = 2；mismatched = 0
```

该结果没有创建 `stub_to_transaction`，因为生成的 Stub 函数确实不在当前源码输入中。

### 5.3 全量无模型流水线

命令：

```text
.venv/bin/python libs/vulnfounder-core/parsers/c/test_pipeline.py \
  source_code_base/multimedia_audio_framework \
  --output /tmp/openant-oh23b-audio-dRtegQ \
  --platform openharmony --processing-level reachable --skip-tests \
  --name oh23b_audio_stage1
```

结果：流水线成功完成，耗时 `317.16s`，没有模型调用。

| 指标 | 结果 |
| --- | ---: |
| 扫描文件 | 1,507 |
| 提取函数 | 21,890 |
| 原生调用图边 | 27,978 |
| 生成 Unit | 21,875 |
| 原生结构化入口 | 28 |
| 修改前原生入口是否包含目标 | 否 |
| reachable 结果 | 1,084 Units |
| 语义 reachability 新增 | 811 Units |
| 语义外部入口新增 | 637 |
| 目标函数是否进入 dataset | 是 |
| 目标函数是否标记 reachable | 是 |
| 语义图中的目标边 | 1 条 `transaction_to_handler` |

输出目录：`/tmp/openant-oh23b-audio-dRtegQ`。其中：

- `semantic_graph.json` 包含目标事务到目标 handler 的契约边；
- `dataset.json` 包含目标函数且标记 `reachable=true`、`is_entry_point=true`；
- `dataset.json` 的 reachability 元数据包含 `entry_points_added=637`。

## 6. 结果解释与边界

本阶段确认该方案能解决用户指出的“生成 Stub 不在源码导致
`UnexcludeOutputDevices` 被裁掉”这一类问题。它不是对所有 IPC 关系的完整证明：

- 如果源码中没有 `class_bases`，不会根据类名自行猜测；
- 如果有多个同名且同分的 Stub 派生实现，会保留歧义诊断；
- 生成 Stub 的真实分派顺序和 `code → handler` 数字映射仍需完整构建产物或后续
  LLM/构建信息验证；
- 本次测试没有调用真实模型，也没有运行设备动态验证。

因此本阶段把 handler 纳入安全分析上下文，但不会把缺失生成代码伪装成已解析源码。
