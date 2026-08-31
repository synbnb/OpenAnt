# OH-22F-2：真实 sensors_medical_sensor 扫描验证记录

**日期**：2026-08-27  
**仓库**：`source_code_base/sensors_medical_sensor`  
**输出目录**：`debug_outputs/OH-22F-2-real-sensors-20260827`  
**目标**：验证 scanner/CLI 接入后的真实 OpenHarmony LLM 间接调用审核链路。

## 1. 执行配置

项目使用的配置文件：

```text
config/openant/config.json
```

解析到的配置名称为 `openharmony-live-gpt`，`llm_reach` 和 `analyze` 均使用
`gpt-5.6-luna`。本次没有打印或修改凭据。

实际执行参数：

```bash
PYTHONPATH=libs/openant-core .venv/bin/python -m openant.cli scan \
  source_code_base/sensors_medical_sensor \
  --output debug_outputs/OH-22F-2-real-sensors-20260827 \
  --platform openharmony \
  --level reachable \
  --limit 1 \
  --workers 1 \
  --backoff 1 \
  --no-context \
  --no-enhance \
  --no-report \
  --llm-call-graph-recovery
```

为了控制费用，本次只让漏洞检测阶段分析 1 个 reachable 单元；调用图恢复阶段仍
读取完整 parser 产物，但按 worklist 上限审核残余点。

## 2. 解析和静态产物

真实仓库解析结果：

```text
OpenHarmony profile confidence: 1.00
发现文件: 67
解析函数: 340
调用图边: 130
残余调用点: 3
候选边: 8
入口函数: 7
reachable units: 340 -> 25
```

原始 residual 为：

1. `compatible_connection.cpp:147`：
   `(reportDataCache_->*cacheData_)(&sensorEvent, reportDataCache_)`；
2. `sensor_event_callback.cpp:55`：
   `(reportDataCallback_->*(reportDataCb_))(&sensorEvent, reportDataCallback_)`；
3. `medical_service_stub.cpp:68`：
   `(this->*memberFunc)(data, reply)`，候选 handler 共 8 个。

## 3. 真实 LLM 审核结果

产物：

```text
debug_outputs/OH-22F-2-real-sensors-20260827/llm_call_graph_recovery.json
debug_outputs/OH-22F-2-real-sensors-20260827/llm-call-graph-recovery.report.json
```

汇总：

```text
status: complete
worklist_sites: 2
attempts: 1
llm_calls: 1
parsed_decisions: 2
accepted: 0
kept_unresolved: 2
rejected: 0
unreviewed_sites: 0
```

### compatible_connection.cpp:147

模型结论：`keep_unresolved`，置信度 `low`。

模型引用了真实源码中的：

- 第 147 行成员函数指针调用；
- 第 152–166 行 `RegisteDataReport()` 中保存 `cacheData_` 的注册证据。

模型认为注册过程只能证明回调被保存，不能确定具体目标函数，因此没有臆造调用边。

### sensor_event_callback.cpp:55

模型结论：`keep_unresolved`，置信度 `low`。

模型引用了第 55 行调用证据，并指出当前检索候选只有析构函数，缺少可信目标和注册证据，
因此拒绝把析构函数误连为回调目标。

## 4. 重要限制和对实际源码的判断

`medical_service_stub.cpp:68` 的 `OnRemoteRequest` 是本仓库最重要的 IPC 分发残余，
源码中可以看到：

```cpp
baseFuncs_[ENABLE_SENSOR] = &MedicalSensorServiceStub::AfeEnableInner;
...
auto memberFunc = itFunc->second;
return (this->*memberFunc)(data, reply);
```

本阶段没有审核它，原因是现有执行器默认
`include_candidate_sites=False`：只要解析器已经给出候选目标，该残余就不会进入首轮
LLM worklist。因此本次结果不能说明模型已经验证了 8 个 handler，也没有新增
`OnRemoteRequest -> Afe*Inner` 边。

另外，两个成员函数指针残余被规则分类为 `template_dispatch`，其
`llm_eligible` 为 `false`，但当前 scanner 没有开启 `security_relevant_only`，所以它们
仍进入了首轮审核。这保证了保守性，但产生了一次模型调用，后续可以优化为先走确定性
注册/类型分析，再把真正未知的间接调用交给模型。

## 5. Stage 1 漏洞分析结果

本次只分析 1 个单元：

```text
verdict: safe
```

费用和 token：

```text
LLM calls: 2
input tokens: 9,784
output tokens: 807
total tokens: 10,591
total cost: ¥0.011876
```

其中：

- 调用图恢复阶段：1 次调用，¥0.009325；
- 漏洞分析阶段：1 次调用，¥0.002551。

应用上下文、增强、验证、报告和动态测试均按执行参数跳过，没有产生对应调用。

## 6. 产物完整性检查

以下文件已生成并可读取：

```text
platform_profile.json
scan_results.json
call_graph.json
call_graph_residuals.json
dispatch_recovery_diff.json
semantic_graph.json
dataset.json
analyzer_output.json
llm_call_graph_recovery.json
llm-call-graph-recovery.report.json
results.json
analyze.report.json
pipeline_output.json
scan.report.json
```

`scan.report.json` 正确记录了恢复产物路径：

```text
llm_call_graph_recovery_path:
.../debug_outputs/OH-22F-2-real-sensors-20260827/llm_call_graph_recovery.json
```

## 7. 发现但未在本轮修复的问题

日志阶段编号出现了 `[5/4]`、`[9/4]` 等情况。原因是 scanner 的 `_count_steps()` 只
统计启用的可选阶段，但显式跳过的阶段仍会调用 `_step_label()`。这只是进度显示错误，
不影响扫描结果和产物，本轮不扩大修改范围。

## 8. 结论

本次验证确认：

- 项目内配置可以被 scanner 正确解析；
- 真实 `gpt-5.6-luna` 调用可以从 `llm_reach` 绑定发出；
- OpenHarmony residual 能被转换成 worklist 并写入审核产物；
- 模型能够基于真实文件、行号和注册代码给出保守结论；
- 审核结果不会修改原始调用图或 reachable。

但本次尚未解决 Stub→handler 的候选边审核。下一步若要覆盖该缺口，需要单独讨论
是否增加“候选边二次审核”模式（例如对 `OnRemoteRequest` 的 8 个候选逐项提供注册表、
code 数字映射和 handler 证据），不能把本轮 `keep_unresolved` 误解为调用图已经完整。
