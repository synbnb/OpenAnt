# OpenHarmony 单函数 Stage 1 → Stage 2 全流程测试记录

## 1. 测试结论

针对真实 OpenHarmony `AudioPolicyServer::UnexcludeOutputDevices` 修复前代码，单元级全流程测试通过：

- Stage 1 实际调用 `gpt-5.6-luna` 后给出 `INCONCLUSIVE`，没有把权限检查误认为输入校验，也没有武断判定为安全。
- Stage 2 原样接收 Stage 1 的 `results.json`，使用真实函数索引补读下游实现后，将结果升级为 `VULNERABLE`。
- 使用官方修复前下游快照复核时，模型准确恢复了 CVE-2026-55989 对应的空 vector / 首元素为空导致的 `front()`/解引用崩溃路径。
- 全流程没有 API 错误、解析错误或人工复核遗留项。

这证明当前 Stage 1 → Stage 2 的“待定结果补证”链路可以覆盖该真实漏洞。这里是静态分析验证，没有在开发板上发送真实 Binder 载荷，也没有宣称完成动态触发。

## 2. 测试对象与版本

- 目标函数：`AudioPolicyServer::UnexcludeOutputDevices(int32_t, const vector<shared_ptr<AudioDeviceDescriptor>>&)`
- 真实仓库：`source_code_base/multimedia_audio_framework`
- 修复前目标代码：Git 提交 `ffe49823d3` 的父提交（目标函数没有空 vector / 首元素判空）
- 官方修复提交：`ffe49823d3`；合并提交：`ac66942015`（对应公开 PR !15303 的合并记录）
- 模型配置：`autodl-openai / gpt-5.6-luna`
- Stage 1 上下文：真实 OpenHarmony `application_context.json`
- Stage 2 函数索引：真实 `analyzer_output.json`，并额外生成一个只把相关下游函数恢复为修复前代码的 `analyzer_output_pre_fix.json`

## 3. 输入与范围

为节省费用、隔离变量，测试夹具只保留一个单元，但目标函数代码来自真实修复前仓库快照，没有手工预置漏洞结论：

- [单函数 dataset.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/input/dataset.json)
- [修复前对照函数索引](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/input/analyzer_output_pre_fix.json)
- [真实源码复核断言](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/source_verification.json)
- [本次 Stage 1 实际 system/user prompt 快照](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage1/prompt_snapshot.txt)

Stage 1 只读取目标函数；Stage 2 通过 `search_definitions`、`read_function`、`search_usages` 等现有工具从真实索引中追踪下游调用，不把 Stage 1 的结论改写后再送入验证。

## 4. Stage 1 结果

- 结果文件：[stage1/results.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage1/results.json)
- 日志：[stage1/run.log](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage1/run.log)
- 单元数：1
- 结论：`INCONCLUSIVE`
- 模型调用：1 次
- Token：5,017（输入 3,505，输出 1,512）
- 成本：¥0.010213
- 耗时：24.3 秒

模型识别到目标函数存在以下事实：

1. `int32_t` 被直接转换为 `AudioDeviceUsage`，没有目标侧范围校验；
2. vector 在权限判断前被复制，目标侧没有大小、空容器或元素有效性检查；
3. `PermissionUtil::VerifySystemPermission()` 只解决授权，不等于参数安全校验；
4. 由于没有下游 `eventEntry_` 实现，具体影响暂时无法闭合，因此保留为 `INCONCLUSIVE`。

这是预期行为：Stage 1 没有在缺少关键下游证据时强行判定 `SAFE`。

## 5. Stage 2 结果（官方修复前下游快照，主结果）

- 结果文件：[stage2_pre_fix/results_verified.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage2_pre_fix/results_verified.json)
- 日志：[stage2_pre_fix/run.log](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage2_pre_fix/run.log)
- 检查点：[stage2_pre_fix/verify_checkpoints](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage2_pre_fix/verify_checkpoints)
- 输入候选：1 个，其中 Stage 1 `INCONCLUSIVE` 1 个
- 最终结论：`VULNERABLE`
- 结论变化：`INCONCLUSIVE → VULNERABLE`
- 模型调用：1 次
- Token：38,029（输入 36,372，输出 1,657）
- 成本：¥0.037607
- 耗时：70.8 秒
- 错误：0；需人工复核：0；确认漏洞：1

模型恢复出的真实路径为：

```text
授权的受限系统应用 / Binder-SA 请求
  → AudioPolicyServer::UnexcludeOutputDevices
  → EventEntry::UnexcludeOutputDevices
  → AudioCoreService::UnexcludeOutputDevices
  → AudioSelectInterfaceService::UnexcludeOutputDevices（修复前）
  → deviceDescs.front()->deviceType_
```

修复前的 `AudioSelectInterfaceService::UnexcludeOutputDevices` 先执行 `deviceDescs.front()->deviceType_`，而 `UnexcludeOutputDevicesInner` 的 `size() > 0` 检查位于之后，不能保护前面的操作。因此：

- 空 vector：调用 `front()`，产生未定义行为并可导致服务崩溃/DoS；
- 首元素为 `nullptr`：执行 `front()->deviceType_`，产生空指针解引用并可导致服务崩溃/DoS；
- 后续 `UnexcludeDevices` 中的 null 跳过逻辑无法保护更早的 `front()`。

模型还指出了未校验 `AudioDeviceUsage` 的次要状态完整性风险，但没有把它冒充为官方 CVE 的唯一原因。

## 6. 使用当前修复后下游索引的对照结果

为检查模型是否依赖错误上下文，另外用原始完整索引（下游包含修复后的首元素检查）重跑了一次 Stage 2：

- [对照结果](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/stage2/results_verified.json)
- 结论同样为 `VULNERABLE`，但主要依据变为未校验枚举/位掩码；模型同时明确空 vector / null 首元素在当前下游已被拦截。
- Token：57,556；成本：¥0.056272；耗时：88.3 秒；错误 0。

这个对照说明：Stage 2 会根据实际提供的下游版本调整漏洞原因，不能把修复后的上下文直接当成 CVE 修复前证据。

## 7. 本地源码逐条复核

[source_verification.json](/Users/shiyu/学习/hyl/new/VulnFounder/debug_outputs/OH-STAGE1-STAGE2-UNEXCLUDE-20260830/source_verification.json) 中的断言全部通过：

- 修复前 `AudioPolicyServer::UnexcludeOutputDevices` 没有 `newAudioDeviceDescriptors` 的空容器/首元素检查；
- `ffe49823d3` 在目标函数授权检查之后增加了该检查；
- 修复前下游无条件使用 `deviceDescs.front()->deviceType_`，且位于 `UnexcludeOutputDevicesInner` 的长度检查之前；
- `AudioRouterInfra::UnexcludeDevice` 确实使用 `excludedUsage & ~usage`，但该路径属于额外风险，不是本次 CVE 空指针触发的必要条件；
- `AudioPolicyUtils::GetDevicesStr` 虽会跳过 null 元素，但不能阻止后续 `front()` 解引用。

## 8. 运行命令

测试使用项目 Python API 构建真实 registry，并分别调用：

```text
core.analyzer.run_analysis(..., workers=1, registry=真实配置 registry)
core.verifier.run_verification(..., workers=1, include_inconclusive=True)
```

完整 stdout/stderr 已保存在上述两个 `run.log` 文件中，未使用伪造 Stage 1 结果作为主测试输入。

## 9. 限制

- 本次是单函数静态全流程测试，不是整仓库扫描；
- 没有在开发板上构造真实 Binder transaction，也没有执行 HAP/native 动态载荷；
- 修复前索引是基于真实完整索引替换相关下游函数得到的受控对照，其他函数沿用索引文件中的版本；
- 资源耗尽阈值、具体调用权限配置和设备状态仍需后续真实 IPC/动态测试确认。

## 10. 项目回归测试

本次没有修改业务代码；为确认现有 Stage 2 与 OpenHarmony 相关回归仍正常，额外执行：

```text
pytest -q libs/vulnfounder-core/tests/openharmony/test_current_behavior_baseline.py \
  libs/vulnfounder-core/tests/openharmony/test_disclosure_platform_context.py \
  libs/vulnfounder-core/tests/openharmony/test_semantic_reachability_overlay.py
结果：16 passed, 1 skipped

pytest -q libs/vulnfounder-core/tests/openharmony/test_llm_call_graph_recovery.py \
  libs/vulnfounder-core/tests/openharmony/test_llm_recovery_execution.py \
  libs/vulnfounder-core/tests/openharmony/test_semantic_reachability_overlay.py
结果：23 passed
```

## 11. 提示词与真实运行路径说明

本次没有把 `docs/AudioPolicyServer_UnexcludeOutputDevices_analysis_prompt_v3.txt` 当作静态输入文件读取。Stage 1 通过 `core.analyzer.run_analysis()` → `core.analysis_core.analyze_unit()` 动态调用 `get_stage1_system_prompt()` 与 `get_analysis_prompt()` 生成消息；该导出文档是同一 prompt 构造路径的快照。

为了只测一个函数，本次 user prompt 仅包含目标函数、真实 OpenHarmony 应用上下文、平台元数据和不可信的 `security_control` 预分类提示，没有包含 v3 快照中原始增强单元携带的全部上下文函数。因此 prompt 不是字节级相同，但 system 规则和判定框架来自同一运行时代码；实际发送内容已保存为 `stage1/prompt_snapshot.txt`。

Stage 1 / Stage 2 的业务逻辑、模型调用、结果解析、检查点、候选筛选、真实工具检索和结果合并均走项目实现；范围缩减只发生在输入单元数量、并发数（`workers=1`）和修复前下游索引对照上。解析、上下文增强、可达性、动态测试和报告生成没有在这次单函数测试中重复执行。
