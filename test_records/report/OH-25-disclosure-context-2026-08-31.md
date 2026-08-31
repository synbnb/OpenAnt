# OH-25：披露报告证据上下文测试记录

日期：2026-08-31

## 1. 修改范围

本阶段只改造报告上下文构建，不改变 Stage 1/Stage 2 判定、CWE 分类或修复建议生成。

修改前，`pipeline_output.json` 的每个漏洞条目主要只有判定、描述、源码片段和位置，
`dataset_enhanced.json`、`call_graph.json`、`semantic_graph.json`、恢复差异以及
Stage 2 的 `exploit_path` 没有统一进入披露数据。

修改后新增 `core/report_context.py`：

- 为每个条目保存精确文件、函数、起止行和 route key；
- 保存 Stage 2 的入口、顺序数据流、sink 到达情况、攻击者控制情况和断链位置；
- 保存有界的调用链节点（角色、文件、行号、函数源码和证据原因）；
- 分开保存 native、semantic、projected/recovered 调用边及统计信息；
- 记录使用过的扫描产物，并标明跨 Binder/SA 路径与本地调用图的覆盖差异；
- 每个条目最多 24 个节点、每个函数最多 8,000 字符、总源码最多 60,000 字符，
  超出时保留截断标记，不让大文件拖垮报告生成或 Web 查看；
- 旧版 `pipeline_output.json` 在重新生成披露时也会从同目录产物进行内存回填，
  不改写原始扫描文件。

为保持源码保真，报告模型提示中的 `report_context` 会去除节点源码；源码仍由报告层
确定性保留，后续阶段再将调用链源码渲染到披露正文。位置、数据流和调用边证据会继续
提供给模型。

## 2. 自动化测试

执行目录：`libs/openant-core`

```text
pytest -q tests/report/test_report_context.py \
  tests/report/test_report_artifact_completeness.py \
  tests/report/test_disclosure_source_fidelity.py
结果：18 passed in 0.10s

../../.venv/bin/ruff check core/report_context.py core/reporter.py \
  report/generator.py tests/report/test_report_context.py
结果：All checks passed!

python -m py_compile core/report_context.py core/reporter.py report/generator.py
结果：通过
```

覆盖点包括：

1. 从临时 `results_verified.json`、增强数据集、native/semantic/recovered 图构建完整
   source-to-sink 上下文；
2. 断言精确起止行、入口/处理器/下游函数源码、语义边和恢复边均被保留；
3. 没有可选产物时仍能生成最小上下文，不抛异常、不伪造源码；
4. 历史 pipeline 只读回填后获得行号和 Stage 2 入口说明；
5. 原有披露源码保真测试继续通过，模型提示不会收到可被重写的原始源码。

## 3. 真实扫描产物回归

对已有 `sensors_medical_sensor` 扫描目录
`/Users/shiyu/.openant/webui/733647a3508bcb02` 使用真实的
`results_verified.json` 和同目录图产物在临时目录重建 pipeline：

```text
findings=16
目标函数：MedicalSensorServiceClient::EnableSensor
目标源码位置：medical_service_client.cpp:97-114
Stage 2 数据流步骤：7
调用链节点：22（未截断）
native/semantic/projected 边：17/1/2
```

该条目可解析出 `MedicalSensorServiceStub::OnRemoteRequest`、
`AfeEnableInner`、`MedicalSensorService::EnableSensor` 等 Stage 2 路径函数，并同时
保留目标函数、客户端调用者/被调用者和语义恢复边。跨进程路径与本地 native 图的
差异会在 `coverage_note` 中明确说明，而不会被误合并成普通 C++ 调用边。

## 4. 结论

本阶段完成了“披露上下文统一构建”并通过自动化和真实产物回归。报告正文目前仍沿用
原有章节和修复建议逻辑；下一阶段再处理完整修复代码、版本元数据，以及将调用链和
source-to-sink 信息直接渲染进 Markdown/HTML 披露正文。

