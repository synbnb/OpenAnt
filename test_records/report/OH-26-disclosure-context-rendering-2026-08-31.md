# OH-26：披露报告上下文渲染测试记录

日期：2026-08-31

## 1. 本阶段目标

第 1 阶段已经把证据放入 `pipeline_output.findings[].report_context`。本阶段将这些
证据接入披露报告：模型可以看到文件/行号、数据流和调用图关系；报告层在模型输出后
确定性追加源码和调用链，避免模型改写真实源码。

## 2. 修改前后逻辑

修改前：模型只生成摘要、复现步骤、影响和修复建议；最终文档只有一个目标函数的
`Vulnerable Code` 片段，没有完整调用链或 source→sink 证据。

修改后：

1. `report/prompts/disclosure.txt` 明确要求模型引用 `report_context` 的证据，不得
   自行补写函数、边或行号；
2. 报告模型提示保留上下文的结构化信息，但继续删除上下文里的原始源码，源码由
   确定性渲染器插入；
3. 披露文档新增 `## Evidence Context`，包含目标位置、Stage 2 数据流、入口和 sink
   状态、调用链中每个函数的文件/行号/源码，以及 native、semantic、恢复边；
4. 如果模型自己输出同名章节，会先删除，再追加扫描产物生成的版本；缺少证据时明确
   写出“源码未保存在当前扫描产物中”，不伪造内容。

## 3. 自动化测试

执行目录：`libs/vulnfounder-core`

```text
python -m py_compile report/generator.py
结果：通过

pytest -q tests/report
结果：66 passed in 0.13s

../../.venv/bin/ruff check core/report_context.py core/reporter.py \
  report/generator.py tests/report/test_report_context.py
结果：All checks passed!
```

新增测试断言：

- 报告正文包含真实文件和起止行号；
- 包含入口函数、调用链源码和调用图边类型；
- Stage 2 的有序 source→sink 步骤可见；
- 模型提示仍不包含原始源码，防止生成器重写源码片段；
- 旧版报告和无上下文产物不会报错。

## 4. 真实产物回归

使用真实扫描目录
`/Users/shiyu/.openant/webui/733647a3508bcb02` 重建 pipeline 后渲染
`MedicalSensorServiceClient::EnableSensor`：

```text
证据上下文长度：34,291 字符
目标位置：frameworks/native/medical_sensor/src/medical_service_client.cpp，第 97-114 行
Stage 2 数据流：7 步
调用链节点：22
调用图边：native 17、semantic 1、projected/recovered 2
```

正文开头包含 `## Evidence Context`，并能看到
`MedicalSensorServiceStub::OnRemoteRequest`、`AfeEnableInner`、
`MedicalSensorService::EnableSensor` 的文件、行号和源码。目标源码和调用链源码均来自
扫描产物，不经过大模型重写。

## 5. 当前限制

本阶段解决了“报告缺少调用链和 source→sink 信息”。缺失具体修复代码和版本信息的
问题仍属于下一阶段：需要根据漏洞类别和真实目标源码生成可审阅的最小补丁，并在无法
安全自动修复时明确给出原因，而不是只输出泛化的人工复核句子。

