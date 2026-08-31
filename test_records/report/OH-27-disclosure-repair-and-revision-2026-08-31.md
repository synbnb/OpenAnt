# OH-27：披露修复代码与版本元数据测试记录

日期：2026-08-31

## 1. 本阶段目标

解决披露报告中 `Suggested Fix` 只有泛化人工复核句子、以及扫描版本缺失的问题。
本阶段不修改漏洞判定和调用图。

## 2. 修改前后逻辑

修改前：当 Stage 1 没有提供修复内容时，报告层直接使用
`[MANUAL REVIEW REQUIRED] Add the missing validation...`，并把这段文字作为模型的
修复代码占位符；版本只读取 pipeline 顶层字段，缺失时无法识别实际 checkout 版本。

修改后：

1. 新增 `report/prompts/repair.txt`，在有目标源码时单独调用报告模型，要求返回严格
   JSON，并生成最小替换片段或 unified diff；输入包括目标源码、漏洞类别、数据流和
   调用链证据；
2. 解析器只接受代码/差异形式，拒绝整篇披露文档、占位符和纯 prose；模型调用失败或
   证据不足时明确写“无法安全生成自动修复代码”，不把泛化句子伪装成代码；
3. `Suggested Fix` 由报告层确定性渲染，展示代码、修复说明、假设和生成状态；模型
   自己生成的同名章节会被替换；
4. 重新生成历史报告时读取 `scan.report.json`/`parse.report.json` 记录的源码路径，
   用无 shell 的 Git 查询补齐 branch、commit 和 tag 描述；优先显示 release 描述，
   再显示 commit，全部缺失时明确写“版本证据缺失”；
5. CLI disclosures 路径也执行同样的历史产物回填。

## 3. 自动化测试

执行目录：`libs/openant-core`

```text
python -m py_compile report/generator.py
结果：通过

pytest -q tests/report
结果：69 passed in 0.13s

../../.venv/bin/ruff check report/generator.py report/__main__.py \
  tests/report/test_report_context.py
结果：All checks passed!
```

新增覆盖点：

- 严格 JSON 修复响应能提取代码；整篇披露文档不会被误当成补丁；
- 模型返回修复代码时，最终报告不再出现 `[MANUAL REVIEW REQUIRED]`，而是显示代码和
  `修复状态：generated`；
- 扫描记录中的 Git checkout 能补齐 commit、branch 和 release_version；
- 没有源码时跳过无意义的修复模型调用，并给出明确缺失原因。

## 4. 真实扫描产物回归

使用真实扫描目录
`/Users/shiyu/.openant/webui/733647a3508bcb02`：

```text
源码 checkout：/Users/shiyu/学习/hyl/new/OpenAnt/source_code_base/sensors_medical_sensor
branch：master
commit：6f87daec8f0a91057336b0b243eee702bd8731e7
release_version：OpenHarmony-v6.1-LTS-5-g6f87dae
Affected：OpenHarmony-v6.1-LTS-5-g6f87dae
```

使用离线脚本模拟修复模型返回代码，对
`MedicalSensorServiceClient::EnableSensor` 生成报告：

```text
修复片段：if (samplingPeriod <= 0) return SENSOR_NATIVE_SAM_ERR;
Evidence Context：存在
目标行号：97-114
占位符：[MANUAL REVIEW REQUIRED] 不存在
```

该脚本只验证报告层的解析和渲染，不调用真实模型，也不修改源码仓库。

## 5. 当前限制

自动生成的补丁仍需维护者编译、单元测试和安全复核；报告层不会宣称补丁已经合入或
已经验证。若模型无法从当前证据安全确定修复位置，会保留明确的人工处理原因。

