# OH-15A-2：OpenHarmony Unit 平台上下文测试记录

日期：2026-08-22
阶段：OH-15A-2
状态：通过，可进入下一阶段评审

## 1. 本阶段范围

本阶段只为 C/C++ Unit 和 analyzer output 增加 OpenHarmony 平台上下文，不接入规则引擎、Prompt 路由或语义图主流程。上下文使用稳定的 additive 字段：

```json
{
  "platform_context": {
    "platform": "openharmony",
    "source_role": "production",
    "component": ["..."],
    "target": ["..."],
    "boundary": ["binder_ipc"],
    "guard": [{"kind": "permission_check", "matched": "CheckPermission"}],
    "evidence": [{"source": "gn_target", "path": "...", "value": "..."}]
  }
}
```

`component`、`target` 使用列表，避免多个 manifest/target 时武断选择一个归属；无法安全匹配时保持空列表。`guard` 是词法信号，不代表该检查在所有控制流路径上都生效，也不等同于权限验证结论。

## 2. 修改前后逻辑

### 修改前

- C/C++ Unit 只有函数代码、调用依赖和一般 metadata，没有 component、GN target、源码角色或边界/guard 证据。
- C pipeline 虽然已保存 `openharmony_scope`，但 scope 没有传递到 UnitGenerator。
- analyzer output 也无法携带平台上下文。
- generic 项目没有平台上下文字段。

### 修改后

1. `CPipelineTest` 从 OpenHarmony scanner scope 构造受限的 `platform_context`，保留文件角色、bundle manifest 和 GN target；优先使用只读详细 GN parser，避免把无 sources 的 group target 误挂到源文件。
2. `UnitGenerator` 对函数源文件执行精确/前缀匹配：manifest 目录归属 component，GN target 的 `sources` 解析为仓库相对路径；每个匹配均保存 evidence。
3. boundary 由显式 profile 边界与 native 代码/路径信号合并；当前识别 Binder IPC、System Ability 和 HDF。
4. guard 由显式 guard 证据与 `Read/WriteInterfaceToken`、调用者身份、权限检查、system-app 检查等词法信号合并。
5. 在识别 boundary/guard 前屏蔽 C/C++ 注释、字符串和字符字面量，避免示例文本形成安全证据。
6. `generate_analyzer_output()` 以 `platformContext` 输出同一上下文；未传 OpenHarmony 上下文的 generic/旧调用路径不新增字段。
7. legacy scope 中一个 BUILD.gn 同时声明多个 target 且没有 target-source 所有权时，不把共享 sources 复制到每个 target，宁可不匹配，避免虚假归属。

## 3. 修改文件

- `libs/vulnfounder-core/parsers/c/unit_generator.py`
  - 新增 OpenHarmony 上下文归一化、component/target 匹配、boundary/guard 信号和证据输出；
  - 新增 C/C++ 注释/字面量屏蔽；
  - Unit 增加 `platform_context`，analyzer function 增加 `platformContext`。
- `libs/vulnfounder-core/parsers/c/test_pipeline.py`
  - 将 scanner scope/build metadata 适配为 UnitGenerator 上下文；
  - dataset metadata 增加简短 `openharmony_unit_context` 摘要，原 `openharmony_scope` 保持；
  - generic pipeline 行为保持不变。
- `libs/vulnfounder-core/tests/openharmony/test_unit_platform_context.py`
  - 新增本阶段 5 项契约测试。

## 4. TDD 记录

### RED

先加入契约测试后运行：

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_unit_platform_context.py
```

结果：`3 failed, 1 passed`。失败点为 Unit 缺少 `platform_context`、analyzer 缺少 `platformContext`，以及 C pipeline 生成的 unit 没有上下文；generic 不增加字段的兼容测试先通过。

### GREEN

实现后运行：

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_unit_platform_context.py
```

结果：`5 passed`。

新增测试覆盖：

- component、GN target、production role、Binder/System Ability boundary、interface-token/caller/permission guard；
- analyzer output 与 Unit 上下文一致；
- generic unit 不增加 OpenHarmony 字段；
- 注释和字符串中的 `CheckPermission`/`MessageParcel`/`ReadInterfaceToken` 不形成信号；
- 真实 C pipeline fixture 从 bundle/GN scope 推导 component/target。

## 5. 回归与质量检查

```text
VulnFounder/.venv/bin/pytest -q \
  VulnFounder/libs/vulnfounder-core/tests/openharmony \
  VulnFounder/libs/vulnfounder-core/tests/platforms/test_openharmony_entry_points.py \
  VulnFounder/libs/vulnfounder-core/tests/test_unit_language_metadata.py \
  VulnFounder/libs/vulnfounder-core/tests/parsers/c/test_c_schema_completeness.py \
  VulnFounder/libs/vulnfounder-core/tests/parsers/c
```

结果：`137 passed, 2 skipped`。

```text
VulnFounder/.venv/bin/ruff check \
  VulnFounder/libs/vulnfounder-core/parsers/c/unit_generator.py \
  VulnFounder/libs/vulnfounder-core/parsers/c/test_pipeline.py \
  VulnFounder/libs/vulnfounder-core/tests/openharmony/test_unit_platform_context.py
```

结果：`All checks passed!`。另外执行 `py_compile` 和 `git diff --check`，均通过。

## 6. 真实 OpenHarmony 仓库验证

验证仓库：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_wifi
```

命令：

```text
VulnFounder/.venv/bin/python \
  VulnFounder/libs/vulnfounder-core/parsers/c/test_pipeline.py \
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/communication_wifi \
  --output /private/tmp/openant-oh15a2-communication_wifi-final \
  --platform openharmony --skip-tests --processing-level all
```

pipeline 结果：成功，C parser 阶段耗时 `89.35s`。

| 指标 | 数量 |
|---|---:|
| 扫描生产 C/C++ 文件 | 683 |
| 提取函数 | 9,263 |
| 生成 Unit | 9,204 |
| 调用图边 | 11,305 |
| 带 platform context 的 Unit | 9,204 |
| component 非空 Unit | 9,204 |
| target 非空 Unit | 3,991 |
| boundary 非空 Unit | 478 |
| guard 非空 Unit | 335 |

boundary 信号分布：`binder_ipc=470`、`system_ability=12`。guard 信号分布：`interface_token=220`、`caller_identity=142`、`permission_check=20`。所有 9,204 个 Unit 的 `source_role` 均为 `production`；analyzer output 同步生成 9,204 个函数记录。

## 7. 阶段边界与后续

本阶段只提供可审计的静态上下文，不判断权限检查是否覆盖所有路径，不把 guard 信号直接转成漏洞结论，也没有把 component/target/boundary/guard 接入 Prompt 或语义图。下一阶段需在用户确认后，再单独讨论“上下文如何进入 Prompt/规则输入”的字段消费逻辑与测试。
