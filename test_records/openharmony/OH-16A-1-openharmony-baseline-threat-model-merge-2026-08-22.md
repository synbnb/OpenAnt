# OH-16A-1：OpenHarmony 最低攻击者基线与 Threat Model 单调合并

日期：2026-08-22
阶段：OH-16A-1
状态：通过，可进入下一阶段评审

## 1. 阶段目标

OH-15 已经把 OpenHarmony 的边界、IDL/SA/IPC 语义和 Unit 上下文接通，但应用级 Threat Model 仍可能声明“没有本地攻击者”或“IPC 输入可信”。本阶段建立平台拥有的最低安全基线，确保仓库内的 `OPENANT.THREATMODEL.md` 只能补充业务上下文，不能删除 OpenHarmony 平台最低攻击者、输入边界和检查标准。

本阶段不实现 `--threat-model-trust` CLI，也不实现 Finding 级 suppression accounting；这两项保留给后续 OH-16A-2。

## 2. 修改前后逻辑

### 修改前

1. `OpenHarmonyProfileBuilder` 能识别 `binder_ipc`、`system_ability`、`hdf`、`idl` 等信号，但信号只进入 `platform_profile.json`。
2. scanner 发现仓库 Threat Model 后，直接把它作为完整 `ApplicationContext`。
3. Threat Model 的 attacker profiles、trust boundaries 和 `not_a_vulnerability` 会直接影响 Stage 1/Stage 2 Prompt。
4. OpenHarmony 没有内置的本地 IPC 调用者和 Parcel 输入边界，因此仓库模型可以间接压制本地 IPC 风险。

### 修改后

1. 新增 `context/openharmony_context.py`，从平台 profile 构造确定性的 OpenHarmony baseline。
2. Binder/SA/IDL 基线至少包含：
   - `openharmony_local_ipc_caller`：无特权本地应用，可调用暴露的 Binder/SA 接口并控制 Parcel 字段、长度和请求频率；不假设 shell/root/宿主文件权限；
   - `openharmony_restricted_system_app`：权限受限的系统应用，可调用其授权范围内的跨 SA 路径；
   - `openharmony_binder_parcel`：`untrusted` 的调用方控制输入；
   - `openharmony_calling_identity`：用于授权判断的 `semi_trusted` 调用者身份元数据。
3. HDF/HDI 边界加入 `openharmony_device_data_source` 和 `openharmony_device_data`；网络/Wi-Fi/蓝牙等 profile 边界加入远程/邻近输入基线。
4. 平台基线的 attacker、input source、vulnerability criteria 以 baseline-first 顺序合并：
   - 同 ID 的仓库 attacker 不能覆盖平台 attacker；
   - 同名 input source 不能把平台的 `untrusted` 降级为 `trusted`；
   - baseline criteria 始终保留；
   - 仓库 `not_a_vulnerability` 保留为 `repository_advisory_exclusions`，Prompt 明确其不能覆盖平台基线；
   - 所有冲突和仓库排除项均进入 provenance。
5. 显式 `--platform openharmony` 但 profile 不完整时，仍使用保守 Binder baseline，避免元数据缺失成为本地 IPC blackout。
6. baseline provenance 写入：
   - `application_context.json` 的 `platform_baseline`、`platform_baseline_conflicts`、`context_provenance`；
   - `ScanResult`/`scan.report.json` 的 `application_context_provenance`；
   - `pipeline_output.json` 的 `application_context_provenance`；
   - 生成报告的确定性 provenance header。
7. generic context、旧 ApplicationContext JSON 和旧 duck-typed context 调用保持兼容；scanner 只对真实 `ApplicationContext` 应用基线合并。

## 3. 修改文件

- [application_context.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/context/application_context.py)
  - 新增 `openharmony_component` 类型；
  - 增加 baseline、冲突、仓库 advisory 和 provenance 的兼容字段；
  - 增加 `has_openharmony_baseline()`。
- [openharmony_context.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/context/openharmony_context.py)
  - 新增 baseline 生成和单调合并实现。
- [scanner.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/scanner.py)
  - OpenHarmony app-context 阶段接入合并；
  - 将 provenance 传递到 ScanResult、scan report 和 pipeline output；
  - 兼容旧版 duck-typed context。
- [schemas.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/schemas.py)
  - 新增可选 `application_context_provenance`。
- [reporter.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/core/reporter.py)
  - `pipeline_output.json` 增加可选 provenance。
- [vulnerability_analysis.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/prompts/vulnerability_analysis.py)
  - Stage 1 强制渲染 OpenHarmony baseline 和 advisory exclusion 语义。
- [verification_prompts.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/prompts/verification_prompts.py)
  - Stage 2 使用同一平台最低基线。
- [threat_model_render.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/prompts/threat_model_render.py)
  - 增加 mandatory baseline、边界、输入和检查项渲染。
- [generator.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/report/generator.py)
  - 报告 header 确定性显示 OpenHarmony baseline 和合并冲突数量。
- [test_application_context_baseline.py](/Users/shiyu/学习/hyl/new/OpenAnt/libs/openant-core/tests/openharmony/test_application_context_baseline.py)
  - 新增 11 项专项测试，包含真实 scanner artifact 链路。

## 4. TDD 记录

### RED

先加入专项测试，再执行：

```text
OpenAnt/.venv/bin/pytest -q \
  OpenAnt/libs/openant-core/tests/openharmony/test_application_context_baseline.py
```

结果：测试收集失败，`ModuleNotFoundError: context.openharmony_context`。该失败对应尚未实现的 baseline 模块，确认测试没有依赖旧实现伪通过。

### GREEN

实现后专项测试结果：

```text
11 passed in 2.01s
```

覆盖内容：IPC/HDF baseline、显式 OpenHarmony 但 profile 不完整、generic 不变、Threat Model 不能移除 baseline、Stage 1/Stage 2 Prompt、context round-trip、三个扫描 artifact 和报告 header。

## 5. 回归测试

### OpenHarmony、Threat Model、Prompt、C parser 相关套件

```text
257 passed, 2 skipped in 1.05s
```

覆盖 `tests/openharmony`、OpenHarmony entry/IPC/SA graph、C parser、Threat Model schema/render/hardening、scanner integration、artifact serialization 和 platform profile。

### generic Python parser/call-graph 套件（独立进程）

```text
77 passed in 3.01s
```

### 静态检查

- Ruff：`All checks passed!`
- 相关 Python 文件 `py_compile`：通过；
- trailing whitespace 检查：空；
- tracked 文件 `git diff --check`：通过。

## 6. 完整测试集观察

曾执行整个 `libs/openant-core/tests`：

```text
3113 passed, 23 failed, 40 skipped
```

失败没有落在 OH-16A-1 代码或专项测试上：

1. Go conformance 测试因当前环境没有 `go` 可执行文件失败；
2. generic Python parser/call-graph 测试在与 OpenHarmony 测试混合收集的单进程顺序下出现既有模块/全局状态污染，表现为扫描到 0 个文件；同一套测试独立进程执行为 `77 passed`；
3. OpenHarmony 测试独立执行时必须同时带上 C parser 测试路径，以避免仓库内同名 `test_pipeline.py` 的 pytest 模块收集冲突；按阶段命令执行结果为 `257 passed, 2 skipped`。

因此本阶段验收采用按边界隔离的专项和回归命令，而不是把环境缺失/既有测试收集冲突误记为 OH-16A-1 回归。

## 7. 当前边界

本阶段已经保证 OpenHarmony 平台最低攻击者集合不会被仓库 Threat Model 删除，并且冲突可审计；但 operator 可选 trust tier、逐 Finding 的 suppression accounting、报告中按 Finding 展示“若无仓库排除会报告什么”仍未实现。这些是下一阶段 OH-16A-2 的范围。
