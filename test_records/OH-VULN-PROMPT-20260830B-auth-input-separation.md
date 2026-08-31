# OH-VULN-PROMPT-20260830B：授权与输入可信度分离测试记录

## 目标

修复 OpenHarmony 漏洞分析提示词把“通过权限检查”误读为“输入可信”、把客户端校验当成服务端防护，以及在下游证据缺失时仍给出 `PROTECTED` 的问题。该阶段只修改提示词和内置 OpenHarmony 威胁模型，不改变漏洞判定代码、调用图或扫描流程。

## 原逻辑与新逻辑

- 原逻辑：攻击者描述容易把权限检查与参数安全混为一谈；Stage 2 采用“只能报告实际可利用漏洞”的表述；预分析分类直接显示为 `Pre-analysis hint`；客户端的长度限制可能被当作服务端证据；下游实现缺失时没有明确禁止 `PROTECTED`。
- 新逻辑：明确“Authorization is not input validation”；授权调用者仍可提交空容器、空指针元素、边界值、畸形值和重复请求；服务崩溃/DoS、资源耗尽、内存安全、生命周期、并发和隔离影响不要求提权；客户端校验不保护服务端；预分析结果标记为不可信假设；缺少关键下游证据时必须保持 `INCONCLUSIVE`；OpenHarmony 功能排除仅覆盖格式正确的正常业务行为，授权调用者导致的服务级 DoS 仍在范围内。

## 测试环境

- 项目：OpenAnt
- Python：当前项目虚拟环境
- 工作目录：`libs/openant-core`
- 测试类型：无模型调用的提示词单元/集成回归测试

## RED 阶段

先加入 4 个回归断言，针对旧提示词运行：

```text
python -m pytest -q tests/test_generalized_vulnerability_prompt.py
结果：5 passed, 4 failed
```

失败项证明旧逻辑缺少授权/输入分离、非提权影响、预分析不可信标记和 OpenHarmony 授权后畸形输入语义。

## GREEN 阶段

新增 Stage 1、Stage 2 和 OpenHarmony 内置基线提示词规则，并补充下游证据与功能排除语义后运行：

```text
python -m pytest -q tests/test_generalized_vulnerability_prompt.py
结果：10 passed

python -m pytest -q tests/test_generalized_vulnerability_prompt.py \
  tests/test_analysis_prompt_injection.py \
  tests/test_threat_model_prompts.py \
  tests/openharmony/test_application_context_baseline.py \
  tests/openharmony/test_prompt_platform_context.py \
  tests/test_cwe_tagging.py
结果：55 passed

python -m pytest -q tests/test_*prompt*.py tests/openharmony/test_prompt_*.py
结果：53 passed

python -m compileall -q prompts/vulnerability_analysis.py \
  prompts/threat_model_render.py context/openharmony_context.py \
  prompts/verification_prompts.py tests/test_generalized_vulnerability_prompt.py
结果：通过
```

## 关键检查结果

完整的 Stage 1 实际提示词导出见：[AudioPolicyServer_UnexcludeOutputDevices_analysis_prompt_v3.txt](../docs/AudioPolicyServer_UnexcludeOutputDevices_analysis_prompt_v3.txt)。

1. `get_analysis_prompt()` 会将预分析分类渲染为 `UNTRUSTED` 的 triage hypothesis，并明确不能把它当作 guard 或 counter-evidence。
2. Stage 1/Stage 2 都明确授权与输入可信度独立，且不要求攻击者获得额外权限才能认定服务级可用性影响。
3. Stage 1/Stage 2 都明确客户端限制不能替代服务端校验。
4. 当危险影响依赖未提供的下游函数时，提示词要求 `INCONCLUSIVE`，禁止用缺失证据推断 `SAFE` 或 `PROTECTED`。
5. OpenHarmony 内置攻击者画像允许“在授权调用之后”提供畸形参数，同时仍禁止假设 shell/root 或绕过授权逻辑本身。
6. 仓库功能排除被限定为格式正确输入下的预期业务行为，不再排除畸形输入导致的崩溃、DoS、资源耗尽、内存、生命周期、并发、隔离和服务级可用性影响。

## 限制与后续

- 本记录未调用真实大模型，不能单凭提示词测试证明 CVE-2026-55989 在所有模型上都一定命中。
- 当前 `core/analysis_core.py` 对 `agent_context` 仍读取旧的 `reasoning` 字段；数据集中的 `classification_reasoning` 字段兼容修复应作为独立阶段处理，避免与本阶段混淆。
- 下一步应使用 multimedia_audio_framework 的漏洞前/后版本做一次固定模型 A/B：记录 Stage 1、Stage 2 的原始提示词、原始响应、最终 verdict 以及是否正确识别 NULL dereference/服务 DoS。
