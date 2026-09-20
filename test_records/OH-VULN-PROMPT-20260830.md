# OH-VULN-PROMPT：通用漏洞分析提示词改造测试记录

- 日期：2026-08-30
- 阶段：漏洞分析提示词最小改造（Stage 1）
- 状态：通过，可进入模型回归验证
- 变更范围：仅 `libs/vulnfounder-core/prompts/vulnerability_analysis.py`；新增提示词契约测试
- 未修改：Stage 2、决策引擎、结果 schema 解析逻辑、Web 和动态测试

## 1. 改造目标

修复旧提示词“必须构造完整攻击载荷、必须说明攻击者获得未授权能力、否则默认安全”的分析偏差，使模型能够同时审查：

- IPC/Parcel/IDL、权限/认证/隔离边界；
- 空指针、越界、UAF、double free、泄漏和未初始化读取；
- 整数/尺寸错误、资源解析和资源耗尽；
- 并发、生命周期、回调、服务启停和死锁；
- 类型/ABI、Socket、NAPI、HDF/HDI、ioctl；
- 信息泄露、密码/传输、状态和业务逻辑；
- 服务崩溃、DoS、完整性破坏等不需要额外权限的影响。

提示词现在把“缺陷存在性、外部可达性、安全影响、证据完整性”分开要求，并规定缺少关键证据时使用 `INCONCLUSIVE`，不将缺少 PoC 当成 `SAFE`。

## 2. TDD 记录

### RED：修改前

先加入 `tests/test_generalized_vulnerability_prompt.py`，旧提示词无法满足以下契约：

- 必须明确“没有构造出完整攻击载荷不等于安全”；
- 必须出现退化输入；
- 必须覆盖崩溃、DoS、资源耗尽、信息泄露、完整性破坏；
- 必须覆盖 OpenHarmony 通用漏洞类别；
- 必须保留 `INCONCLUSIVE` 和上下文证据要求。

执行结果：`4 failed, 1 passed`，确认测试能够捕获旧提示词的不足。

### GREEN：修改后

执行：

```text
python -m pytest -q tests/test_generalized_vulnerability_prompt.py
```

结果：`5 passed in 0.02s`。

## 3. 回归测试

执行：

```text
python -m pytest -q \
  tests/test_generalized_vulnerability_prompt.py \
  tests/test_analysis_prompt_injection.py \
  tests/test_file_boundary.py \
  tests/test_threat_model_prompts.py \
  tests/openharmony/test_prompt_platform_context.py \
  tests/test_cwe_tagging.py
```

结果：`64 passed in 0.11s`。

另外执行提示词相关测试集合：

```text
python -m pytest -q tests/test_*prompt*.py tests/openharmony/test_prompt_*.py
```

结果：`48 passed in 0.11s`。

## 4. 静态检查

执行：

```text
python -m compileall -q prompts/vulnerability_analysis.py \
  tests/test_generalized_vulnerability_prompt.py
```

结果：通过。

当前虚拟环境未安装 `ruff`，执行 `python -m ruff check ...` 返回 `No module named ruff`，因此本阶段没有获得 ruff 检查结果。

## 5. CVE 目标函数提示词探针

从本地 `multimedia_audio_framework` 读取 `AudioPolicyServer::UnexcludeOutputDevices` 当前函数源码，生成不调用模型的 Stage-1 提示词：

```text
退化输入: True
服务崩溃: True
IPC/Parcel/IDL: True
vulnerability_categories: True
INCONCLUSIVE: True
target_chars=822 prompt_chars=5589
```

这只验证目标函数提示词包含了新的审查范围和输出字段，不代表模型已经给出正确漏洞结论；真实模型 A/B 需要在下一步固定 API、温度、版本和预算后执行。

## 6. 已知环境问题

尝试运行包含解析器的旧测试 `tests/openharmony/test_unit_semantic_context.py` 时，在测试收集阶段报：

```text
ModuleNotFoundError: No module named 'tree_sitter_c'
```

该问题发生在导入 tree-sitter 测试依赖时，未进入提示词代码；提示词相关的纯字符串测试不受影响。后续运行仓库解析器回归前，需要在项目虚拟环境中补齐 `tree-sitter-c` 依赖。

## 7. 本阶段结论

- 新提示词已经通过新增契约测试和现有提示词安全回归测试。
- 代码围栏、提示词注入防护、威胁模型分支、平台上下文和旧 finding 字段要求保持兼容。
- 当前只证明“提示词结构和字符串契约正确”，还没有证明任意大模型都能正确识别 CVE-2026-55989 或其他漏洞；下一步必须用固定的漏洞前/修复后代码和代表性安全样例进行真实模型 A/B 回归。
- `classification_reasoning` 字段读取不一致仍是后续需要单独修复和测试的问题，本阶段没有混入该行为改动。
