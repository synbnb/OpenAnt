# OH-21B-1：Stage 2 验证 Prompt 接入共享 OpenHarmony 上下文

日期：2026-08-23  
阶段：OH-21B-1  
状态：通过

## 1. 阶段边界

本阶段只把 `PlatformPromptContext` 接入 Stage 2 验证链路：

```text
analyzer_output function index
  → FindingVerifier
  → get_verification_prompt(...)
  → verify-phase platform context
```

本阶段不修改：

- Stage 2 的攻击模拟、工具调用、verdict 解析和结果融合；
- Context Enhancer；
- LLM Reachability；
- OpenHarmony 规则命中逻辑；
- generic 平台 Prompt；
- 真实远程 LLM 调用。

## 2. 原项目逻辑与修改后逻辑

### 修改前

`FindingVerifier.verify_result()` 只把代码、Stage 1 finding、攻击向量、
reasoning、文件列表和 `ApplicationContext` 传给
`prompts.verification_prompts.get_verification_prompt()`。

虽然 C/C++ analyzer output 中已经保存了当前函数的平台字段
`platformContext`，但 Stage 2 没有读取它。因此验证模型看不到当前函数的：

- Binder/System Ability 边界；
- `MessageParcel`、调用 UID、权限检查等 guard 信号；
- GN target、组件和 source role；
- `stub → transaction → handler` 语义关系。

### 修改后

1. `FindingVerifier` 根据当前 finding 的 `route_key` 查询已有的
   `RepositoryIndex`；
2. 优先读取静态 analyzer metadata 中的 `platformContext`，兼容读取
   `platform_context`；
3. 如果旧结果自身携带平台上下文，才回退读取结果字段；
4. 将上下文交给 `PlatformPromptContext` 做字段白名单、换行折叠、长度限制和
   结构化渲染；
5. 使用 `render_for_phase("verify")` 加入 Stage 2 Prompt；
6. generic、缺失上下文和 malformed 上下文都会安全地渲染为空，不改变原验证
   Prompt；
7. `PlatformPromptContext.from_mapping()` 现在同时接受 unit 的单数键名和
   `to_dict()` 的复数键名，保证 JSON round-trip 不丢字段。

## 3. 修改文件

- `libs/vulnfounder-core/prompts/verification_prompts.py`
  - 新增 `format_platform_context_for_verification()`；
  - `get_verification_prompt()` 增加可选 `platform_context` 参数；
  - 仅在存在 OpenHarmony 上下文时插入上下文区块。
- `libs/vulnfounder-core/utilities/finding_verifier.py`
  - 增加按 route key 获取静态平台上下文的逻辑；
  - 将上下文传递给 Stage 2 Prompt；
  - 保持原有 verification verdict 和错误处理流程。
- `libs/vulnfounder-core/core/platforms/prompt_context.py`
  - 增加单数/复数及 camelCase 字段别名读取，支持稳定 round-trip。
- `libs/vulnfounder-core/tests/openharmony/test_stage2_platform_context.py`
  - 新增 Stage 2 Prompt、FindingVerifier 转发、generic 隔离、注入清理和 round-trip
    测试；fake adapter 全程离线运行。

## 4. TDD 过程

新增测试第一次运行时发现：

```text
test_shared_context_round_trip_keeps_stage2_fields FAILED
components: expected ('health_service',), got ()
```

原因是共享对象输出 `components/targets/...` 复数键，而原解析器只识别
`component/target/...` 单数键。增加别名读取后重新执行，全部通过。

## 5. 测试结果

### 5.1 Stage 2 OpenHarmony 专项

```bash
../../.venv/bin/python -m pytest \
  tests/openharmony/test_stage2_platform_context.py -q
```

结果：

```text
5 passed in 0.02s
```

### 5.2 Stage 2 与 Prompt 安全回归

```bash
../../.venv/bin/python -m pytest \
  tests/test_analyze_verify_chain_llm_config.py \
  tests/test_fence_live_sites_escape.py \
  tests/test_json_corrector_verify_schema.py \
  tests/test_pr69_round4_verifier_bias.py \
  tests/test_pr69_round5_unverified.py \
  tests/test_threat_model_prompts.py \
  tests/test_verification_prompt_injection.py \
  tests/test_verifier_casing_ingestion_normalize.py \
  tests/test_verifier_consistency_disclosure_dropped_downgrade.py \
  tests/test_verifier_consistency_no_exploitable_downgrade.py \
  tests/test_verifier_max_tokens_finish_incomplete.py \
  tests/test_verifier_verdictonly_confirmed_drop.py -q
```

结果：

```text
74 passed in 0.44s
```

### 5.3 OpenHarmony 目录回归

```bash
../../.venv/bin/python -m pytest tests/openharmony -q
```

结果：

```text
55 passed, 2 skipped in 2.00s
```

### 5.4 静态与编译检查

以下检查均通过：

```bash
../../.venv/bin/ruff check \
  core/platforms/prompt_context.py \
  prompts/verification_prompts.py \
  utilities/finding_verifier.py \
  tests/openharmony/test_stage2_platform_context.py

git diff --check
../../.venv/bin/python -m compileall -q \
  core/platforms/prompt_context.py \
  prompts/verification_prompts.py \
  utilities/finding_verifier.py \
  tests/openharmony/test_stage2_platform_context.py
```

fake adapter 验证只捕获 Prompt 并返回离线 `finish` 工具结果，没有访问任何真实
LLM 服务。

## 6. 代表性 Prompt 结果

当 analyzer index 中存在如下平台信息时：

```text
platformContext.component = ["health_service"]
platformContext.boundary = ["binder_ipc"]
platformContext.guard = [{"kind": "permission_check", "matched": "CheckPermission"}]
```

Stage 2 Prompt 能看到：

```text
## OpenHarmony Platform Context

- Platform: openharmony
- Components: health_service
- Boundary signals: binder_ipc
- Guard signals: permission_check (matched: CheckPermission)
```

## 7. 结论与下一步

OH-21B-1 已完成。Stage 2 现在能够获得当前函数对应的、经过统一清理和限长的
OpenHarmony 静态证据；generic Prompt 和原有验证结论逻辑保持兼容。

下一阶段候选为 OH-21B-2：将共享上下文接入 Context Enhancer。该阶段需要额外
处理当前增强 Prompt 默认写成 JavaScript/TypeScript 的问题，并决定 OpenHarmony
上下文只作为证据还是参与缺失依赖/调用者提示；应另行确认后再修改。
