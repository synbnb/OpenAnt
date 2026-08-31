# OH-22F-3D：LLM 分派证据复核协议测试记录

## 1. 阶段范围

本阶段新增一个独立的 OpenHarmony LLM selector/value 复核模块：

- `libs/openant-core/core/platforms/openharmony/llm_dispatch_review.py`
- `libs/openant-core/tests/openharmony/test_llm_dispatch_review.py`

本阶段只建立上下文、协议、校验和重试边界，不接入 scanner，不修改 `call_graph.json`、`openharmony_dispatch_code_evidence.json`、reachable 或 dataset，也没有调用真实大模型 API。

## 2. 原逻辑与新逻辑

原逻辑只有确定性数字证据解析：当 selector 是复杂 C++ 表达式、具名 enum、字符串命令或运行时值时，直接保留为 `unresolved_symbol`。

新逻辑增加独立的 advisory 复核路径：

1. 只提取当前 evidence 中未解析的 case；
2. 为每个 case 打包 caller、dispatch 表达式、注册证据、候选 target、相关 enum/macro/constant 源码片段；
3. 按最大 case 数和 prompt 字符数自动分批；
4. 要求模型返回严格 JSON，只解释 selector/value，不允许新增 handler 或调用边；
5. 校验 case id、值类型、证据文件/行号/文本是否出现在提供的上下文中；
6. 高置信且证据匹配的结果标记 `llm_verified`，中低置信结果标记 `llm_advisory`，其余保留 `keep_unresolved` 或拒绝。

## 3. TDD 测试过程

### RED

先添加测试，再运行：

```text
.venv/bin/pytest -q libs/openant-core/tests/openharmony/test_llm_dispatch_review.py
```

结果：测试收集失败，`ModuleNotFoundError: core.platforms.openharmony.llm_dispatch_review`。这确认测试确实约束了待实现模块。

### GREEN

完成模块后运行同一命令：

```text
7 passed in 0.02s
```

覆盖内容：

- 未解析 case 筛选及源码上下文打包；
- enum 定义、注册语句、caller/target 上下文保留；
- 安全 prompt fence 和禁止新增调用边的规则；
- 高置信 source-backed integer 结果接受；
- 未知 case、上下文外证据拒绝；
- malformed response 重试；
- 空 worklist 不调用模型；
- prompt 字符限制下的批处理不丢 case。

## 4. OpenHarmony 定向回归

```text
.venv/bin/pytest -q libs/openant-core/tests/openharmony
145 passed, 2 skipped in 2.31s
```

静态检查：

```text
.venv/bin/ruff check ...
All checks passed!
git diff --check
通过
```

## 5. 真实参考仓库离线打包验证

输入使用已生成的 `debug_outputs/OH-22F-3C-reference-corpus-20260827/<仓库>/openharmony_dispatch_code_evidence.json`，源码使用 `/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code`，函数索引使用同批次的 `call_graph.json`。

结果：

| 仓库 | 未解析 case | 自动 batch 数 | prompt 长度范围 |
|---|---:|---:|---:|
| communication_netmanager_base | 307 | 41 | 约 10.2 万～12.0 万字符 |
| developtools_hdc | 0 | 0 | 不适用 |
| hiviewdfx_faultloggerd | 18 | 1 | 约 9.8 万字符 |
| hiviewdfx_hilog | 6 | 1 | 约 5.1 万字符 |
| hiviewdfx_hiview | 18 | 2 | 约 10.3 万～11.8 万字符 |
| multimedia_audio_framework | 114 | 10 | 约 5.9 万～11.9 万字符 |
| startup_appspawn | 0 | 0 | 不适用 |
| startup_init | 0 | 0 | 不适用 |
| telephony_core_service | 285 | 69 | 约 5.5 万～12.0 万字符 |

合计 748 个未解析 case，分为 124 个受控 batch；上下文构造过程中没有调用 API，也没有丢弃 case。源码索引建立为每仓库一次，避免每个 case 重复扫描全部文件。

## 6. 产物与当前限制

本阶段主要产物是代码和测试，不生成 LLM 结果文件。下一阶段接入 scanner 时应新增独立的 `openharmony_dispatch_llm_review.json` 及阶段 report，并将每个 batch 的 prompt hash、调用次数、重试次数、accepted/advisory/keep_unresolved/rejected 记录下来。

当前 `llm_verified` 表示“模型引用的证据确实来自提供上下文且值类型合法”，不等于编译器级别的语义证明；无法独立验证的结果仍应作为 advisory 展示，不能直接覆盖确定性证据。

